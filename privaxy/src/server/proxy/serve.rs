use super::html_rewriter::Rewriter;
use super::mitm::BoxBodyType;
use crate::blocker::AdblockRequester;
use crate::events::Event;
use crate::statistics::Statistics;
use adblock::blocker::BlockerResult;
use bytes::Bytes;
use http::uri::{Authority, Scheme};
use http::{StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::Request;
use hyper::Response;
use std::net::IpAddr;
use tokio::sync::broadcast;

fn empty_body() -> BoxBodyType {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

fn full_body<T: Into<Bytes>>(chunk: T) -> BoxBodyType {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve(
    adblock_requester: AdblockRequester,
    request: Request<Incoming>,
    client: reqwest::Client,
    authority: Authority,
    scheme: Scheme,
    broadcast_sender: broadcast::Sender<Event>,
    statistics: Statistics,
    client_ip_address: IpAddr,
) -> Result<Response<BoxBodyType>, hyper::Error> {
    let scheme_string = scheme.to_string();

    let uri = match http::uri::Builder::new()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(match request.uri().path_and_query() {
            Some(path_and_query) => path_and_query.as_str(),
            None => "/",
        })
        .build()
    {
        Ok(uri) => uri,
        Err(_err) => {
            return Ok(get_empty_response(http::StatusCode::BAD_REQUEST));
        }
    };

    if request.headers().contains_key(http::header::UPGRADE) {
        return Ok(perform_two_ends_upgrade(request, uri, client).await);
    }

    let (parts, body) = request.into_parts();
    let method = parts.method.clone();
    let headers = parts.headers.clone();
    let request_uri = uri.clone();

    log::debug!("{} {}", method, request_uri);

    statistics.increment_top_clients(client_ip_address);

    let (is_request_blocked, blocker_result) = adblock_requester
        .is_network_url_blocked(
            uri.to_string(),
            match headers.get(http::header::REFERER) {
                Some(referer) => referer.to_str().unwrap().to_string(),
                // When no referer, we default to `uri` as we otherwise may get many false
                // positives due to the blocker thinking it's third party requests.
                None => uri.to_string(),
            },
        )
        .await;

    let _result = broadcast_sender.send(Event {
        now: chrono::Utc::now(),
        method: method.to_string(),
        url: request_uri.to_string(),
        is_request_blocked,
    });

    if is_request_blocked {
        statistics.increment_blocked_requests();
        statistics.increment_top_blocked_paths(format!(
            "{}://{}{}",
            scheme_string,
            uri.host().unwrap(),
            uri.path()
        ));

        log::debug!("Blocked request: {}", uri);

        return Ok(get_blocked_by_privaxy_response(blocker_result));
    }

    let mut request_headers = headers.clone();
    request_headers.remove(http::header::CONNECTION);
    request_headers.remove(http::header::HOST);

    // Collect the body
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => Bytes::new(),
    };

    let mut response = match client
        .request(method, uri.to_string())
        .headers(request_headers)
        .body(body_bytes)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => return Ok(get_informative_error_response(&err.to_string())),
    };

    statistics.increment_proxied_requests();

    let response_status = response.status();
    let response_headers = response.headers().clone();

    // Check if we need to rewrite HTML
    if let Some(content_type) = response_headers.get(http::header::CONTENT_TYPE) {
        if let Ok(value) = content_type.to_str() {
            if value.contains("text/html") {
                let (body_sender, body_receiver) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, hyper::Error>>(32);
                let (sender_rewriter, receiver_rewriter) = crossbeam_channel::unbounded::<Bytes>();

                let rewriter = Rewriter::new(
                    uri.to_string(),
                    adblock_requester,
                    receiver_rewriter,
                    body_sender.clone(),
                    statistics,
                );

                tokio::task::spawn_blocking(move || rewriter.rewrite());

                // Stream response body to rewriter
                tokio::spawn(async move {
                    while let Ok(Some(chunk)) = response.chunk().await {
                        if sender_rewriter.send(chunk).is_err() {
                            break;
                        }
                    }
                    drop(sender_rewriter);
                });

                let body_stream = tokio_stream::wrappers::ReceiverStream::new(body_receiver);
                let stream_body = StreamBody::new(body_stream);

                let mut new_response = Response::builder()
                    .status(response_status)
                    .body(stream_body.boxed())
                    .unwrap();

                *new_response.headers_mut() = response_headers;
                return Ok(new_response);
            }
        }
    }

    // For non-HTML responses, stream directly
    let (body_sender, body_receiver) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, hyper::Error>>(32);

    tokio::spawn(async move {
        while let Ok(Some(chunk)) = response.chunk().await {
            if body_sender.send(Ok(Frame::data(chunk))).await.is_err() {
                break;
            }
        }
    });

    let body_stream = tokio_stream::wrappers::ReceiverStream::new(body_receiver);
    let stream_body = StreamBody::new(body_stream);

    let mut new_response = Response::builder()
        .status(response_status)
        .body(stream_body.boxed())
        .unwrap();

    *new_response.headers_mut() = response_headers;
    Ok(new_response)
}

fn get_informative_error_response(reason: &str) -> Response<BoxBodyType> {
    let mut response_body = String::from(include_str!("../../resources/head.html"));
    response_body +=
        &include_str!("../../resources/error.html").replace("#{request_error_reson}#", reason);

    Response::builder()
        .status(http::StatusCode::BAD_GATEWAY)
        .body(full_body(response_body))
        .unwrap()
}

fn get_blocked_by_privaxy_response(blocker_result: BlockerResult) -> Response<BoxBodyType> {
    // We don't redirect to network urls due to security concerns.
    if let Some(resource) = blocker_result.redirect {
        return Response::builder()
            .status(http::StatusCode::OK)
            .body(full_body(resource))
            .unwrap();
    }

    let filter_information = match blocker_result.filter {
        Some(filter) => filter,
        None => "No information".to_string(),
    };

    let mut response_body = String::from(include_str!("../../resources/head.html"));
    response_body += &include_str!("../../resources/blocked_by_privaxy.html")
        .replace("#{matching_filter}#", &filter_information);

    Response::builder()
        .status(http::StatusCode::FORBIDDEN)
        .body(full_body(response_body))
        .unwrap()
}

fn get_empty_response(status_code: http::StatusCode) -> Response<BoxBodyType> {
    Response::builder()
        .status(status_code)
        .body(empty_body())
        .unwrap()
}

/// When we receive a request to perform an upgrade, we need to initiate a bidirectional tunnel.
async fn perform_two_ends_upgrade(
    request: Request<Incoming>,
    uri: Uri,
    _client: reqwest::Client,
) -> Response<BoxBodyType> {
    // For WebSocket upgrades, we'll tunnel directly
    let (mut duplex_client, mut duplex_server) = tokio::io::duplex(32 * 1024);

    tokio::spawn(async move {
        match hyper::upgrade::on(request).await {
            Ok(upgraded) => {
                let mut upgraded = hyper_util::rt::TokioIo::new(upgraded);
                let _result = tokio::io::copy_bidirectional(&mut upgraded, &mut duplex_client).await;
            }
            Err(e) => {
                log::debug!("Unable to upgrade: {}", e)
            }
        }
    });

    // Connect to upstream
    let host = uri.host().unwrap_or("localhost");
    let port = uri.port_u16().unwrap_or(443);
    let addr = format!("{}:{}", host, port);

    tokio::spawn(async move {
        match tokio::net::TcpStream::connect(&addr).await {
            Ok(mut server) => {
                let _result = tokio::io::copy_bidirectional(&mut duplex_server, &mut server).await;
            }
            Err(e) => {
                log::debug!("Unable to connect to upstream for upgrade: {}", e)
            }
        }
    });

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .body(empty_body())
        .unwrap()
}

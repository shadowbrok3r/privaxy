use super::mitm::{BodyError, BoxBodyType, Peer, Proxy};
use crate::{
    blocker::AdblockRequester,
    body::CaptureBody,
    capture::{Exchange, PendingResponse, header_pairs},
    statistics::Statistics,
};
use adblock::blocker::BlockerResult;
use bytes::Bytes;
use futures_util::StreamExt;
use http::uri::{Authority, Scheme};
use http::{StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Full, StreamBody};
use hyper::{
    Request, Response,
    body::{Frame, Incoming},
};
use std::sync::Arc;

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

fn strip_hop_headers(headers: &mut http::HeaderMap) {
    let nominated: Vec<String> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|name| name.trim().to_owned())
        .collect();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "proxy-connection",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

/// Clients for upstream requests: reqwest for ordinary traffic, and hyper, which keeps trailers, for gRPC.
#[derive(Clone)]
pub(crate) struct Upstream {
    pub(crate) http: reqwest::Client,
    grpc: GrpcClient,
}

type GrpcClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    BoxBodyType,
>;

impl Upstream {
    /// gRPC trusts the public web roots, as `http` does.
    pub(crate) fn new(http: reqwest::Client) -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        Self::with_roots(http, roots)
    }

    pub(crate) fn with_roots(http: reqwest::Client, roots: rustls::RootCertStore) -> Self {
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        Self {
            http,
            grpc: hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build(connector),
        }
    }
}

/// gRPC over HTTP/2, which reports its status in trailers; gRPC-Web carries them in the body.
fn is_grpc(headers: &http::HeaderMap) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.starts_with("application/grpc") && !value.starts_with("application/grpc-web")
        })
}

/// Forwards a gRPC call over HTTP/2 with its trailers in both directions.
async fn forward_grpc(
    client: &GrpcClient,
    method: http::Method,
    uri: Uri,
    headers: http::HeaderMap,
    body: BoxBodyType,
) -> Result<Response<BoxBodyType>, String> {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .version(http::Version::HTTP_2)
        .body(body)
        .map_err(|error| error.to_string())?;
    *request.headers_mut() = headers;
    let response = client
        .request(request)
        .await
        .map_err(|error| error.to_string())?;
    Ok(response.map(|body| {
        body.map_err(|error| -> BodyError { Box::new(error) })
            .boxed()
    }))
}

/// Whether `authority` names the proxy listener `peer` connected to.
fn is_direct(authority: &Authority, peer: &Peer) -> bool {
    if authority.port_u16() != Some(peer.proxy.port()) {
        return false;
    }
    match authority
        .host()
        .trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
    {
        Ok(ip) => ip.is_loopback() || ip == peer.proxy.ip(),
        Err(_) => authority.host().eq_ignore_ascii_case("localhost"),
    }
}

pub(crate) async fn serve(
    proxy: Proxy,
    request: Request<Incoming>,
    authority: Authority,
    scheme: Scheme,
    peer: Peer,
) -> Result<Response<BoxBodyType>, hyper::Error> {
    if is_direct(&authority, &peer) {
        return Ok(direct_response(request.uri().path(), &proxy.ca_der));
    }
    let Proxy {
        adblock: adblock_requester,
        upstream,
        events: broadcast_sender,
        statistics,
        capture,
        ..
    } = proxy;
    let scheme_string = scheme.to_string();
    let uri = match http::uri::Builder::new()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(request.uri().path_and_query().map_or("/", |p| p.as_str()))
        .build()
    {
        Ok(uri) => uri,
        Err(_) => return Ok(get_empty_response(StatusCode::BAD_REQUEST)),
    };
    let headers = request.headers().clone();
    let method = request.method().clone();
    let is_head = method == http::Method::HEAD;
    let (blocked, blocker_result) = adblock_requester
        .is_network_url_blocked(
            uri.to_string(),
            headers
                .get(http::header::REFERER)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
                .unwrap_or_else(|| uri.to_string()),
        )
        .await;
    let mut details = Exchange::default();
    details.request_headers = header_pairs(&headers);
    details.request_version = request.version();
    details.client = peer.ip;
    details.app = peer.app.as_deref().map(str::to_owned);
    let event = capture.begin(method.to_string(), uri.to_string(), blocked, details);
    log::debug!(
        "HTTP id={} method={} host={} blocked={blocked}",
        event.id,
        method,
        uri.host().unwrap_or_default()
    );
    let exchange = event.exchange.clone();
    let _ = broadcast_sender.send(event);
    let mut pending = PendingResponse(Some(exchange.clone()));
    statistics.increment_top_clients(peer.ip);

    let response = async {
        if !blocked && headers.contains_key(http::header::UPGRADE) {
            exchange.lock().unwrap().note = Some(
                "Protocol upgrade: HTTP handshake captured; upgraded frames are not decoded."
                    .into(),
            );
            return perform_two_ends_upgrade(request, uri, peer.cancellation.clone()).await;
        }
        let (_, body) = request.into_parts();
        let body = CaptureBody::new(body, exchange.clone(), true);
        if blocked {
            statistics.increment_blocked_requests();
            statistics.increment_top_blocked_paths(format!(
                "{}://{}{}",
                scheme_string,
                uri.host().unwrap_or_default(),
                uri.path()
            ));
            // Preserve the received request body even when the filter rejects the request.
            if let Err(error) = body.collect().await {
                exchange
                    .lock()
                    .unwrap()
                    .fail(format!("Request body failed: {error}"));
            }
            return get_blocked_by_privaxy_response(blocker_result);
        }
        let grpc = is_grpc(&headers);
        let te_trailers = headers
            .get(http::header::TE)
            .is_some_and(|te| te.as_bytes().eq_ignore_ascii_case(b"trailers"));
        let mut request_headers = headers;
        strip_hop_headers(&mut request_headers);
        request_headers.remove(http::header::HOST);
        if grpc {
            if te_trailers {
                request_headers
                    .insert(http::header::TE, http::HeaderValue::from_static("trailers"));
            }
            let body = BodyExt::boxed(body.map_err(|error| -> BodyError { Box::new(error) }));
            return match forward_grpc(&upstream.grpc, method, uri, request_headers, body).await {
                Ok(mut response) => {
                    statistics.increment_proxied_requests();
                    exchange.lock().unwrap().response(
                        response.status().as_u16(),
                        response.version(),
                        response.headers(),
                    );
                    strip_hop_headers(response.headers_mut());
                    response
                }
                Err(error) => {
                    log::warn!("Upstream gRPC request failed: {error}");
                    exchange
                        .lock()
                        .unwrap()
                        .fail(format!("Upstream request failed: {error}"));
                    get_informative_error_response(&error)
                }
            };
        }
        let mut response = match upstream
            .http
            .request(method, uri.to_string())
            .headers(request_headers)
            .body(reqwest::Body::wrap_stream(body.into_data_stream()))
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                let error = error.without_url();
                log::warn!("Upstream request failed: {error}");
                exchange
                    .lock()
                    .unwrap()
                    .fail(format!("Upstream request failed: {error}"));
                return get_informative_error_response(&error.to_string());
            }
        };
        statistics.increment_proxied_requests();
        let status = response.status();
        let mut headers = response.headers().clone();
        exchange
            .lock()
            .unwrap()
            .response(status.as_u16(), response.version(), &headers);
        strip_hop_headers(&mut headers);
        if is_head {
            let mut response = Response::new(empty_body());
            *response.status_mut() = status;
            *response.headers_mut() = headers;
            return response;
        }
        let html = headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("text/html"));
        // Only small HTML documents need buffering for cosmetic rewriting. Everything else,
        // including SSE and large/binary downloads, is forwarded and captured incrementally.
        const MAX_REWRITE: usize = 1024 * 1024;
        let mut prefix = Vec::new();
        if html && adblock_requester.filtering_enabled() {
            loop {
                match response.chunk().await {
                    Ok(Some(chunk)) => {
                        prefix.extend_from_slice(&chunk);
                        if prefix.len() > MAX_REWRITE {
                            break;
                        }
                    }
                    Ok(None) => {
                        let rewritten = rewrite_html(
                            uri.to_string(),
                            Bytes::from(prefix),
                            adblock_requester,
                            statistics,
                        )
                        .await;
                        headers.remove(http::header::CONTENT_LENGTH);
                        let mut response = Response::new(full_body(rewritten));
                        *response.status_mut() = status;
                        *response.headers_mut() = headers;
                        return response;
                    }
                    Err(error) => {
                        exchange
                            .lock()
                            .unwrap()
                            .fail(format!("Upstream response body failed: {error}"));
                        return get_informative_error_response(&error.to_string());
                    }
                }
            }
        }
        let first = futures_util::stream::iter(
            (!prefix.is_empty()).then(|| Ok::<_, BodyError>(Frame::data(Bytes::from(prefix)))),
        );
        let rest = response.bytes_stream().map(|chunk| {
            chunk
                .map(Frame::data)
                .map_err(|e| -> BodyError { Box::new(e) })
        });
        let body = BodyExt::boxed(StreamBody::new(first.chain(rest)));
        let mut response = Response::new(body);
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        response
    }
    .await;

    exchange.lock().unwrap().response(
        response.status().as_u16(),
        response.version(),
        response.headers(),
    );
    log::debug!(
        "HTTP response status={} client={}",
        response.status(),
        peer.ip
    );
    pending.disarm();
    let (parts, body) = response.into_parts();
    Ok(Response::from_parts(
        parts,
        CaptureBody::new(body, exchange, false).boxed(),
    ))
}

async fn rewrite_html(
    url: String,
    body: Bytes,
    adblock_requester: AdblockRequester,
    statistics: Statistics,
) -> Bytes {
    use lol_html::{HtmlRewriter, Settings, element};
    use regex::Regex;
    use std::collections::HashSet;
    use std::fmt::Write;

    let mut output = Vec::new();
    let mut classes = HashSet::new();
    let mut ids = HashSet::new();

    // First pass: rewrite HTML and collect classes/ids
    {
        let mut rewriter = HtmlRewriter::new(
            Settings {
                element_content_handlers: vec![
                    element!("*", |element| {
                        if let Some(id) = element.get_attribute("id") {
                            ids.insert(id);
                        }
                        Ok(())
                    }),
                    element!("*", |element| {
                        if let Some(class) = element.get_attribute("class") {
                            let re = Regex::new(r"\s+").unwrap();
                            let classes_without_duplicate_spaces = re.replace_all(&class, " ");
                            for c in classes_without_duplicate_spaces.split(' ') {
                                if !c.is_empty() {
                                    classes.insert(c.to_string());
                                }
                            }
                        }
                        Ok(())
                    }),
                ],
                ..Settings::default()
            },
            |c: &[u8]| {
                output.extend_from_slice(c);
            },
        );

        if rewriter.write(&body).is_err() {
            return body;
        }
        let _ = rewriter.end();
    }

    // Get cosmetic filters
    {
        let blocker_result = adblock_requester
            .get_cosmetic_response(
                url,
                Vec::from_iter(ids.into_iter()),
                Vec::from_iter(classes.into_iter()),
            )
            .await;

        if blocker_result.hidden_selectors.is_empty()
            && blocker_result.style_selectors.is_empty()
            && blocker_result.injected_script.is_none()
        {
            return body;
        }
        let mut response_has_been_modified = !blocker_result.hidden_selectors.is_empty();

        let mut to_append = format!(
            r#"
<!-- privaxy proxy -->
<style>{hidden_selectors}
{style_selectors}
</style>
<!-- privaxy proxy -->"#,
            hidden_selectors = {
                blocker_result
                    .hidden_selectors
                    .into_iter()
                    .map(|selector| {
                        format!(
                            r#"
                            {}
                            {{
                                display: none !important;
                            }}
                    "#,
                            selector
                        )
                    })
                    .collect::<String>()
            },
            style_selectors = {
                let style_selectors = blocker_result.style_selectors;
                if !style_selectors.is_empty() {
                    response_has_been_modified = true
                }
                style_selectors
                    .into_iter()
                    .map(|(selector, content)| {
                        format!(
                            "{selector} {{ {content} }}",
                            selector = selector,
                            content = content.join(";")
                        )
                    })
                    .collect::<String>()
            }
        );

        if let Some(injected_script) = blocker_result.injected_script {
            response_has_been_modified = true;
            write!(
                to_append,
                r#"
<!-- Privaxy proxy -->
<script type="application/javascript">{}</script>
<!-- privaxy proxy -->
"#,
                injected_script
            )
            .unwrap();
        }

        if response_has_been_modified {
            statistics.increment_modified_responses();
        }

        output.extend_from_slice(to_append.as_bytes());
    }

    Bytes::from(output)
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

/// A request addressed to the proxy itself: the inspection CA, or the status page.
fn direct_response(path: &str, ca_der: &Bytes) -> Response<BoxBodyType> {
    if path == "/privaxy-ca.crt" {
        return Response::builder()
            .status(http::StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/x-x509-ca-cert")
            .header(
                http::header::CONTENT_DISPOSITION,
                "attachment; filename=\"privaxy-ca.crt\"",
            )
            .body(full_body(ca_der.clone()))
            .unwrap();
    }
    get_proxy_status_page()
}

fn get_proxy_status_page() -> Response<BoxBodyType> {
    let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>Privaxy Proxy</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 50%, #16213e 100%);
            color: #e0e0e0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
        }
        .container {
            text-align: center;
            padding: 2rem;
            background: rgba(255,255,255,0.05);
            border-radius: 1rem;
            border: 1px solid rgba(168, 85, 247, 0.3);
        }
        h1 {
            background: linear-gradient(90deg, #a855f7, #ec4899, #3b82f6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }
        .status { color: #4ade80; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Privaxy</h1>
        <p class="status">✓ Proxy is running</p>
        <p>Configure your browser to use this address as HTTP/HTTPS proxy.</p>
        <p><a href="/privaxy-ca.crt" style="color: #a855f7">Download the inspection CA</a></p>
    </div>
</body>
</html>"#;

    Response::builder()
        .status(http::StatusCode::OK)
        .header(http::header::CONTENT_TYPE, "text/html; charset=utf-8")
        .body(full_body(html))
        .unwrap()
}

/// When we receive a request to perform an upgrade, we need to initiate a bidirectional tunnel.
async fn perform_two_ends_upgrade(
    request: Request<Incoming>,
    uri: Uri,
    cancellation: tokio_util::sync::CancellationToken,
) -> Response<BoxBodyType> {
    // For WebSocket upgrades, we'll tunnel directly
    let host = uri.host().unwrap_or("localhost");
    let port = uri.port_u16().unwrap_or(443);
    let addr = format!("{}:{}", host, port);

    tokio::spawn(async move {
        let session = async move {
            match hyper::upgrade::on(request).await {
                Ok(upgraded) => match tokio::net::TcpStream::connect(&addr).await {
                    Ok(mut server) => {
                        let mut upgraded = hyper_util::rt::TokioIo::new(upgraded);
                        let _ = tokio::io::copy_bidirectional(&mut upgraded, &mut server).await;
                    }
                    Err(e) => {
                        log::debug!("Unable to connect to upstream for upgrade: {}", e)
                    }
                },
                Err(e) => {
                    log::debug!("Unable to upgrade: {}", e)
                }
            }
        };
        tokio::select! { biased; _ = cancellation.cancelled() => {}, _ = session => {} }
    });

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .body(empty_body())
        .unwrap()
}

#[cfg(test)]
mod inspection_tests {
    use super::*;
    use crate::blocker::{BlockerRequest, BlockerResult as Decision};
    use crate::capture::CaptureStore;
    use hyper::{server::conn::http1, service::service_fn};
    use hyper_util::rt::TokioIo;
    use std::{convert::Infallible, sync::Mutex};
    use tokio::{
        net::TcpListener,
        sync::{broadcast, oneshot},
    };

    #[tokio::test]
    async fn observe_only_bypasses_filter_decisions_and_empty_cosmetics_preserve_exact_body() {
        let (sender, receiver) = crossbeam_channel::unbounded::<BlockerRequest>();
        let filtering =
            crate::blocker::BlockingDisabledStore(Arc::new(std::sync::RwLock::new(true)));
        let requester = AdblockRequester::new(sender, filtering.clone());
        // No worker is running: Observe only must bypass filter decisions entirely.
        let (blocked, _) = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            requester.is_network_url_blocked(
                "https://ads.example/".into(),
                "https://example.com/".into(),
            ),
        )
        .await
        .unwrap();
        assert!(!blocked);
        assert!(receiver.try_recv().is_err());
        filtering.set(true);
        let worker = std::thread::spawn(move || {
            let request = receiver.recv().unwrap();
            request
                .respond_to
                .send(Decision::Cosmetic(crate::blocker::CosmeticBlockerResult {
                    hidden_selectors: Vec::new(),
                    style_selectors: std::collections::HashMap::new(),
                    injected_script: None,
                }))
                .unwrap();
        });
        let html = Bytes::from_static(b"<!DOCTYPE html><BODY><DIV class='ad' > keep </DIV></BODY>");
        let output = rewrite_html(
            "https://example.com".into(),
            html.clone(),
            requester,
            Statistics::new(),
        )
        .await;
        assert_eq!(output, html);
        worker.join().unwrap();
    }

    #[tokio::test]
    async fn captures_exact_upload_download_and_streams_before_completion() {
        let (sender, receiver) = crossbeam_channel::unbounded::<BlockerRequest>();
        let blocker = std::thread::spawn(move || {
            while let Ok(request) = receiver.recv() {
                let _ = request
                    .respond_to
                    .send(Decision::Network(BlockerResult::default()));
            }
        });
        let filtering =
            crate::blocker::BlockingDisabledStore(Arc::new(std::sync::RwLock::new(false)));
        let requester = AdblockRequester::new(sender, filtering.clone());
        let capture = CaptureStore::new(&std::env::temp_dir().join("privaxy-http-test")).unwrap();
        let (release, pending) = oneshot::channel::<()>();
        let pending = Arc::new(Mutex::new(Some(pending)));
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_address = origin.local_addr().unwrap();
        let origin_task = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                let (tcp, _) = origin.accept().await.unwrap();
                let pending = pending.clone();
                tasks.spawn(async move {
                    let _ = http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(tcp),
                            service_fn(move |request: Request<Incoming>| {
                                let pending = pending.clone();
                                async move {
                                    let html = request.uri().path() == "/html";
                                    let response = if request.uri().path() == "/stream" {
                                        let pending = pending.lock().unwrap().take().unwrap();
                                        let stream = futures_util::stream::once(async {
                                            Ok::<_, Infallible>(Frame::data(Bytes::from_static(
                                                b"first\n",
                                            )))
                                        })
                                        .chain(futures_util::stream::once(async move {
                                            pending.await.unwrap();
                                            Ok(Frame::data(Bytes::from_static(b"last\n")))
                                        }));
                                        Response::builder()
                                            .header("content-type", "text/event-stream")
                                            .body(BodyExt::boxed(
                                                StreamBody::new(stream)
                                                    .map_err(|never| match never {}),
                                            ))
                                            .unwrap()
                                    } else {
                                        let data =
                                            request.into_body().collect().await.unwrap().to_bytes();
                                        Response::builder()
                                            .status(201)
                                            .header(
                                                "content-type",
                                                if html {
                                                    "text/html"
                                                } else {
                                                    "application/octet-stream"
                                                },
                                            )
                                            .header("x-duplicate", "one")
                                            .header("x-duplicate", "two")
                                            .header("content-length", data.len())
                                            .body(full_body(data))
                                            .unwrap()
                                    };
                                    Ok::<_, Infallible>(response)
                                }
                            }),
                        )
                        .await;
                });
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let capture_server = capture.clone();
        let proxy = tokio::spawn(async move {
            let (ca, key) = crate::ca::make_ca_certificate();
            let shared = Proxy {
                adblock: requester,
                upstream: Upstream::new(reqwest::Client::builder().no_proxy().build().unwrap()),
                cert_cache: crate::cert::CertCache::new(ca, key),
                events: broadcast::channel(10).0,
                statistics: Statistics::new(),
                exclusions: crate::proxy::exclusions::LocalExclusionStore::new(Vec::new()),
                capture: capture_server,
                inspection: crate::inspection::Inspection::new(Default::default(), false),
                ca_der: Bytes::new(),
            };
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                let (tcp, addr) = listener.accept().await.unwrap();
                let shared = shared.clone();
                tasks.spawn(async move {
                    let _ = http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(tcp),
                            service_fn(move |request: Request<Incoming>| {
                                let authority = request.uri().authority().unwrap().clone();
                                serve(
                                    shared.clone(),
                                    request,
                                    authority,
                                    Scheme::HTTP,
                                    Peer {
                                        ip: addr.ip(),
                                        app: None,
                                        proxy: proxy_address,
                                        cancellation: Default::default(),
                                    },
                                )
                            }),
                        )
                        .await;
                });
            }
        });
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::http(format!("http://{proxy_address}")).unwrap())
            .build()
            .unwrap();
        let payload: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let response = client
            .post(format!("http://{origin_address}/echo"))
            .body(payload.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 201);
        assert_eq!(response.bytes().await.unwrap().as_ref(), payload);
        let event = capture.events().remove(0);
        let details = event.exchange.lock().unwrap();
        assert_eq!(details.status, Some(201));
        assert!(details.request_complete && details.finished_at.is_some());
        assert!(details.error.is_none(), "{:?}", details.error);
        assert_eq!(
            details
                .response_headers
                .iter()
                .filter(|(key, _)| key == "x-duplicate")
                .count(),
            2
        );
        for body in [&details.request_body, &details.response_body] {
            assert!(body.snapshot().error.is_none());
            assert_eq!(
                body.snapshot().read_range(0, payload.len()).unwrap(),
                payload
            );
        }
        drop(details);
        let mut response = client
            .get(format!("http://{origin_address}/stream"))
            .send()
            .await
            .unwrap();
        let first = tokio::time::timeout(std::time::Duration::from_secs(2), response.chunk())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(first, "first\n");
        let stream = capture.events().remove(1);
        assert!(stream.exchange.lock().unwrap().finished_at.is_none());
        release.send(()).unwrap();
        assert_eq!(response.bytes().await.unwrap(), "last\n");
        let details = stream.exchange.lock().unwrap();
        assert!(details.finished_at.is_some());
        assert!(details.error.is_none());
        assert_eq!(
            details.response_body.snapshot().read_range(0, 64).unwrap(),
            b"first\nlast\n"
        );
        drop(details);
        // Observe only must neither buffer/rewrite HTML nor stop capture.
        filtering.set(false);
        let html = "<!DOCTYPE html>\n<body><DIV class='ad' >  exact bytes </DIV></body>";
        let response = client
            .post(format!("http://{origin_address}/html"))
            .body(html)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 201);
        assert_eq!(
            response.headers()[http::header::CONTENT_LENGTH],
            html.len().to_string()
        );
        assert_eq!(response.text().await.unwrap(), html);
        let events = capture.events();
        let html_event = events
            .iter()
            .find(|event| event.url.ends_with("/html"))
            .unwrap();
        let details = html_event.exchange.lock().unwrap();
        assert_eq!(
            details
                .response_body
                .snapshot()
                .read_range(0, html.len())
                .unwrap(),
            html.as_bytes()
        );
        drop(details);
        proxy.abort();
        origin_task.abort();
        let _ = proxy.await;
        let _ = origin_task.await;
        blocker.join().unwrap();
    }
}

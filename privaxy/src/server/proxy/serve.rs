use super::mitm::BoxBodyType;
use crate::blocker::AdblockRequester;
use crate::events::Event;
use crate::statistics::Statistics;
use adblock::blocker::BlockerResult;
use bytes::Bytes;
use http::uri::{Authority, Scheme};
use http::{StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
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
    // Check if this is a direct request to the proxy itself (not a proxy request)
    // This happens with PAC file checks, WPAD, or direct browser access
    let is_direct_proxy_request = authority.host() == "127.0.0.1" || 
                                   authority.host() == "localhost" ||
                                   authority.host() == "::1";
    
    if is_direct_proxy_request && authority.port_u16() == Some(8100) {
        // Return a simple status page for direct requests to the proxy
        return Ok(get_proxy_status_page());
    }

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

    // Collect the request body
    let body_bytes = match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => Bytes::new(),
    };

    let response = match client
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

    // Collect the response body
    let response_bytes = match response.bytes().await {
        Ok(bytes) => bytes,
        Err(err) => {
            log::debug!("Failed to read response body: {}", err);
            return Ok(get_informative_error_response(&err.to_string()));
        }
    };

    // Check if we need to rewrite HTML
    if let Some(content_type) = response_headers.get(http::header::CONTENT_TYPE) {
        if let Ok(value) = content_type.to_str() {
            if value.contains("text/html") {
                // Use the rewriter synchronously with collected body
                let rewritten_body = rewrite_html(
                    uri.to_string(),
                    response_bytes,
                    adblock_requester,
                    statistics,
                );

                let mut new_response = Response::builder()
                    .status(response_status)
                    .body(full_body(rewritten_body))
                    .unwrap();

                // Copy headers but remove content-length since we may have modified the body
                let mut headers = response_headers;
                headers.remove(http::header::CONTENT_LENGTH);
                headers.remove(http::header::TRANSFER_ENCODING);
                *new_response.headers_mut() = headers;
                
                return Ok(new_response);
            }
        }
    }

    // For non-HTML responses, return the collected body directly
    let mut new_response = Response::builder()
        .status(response_status)
        .body(full_body(response_bytes))
        .unwrap();

    *new_response.headers_mut() = response_headers;
    Ok(new_response)
}

fn rewrite_html(
    url: String,
    body: Bytes,
    adblock_requester: AdblockRequester,
    statistics: Statistics,
) -> Bytes {
    use lol_html::{element, HtmlRewriter, Settings};
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
    let rt = tokio::runtime::Handle::try_current();
    if let Ok(handle) = rt {
        let blocker_result = handle.block_on(adblock_requester.get_cosmetic_response(
            url,
            Vec::from_iter(ids.into_iter()),
            Vec::from_iter(classes.into_iter()),
        ));

        let mut response_has_been_modified = false;

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
    _client: reqwest::Client,
) -> Response<BoxBodyType> {
    // For WebSocket upgrades, we'll tunnel directly
    let host = uri.host().unwrap_or("localhost");
    let port = uri.port_u16().unwrap_or(443);
    let addr = format!("{}:{}", host, port);

    tokio::spawn(async move {
        match hyper::upgrade::on(request).await {
            Ok(upgraded) => {
                match tokio::net::TcpStream::connect(&addr).await {
                    Ok(mut server) => {
                        let mut upgraded = hyper_util::rt::TokioIo::new(upgraded);
                        let _ = tokio::io::copy_bidirectional(&mut upgraded, &mut server).await;
                    }
                    Err(e) => {
                        log::debug!("Unable to connect to upstream for upgrade: {}", e)
                    }
                }
            }
            Err(e) => {
                log::debug!("Unable to upgrade: {}", e)
            }
        }
    });

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .body(empty_body())
        .unwrap()
}

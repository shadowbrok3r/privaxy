use super::{exclusions::LocalExclusionStore, serve::serve};
use crate::{blocker::AdblockRequester, cert::CertCache, events::Event, statistics::Statistics};
use bytes::Bytes;
use http::uri::{Authority, Scheme};
use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;

pub type BoxBodyType = BoxBody<Bytes, hyper::Error>;

// Timeout for TLS handshake and tunnel connections
const TLS_TIMEOUT: Duration = Duration::from_secs(10);
const TUNNEL_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes for tunnels

fn empty_body() -> BoxBodyType {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Extract authority from request - first try URI, then fall back to Host header
fn extract_authority(req: &Request<Incoming>) -> Option<Authority> {
    // First, try to get authority from the URI (works for CONNECT and absolute-form requests)
    if let Some(authority) = req.uri().authority().cloned() {
        return Some(authority);
    }

    // For regular HTTP proxy requests, the URI might just be a path.
    // In this case, we need to get the host from the Host header.
    if let Some(host_header) = req.headers().get(http::header::HOST) {
        if let Ok(host_str) = host_header.to_str() {
            if let Ok(authority) = Authority::from_str(host_str) {
                return Some(authority);
            }
        }
    }

    None
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn serve_mitm_session(
    adblock_requester: AdblockRequester,
    client: reqwest::Client,
    req: Request<Incoming>,
    cert_cache: CertCache,
    broadcast_tx: broadcast::Sender<Event>,
    statistics: Statistics,
    client_ip_address: IpAddr,
    local_exclusion_store: LocalExclusionStore,
) -> Result<Response<BoxBodyType>, hyper::Error> {
    let authority = match extract_authority(&req) {
        Some(authority) => authority,
        None => {
            let response = Response::builder()
                .status(http::StatusCode::BAD_REQUEST)
                .body(empty_body())
                .unwrap();

            log::warn!(
                "Received a request without proper authority (URI: {}, Host header: {:?}), sending bad request",
                req.uri(),
                req.headers().get(http::header::HOST)
            );

            return Ok(response);
        }
    };

    if Method::CONNECT == req.method() {
        // Received an HTTP request like:
        // ```
        // CONNECT www.domain.com:443 HTTP/1.1
        // Host: www.domain.com:443
        // Proxy-Connection: Keep-Alive
        // ```
        //
        // When HTTP method is CONNECT we should return an empty body
        // then we can eventually upgrade the connection and talk a new protocol.
        let server_configuration = cert_cache.get(authority.clone()).await.server_configuration;

        tokio::task::spawn(async move {
            let upgraded = match tokio::time::timeout(TLS_TIMEOUT, hyper::upgrade::on(req)).await {
                Ok(Ok(upgraded)) => upgraded,
                Ok(Err(e)) => {
                    log::debug!("Upgrade error: {}", e);
                    return;
                }
                Err(_) => {
                    log::debug!("Upgrade timed out for {}", authority);
                    return;
                }
            };

            let is_host_blacklisted = local_exclusion_store.contains(authority.host());

            if is_host_blacklisted {
                let mut upgraded = TokioIo::new(upgraded);
                let _ = tokio::time::timeout(
                    TUNNEL_TIMEOUT,
                    tunnel(&mut upgraded, &authority)
                ).await;
                return;
            }

            let tls_stream = match tokio::time::timeout(
                TLS_TIMEOUT,
                TlsAcceptor::from(server_configuration).accept(TokioIo::new(upgraded))
            ).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    if error.kind() == std::io::ErrorKind::UnexpectedEof {
                        log::debug!("TLS handshake failed for {}: connection closed", authority);
                    } else {
                        log::debug!("TLS handshake failed for {}: {}", authority, error);
                    }
                    return;
                }
                Err(_) => {
                    log::debug!("TLS handshake timed out for {}", authority);
                    return;
                }
            };

            let io = TokioIo::new(tls_stream);

            let service = service_fn(move |req| {
                serve(
                    adblock_requester.clone(),
                    req,
                    client.clone(),
                    authority.clone(),
                    Scheme::HTTPS,
                    broadcast_tx.clone(),
                    statistics.clone(),
                    client_ip_address,
                )
            });

            let _ = tokio::time::timeout(
                TUNNEL_TIMEOUT,
                http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .serve_connection(io, service)
                    .with_upgrades()
            ).await;
        });

        Ok(Response::new(empty_body()))
    } else {
        // The request is not of method `CONNECT`. Therefore,
        // this request is for an HTTP resource.
        serve(
            adblock_requester,
            req,
            client.clone(),
            authority,
            Scheme::HTTP,
            broadcast_tx,
            statistics,
            client_ip_address,
        )
        .await
    }
}

async fn tunnel<T>(upgraded: &mut T, authority: &Authority) -> std::io::Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut server = TcpStream::connect(authority.to_string()).await?;

    tokio::io::copy_bidirectional(upgraded, &mut server).await?;

    log::debug!("Tunnel closed for host: {}", authority);

    Ok(())
}

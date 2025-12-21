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
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio_rustls::TlsAcceptor;

pub type BoxBodyType = BoxBody<Bytes, hyper::Error>;

fn empty_body() -> BoxBodyType {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
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
    let authority = match req.uri().authority().cloned() {
        Some(authority) => authority,
        None => {
            let response = Response::builder()
                .status(http::StatusCode::BAD_REQUEST)
                .body(empty_body())
                .unwrap();

            log::warn!("Received a request without proper authority, sending bad request");

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
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let is_host_blacklisted = local_exclusion_store.contains(authority.host());

                    if is_host_blacklisted {
                        let mut upgraded = TokioIo::new(upgraded);
                        let _result = tunnel(&mut upgraded, &authority).await;

                        return;
                    }

                    match TlsAcceptor::from(server_configuration)
                        .accept(TokioIo::new(upgraded))
                        .await
                    {
                        Ok(tls_stream) => {
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

                            let _result = http1::Builder::new()
                                .preserve_header_case(true)
                                .title_case_headers(true)
                                .serve_connection(io, service)
                                .with_upgrades()
                                .await;
                        }
                        // Couldn't perform the tls handshake, they may only support TLS features that we don't or
                        // make use of untrusted certificates. Let's add them to a blacklist so we'll be able to
                        // tunnel them instead of trying to perform MITM.
                        // No blocking will be able to be performed.
                        Err(error) => {
                            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                                log::warn!("Unable to perform handshake for host: {}. Consider excluding it from blocking. The service may not tolerate TLS interception.", authority);
                            }
                        }
                    }
                }
                Err(e) => log::error!("upgrade error: {}", e),
            }
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

    log::debug!("Started tunneling host: {}", authority);

    Ok(())
}

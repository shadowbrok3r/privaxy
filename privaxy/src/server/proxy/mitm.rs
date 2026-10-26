use super::{
    exclusions::LocalExclusionStore,
    serve::{Upstream, serve},
};
use crate::{
    blocker::AdblockRequester,
    capture::{CaptureStore, Exchange, PendingResponse},
    cert::CertCache,
    events::Event,
    inspection::Inspection,
    statistics::Statistics,
};
use bytes::Bytes;
use http::uri::{Authority, Scheme};
use http_body_util::{BodyExt, Empty, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio_rustls::LazyConfigAcceptor;
use tokio_util::sync::CancellationToken;

pub type BodyError = Box<dyn std::error::Error + Send + Sync>;
pub type BoxBodyType = BoxBody<Bytes, BodyError>;

// Timeout for TLS handshake and tunnel connections
pub(crate) const TLS_TIMEOUT: Duration = Duration::from_secs(10);
const TUNNEL_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes for tunnels
// Decrypted connections that end unused within this time count as certificate refusals.
const ENDED_UNUSED_WITHIN: Duration = Duration::from_secs(1);
// Handshakes still unfinished this long after the client hello count as certificate refusals.
const HELLO_REPLY_TIMEOUT: Duration = Duration::from_secs(5);
/// Request header a paired phone adds to CONNECT: the Android package that opened the connection.
const APP_HEADER: &str = "privaxy-app";
/// Request header with the app's display name.
const APP_NAME_HEADER: &str = "privaxy-app-name";

/// Everything the connections of one proxy share.
#[derive(Clone)]
pub(crate) struct Proxy {
    pub(crate) adblock: AdblockRequester,
    pub(crate) upstream: Upstream,
    pub(crate) cert_cache: CertCache,
    pub(crate) events: broadcast::Sender<Event>,
    pub(crate) statistics: Statistics,
    pub(crate) exclusions: LocalExclusionStore,
    pub(crate) capture: CaptureStore,
    pub(crate) inspection: Inspection,
    /// The inspection CA in DER, served to LAN devices that ask the proxy for it.
    pub(crate) ca_der: Bytes,
}

/// Who a connection came from.
#[derive(Clone)]
pub(crate) struct Peer {
    pub(crate) ip: IpAddr,
    /// The Android app a paired phone attributed the connection to.
    pub(crate) app: Option<Arc<str>>,
    /// The listener address the client reached.
    pub(crate) proxy: SocketAddr,
    pub(crate) cancellation: CancellationToken,
}

/// The Android app a paired phone attributed a CONNECT to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayedApp {
    package: Option<String>,
    name: Option<String>,
}

impl RelayedApp {
    fn from_headers(headers: &http::HeaderMap) -> Option<Self> {
        let read = |name| {
            headers
                .get(name)
                .map(|value: &http::HeaderValue| {
                    String::from_utf8_lossy(value.as_bytes()).trim().to_owned()
                })
                .filter(|value| !value.is_empty())
        };
        let app = Self {
            package: read(APP_HEADER),
            name: read(APP_NAME_HEADER),
        };
        (app.package.is_some() || app.name.is_some()).then_some(app)
    }

    /// "Instagram (com.instagram.android)", or whichever of the two is known.
    fn describe(&self) -> String {
        match (&self.name, &self.package) {
            (Some(name), Some(package)) if name != package => format!("{name} ({package})"),
            (Some(name), _) => name.clone(),
            (None, Some(package)) => package.clone(),
            (None, None) => "Unknown app".into(),
        }
    }
}

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

pub(crate) async fn serve_mitm_session(
    proxy: Proxy,
    peer: Peer,
    req: Request<Incoming>,
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
        let app = RelayedApp::from_headers(req.headers());
        let peer = Peer {
            app: app.as_ref().map(|app| app.describe().into()),
            ..peer
        };
        let passthrough = passthrough(&authority, &proxy, app.as_ref());
        let Some(exchange) = open_tunnel(
            &proxy,
            &peer,
            &authority,
            passthrough.as_deref(),
            crate::capture::header_pairs(req.headers()),
            req.version(),
            None,
        )
        .await
        else {
            return Ok(Response::builder()
                .status(http::StatusCode::FORBIDDEN)
                .body(empty_body())
                .unwrap());
        };
        // Received an HTTP request like:
        // ```
        // CONNECT www.domain.com:443 HTTP/1.1
        // Host: www.domain.com:443
        // Proxy-Connection: Keep-Alive
        // ```
        //
        // When HTTP method is CONNECT we should return an empty body
        // then we can eventually upgrade the connection and talk a new protocol.
        tokio::task::spawn(async move {
            let upgraded = match tokio::time::timeout(TLS_TIMEOUT, hyper::upgrade::on(req)).await {
                Ok(Ok(upgraded)) => upgraded,
                Ok(Err(e)) => {
                    exchange
                        .lock()
                        .unwrap()
                        .fail(format!("CONNECT upgrade failed: {e}"));
                    log::debug!("Upgrade error: {}", e);
                    return;
                }
                Err(_) => {
                    exchange.lock().unwrap().fail("CONNECT upgrade timed out");
                    log::debug!("Upgrade timed out for {}", authority);
                    return;
                }
            };
            serve_tunnel(
                proxy,
                peer,
                TokioIo::new(upgraded),
                authority,
                passthrough,
                exchange,
                None,
            )
            .await;
        });

        Ok(Response::new(empty_body()))
    } else {
        // The request is not of method `CONNECT`. Therefore,
        // this request is for an HTTP resource.
        serve(proxy, req, authority, Scheme::HTTP, peer).await
    }
}

/// Records a tunnel opening to `authority`; `None` when a hostname rule refused it.
///
/// `destination` is the address a connection captured at the network level was bound for.
pub(crate) async fn open_tunnel(
    proxy: &Proxy,
    peer: &Peer,
    authority: &Authority,
    passthrough: Option<&str>,
    request_headers: crate::capture::Headers,
    request_version: http::Version,
    destination: Option<SocketAddr>,
) -> Option<Arc<Mutex<Exchange>>> {
    let host_url = format!("https://{}/", authority.host());
    let refused = match passthrough {
        // Undecrypted tunnels are checked against hostname rules.
        Some(_) => {
            let (blocked, decision) = proxy
                .adblock
                .is_network_url_blocked(host_url.clone(), host_url.clone())
                .await;
            blocked.then(|| match decision.filter {
                Some(filter) => format!("Refused as the tunnel opened, on the hostname alone ({filter}). Nothing was sent."),
                None => "Refused as the tunnel opened, on the hostname alone. Nothing was sent.".into(),
            })
        }
        None => None,
    };
    let mut details = Exchange::default();
    details.client = peer.ip;
    details.app = peer.app.as_deref().map(str::to_owned);
    details.request_headers = request_headers;
    details.request_version = request_version;
    details.status = Some(if refused.is_some() { 403 } else { 200 });
    details.response_version = Some(http::Version::HTTP_11);
    let note = refused
        .clone()
        .or_else(|| passthrough.map(str::to_owned))
        .unwrap_or_else(|| {
            "TLS tunnel negotiation. Decrypted HTTP exchanges appear as separate sessions.".into()
        });
    details.note = Some(match destination {
        Some(destination) => {
            format!("Captured at the network level on its way to {destination}. {note}")
        }
        None => note,
    });
    let event = proxy.capture.begin(
        "CONNECT".into(),
        authority.to_string(),
        refused.is_some(),
        details,
    );
    let exchange = event.exchange.clone();
    let _ = proxy.events.send(event);
    if refused.is_some() {
        exchange.lock().unwrap().finish();
        proxy.statistics.increment_blocked_requests();
        proxy.statistics.increment_top_blocked_paths(host_url);
        log::debug!("CONNECT {authority} refused by a hostname rule");
        return None;
    }
    Some(exchange)
}

/// Tunnels `io` to `authority`, or decrypts it and serves the requests inside.
///
/// `destination`, when known, is where a tunnel connects instead of resolving `authority`.
pub(crate) async fn serve_tunnel<IO>(
    proxy: Proxy,
    peer: Peer,
    io: IO,
    authority: Authority,
    passthrough: Option<String>,
    exchange: Arc<Mutex<Exchange>>,
    destination: Option<SocketAddr>,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let cancellation = peer.cancellation.clone();
    let session = async move {
        let mut pending = PendingResponse(Some(exchange.clone()));
        if let Some(reason) = passthrough {
            log::debug!("Tunnelling {authority}: {reason}");
            let mut io = io;
            match tokio::time::timeout(TUNNEL_TIMEOUT, tunnel(&mut io, &authority, destination))
                .await
            {
                Ok(Ok(())) => exchange.lock().unwrap().finish(),
                Ok(Err(error)) => exchange
                    .lock()
                    .unwrap()
                    .fail(format!("Tunnel failed: {error}")),
                Err(_) => exchange.lock().unwrap().fail("Tunnel timed out"),
            }
            pending.disarm();
            return;
        }

        let hello = tokio::time::timeout(
            TLS_TIMEOUT,
            LazyConfigAcceptor::new(rustls::server::Acceptor::default(), io),
        )
        .await;
        let start = match hello {
            Ok(Ok(start)) => start,
            Ok(Err(error)) => {
                exchange.lock().unwrap().fail(format!(
                    "TLS handshake failed before the client hello: {error}"
                ));
                log::debug!("TLS client hello failed for {authority}: {error}");
                return;
            }
            Err(_) => {
                exchange
                    .lock()
                    .unwrap()
                    .fail("TLS handshake timed out before the client hello");
                log::debug!("TLS client hello timed out for {authority}");
                return;
            }
        };
        let server_configuration = proxy
            .cert_cache
            .get(authority.clone())
            .await
            .server_configuration;
        let tls_stream = match tokio::time::timeout(
            HELLO_REPLY_TIMEOUT,
            start.into_stream(server_configuration),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                let mut failed = exchange.lock().unwrap();
                failed.fail(format!("TLS handshake failed: {error}"));
                if let Some(reason) = crate::inspection::refusal(&error) {
                    failed.note = Some(refused_note(
                        proxy.inspection.reject(&authority, reason),
                        &authority,
                    ));
                }
                drop(failed);
                if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    log::debug!("TLS handshake failed for {}: connection closed", authority);
                } else {
                    log::debug!("TLS handshake failed for {}: {}", authority, error);
                }
                return;
            }
            Err(_) => {
                let passing = proxy
                    .inspection
                    .reject(&authority, "Handshake timed out".into());
                let mut failed = exchange.lock().unwrap();
                failed.fail("TLS handshake timed out after the client hello");
                failed.note = Some(refused_note(passing, &authority));
                log::debug!("TLS handshake timed out for {}", authority);
                return;
            }
        };

        let h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
        let io = TokioIo::new(tls_stream);
        exchange.lock().unwrap().finish();
        pending.disarm();

        let established = Instant::now();
        let requested = Arc::new(AtomicBool::new(false));
        let service = {
            let (requested, authority, proxy, peer) = (
                requested.clone(),
                authority.clone(),
                proxy.clone(),
                peer.clone(),
            );
            service_fn(move |req| {
                requested.store(true, Ordering::Relaxed);
                serve(
                    proxy.clone(),
                    req,
                    authority.clone(),
                    Scheme::HTTPS,
                    peer.clone(),
                )
            })
        };

        if h2 {
            let _ = tokio::time::timeout(
                TUNNEL_TIMEOUT,
                http2::Builder::new(TokioExecutor::new()).serve_connection(io, service),
            )
            .await;
        } else {
            let _ = tokio::time::timeout(
                TUNNEL_TIMEOUT,
                http1::Builder::new()
                    .preserve_header_case(true)
                    .title_case_headers(true)
                    .serve_connection(io, service)
                    .with_upgrades(),
            )
            .await;
        }

        // Records a connection that ended unused right after the handshake as a refusal.
        if !requested.load(Ordering::Relaxed) && established.elapsed() < ENDED_UNUSED_WITHIN {
            log::debug!("{authority} ended right after the TLS handshake without a request");
            let passing = proxy
                .inspection
                .reject(&authority, "Ended after handshake".into());
            let mut ended = exchange.lock().unwrap();
            ended.fail(
                "The connection ended right after the TLS handshake, before any HTTP request.",
            );
            ended.note = Some(if passing {
                format!(
                    "The client checked the certificate after the handshake and refused it, or it speaks a protocol other than HTTP. Later connections to {} pass through encrypted for this session.",
                    crate::inspection::domain(authority.host())
                )
            } else {
                "The client checked the certificate after the handshake and refused it, or it speaks a protocol other than HTTP.".into()
            });
        }
    };
    tokio::select! { biased; _ = cancellation.cancelled() => {}, _ = session => {} }
}

/// Why a tunnel passes through without being decrypted, if it does.
pub(crate) fn passthrough(
    authority: &Authority,
    proxy: &Proxy,
    app: Option<&RelayedApp>,
) -> Option<String> {
    let port = authority.port_u16().unwrap_or(443);
    let undecrypted_app = app.filter(|app| {
        !proxy
            .inspection
            .decrypts_app(app.package.as_deref().unwrap_or_default())
    });
    if proxy.exclusions.contains(authority.host()) {
        Some("Host excluded from HTTPS inspection. Encrypted tunnel bytes are not decoded.".into())
    } else if !proxy.inspection.inspects_port(port) {
        Some(format!(
            "Port {port} is not inspected, so this tunnel passes through encrypted. If it carries HTTPS, add the port under Settings > HTTPS inspection."
        ))
    } else if let Some(app) = undecrypted_app {
        Some(format!(
            "{} is not on Decrypt these Android apps, so its connections pass through encrypted.",
            app.describe()
        ))
    } else {
        proxy.inspection.rejection(authority).map(|rejection| {
            format!(
                "Passed through encrypted: a client refused the inspection certificate for {} at {} ({}). Retry inspection under Settings > HTTPS inspection.",
                rejection.domain,
                rejection.at.with_timezone(&chrono::Local).format("%H:%M:%S"),
                rejection.reason
            )
        })
    }
}

/// The traffic note for a handshake the client refused; `passing` when later connections pass through.
fn refused_note(passing: bool, authority: &Authority) -> String {
    if passing {
        format!(
            "The client refused the inspection certificate. Later connections to {} pass through encrypted for this session.",
            crate::inspection::domain(authority.host())
        )
    } else {
        "The client refused the inspection certificate: it does not trust this desktop's CA, or it pins its own certificates.".into()
    }
}

async fn tunnel<T>(
    upgraded: &mut T,
    authority: &Authority,
    destination: Option<SocketAddr>,
) -> std::io::Result<()>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let mut server = match destination {
        Some(destination) => TcpStream::connect(destination).await?,
        None => TcpStream::connect(authority.to_string()).await?,
    };

    tokio::io::copy_bidirectional(upgraded, &mut server).await?;

    log::debug!("Tunnel closed for host: {}", authority);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blocker::{Blocker, BlockingDisabledStore};
    use crate::capture::CaptureStore;
    use crate::inspection::Rejection;
    use rustls_pki_types::{CertificateDer, ServerName};
    use std::{collections::BTreeSet, net::SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A proxy whose filters refuse `blocked.test`, with the CA it signs with.
    async fn proxy(
        inspection: Inspection,
        capture: CaptureStore,
    ) -> (SocketAddr, CertificateDer<'static>) {
        proxy_trusting(inspection, capture, rustls::RootCertStore::empty()).await
    }

    /// [`proxy`], with `roots` as the upstream gRPC client's trust.
    async fn proxy_trusting(
        inspection: Inspection,
        capture: CaptureStore,
        roots: rustls::RootCertStore,
    ) -> (SocketAddr, CertificateDer<'static>) {
        let (sender, receiver) = crossbeam_channel::unbounded();
        let filtering = BlockingDisabledStore(Arc::new(std::sync::RwLock::new(false)));
        let requester = AdblockRequester::new(sender.clone(), filtering.clone());
        std::thread::spawn(move || Blocker::new(sender, receiver, filtering).handle_requests());
        requester
            .replace_engine(vec!["||blocked.test^".into()])
            .await;
        let (ca_certificate, ca_private_key) = crate::ca::make_ca_certificate();
        let ca = CertificateDer::from(ca_certificate.to_der().unwrap());
        let shared = Proxy {
            adblock: requester,
            upstream: Upstream::with_roots(
                reqwest::Client::builder().no_proxy().build().unwrap(),
                roots,
            ),
            cert_cache: CertCache::new(ca_certificate, ca_private_key),
            events: broadcast::channel(64).0,
            statistics: Statistics::new(),
            exclusions: LocalExclusionStore::new(Vec::new()),
            capture,
            inspection,
            ca_der: Bytes::from(ca.to_vec()),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (tcp, client) = listener.accept().await.unwrap();
                let shared = shared.clone();
                let peer = Peer {
                    ip: client.ip(),
                    app: None,
                    proxy: address,
                    cancellation: Default::default(),
                };
                tokio::spawn(async move {
                    let service = service_fn(move |req| {
                        serve_mitm_session(shared.clone(), peer.clone(), req)
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(tcp), service)
                        .with_upgrades()
                        .await;
                });
            }
        });
        (address, ca)
    }

    /// An origin that echoes every byte back.
    async fn echo() -> u16 {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = origin.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut tcp, _) = origin.accept().await.unwrap();
                tokio::spawn(async move {
                    let (mut reader, mut writer) = tcp.split();
                    let _ = tokio::io::copy(&mut reader, &mut writer).await;
                });
            }
        });
        port
    }

    /// Sends CONNECT and returns the proxy's status with the stream it answered on.
    async fn connect(proxy: SocketAddr, authority: &str) -> (u16, TcpStream) {
        connect_with(proxy, authority, "").await
    }

    /// [`connect`] with extra request header lines, each ending in CRLF.
    async fn connect_with(proxy: SocketAddr, authority: &str, headers: &str) -> (u16, TcpStream) {
        let mut stream = TcpStream::connect(proxy).await.unwrap();
        let request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{headers}\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
        let status = String::from_utf8(head).unwrap()[9..12].parse().unwrap();
        (status, stream)
    }

    async fn assert_tunnelled(proxy: SocketAddr, authority: &str) {
        let (status, mut stream) = connect(proxy, authority).await;
        assert_eq!(status, 200);
        stream.write_all(b"not tls").await.unwrap();
        let mut echoed = [0; 7];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echoed, b"not tls");
    }

    /// Opens TLS through the proxy with a client that trusts only `roots`.
    async fn open_tls(
        proxy: SocketAddr,
        roots: rustls::RootCertStore,
        authority: &str,
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        open_tls_with(proxy, roots, authority, Vec::new()).await
    }

    /// [`open_tls`], offering `alpn`.
    async fn open_tls_with(
        proxy: SocketAddr,
        roots: rustls::RootCertStore,
        authority: &str,
        alpn: Vec<Vec<u8>>,
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let (status, stream) = connect(proxy, authority).await;
        assert_eq!(status, 200);
        handshake(stream, roots, authority, alpn).await
    }

    /// Starts TLS for `authority` on a tunnel the proxy already answered.
    async fn handshake(
        stream: TcpStream,
        roots: rustls::RootCertStore,
        authority: &str,
        alpn: Vec<Vec<u8>>,
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = alpn;
        let host = authority.rsplit_once(':').unwrap().0.to_owned();
        tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from(host).unwrap(), stream)
            .await
    }

    /// The first flight a rustls client sends to `host`.
    fn client_hello(host: &str) -> Vec<u8> {
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let mut client = rustls::ClientConnection::new(
            Arc::new(config),
            ServerName::try_from(host.to_owned()).unwrap(),
        )
        .unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        hello
    }

    async fn first_rejection(inspection: &Inspection) -> Vec<Rejection> {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let rejected = inspection.rejected();
                if !rejected.is_empty() {
                    return rejected;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn uninspected_ports_tunnel_filtered_hosts_are_refused_and_refusing_hosts_pass_through() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let port = echo().await;
        let origin = format!("127.0.0.1:{port}");
        let inspection = Inspection::new(BTreeSet::from(crate::inspection::DEFAULT_PORTS), true);
        let root = tempfile::tempdir().unwrap();
        let capture = CaptureStore::new(root.path()).unwrap();
        let (proxy, ca) = proxy(inspection.clone(), capture.clone()).await;
        let mut trusted = rustls::RootCertStore::empty();
        trusted.add(ca).unwrap();

        assert_tunnelled(proxy, &origin).await;
        assert_eq!(connect(proxy, "blocked.test:5228").await.0, 403);

        // A client that trusts no CA refuses with an alert during the handshake.
        inspection.configure(BTreeSet::from([port]), true);
        let error = open_tls(proxy, rustls::RootCertStore::empty(), &origin)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("UnknownIssuer"), "{error}");
        let rejected = first_rejection(&inspection).await;
        assert_eq!(
            (
                rejected[0].host.as_str(),
                rejected[0].port,
                rejected[0].reason.as_str()
            ),
            ("127.0.0.1", port, "UnknownCA")
        );
        assert_tunnelled(proxy, &origin).await;

        // A client that sends a request is not refusing, even when it disconnects at once.
        inspection.retry();
        let localhost = format!("localhost:{port}");
        let mut tls = open_tls(proxy, trusted.clone(), &localhost).await.unwrap();
        let request = format!("GET / HTTP/1.1\r\nHost: {localhost}\r\nConnection: close\r\n\r\n");
        tls.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        let _ = tls.read_to_end(&mut response).await;
        assert!(response.starts_with(b"HTTP/1.1 "), "{response:?}");

        // A client that verifies after the handshake refuses by hanging up unused.
        let mut tls = open_tls(proxy, trusted, &origin).await.unwrap();
        tls.shutdown().await.unwrap();
        let rejected = first_rejection(&inspection).await;
        assert_eq!(rejected.len(), 1, "{rejected:?}");
        assert_eq!(
            (rejected[0].host.as_str(), rejected[0].reason.as_str()),
            ("127.0.0.1", "Ended after handshake")
        );
        assert_tunnelled(proxy, &origin).await;

        let rows: Vec<_> = capture
            .events()
            .iter()
            .map(|event| {
                let exchange = event.exchange.lock().unwrap();
                let note = exchange.note.clone().unwrap_or_default();
                let error = exchange.error.clone().unwrap_or_default();
                (
                    event.method.clone(),
                    event.is_request_blocked,
                    exchange.status,
                    note,
                    error,
                )
            })
            .collect();
        let methods: Vec<_> = rows.iter().map(|row| row.0.as_str()).collect();
        assert_eq!(
            methods,
            [
                "CONNECT", "CONNECT", "CONNECT", "CONNECT", "CONNECT", "GET", "CONNECT", "CONNECT"
            ]
        );
        assert!(
            rows[0]
                .3
                .starts_with(&format!("Port {port} is not inspected")),
            "{rows:#?}"
        );
        assert!(rows[1].1 && rows[1].2 == Some(403), "{rows:#?}");
        assert!(
            rows[1].3.starts_with("Refused as the tunnel opened"),
            "{rows:#?}"
        );
        assert!(
            rows[2].4.contains("UnknownCA") && rows[2].3.contains("Later connections"),
            "{rows:#?}"
        );
        assert!(
            rows[3].3.starts_with("Passed through encrypted") && rows[3].3.contains("(UnknownCA)"),
            "{rows:#?}"
        );
        assert!(
            rows[4].4.is_empty() && rows[4].3.starts_with("TLS tunnel negotiation"),
            "{rows:#?}"
        );
        assert!(
            rows[6].4.contains("ended right after") && rows[6].3.contains("Later connections"),
            "{rows:#?}"
        );
        assert!(rows[7].3.contains("(Ended after handshake)"), "{rows:#?}");
        assert!(
            rows.iter().all(|row| row.1 == (row.2 == Some(403))),
            "{rows:#?}"
        );
    }

    #[tokio::test]
    async fn hanging_up_after_the_hello_refuses_but_hanging_up_during_it_does_not() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let port = echo().await;
        let origin = format!("127.0.0.1:{port}");
        let inspection = Inspection::new(BTreeSet::from([port]), true);
        let root = tempfile::tempdir().unwrap();
        let capture = CaptureStore::new(root.path()).unwrap();
        let (proxy, _) = proxy(inspection.clone(), capture.clone()).await;
        let hello = client_hello("127.0.0.1");

        // Half a hello, then a hang-up: the client never saw the certificate.
        let (status, mut stream) = connect(proxy, &origin).await;
        assert_eq!(status, 200);
        stream.write_all(&hello[..hello.len() / 2]).await.unwrap();
        drop(stream);
        tokio::time::timeout(Duration::from_secs(5), async {
            while !capture.events().iter().any(|event| {
                let exchange = event.exchange.lock().unwrap();
                exchange
                    .error
                    .as_deref()
                    .is_some_and(|error| error.contains("before the client hello"))
            }) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert!(inspection.rejected().is_empty());

        // A whole hello, the proxy's reply, then a hang-up without an alert.
        let (_, mut stream) = connect(proxy, &origin).await;
        stream.write_all(&hello).await.unwrap();
        let mut record = [0; 5];
        stream.read_exact(&mut record).await.unwrap();
        assert_eq!(record[0], 0x16, "a TLS handshake record");
        drop(stream);
        let rejected = first_rejection(&inspection).await;
        assert_eq!(
            (rejected[0].domain.as_str(), rejected[0].reason.as_str()),
            ("127.0.0.1", "Closed during handshake")
        );
        assert_tunnelled(proxy, &origin).await;
    }

    #[tokio::test]
    async fn phone_apps_off_the_decrypt_list_tunnel_and_listed_ones_are_decrypted() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let port = echo().await;
        let origin = format!("127.0.0.1:{port}");
        let inspection = Inspection::new(BTreeSet::from([port]), true);
        inspection.set_decrypted_apps(&["com.android.chrome".to_owned()]);
        let root = tempfile::tempdir().unwrap();
        let capture = CaptureStore::new(root.path()).unwrap();
        let (proxy, ca) = proxy(inspection.clone(), capture.clone()).await;
        let mut trusted = rustls::RootCertStore::empty();
        trusted.add(ca).unwrap();

        // A pinned app tunnels from its first connection.
        let (status, mut stream) = connect_with(
            proxy,
            &origin,
            "Privaxy-App: com.instagram.android\r\nPrivaxy-App-Name: Instagram\r\n",
        )
        .await;
        assert_eq!(status, 200);
        stream.write_all(b"pinned").await.unwrap();
        let mut echoed = [0; 6];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echoed))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echoed, b"pinned");

        // A browser on the list is decrypted, and its requests carry the app.
        let localhost = format!("localhost:{port}");
        let (status, stream) =
            connect_with(proxy, &localhost, "Privaxy-App: com.android.chrome\r\n").await;
        assert_eq!(status, 200);
        let mut tls = handshake(stream, trusted, &localhost, Vec::new())
            .await
            .unwrap();
        let request = format!("GET / HTTP/1.1\r\nHost: {localhost}\r\nConnection: close\r\n\r\n");
        tls.write_all(request.as_bytes()).await.unwrap();
        let mut response = Vec::new();
        let _ = tls.read_to_end(&mut response).await;
        assert!(response.starts_with(b"HTTP/1.1 "), "{response:?}");
        assert!(inspection.rejected().is_empty());

        let events = capture.events();
        let described: Vec<_> = events
            .iter()
            .map(|event| {
                let exchange = event.exchange.lock().unwrap();
                (
                    event.method.clone(),
                    exchange.app.clone(),
                    exchange.note.clone().unwrap_or_default(),
                )
            })
            .collect();
        assert_eq!(described.len(), 3, "{described:#?}");
        assert_eq!(
            described[0].1.as_deref(),
            Some("Instagram (com.instagram.android)")
        );
        assert!(
            described[0]
                .2
                .contains("is not on Decrypt these Android apps"),
            "{described:#?}"
        );
        assert_eq!(described[1].1.as_deref(), Some("com.android.chrome"));
        assert!(described[1].2.starts_with("TLS tunnel negotiation"));
        assert_eq!(
            (described[2].0.as_str(), described[2].1.as_deref()),
            ("GET", Some("com.android.chrome"))
        );
    }

    #[tokio::test]
    async fn decrypted_clients_that_offer_http2_get_it() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let port = echo().await;
        let inspection = Inspection::new(BTreeSet::from([port]), true);
        let root = tempfile::tempdir().unwrap();
        let (proxy, ca) = proxy(inspection, CaptureStore::new(root.path()).unwrap()).await;
        let mut trusted = rustls::RootCertStore::empty();
        trusted.add(ca).unwrap();
        let authority = format!("localhost:{port}");
        let tls = open_tls_with(
            proxy,
            trusted,
            &authority,
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        )
        .await
        .unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .unwrap();
        tokio::spawn(connection);
        let response = sender
            .send_request(
                Request::get(format!("https://{authority}/"))
                    .body(Empty::<Bytes>::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        // The echo origin does not speak HTTPS, so the proxy answers itself, over HTTP/2.
        assert_eq!(response.status(), 502);
        assert_eq!(response.version(), http::Version::HTTP_2);
    }

    #[tokio::test]
    async fn grpc_calls_keep_their_trailers_both_ways() {
        use http_body_util::StreamBody;
        use hyper::body::Frame;
        use std::convert::Infallible;
        let _ = rustls::crypto::ring::default_provider().install_default();

        // An HTTP/2 origin that only the proxy's upstream client trusts.
        let (origin_ca, origin_key) = crate::ca::make_ca_certificate();
        let mut upstream_roots = rustls::RootCertStore::empty();
        upstream_roots
            .add(CertificateDer::from(origin_ca.to_der().unwrap()))
            .unwrap();
        let origin_certs = CertCache::new(origin_ca, origin_key);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let authority: Authority = format!("localhost:{port}").parse().unwrap();
        let server_config = origin_certs
            .get(authority.clone())
            .await
            .server_configuration;
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let acceptor = tokio_rustls::TlsAcceptor::from(server_config.clone());
                tokio::spawn(async move {
                    let tls = acceptor.accept(tcp).await.unwrap();
                    let service = service_fn(|request: Request<Incoming>| async move {
                        let te = request.headers().get("te").cloned();
                        let collected = request.into_body().collect().await.unwrap();
                        let mut trailers = http::HeaderMap::new();
                        trailers.insert("grpc-status", "0".parse().unwrap());
                        trailers.insert(
                            "x-echo-te",
                            te.unwrap_or(http::HeaderValue::from_static("none")),
                        );
                        if let Some(sent) = collected
                            .trailers()
                            .and_then(|trailers| trailers.get("x-client-trailer"))
                        {
                            trailers.insert("x-client-trailer", sent.clone());
                        }
                        let frames = vec![
                            Ok::<_, Infallible>(Frame::data(collected.to_bytes())),
                            Ok(Frame::trailers(trailers)),
                        ];
                        Ok::<_, Infallible>(
                            Response::builder()
                                .header("content-type", "application/grpc")
                                .body(StreamBody::new(futures_util::stream::iter(frames)))
                                .unwrap(),
                        )
                    });
                    let _ = http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls), service)
                        .await;
                });
            }
        });

        let inspection = Inspection::new(BTreeSet::from([port]), true);
        let root = tempfile::tempdir().unwrap();
        let capture = CaptureStore::new(root.path()).unwrap();
        let (proxy, ca) = proxy_trusting(inspection, capture.clone(), upstream_roots).await;
        let mut trusted = rustls::RootCertStore::empty();
        trusted.add(ca).unwrap();
        let tls = open_tls_with(proxy, trusted, authority.as_str(), vec![b"h2".to_vec()])
            .await
            .unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .unwrap();
        tokio::spawn(connection);
        let mut client_trailers = http::HeaderMap::new();
        client_trailers.insert("x-client-trailer", "sent".parse().unwrap());
        let message = Bytes::from_static(b"\0\0\0\0\x02hi");
        let body = StreamBody::new(futures_util::stream::iter(vec![
            Ok::<_, Infallible>(Frame::data(message.clone())),
            Ok(Frame::trailers(client_trailers)),
        ]));
        let request = Request::post(format!("https://{authority}/echo.Echo/Say"))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(body)
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), 200);
        let collected = response.into_body().collect().await.unwrap();
        let trailers = collected.trailers().cloned().unwrap();
        assert_eq!(trailers["grpc-status"], "0");
        assert_eq!(trailers["x-echo-te"], "trailers");
        assert_eq!(trailers["x-client-trailer"], "sent");
        assert_eq!(collected.to_bytes(), message);

        let events = capture.events();
        let call = events.iter().find(|event| event.method == "POST").unwrap();
        let details = call.exchange.lock().unwrap();
        assert!(
            details
                .response_trailers
                .iter()
                .any(|(name, value)| name == "grpc-status" && value == "0"),
            "{:?}",
            details.response_trailers
        );
        assert!(
            details
                .request_trailers
                .iter()
                .any(|(name, value)| name == "x-client-trailer" && value == "sent"),
            "{:?}",
            details.request_trailers
        );
    }
}

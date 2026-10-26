//! Network-level capture: connections the firewall redirects here instead of the apps sending them to the proxy.
use crate::listener::{ListenerStatus, ProxyListener};
use crate::proxy::mitm::{self, Peer, Proxy, TLS_TIMEOUT};
use http::uri::Authority;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

/// The port the firewall redirects captured connections to, on 127.0.0.1 and ::1.
pub const PORT: u16 = 8103;
/// Longest ClientHello read while looking for the server name.
const MAX_HELLO: usize = 64 * 1024;

/// Loopback listeners for redirected IPv4 and IPv6 connections; stopped until capture is switched on.
#[derive(Clone, Debug)]
pub struct TransparentListener {
    v4: ProxyListener,
    v6: ProxyListener,
}

impl TransparentListener {
    pub(crate) fn spawn(proxy: Proxy) -> Self {
        let listen = |ip| {
            let proxy = proxy.clone();
            ProxyListener::spawn_with(
                SocketAddr::new(ip, PORT),
                false,
                move |stream, client, cancellation| {
                    serve(proxy.clone(), stream, client, cancellation)
                },
            )
        };
        Self {
            v4: listen(Ipv4Addr::LOCALHOST.into()),
            v6: listen(Ipv6Addr::LOCALHOST.into()),
        }
    }

    pub fn start(&self) {
        self.v4.start();
        self.v6.start();
    }

    pub fn stop(&self) {
        self.v4.stop();
        self.v6.stop();
    }

    /// The IPv4 listener's status; IPv6 follows it, and a host without IPv6 never redirects there.
    pub fn status(&self) -> ListenerStatus {
        self.v4.status()
    }
}

/// Where a redirected connection was going before the firewall sent it here.
fn original_destination(stream: &TcpStream) -> std::io::Result<SocketAddr> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    // SAFETY: getsockopt writes at most `length` bytes into the zeroed address it is given.
    unsafe {
        if stream.local_addr()?.is_ipv4() {
            let mut address: libc::sockaddr_in = std::mem::zeroed();
            let mut length = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            if libc::getsockopt(
                fd,
                libc::SOL_IP,
                libc::SO_ORIGINAL_DST,
                (&mut address as *mut libc::sockaddr_in).cast(),
                &mut length,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(SocketAddr::from((
                u32::from_be(address.sin_addr.s_addr).to_be_bytes(),
                u16::from_be(address.sin_port),
            )))
        } else {
            let mut address: libc::sockaddr_in6 = std::mem::zeroed();
            let mut length = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            if libc::getsockopt(
                fd,
                libc::SOL_IPV6,
                libc::IP6T_SO_ORIGINAL_DST,
                (&mut address as *mut libc::sockaddr_in6).cast(),
                &mut length,
            ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(SocketAddr::from((
                address.sin6_addr.s6_addr,
                u16::from_be(address.sin6_port),
            )))
        }
    }
}

async fn serve(
    proxy: Proxy,
    mut stream: TcpStream,
    client: SocketAddr,
    cancellation: CancellationToken,
) {
    let Ok(local) = stream.local_addr() else {
        return;
    };
    let destination = match original_destination(&stream) {
        Ok(destination) if destination != local => destination,
        Ok(_) => {
            log::debug!("Network capture ignored a direct connection from {client}");
            return;
        }
        Err(error) => {
            log::warn!("Network capture has no original destination for {client}: {error}");
            return;
        }
    };
    let peer = Peer {
        ip: client.ip(),
        app: None,
        proxy: local,
        cancellation,
    };

    if destination.port() == 80 {
        // Each plain HTTP request names its host.
        let service =
            service_fn(move |req| mitm::serve_mitm_session(proxy.clone(), peer.clone(), req));
        let _ = http1::Builder::new()
            .preserve_header_case(true)
            .title_case_headers(true)
            .serve_connection(TokioIo::new(stream), service)
            .with_upgrades()
            .await;
        return;
    }

    let (head, hello) = read_client_hello(&mut stream).await;
    let host = match &hello {
        Hello::Tls(Some(name)) => name.clone(),
        Hello::Tls(None) | Hello::Other => match destination.ip() {
            std::net::IpAddr::V4(ip) => ip.to_string(),
            std::net::IpAddr::V6(ip) => format!("[{ip}]"),
        },
    };
    let Ok(authority) = Authority::from_str(&format!("{host}:{}", destination.port())) else {
        log::debug!("Network capture could not name {destination} ({host})");
        return;
    };
    let passthrough = match hello {
        Hello::Other => Some(
            "Not TLS, so this connection passes through unchanged. Only its destination is known."
                .to_owned(),
        ),
        Hello::Tls(_) => mitm::passthrough(&authority, &proxy, None),
    };
    let Some(exchange) = mitm::open_tunnel(
        &proxy,
        &peer,
        &authority,
        passthrough.as_deref(),
        Vec::new(),
        http::Version::HTTP_11,
        Some(destination),
    )
    .await
    else {
        return;
    };
    mitm::serve_tunnel(
        proxy,
        peer,
        Prefixed {
            prefix: head,
            offset: 0,
            inner: stream,
        },
        authority,
        passthrough,
        exchange,
        Some(destination),
    )
    .await;
}

/// What a captured connection opened with.
#[derive(Debug, PartialEq, Eq)]
enum Hello {
    /// A TLS ClientHello, with its server name when it sent one.
    Tls(Option<String>),
    /// Anything else, or nothing before the deadline.
    Other,
}

/// Reads until a whole ClientHello arrives, returning the bytes read so they can be replayed.
async fn read_client_hello<R: AsyncRead + Unpin>(stream: &mut R) -> (Vec<u8>, Hello) {
    let mut acceptor = rustls::server::Acceptor::default();
    let mut head = Vec::new();
    let mut buffer = [0_u8; 4096];
    let deadline = tokio::time::Instant::now() + TLS_TIMEOUT;
    while head.len() < MAX_HELLO {
        let count = match tokio::time::timeout_at(deadline, stream.read(&mut buffer)).await {
            Ok(Ok(count)) if count > 0 => count,
            _ => break,
        };
        head.extend_from_slice(&buffer[..count]);
        let mut fresh = &buffer[..count];
        while !fresh.is_empty() {
            if matches!(acceptor.read_tls(&mut fresh), Ok(0) | Err(_)) {
                return (head, Hello::Other);
            }
        }
        match acceptor.accept() {
            Ok(Some(accepted)) => {
                let name = accepted.client_hello().server_name().map(str::to_owned);
                return (head, Hello::Tls(name));
            }
            Ok(None) => {}
            Err(_) => return (head, Hello::Other),
        }
    }
    (head, Hello::Other)
}

/// A stream that first replays bytes already read from it.
struct Prefixed<IO> {
    prefix: Vec<u8>,
    offset: usize,
    inner: IO,
}

impl<IO: AsyncRead + Unpin> AsyncRead for Prefixed<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.offset < this.prefix.len() {
            let count = (this.prefix.len() - this.offset).min(buf.remaining());
            buf.put_slice(&this.prefix[this.offset..this.offset + count]);
            this.offset += count;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for Prefixed<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn client_hello(host: &str) -> Vec<u8> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let mut client = rustls::ClientConnection::new(
            std::sync::Arc::new(config),
            rustls_pki_types::ServerName::try_from(host.to_owned()).unwrap(),
        )
        .unwrap();
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        hello
    }

    #[tokio::test]
    async fn a_hello_split_across_reads_yields_its_server_name_and_every_byte() {
        let hello = client_hello("scontent.cdninstagram.com");
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let sent = hello.clone();
        let sender = tokio::spawn(async move {
            for chunk in sent.chunks(50) {
                writer.write_all(chunk).await.unwrap();
            }
            writer
        });
        let (head, found) = read_client_hello(&mut reader).await;
        assert_eq!(found, Hello::Tls(Some("scontent.cdninstagram.com".into())));
        assert_eq!(head, hello);
        drop(sender.await.unwrap());

        let mut replay = Prefixed {
            prefix: head,
            offset: 0,
            inner: tokio::io::empty(),
        };
        let mut replayed = Vec::new();
        replay.read_to_end(&mut replayed).await.unwrap();
        assert_eq!(replayed, hello);
    }

    #[tokio::test]
    async fn plain_bytes_are_not_a_hello() {
        let mut stream: &[u8] = b"SSH-2.0-OpenSSH_9.9\r\n";
        let (head, found) = read_client_hello(&mut stream).await;
        assert_eq!(found, Hello::Other);
        assert_eq!(head, b"SSH-2.0-OpenSSH_9.9\r\n");
    }
}

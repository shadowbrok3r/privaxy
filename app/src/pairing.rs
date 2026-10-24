use serde::{Deserialize, Serialize};
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const LISTEN_ADDRESS: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 8101);

#[derive(Serialize, Deserialize, Clone)]
pub struct Identity {
    pub token: String,
    pub certificate_pem: String,
    cert: Vec<u8>,
    key: Vec<u8>,
}
impl Identity {
    pub fn load() -> Result<Self, String> {
        let path = Self::path()?;
        if path.exists() {
            return serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string());
        }
        Self::generate()
    }
    fn path() -> Result<PathBuf, String> {
        Ok(dirs::home_dir()
            .ok_or("No home directory")?
            .join(".privaxy/desktop-pairing.json"))
    }
    pub fn generate() -> Result<Self, String> {
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["privaxy-desktop".into()])
                .map_err(|e| e.to_string())?;
        let token: [u8; 32] = rand::random();
        let identity = Self {
            token: token.iter().map(|b| format!("{b:02x}")).collect(),
            certificate_pem: cert.pem(),
            cert: cert.der().to_vec(),
            key: signing_key.serialize_der(),
        };
        let path = Self::path()?;
        std::fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(|e| e.to_string())?;
        file.write_all(&serde_json::to_vec(&identity).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        Ok(identity)
    }
    pub fn code(&self, host: &str) -> Result<String, &'static str> {
        use base64::Engine as _;
        let host = host.trim();
        if host.is_empty()
            || host.contains(['/', '\\', ':', '@', '?', '#'])
            || host.chars().any(char::is_whitespace)
        {
            return Err("Enter the desktop's IPv4 address or hostname, without a port.");
        }
        if host.trim_end_matches('.').eq_ignore_ascii_case("localhost")
            || host.parse::<Ipv4Addr>().is_ok_and(|ip| {
                ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast()
            })
        {
            return Err(
                "Android needs this computer's IP address; 0.0.0.0 is only a listening address.",
            );
        }
        let json = serde_json::json!({"version":1,"host":host,"port":LISTEN_ADDRESS.port(),"token":self.token,"certificate_pem":self.certificate_pem}).to_string();
        Ok(format!(
            "privaxy-pair-v1:{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
        ))
    }
    pub async fn serve(self, status: Arc<Mutex<String>>) -> Result<(), String> {
        let listener = tokio::net::TcpListener::bind(LISTEN_ADDRESS)
            .await
            .map_err(|e| e.to_string())?;
        *status.lock().unwrap() =
            format!("Listening on {LISTEN_ADDRESS} (encrypted, paired clients only)");
        self.serve_on(listener, "127.0.0.1:8100".parse().unwrap())
            .await
    }
    async fn serve_on(
        self,
        listener: tokio::net::TcpListener,
        upstream: std::net::SocketAddr,
    ) -> Result<(), String> {
        if self.token.len() != 64 || !self.token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(
                "Stored pairing credentials are invalid; revoke pairings to regenerate them."
                    .into(),
            );
        }
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![self.cert.into()],
                rustls_pki_types::PrivatePkcs8KeyDer::from(self.key).into(),
            )
            .map_err(|e| e.to_string())?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let limit = Arc::new(tokio::sync::Semaphore::new(128));
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            while tasks.try_join_next().is_some() {}
            let (tcp, _) = listener.accept().await.map_err(|e| e.to_string())?;
            let Ok(permit) = limit.clone().try_acquire_owned() else {
                continue;
            };
            let acceptor = acceptor.clone();
            let token = self.token.clone();
            tasks.spawn(async move {
                let _permit = permit;
                let handshake = async {
                    let mut tls = acceptor.accept(tcp).await?;
                    let mut received = [0; 64];
                    tls.read_exact(&mut received).await?;
                    let difference = received
                        .iter()
                        .zip(token.bytes())
                        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
                    if difference != 0 {
                        return Err(std::io::Error::other("Pairing rejected"));
                    }
                    let local = tokio::net::TcpStream::connect(upstream).await?;
                    tls.write_all(b"OK").await?;
                    Ok::<_, std::io::Error>((tls, local))
                };
                if let Ok(Ok((mut tls, mut local))) =
                    tokio::time::timeout(std::time::Duration::from_secs(15), handshake).await
                {
                    let _ = tokio::io::copy_bidirectional(&mut tls, &mut local).await;
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_code_uses_selected_address_and_relay_port() {
        use base64::Engine as _;
        let identity = Identity {
            token: "a".repeat(64),
            certificate_pem: "test certificate".into(),
            cert: Vec::new(),
            key: Vec::new(),
        };
        for host in ["100.64.0.5", "192.168.1.10", "desktop.example"] {
            let code = identity.code(&format!(" {host} ")).unwrap();
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(code.strip_prefix("privaxy-pair-v1:").unwrap())
                .unwrap();
            let payload: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(payload["host"], host);
            assert_eq!(payload["port"], 8101);
        }
        for host in [
            "",
            "0.0.0.0",
            "127.0.0.1",
            "localhost",
            "::",
            "192.168.1.10:8100",
            "http://desktop.example",
        ] {
            assert!(
                identity.code(host).is_err(),
                "Unexpected pairing code for {host}"
            );
        }
    }

    #[tokio::test]
    async fn paired_tls_relay_transfers_bytes_rejects_bad_tokens_and_revokes_open_streams() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["privaxy-desktop".into()]).unwrap();
        let identity = Identity {
            token: "a".repeat(64),
            certificate_pem: cert.pem(),
            cert: cert.der().to_vec(),
            key: signing_key.serialize_der(),
        };
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let origin = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = origin.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = origin.accept().await.unwrap();
            let (mut r, mut w) = stream.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_address = listener.local_addr().unwrap();
        let server = tokio::spawn(identity.serve_on(listener, address));
        let connect = || async {
            connector
                .connect(
                    rustls_pki_types::ServerName::try_from("privaxy-desktop").unwrap(),
                    tokio::net::TcpStream::connect(relay_address).await.unwrap(),
                )
                .await
                .unwrap()
        };
        let mut invalid = connect().await;
        invalid.write_all(&[b'b'; 64]).await.unwrap();
        let mut ack = [0; 2];
        assert!(invalid.read_exact(&mut ack).await.is_err());
        let mut valid = connect().await;
        valid.write_all(&[b'a'; 64]).await.unwrap();
        valid.read_exact(&mut ack).await.unwrap();
        assert_eq!(&ack, b"OK");
        valid
            .write_all(b"CONNECT example.test:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut output = vec![0; 38];
        // Read exactly the request bytes; a raw relay must preserve every byte.
        output.resize(b"CONNECT example.test:443 HTTP/1.1\r\n\r\n".len(), 0);
        valid.read_exact(&mut output).await.unwrap();
        assert_eq!(output, b"CONNECT example.test:443 HTTP/1.1\r\n\r\n");
        server.abort();
        let _ = server.await;
        let closed = tokio::time::timeout(std::time::Duration::from_secs(2), valid.read(&mut ack))
            .await
            .unwrap();
        assert!(matches!(closed, Ok(0) | Err(_)));
        echo.abort();
    }
}

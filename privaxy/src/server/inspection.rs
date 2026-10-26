//! Which CONNECT tunnels are decrypted, and the domains whose clients refused the inspection CA.
use chrono::{DateTime, Utc};
use http::uri::Authority;
use rustls::AlertDescription;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};
use wildmatch::WildMatch;

pub const DEFAULT_PORTS: [u16; 2] = [443, 8443];
const MAX_REJECTED: usize = 1024;

/// A domain and port whose clients refused the inspection certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    /// The registrable domain of the refusing host, or the host itself when it has none.
    pub domain: String,
    pub port: u16,
    /// The host whose refusal was recorded.
    pub host: String,
    /// The alert the client sent, or how the connection ended.
    pub reason: String,
    pub at: DateTime<Utc>,
}

impl Rejection {
    /// The exclusion pattern that never intercepts this domain.
    pub fn exclusion(&self) -> String {
        if self.domain.contains('.') && self.domain.parse::<IpAddr>().is_err() {
            format!("*.{}", self.domain)
        } else {
            self.domain.clone()
        }
    }
}

#[derive(Debug, Clone)]
pub struct Inspection(Arc<State>);

#[derive(Debug)]
struct State {
    ports: RwLock<BTreeSet<u16>>,
    pass_rejected: AtomicBool,
    // Android packages whose relayed connections are decrypted.
    apps: RwLock<Vec<WildMatch>>,
    // Keyed by domain and port, not by client.
    rejected: RwLock<Rejected>,
}

#[derive(Debug, Default)]
struct Rejected {
    added: u64,
    domains: BTreeMap<String, (u64, Rejection)>,
}

impl Inspection {
    pub fn new(ports: BTreeSet<u16>, pass_rejected: bool) -> Self {
        Self(Arc::new(State {
            ports: RwLock::new(ports),
            pass_rejected: AtomicBool::new(pass_rejected),
            apps: RwLock::default(),
            rejected: RwLock::default(),
        }))
    }

    /// Applies saved settings; turning pass-through off forgets every refusal.
    pub fn configure(&self, ports: BTreeSet<u16>, pass_rejected: bool) {
        *self.0.ports.write().unwrap() = ports;
        self.0.pass_rejected.store(pass_rejected, Ordering::Relaxed);
        if !pass_rejected {
            self.retry();
        }
    }

    pub(crate) fn inspects_port(&self, port: u16) -> bool {
        self.0.ports.read().unwrap().contains(&port)
    }

    /// Replaces the Android packages, `*` wildcards allowed, whose relayed connections are decrypted.
    pub fn set_decrypted_apps<'a>(&self, apps: impl IntoIterator<Item = &'a String>) {
        *self.0.apps.write().unwrap() = apps
            .into_iter()
            .map(|app| WildMatch::new(&app.trim().to_ascii_lowercase()))
            .collect();
    }

    /// Whether connections a paired phone attributed to `package` are decrypted.
    pub fn decrypts_app(&self, package: &str) -> bool {
        let package = package.to_ascii_lowercase();
        self.0
            .apps
            .read()
            .unwrap()
            .iter()
            .any(|pattern| pattern.matches(&package))
    }

    /// The earlier refusal that sends this authority through undecrypted.
    pub(crate) fn rejection(&self, authority: &Authority) -> Option<Rejection> {
        if !self.0.pass_rejected.load(Ordering::Relaxed) {
            return None;
        }
        let rejected = self.0.rejected.read().unwrap();
        rejected
            .domains
            .get(&key(authority))
            .map(|(_, rejection)| rejection.clone())
    }

    /// Records a refusal for the host's whole domain; false when pass-through is off and nothing was recorded.
    pub(crate) fn reject(&self, authority: &Authority, reason: String) -> bool {
        if !self.0.pass_rejected.load(Ordering::Relaxed) {
            return false;
        }
        let key = key(authority);
        let mut rejected = self.0.rejected.write().unwrap();
        if rejected.domains.contains_key(&key) {
            return true;
        }
        if rejected.domains.len() >= MAX_REJECTED {
            let oldest = rejected.domains.iter().min_by_key(|(_, (added, _))| *added);
            if let Some(oldest) = oldest.map(|(key, _)| key.clone()) {
                rejected.domains.remove(&oldest);
            }
        }
        let host = authority.host().to_ascii_lowercase();
        let rejection = Rejection {
            domain: domain(&host),
            port: port(authority),
            host,
            reason,
            at: Utc::now(),
        };
        log::info!(
            "{}:{} rejected the inspection certificate ({}); passing {} through for this session",
            rejection.host,
            rejection.port,
            rejection.reason,
            rejection.domain
        );
        rejected.added += 1;
        let added = rejected.added;
        rejected.domains.insert(key, (added, rejection));
        true
    }

    /// Refusals recorded this session, newest first.
    pub fn rejected(&self) -> Vec<Rejection> {
        let rejected = self.0.rejected.read().unwrap();
        let mut domains: Vec<_> = rejected.domains.values().collect();
        domains.sort_by(|a, b| b.0.cmp(&a.0));
        domains
            .into_iter()
            .map(|(_, rejection)| rejection.clone())
            .collect()
    }

    /// Forgets every refusal, so each domain is inspected again on its next connection.
    pub fn retry(&self) {
        self.0.rejected.write().unwrap().domains.clear();
    }
}

fn port(authority: &Authority) -> u16 {
    authority.port_u16().unwrap_or(443)
}

fn key(authority: &Authority) -> String {
    format!("{}:{}", domain(authority.host()), port(authority))
}

/// The registrable domain of `host`, shared by a service's shard and CDN hosts; IP addresses and single labels stand alone.
pub fn domain(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host.starts_with('[') || host.parse::<IpAddr>().is_ok() {
        return host;
    }
    psl::domain_str(&host).map(str::to_owned).unwrap_or(host)
}

/// The alert a client sent when it refused the certificate during the handshake.
pub(crate) fn rejection_alert(error: &std::io::Error) -> Option<AlertDescription> {
    use AlertDescription::*;
    match error.get_ref()?.downcast_ref::<rustls::Error>()? {
        rustls::Error::AlertReceived(
            alert @ (BadCertificate
            | UnsupportedCertificate
            | CertificateRevoked
            | CertificateExpired
            | CertificateUnknown
            | UnknownCA
            | AccessDenied),
        ) => Some(*alert),
        _ => None,
    }
}

/// How a handshake that failed after the client hello refused the certificate: its alert, or a close without one.
pub(crate) fn refusal(error: &std::io::Error) -> Option<String> {
    use std::io::ErrorKind::*;
    let closed = matches!(
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::AlertReceived(
            AlertDescription::CloseNotify | AlertDescription::UserCanceled
        ))
    );
    if let Some(alert) = rejection_alert(error) {
        Some(format!("{alert:?}"))
    } else if closed
        || matches!(
            error.kind(),
            UnexpectedEof | ConnectionReset | ConnectionAborted | BrokenPipe
        )
    {
        Some("Closed during handshake".into())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use AlertDescription::*;

    fn received(alert: AlertDescription) -> std::io::Error {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            rustls::Error::AlertReceived(alert),
        )
    }

    fn authority(text: &str) -> Authority {
        text.parse().unwrap()
    }

    #[test]
    fn only_certificate_alerts_count_as_rejections() {
        for alert in [CertificateUnknown, AccessDenied, UnknownCA, BadCertificate] {
            assert_eq!(rejection_alert(&received(alert)), Some(alert));
        }
        for error in [
            received(HandshakeFailure),
            received(DecryptError),
            received(NoApplicationProtocol),
            std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
            std::io::Error::other("connection reset"),
        ] {
            assert_eq!(rejection_alert(&error), None, "{error}");
        }
    }

    #[test]
    fn rejected_hosts_pass_through_per_port_until_retried_and_only_while_enabled() {
        let inspection = Inspection::new(BTreeSet::from(DEFAULT_PORTS), true);
        assert!(inspection.inspects_port(443) && inspection.inspects_port(8443));
        assert!(!inspection.inspects_port(5228));
        let graph = authority("Graph.Facebook.com:443");
        assert!(inspection.rejection(&graph).is_none());
        assert!(inspection.reject(&graph, "CertificateUnknown".into()));
        assert!(inspection.reject(&authority("graph.facebook.com:443"), "AccessDenied".into()));
        let rejection = inspection
            .rejection(&authority("graph.facebook.com:443"))
            .unwrap();
        assert_eq!(
            (
                rejection.domain.as_str(),
                rejection.host.as_str(),
                rejection.port
            ),
            ("facebook.com", "graph.facebook.com", 443)
        );
        assert_eq!(rejection.reason, "CertificateUnknown");
        assert!(
            inspection
                .rejection(&authority("graph.facebook.com:8443"))
                .is_none()
        );

        inspection.configure(BTreeSet::from(DEFAULT_PORTS), false);
        assert!(inspection.rejection(&graph).is_none());
        assert!(inspection.rejected().is_empty());
        assert!(!inspection.reject(&authority("other.example:443"), "UnknownCA".into()));
        inspection.configure(BTreeSet::new(), true);
        assert!(!inspection.inspects_port(443));
        assert!(inspection.rejected().is_empty());
        assert!(inspection.reject(&graph, "CertificateUnknown".into()));
        assert_eq!(inspection.rejected().len(), 1);

        inspection.retry();
        assert!(inspection.rejected().is_empty());
        assert!(inspection.rejection(&graph).is_none());
    }

    #[test]
    fn refusals_after_the_hello_include_closes_without_an_alert() {
        assert_eq!(
            refusal(&received(CertificateUnknown)).as_deref(),
            Some("CertificateUnknown")
        );
        for error in [
            std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
            std::io::Error::from(std::io::ErrorKind::ConnectionReset),
            received(UserCanceled),
        ] {
            assert_eq!(
                refusal(&error).as_deref(),
                Some("Closed during handshake"),
                "{error}"
            );
        }
        for error in [
            received(HandshakeFailure),
            received(ProtocolVersion),
            std::io::Error::other("no shared cipher suite"),
        ] {
            assert_eq!(refusal(&error), None, "{error}");
        }
    }

    #[test]
    fn a_refusal_covers_the_registrable_domain_on_its_port() {
        let inspection = Inspection::new(BTreeSet::from(DEFAULT_PORTS), true);
        assert!(inspection.reject(
            &authority("scontent-den2-1.cdninstagram.com:443"),
            "Closed during handshake".into()
        ));
        for sibling in [
            "scontent-sjc3-1.cdninstagram.com:443",
            "cdninstagram.com:443",
        ] {
            let rejection = inspection.rejection(&authority(sibling)).unwrap();
            assert_eq!(
                (rejection.domain.as_str(), rejection.host.as_str()),
                ("cdninstagram.com", "scontent-den2-1.cdninstagram.com")
            );
            assert_eq!(rejection.exclusion(), "*.cdninstagram.com");
        }
        for unrelated in [
            "scontent-sjc3-1.cdninstagram.com:8443",
            "instagram.com:443",
            "evilcdninstagram.com:443",
        ] {
            assert!(
                inspection.rejection(&authority(unrelated)).is_none(),
                "{unrelated}"
            );
        }

        assert!(inspection.reject(&authority("d1.cloudfront.net:443"), "UnknownCA".into()));
        assert!(
            inspection
                .rejection(&authority("d2.cloudfront.net:443"))
                .is_none()
        );
        assert!(inspection.reject(&authority("127.0.0.1:443"), "UnknownCA".into()));
        assert!(inspection.rejection(&authority("127.0.0.2:443")).is_none());
        assert_eq!(
            inspection
                .rejection(&authority("127.0.0.1:443"))
                .unwrap()
                .exclusion(),
            "127.0.0.1"
        );
        assert_eq!(domain("LOCALHOST."), "localhost");
        assert_eq!(domain("www.example.co.uk"), "example.co.uk");
        assert_eq!(domain("[::1]"), "[::1]");
        assert_eq!(inspection.rejected().len(), 3);
    }

    #[test]
    fn only_listed_android_apps_are_decrypted() {
        let inspection = Inspection::new(BTreeSet::from(DEFAULT_PORTS), true);
        assert!(!inspection.decrypts_app("com.android.chrome"));
        inspection.set_decrypted_apps(&[
            "com.android.chrome".to_owned(),
            " org.mozilla.* ".to_owned(),
        ]);
        for app in [
            "com.android.chrome",
            "org.mozilla.firefox",
            "ORG.MOZILLA.FENIX",
        ] {
            assert!(inspection.decrypts_app(app), "{app}");
        }
        for app in ["com.instagram.android", "com.android.chrome.beta", ""] {
            assert!(!inspection.decrypts_app(app), "{app}");
        }
        inspection.set_decrypted_apps(&["*".to_owned()]);
        assert!(inspection.decrypts_app("com.instagram.android"));
    }

    #[test]
    fn the_oldest_rejection_makes_room_and_the_newest_lists_first() {
        let inspection = Inspection::new(BTreeSet::new(), true);
        for index in 0..=MAX_REJECTED {
            inspection.reject(
                &authority(&format!("host{index}.example:443")),
                "UnknownCA".into(),
            );
        }
        let rejected = inspection.rejected();
        assert_eq!(rejected.len(), MAX_REJECTED);
        assert_eq!(rejected[0].host, format!("host{MAX_REJECTED}.example"));
        assert!(
            !rejected
                .iter()
                .any(|rejection| rejection.host == "host0.example")
        );
    }
}

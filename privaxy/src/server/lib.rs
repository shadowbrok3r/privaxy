use crate::blocker::AdblockRequester;
use crate::events::Event;
use crate::proxy::exclusions::LocalExclusionStore;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use reqwest::redirect::Policy;
use rustls::crypto::CryptoProvider;
use rustls::crypto::ring::default_provider;
use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::sync::broadcast;

pub mod blocker;
mod blocker_utils;
mod body;
mod ca;
pub mod capture;
mod cert;
pub mod configuration;
pub mod events;
mod idle;
pub mod inspection;
pub mod listener;
mod proxy;
pub mod statistics;
pub mod storage;
pub mod transparent;

/// Client connections close after this long without traffic.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
pub struct PrivaxyServer {
    pub capture: capture::CaptureStore,
    pub listener: listener::ProxyListener,
    pub ca_certificate_pem: String,
    pub configuration_updater_sender: tokio::sync::mpsc::Sender<configuration::Configuration>,
    pub configuration_save_lock: Arc<tokio::sync::Mutex<()>>,
    pub blocking_disabled_store: blocker::BlockingDisabledStore,
    pub statistics: statistics::Statistics,
    pub local_exclusion_store: LocalExclusionStore,
    pub inspection: inspection::Inspection,
    /// Network-level capture: connections the firewall redirects to port 8103 on loopback.
    pub network_capture: transparent::TransparentListener,
    /// SHA-256 of the inspection CA's public key, base64, as Chromium's `--ignore-certificate-errors-spki-list` takes it.
    pub ca_spki_sha256: String,
    // A Sender is required to subscribe to broadcasted messages
    pub requests_broadcast_sender: broadcast::Sender<Event>,
}

pub async fn start_privaxy() -> PrivaxyServer {
    try_start_privaxy()
        .await
        .expect("Unable to initialize Privaxy")
}

pub async fn try_start_privaxy() -> Result<PrivaxyServer, String> {
    // Install the ring crypto provider for rustls
    let _ = CryptoProvider::install_default(default_provider());

    let ip = [127, 0, 0, 1];

    // We use reqwest instead of hyper's client to perform most of the proxying as it's more convenient
    // to handle compression as well as offers a more convenient interface.
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .redirect(Policy::none())
        .no_proxy()
        .gzip(true)
        .brotli(true)
        .deflate(true)
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(10)
        .build()
        .map_err(|error| error.to_string())?;

    let configuration = configuration::Configuration::read_from_home(client.clone())
        .await
        .map_err(|error| format!("Cannot load configuration: {error}"))?;

    let local_exclusion_store =
        LocalExclusionStore::new(Vec::from_iter(configuration.exclusions.clone().into_iter()));
    let local_exclusion_store_clone = local_exclusion_store.clone();
    let inspection = inspection::Inspection::new(
        configuration.inspected_ports.clone(),
        configuration.pass_through_rejected,
    );
    inspection.set_decrypted_apps(&configuration.decrypted_apps);
    let inspection_clone = inspection.clone();
    let (lan_proxy, lan_clients) = (configuration.lan_proxy, configuration.lan_clients.clone());

    let ca_certificate = configuration.ca_certificate().map_err(|e| e.to_string())?;
    let ca_certificate_pem = String::from_utf8(ca_certificate.to_pem().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let ca_der = bytes::Bytes::from(ca_certificate.to_der().map_err(|e| e.to_string())?);
    let ca_spki_sha256 = ca::spki_sha256(&ca_certificate).map_err(|e| e.to_string())?;
    let ca_private_key = configuration.ca_private_key().map_err(|e| e.to_string())?;

    let cert_cache = cert::CertCache::new(ca_certificate, ca_private_key);
    let capture = capture::CaptureStore::new(
        &dirs::cache_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("privaxy/captures"),
    )
    .map_err(|error| format!("Cannot create capture storage: {error}"))?;
    let capture_for_server = capture.clone();

    let statistics = statistics::Statistics::new();
    let statistics_clone = statistics.clone();

    let (broadcast_tx, _broadcast_rx) = broadcast::channel(32);
    let broadcast_tx_clone = broadcast_tx.clone();

    let blocking_disabled_store = blocker::BlockingDisabledStore(Arc::new(std::sync::RwLock::new(
        configuration.observe_only,
    )));
    let blocking_disabled_store_clone = blocking_disabled_store.clone();

    let (crossbeam_sender, crossbeam_receiver) = crossbeam_channel::unbounded();
    let blocker_sender = crossbeam_sender.clone();

    let blocker_requester = AdblockRequester::new(blocker_sender, blocking_disabled_store.clone());

    let configuration_updater = configuration::ConfigurationUpdater::new(
        configuration.clone(),
        client.clone(),
        blocker_requester.clone(),
        None,
    )
    .await;

    let configuration_updater_tx = configuration_updater.tx.clone();
    configuration_updater_tx.send(configuration).await.unwrap();

    configuration_updater.start();

    thread::spawn(move || {
        let blocker = blocker::Blocker::new(
            crossbeam_sender,
            crossbeam_receiver,
            blocking_disabled_store,
        );

        blocker.handle_requests()
    });

    let proxy_server_addr = SocketAddr::from((ip, 8100));

    let proxy = proxy::mitm::Proxy {
        adblock: blocker_requester,
        upstream: proxy::serve::Upstream::new(client),
        cert_cache,
        events: broadcast_tx,
        statistics,
        exclusions: local_exclusion_store,
        capture: capture_for_server,
        inspection,
        ca_der,
    };
    let network_capture = transparent::TransparentListener::spawn(proxy.clone());
    let listener = listener::ProxyListener::spawn(
        proxy_server_addr,
        move |stream, client_addr, cancellation| {
            let proxy = proxy.clone();
            async move {
                let peer = proxy::mitm::Peer {
                    ip: client_addr.ip(),
                    app: None,
                    proxy: stream.local_addr().unwrap_or(proxy_server_addr),
                    cancellation,
                };
                let service = service_fn(move |req| {
                    proxy::serve_mitm_session(proxy.clone(), peer.clone(), req)
                });
                let activity = idle::Activity::new();
                let stream = idle::Watched::new(stream, activity.clone());
                let result = activity
                    .until_idle(
                        IDLE_TIMEOUT,
                        http1::Builder::new()
                            .preserve_header_case(true)
                            .title_case_headers(true)
                            .keep_alive(true)
                            .serve_connection(TokioIo::new(stream), service)
                            .with_upgrades(),
                    )
                    .await;
                if let Some(Err(error)) = result {
                    log::debug!("Connection error: {error}");
                }
            }
        },
    );
    for entry in listener.serve_lan(lan_proxy, &lan_clients) {
        log::warn!("Ignoring LAN client {entry:?}: not an address or CIDR range");
    }

    Ok(PrivaxyServer {
        capture,
        listener,
        ca_certificate_pem,
        configuration_updater_sender: configuration_updater_tx,
        configuration_save_lock: Arc::new(tokio::sync::Mutex::new(())),
        blocking_disabled_store: blocking_disabled_store_clone,
        statistics: statistics_clone,
        local_exclusion_store: local_exclusion_store_clone,
        inspection: inspection_clone,
        network_capture,
        ca_spki_sha256,
        requests_broadcast_sender: broadcast_tx_clone,
    })
}

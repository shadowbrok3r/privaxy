use eframe::egui;
use egui_icon_pack::{phosphor_regular as svg, widgets as icons};
use egui_theme_kit::{chrome, picker, store::JsonDirStore, title_bar::TitleBar};
use privaxy::{PrivaxyServer, events::Event, listener::ListenerStatus};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
mod accent;
mod connect;
mod dashboard;
mod diagnostics;
mod network;
mod network_capture;
mod pairing;
mod traffic;
mod traffic_search;

/// Network-level capture, as far as it got.
#[derive(Default)]
enum Capture {
    #[default]
    Off,
    /// Waiting for administrator authorization and the firewall rules.
    Starting,
    /// The helper holding the firewall rules; dropping it removes them.
    On(#[allow(dead_code)] network_capture::NetworkCapture),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Dashboard,
    Traffic,
    Settings,
    Logs,
}

struct App {
    ctx: egui::Context,
    runtime: tokio::runtime::Runtime,
    server: Arc<Mutex<Option<PrivaxyServer>>>,
    startup_error: Arc<Mutex<Option<String>>>,
    config: Arc<Mutex<Option<privaxy::configuration::Configuration>>>,
    chrome: chrome::Chrome,
    store: Arc<JsonDirStore>,
    picker: picker::PickerState,
    tab: Tab,
    traffic: traffic::Traffic,
    logs: diagnostics::LogView,
    custom: String,
    exclusions: String,
    ports: String,
    decrypted_apps: String,
    lan_clients: String,
    drafts_loaded: bool,
    /// Settings as last loaded or saved, to tell when Settings has unsaved edits.
    settings_saved: Option<privaxy::configuration::Configuration>,
    identity: Option<pairing::Identity>,
    relay: Option<tokio::task::JoinHandle<()>>,
    relay_status: Arc<Mutex<String>>,
    connections: Arc<pairing::Connections>,
    host: String,
    addresses: network::Addresses,
    notice: Arc<Mutex<String>>,
    pairing_qr: bool,
    revoke_confirm: bool,
    checking_proxy: Arc<AtomicBool>,
    /// The desktop's proxy settings point at Privaxy.
    system_proxy: Arc<AtomicBool>,
    network_capture: Arc<Mutex<Capture>>,
}
impl App {
    fn new(cc: &eframe::CreationContext<'_>, chrome: chrome::Chrome) -> Self {
        egui_theme_kit::init(cc, Default::default());
        egui_icon_pack::install(&cc.egui_ctx);
        egui_theme_kit::title_bar::windows::client_area::install(cc);
        let store =
            Arc::new(JsonDirStore::open(JsonDirStore::default_dir("privaxy").unwrap()).unwrap());
        egui_theme_kit::persist::apply_startup_from_store(&cc.egui_ctx, &*store, None);
        let identity = pairing::Identity::load();
        let notice = identity.as_ref().err().cloned().unwrap_or_default();
        let addresses = network::Addresses::detect();
        let host = addresses.preferred_host();
        let app = Self {
            ctx: cc.egui_ctx.clone(),
            runtime: tokio::runtime::Runtime::new().unwrap(),
            server: Arc::default(),
            startup_error: Arc::default(),
            config: Arc::default(),
            chrome,
            store,
            picker: Default::default(),
            tab: Tab::Dashboard,
            traffic: Default::default(),
            logs: Default::default(),
            custom: String::new(),
            exclusions: String::new(),
            ports: String::new(),
            decrypted_apps: String::new(),
            lan_clients: String::new(),
            drafts_loaded: false,
            settings_saved: None,
            identity: identity.ok(),
            relay: None,
            connections: Arc::default(),
            relay_status: Arc::new(Mutex::new("Relay is off".into())),
            host,
            addresses,
            notice: Arc::new(Mutex::new(notice)),
            pairing_qr: false,
            revoke_confirm: false,
            checking_proxy: Arc::default(),
            system_proxy: Arc::default(),
            network_capture: Arc::default(),
        };
        app.initialize_backend();
        app
    }
    fn initialize_backend(&self) {
        *self.startup_error.lock().unwrap() = None;
        let (server, config, error, system_proxy, notice) = (
            self.server.clone(),
            self.config.clone(),
            self.startup_error.clone(),
            self.system_proxy.clone(),
            self.notice.clone(),
        );
        self.runtime.spawn(async move {
            let backend = match privaxy::try_start_privaxy().await {
                Ok(backend) => backend,
                Err(reason) => {
                    log::error!("Proxy initialization failed: {reason}");
                    *error.lock().unwrap() = Some(reason);
                    return;
                }
            };
            *server.lock().unwrap() = Some(backend);
            match privaxy::configuration::Configuration::read_from_home(reqwest::Client::new())
                .await
            {
                Ok(cfg) => {
                    let wanted = cfg.system_proxy;
                    *config.lock().unwrap() = Some(cfg);
                    let applied = tokio::task::spawn_blocking(move || {
                        let proxy = connect::SystemProxy::detect()?;
                        if wanted && !proxy.is_active() {
                            proxy.apply()?;
                        }
                        Ok::<_, String>(proxy.is_active())
                    })
                    .await;
                    match applied {
                        Ok(Ok(active)) => system_proxy.store(active, Ordering::Relaxed),
                        Ok(Err(reason)) if wanted => {
                            *notice.lock().unwrap() = format!("System proxy: {reason}")
                        }
                        _ => {}
                    }
                }
                Err(reason) => *error.lock().unwrap() = Some(reason.to_string()),
            }
        });
    }
    fn connection_label(&self) -> String {
        let count = self.connections.count();
        if count > 0 {
            format!("Android connected ({count})")
        } else if self.relay.is_some() {
            "Android offline".into()
        } else {
            "Android relay off".into()
        }
    }
    fn start_relay(&mut self, server: &PrivaxyServer) {
        if self.relay.is_some() {
            return;
        }
        let Some(identity) = self.identity.clone() else {
            return;
        };
        if !server.listener.status().is_running() {
            server.listener.start();
        }
        *self.relay_status.lock().unwrap() = "Starting relay…".into();
        let (status, connections) = (self.relay_status.clone(), self.connections.clone());
        let inspection_ca_pem = server.ca_certificate_pem.clone();
        self.relay = Some(self.runtime.spawn(async move {
            if let Err(e) = identity
                .serve(status.clone(), connections, inspection_ca_pem)
                .await
            {
                log::error!("Android relay failed: {e}");
                *status.lock().unwrap() = e;
            }
        }));
    }
    fn stop_relay(&mut self) {
        log::info!("Android relay stop requested");
        if let Some(task) = self.relay.take() {
            task.abort();
        }
        *self.relay_status.lock().unwrap() = "Relay is off".into();
    }
    fn export_ca(&self, server: &PrivaxyServer) {
        if let Some(path) = rfd::FileDialog::new()
            .set_file_name("privaxy-desktop-ca.crt")
            .save_file()
        {
            *self.notice.lock().unwrap() = match std::fs::write(path, &server.ca_certificate_pem) {
                Ok(()) => {
                    "Inspection CA exported. Install it in your browser or device trust store."
                        .into()
                }
                Err(e) => format!("Could not export CA: {e}"),
            };
        }
    }
    fn check_proxy(&self) {
        use std::sync::atomic::Ordering;
        if self.checking_proxy.swap(true, Ordering::Relaxed) {
            return;
        }
        let (notice, running) = (self.notice.clone(), self.checking_proxy.clone());
        self.runtime.spawn(async move {
            let start = std::time::Instant::now();
            let result = async {
                let client = reqwest::Client::builder()
                    .no_proxy()
                    .proxy(reqwest::Proxy::all("http://127.0.0.1:8100")?)
                    .timeout(std::time::Duration::from_secs(10))
                    .build()?;
                client
                    .head("http://example.com")
                    .send()
                    .await?
                    .error_for_status()
            }
            .await;
            *notice.lock().unwrap() = match result {
                Ok(response) => format!(
                    "Proxy check passed: HTTP {} from example.com in {} ms.",
                    response.status().as_u16(),
                    start.elapsed().as_millis()
                ),
                Err(error) => format!("Proxy check failed: {error}"),
            };
            running.store(false, Ordering::Relaxed);
        });
    }
    /// Saves the configuration without reloading filters.
    fn save_config(&self, config: privaxy::configuration::Configuration, server: &PrivaxyServer) {
        let (lock, notice) = (server.configuration_save_lock.clone(), self.notice.clone());
        self.runtime.spawn(async move {
            let _guard = lock.lock().await;
            if let Err(error) = config.save().await {
                *notice.lock().unwrap() = format!("Could not save settings: {error}");
            }
        });
    }
    /// Changes a configuration field in memory and on disk.
    fn update_config(
        &self,
        server: &PrivaxyServer,
        change: impl FnOnce(&mut privaxy::configuration::Configuration),
    ) {
        let config = {
            let mut config = self.config.lock().unwrap();
            config.as_mut().map(|cfg| {
                change(cfg);
                cfg.clone()
            })
        };
        if let Some(config) = config {
            self.save_config(config, server);
        }
    }
    /// Adds or removes an app on Decrypt these Android apps, effective from its next connection.
    fn decrypt_app(&mut self, change: traffic::AppDecryption, server: &PrivaxyServer) {
        let traffic::AppDecryption {
            package,
            label,
            decrypt,
        } = change;
        self.update_config(server, |cfg| {
            cfg.decrypted_apps
                .retain(|app| !app.trim().eq_ignore_ascii_case(&package));
            if decrypt {
                cfg.decrypted_apps.insert(package.clone());
            }
        });
        if let Some(cfg) = self.config.lock().unwrap().as_ref() {
            server.inspection.set_decrypted_apps(&cfg.decrypted_apps);
            if let Some(saved) = &mut self.settings_saved {
                saved.decrypted_apps = cfg.decrypted_apps.clone();
            }
        }
        // The Settings draft follows, keeping any other unsaved lines.
        let mut lines: Vec<&str> = self
            .decrypted_apps
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.eq_ignore_ascii_case(&package))
            .collect();
        if decrypt {
            lines.push(&package);
        }
        self.decrypted_apps = lines.join("\n");
        *self.notice.lock().unwrap() = if decrypt {
            format!(
                "Decrypting {label} from its next connection. Apps that pin certificates or ignore user-installed CAs refuse and pass through encrypted."
            )
        } else {
            format!("{label} passes through encrypted from its next connection.")
        };
    }
    fn set_system_proxy(&self, on: bool, server: &PrivaxyServer) {
        self.update_config(server, |cfg| cfg.system_proxy = on);
        let (state, notice) = (self.system_proxy.clone(), self.notice.clone());
        std::thread::spawn(move || {
            let result = connect::SystemProxy::detect().and_then(|proxy| {
                if on { proxy.apply() } else { proxy.restore() }?;
                Ok(proxy.is_active())
            });
            match result {
                Ok(active) => state.store(active, Ordering::Relaxed),
                Err(reason) => *notice.lock().unwrap() = format!("System proxy: {reason}"),
            }
        });
    }
    fn set_lan_proxy(&self, on: bool, server: &PrivaxyServer) {
        self.update_config(server, |cfg| cfg.lan_proxy = on);
        let clients = self
            .config
            .lock()
            .unwrap()
            .as_ref()
            .map(|cfg| cfg.lan_clients.clone())
            .unwrap_or_default();
        let invalid = server.listener.serve_lan(on, &clients);
        if !invalid.is_empty() {
            *self.notice.lock().unwrap() = format!(
                "Ignored LAN clients that are not addresses or ranges: {}",
                invalid.join(", ")
            );
        }
        log::info!("LAN proxy {}", if on { "enabled" } else { "disabled" });
    }
    fn set_network_capture(&self, on: bool, server: &PrivaxyServer) {
        if !on {
            let previous = std::mem::take(&mut *self.network_capture.lock().unwrap());
            server.network_capture.stop();
            std::thread::spawn(move || drop(previous));
            log::info!("Network capture disabled");
            return;
        }
        let mut ports: Vec<u16> = self
            .config
            .lock()
            .unwrap()
            .as_ref()
            .map(|cfg| cfg.inspected_ports.iter().copied().collect())
            .unwrap_or_else(|| privaxy::inspection::DEFAULT_PORTS.to_vec());
        ports.insert(0, 80);
        ports.dedup();
        server.network_capture.start();
        *self.network_capture.lock().unwrap() = Capture::Starting;
        let (state, notice, listener) = (
            self.network_capture.clone(),
            self.notice.clone(),
            server.network_capture.clone(),
        );
        std::thread::spawn(move || {
            match network_capture::NetworkCapture::start(&ports, privaxy::transparent::PORT) {
                Ok(capture) => {
                    log::info!("Network capture enabled for ports {ports:?}");
                    *state.lock().unwrap() = Capture::On(capture);
                }
                Err(reason) => {
                    log::warn!("Network capture failed: {reason}");
                    *state.lock().unwrap() = Capture::Off;
                    listener.stop();
                    *notice.lock().unwrap() = format!("Network capture is off: {reason}");
                }
            }
        });
    }
    fn save_settings(&self, config: privaxy::configuration::Configuration, server: &PrivaxyServer) {
        let (mut server, notice) = (server.clone(), self.notice.clone());
        self.runtime.spawn(async move {
            let result = async {
                let lock = server.configuration_save_lock.clone();
                let _guard = lock.lock().await;
                config.save().await.map_err(|e| e.to_string())?;
                server
                    .local_exclusion_store
                    .replace_exclusions(config.exclusions.iter().cloned().collect());
                server
                    .inspection
                    .configure(config.inspected_ports.clone(), config.pass_through_rejected);
                server.inspection.set_decrypted_apps(&config.decrypted_apps);
                let invalid = server.listener.serve_lan(config.lan_proxy, &config.lan_clients);
                server
                    .configuration_updater_sender
                    .send(config)
                    .await
                    .map_err(|e| e.to_string())?;
                if invalid.is_empty() {
                    Ok(())
                } else {
                    Err(format!(
                        "Settings saved; filters reloading. Ignored LAN clients that are not addresses or ranges: {}",
                        invalid.join(", ")
                    ))
                }
            }
            .await;
            *notice.lock().unwrap() = result
                .err()
                .unwrap_or_else(|| "Settings saved; filters reloading.".into());
        });
    }
}
impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // Keep a full-width, opaque track even when idle. egui 0.37's solid geometry can
        // invert the vertical handle when a wide table is clipped by horizontal scrolling;
        // fixed-width floating geometry pins it to the visible edge and still reserves space.
        ui.style_mut().spacing.scroll = egui::style::ScrollStyle {
            bar_width: 12.0,
            handle_min_length: 32.0,
            foreground_color: true,
            floating: true,
            floating_width: 12.0,
            floating_allocated_width: 12.0,
            dormant_background_opacity: 1.0,
            active_background_opacity: 1.0,
            interact_background_opacity: 1.0,
            dormant_handle_opacity: 1.0,
            active_handle_opacity: 1.0,
            interact_handle_opacity: 1.0,
            ..egui::style::ScrollStyle::solid()
        };
        if self.relay.as_ref().is_some_and(|task| task.is_finished()) {
            self.relay = None;
        }
        let server = self.server.lock().unwrap().clone();
        TitleBar::new("privaxy.title", "Privaxy")
            .frameless(self.chrome.frameless)
            .show(ui, |ui, side| match side {
                egui_theme_kit::title_bar::Side::Left => {
                    let primary = egui_theme_kit::Tokens::get(ui.ctx()).primary;
                    for (tab, icon, label) in [
                        (Tab::Dashboard, svg::GAUGE, "Dashboard"),
                        (Tab::Traffic, svg::ARROWS_DOWN_UP, "Traffic"),
                        (Tab::Settings, svg::SLIDERS, "Settings"),
                        (Tab::Logs, svg::SCROLL, "Logs"),
                    ] {
                        if accent::tab(ui, icon, self.tab == tab, label, primary).clicked() {
                            self.tab = tab;
                        }
                    }
                }
                egui_theme_kit::title_bar::Side::Right => {
                    let t = egui_theme_kit::Tokens::get(ui.ctx());
                    if icons::button(
                        ui,
                        svg::DEVICE_MOBILE,
                        egui::RichText::new(self.connection_label()).color(
                            if self.connections.count() > 0 {
                                t.success
                            } else {
                                t.text_dim
                            },
                        ),
                    )
                    .clicked()
                    {
                        self.tab = Tab::Dashboard;
                    }
                }
            });
        egui::CentralPanel::default()
            .frame(egui::Frame::new().inner_margin(18))
            .show(ui, |ui| {
                let error = self.startup_error.lock().unwrap().clone();
                if let Some(error) = error {
                    ui.colored_label(egui_theme_kit::Tokens::get(ui.ctx()).error, error);
                    if server.is_none()
                        && icons::button(ui, svg::ARROWS_CLOCKWISE, "Retry startup").clicked()
                    {
                        self.initialize_backend();
                    }
                } else if server.is_none() {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Loading proxy and filters…");
                    });
                }
                let notice = self.notice.lock().unwrap().clone();
                if !notice.is_empty() {
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(notice);
                            if icons::small_button(ui, svg::X, "Dismiss").clicked() {
                                self.notice.lock().unwrap().clear();
                            }
                        });
                    });
                    ui.add_space(8.);
                }
                let events = server
                    .as_ref()
                    .map(|server| server.capture.events())
                    .unwrap_or_default();
                match self.tab {
                    Tab::Dashboard => {
                        egui::ScrollArea::vertical()
                            .id_salt("dashboard")
                            .show(ui, |ui| self.dashboard(ui, server.as_ref(), &events))
                            .inner
                    }
                    Tab::Traffic => {
                        let decrypted = self
                            .config
                            .lock()
                            .unwrap()
                            .as_ref()
                            .map(|config| config.decrypted_apps.clone())
                            .unwrap_or_default();
                        self.traffic.show(
                            ui,
                            server.as_ref(),
                            &events,
                            &decrypted,
                            self.notice.clone(),
                        );
                        if let Some(change) = self.traffic.take_app_decryption()
                            && let Some(server) = &server
                        {
                            self.decrypt_app(change, server);
                        }
                    }
                    Tab::Logs => self.logs.show(ui, self.notice.clone()),
                    Tab::Settings => self.settings(ui, server.as_ref()),
                }
            });
        self.dialogs(ui.ctx());
        picker::window(ui.ctx(), &mut self.picker, &*self.store);
        if self.chrome.frameless {
            egui_theme_kit::title_bar::window_edges(ui);
        }
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(250));
    }
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        egui_theme_kit::Tokens::get(&self.ctx)
            .base
            .to_normalized_gamma_f32()
    }
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        egui_theme_kit::save(&self.ctx, storage);
    }
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        drop(std::mem::take(&mut *self.network_capture.lock().unwrap()));
        if self.system_proxy.load(Ordering::Relaxed)
            && let Err(error) = connect::SystemProxy::detect().and_then(|proxy| proxy.release())
        {
            log::error!("Could not restore the system proxy settings: {error}");
        }
    }
}
fn main() -> eframe::Result {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some(network_capture::HELPER_FLAG) {
        std::process::exit(network_capture::run_helper(&args[2..]));
    }
    let _ = privaxy_diagnostics::init(None);
    let logs = dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("privaxy/logs/desktop.log");
    if let Err(error) = privaxy_diagnostics::attach_file(&logs) {
        log::error!("Cannot open diagnostic log: {error}");
    }
    log::info!(
        "Privaxy desktop {} starting on {}",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS
    );
    let _ = rustls::crypto::ring::default_provider().install_default();
    let chrome = chrome::resolve_from_process("privaxy");
    let viewport = chrome::viewport(
        egui::ViewportBuilder::default()
            .with_inner_size([1240., 860.])
            .with_min_inner_size([800., 580.])
            .with_title("Privaxy"),
        &chrome,
    );
    eframe::run_native(
        "Privaxy",
        eframe::NativeOptions {
            viewport,
            renderer: eframe::Renderer::Glow,
            ..Default::default()
        },
        Box::new(move |cc| Ok(Box::new(App::new(cc, chrome)))),
    )
}

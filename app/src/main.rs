use eframe::egui;
use egui_theme_kit::{chrome, picker, store::JsonDirStore, title_bar::TitleBar};
use std::sync::{Arc, Mutex};
mod pairing;

struct App {
    ctx: egui::Context,
    runtime: tokio::runtime::Runtime,
    server: Arc<Mutex<Option<privaxy::PrivaxyServer>>>,
    events: Arc<Mutex<std::collections::VecDeque<privaxy::events::Event>>>,
    config: Arc<Mutex<Option<privaxy::configuration::Configuration>>>,
    chrome: chrome::Chrome,
    store: Arc<JsonDirStore>,
    picker: picker::PickerState,
    tab: usize,
    query: String,
    custom: String,
    exclusions: String,
    drafts_loaded: bool,
    identity: Option<pairing::Identity>,
    relay: Option<tokio::task::JoinHandle<()>>,
    relay_status: Arc<Mutex<String>>,
    host: String,
    notice: Arc<Mutex<String>>,
}
impl App {
    fn new(cc: &eframe::CreationContext<'_>, chrome: chrome::Chrome) -> Self {
        egui_theme_kit::init(cc, Default::default());
        egui_theme_kit::title_bar::windows::client_area::install(cc);
        let store =
            Arc::new(JsonDirStore::open(JsonDirStore::default_dir("privaxy").unwrap()).unwrap());
        egui_theme_kit::persist::apply_startup_from_store(&cc.egui_ctx, &*store, None);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let server = Arc::new(Mutex::new(None));
        let events = Arc::new(Mutex::new(std::collections::VecDeque::new()));
        let config = Arc::new(Mutex::new(None));
        let (s, e, c) = (server.clone(), events.clone(), config.clone());
        runtime.spawn(async move {
            let backend = privaxy::start_privaxy().await;
            let mut rx = backend.requests_broadcast_sender.subscribe();
            *s.lock().unwrap() = Some(backend);
            if let Ok(cfg) =
                privaxy::configuration::Configuration::read_from_home(reqwest::Client::new()).await
            {
                *c.lock().unwrap() = Some(cfg);
            }
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        let mut rows = e.lock().unwrap();
                        rows.push_back(event);
                        while rows.len() > 5000 {
                            rows.pop_front();
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
        });
        let identity = pairing::Identity::load();
        let notice = identity.as_ref().err().cloned().unwrap_or_default();
        Self {
            ctx: cc.egui_ctx.clone(),
            runtime,
            server,
            events,
            config,
            chrome,
            store,
            picker: Default::default(),
            tab: 0,
            query: String::new(),
            custom: String::new(),
            exclusions: String::new(),
            drafts_loaded: false,
            identity: identity.ok(),
            relay: None,
            relay_status: Arc::new(Mutex::new("Disabled".into())),
            host: "".into(),
            notice: Arc::new(Mutex::new(notice)),
        }
    }
    fn content(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            for (i, label) in [
                "Dashboard",
                "Requests",
                "Filters",
                "Settings",
                "Android pairing",
            ]
            .iter()
            .enumerate()
            {
                ui.selectable_value(&mut self.tab, i, *label);
            }
        });
        ui.separator();
        let server = self.server.lock().unwrap().clone();
        if server.is_none() {
            ui.spinner();
            ui.label("Starting proxy and loading filters…");
        }
        match self.tab {
            0 => {
                if let Some(server) = &server {
                    ui.heading("Privaxy");
                    ui.label("HTTP proxy · 127.0.0.1:8100");
                    let stats = server.statistics.get_serialized();
                    ui.label(format!(
                        "{} requests  ·  {} blocked  ·  {} modified",
                        stats.proxied_requests, stats.blocked_requests, stats.modified_responses
                    ));
                    if let Ok(mut disabled) = server.blocking_disabled_store.0.write() {
                        ui.checkbox(&mut disabled, "Disable filtering (capture only)");
                    }
                }
            }
            1 => {
                ui.text_edit_singleline(&mut self.query);
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for event in self
                        .events
                        .lock()
                        .unwrap()
                        .iter()
                        .rev()
                        .filter(|e| self.query.is_empty() || e.url.contains(&self.query))
                    {
                        ui.horizontal_wrapped(|ui| {
                            ui.monospace(&event.method);
                            ui.label(if event.is_request_blocked {
                                "Blocked"
                            } else {
                                "Allowed"
                            });
                            ui.label(&event.url);
                        });
                    }
                });
            }
            2 | 3 => {
                let mut cfg = self.config.lock().unwrap().clone();
                if let Some(config) = &mut cfg {
                    if !self.drafts_loaded {
                        self.custom = config.custom_filters.join("\n");
                        self.exclusions = config
                            .exclusions
                            .iter()
                            .cloned()
                            .collect::<Vec<_>>()
                            .join("\n");
                        self.drafts_loaded = true;
                    }
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        if self.tab == 2 { for filter in &mut config.filters { ui.checkbox(&mut filter.enabled, &filter.title); } }
                        else {
                            if ui.button("Appearance — theme presets and templates").clicked() { self.picker.open = true; }
                            chrome::toggle_row(ui, &mut self.chrome, "Custom title bar");
                            ui.label("Custom filter rules"); ui.text_edit_multiline(&mut self.custom);
                            ui.label("Never intercept hosts (one per line)"); ui.text_edit_multiline(&mut self.exclusions);
                            if let Some(server) = &server { if ui.button("Export inspection CA").clicked() {
                                if let Some(path) = rfd::FileDialog::new().set_file_name("privaxy-desktop-ca.crt").save_file() { *self.notice.lock().unwrap() = match std::fs::write(path, &server.ca_certificate_pem) { Ok(()) => "CA exported. Install it on Android for desktop inspection.".into(), Err(e) => e.to_string() }; }
                            } }
                        }
                        if ui.button("Save settings and reload filters").clicked() {
                            config.custom_filters = self.custom.lines().filter(|s| !s.trim().is_empty()).map(str::to_owned).collect();
                            config.exclusions = self.exclusions.lines().map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned).collect();
                            if let Some(server) = &server {
                                let config = config.clone(); let mut server = server.clone(); let notice = self.notice.clone();
                                self.runtime.spawn(async move { let result = async { config.save().await.map_err(|e|e.to_string())?; server.local_exclusion_store.replace_exclusions(config.exclusions.iter().cloned().collect()); server.configuration_updater_sender.send(config).await.map_err(|e|e.to_string()) }.await; *notice.lock().unwrap() = result.err().unwrap_or_else(|| "Settings saved".into()); });
                            }
                        }
                    });
                }
                *self.config.lock().unwrap() = cfg;
            }
            4 => {
                ui.heading("Pair Android");
                ui.label(
                    "Enter this computer's LAN address. Android remembers the encrypted pairing.",
                );
                ui.text_edit_singleline(&mut self.host);
                if self.relay.is_none() {
                    if ui
                        .add_enabled(
                            self.identity.is_some() && server.is_some(),
                            egui::Button::new("Enable Android relay"),
                        )
                        .clicked()
                    {
                        let identity = self.identity.clone().unwrap();
                        let status = self.relay_status.clone();
                        self.relay = Some(self.runtime.spawn(async move {
                            if let Err(e) = identity.serve(status.clone()).await {
                                *status.lock().unwrap() = e;
                            }
                        }));
                    }
                } else if ui.button("Disable Android relay").clicked() {
                    self.relay.take().unwrap().abort();
                    *self.relay_status.lock().unwrap() = "Disabled".into();
                }
                ui.label(self.relay_status.lock().unwrap().clone());
                if let Some(identity) = &self.identity {
                    if !self.host.trim().is_empty() {
                        let code = identity.code(self.host.trim());
                        if ui.button("Copy pairing code").clicked() {
                            ui.ctx().copy_text(code.clone());
                        }
                        ui.label("Paste into Android Settings → Desktop pairing. Install the desktop inspection CA from Settings.");
                        if let Ok(qr) = qrcode::QrCode::new(code.as_bytes()) {
                            let quiet = 4;
                            let modules = qr.width() + quiet * 2;
                            let scale = (ui.available_width().min(420.) / modules as f32)
                                .floor()
                                .max(1.);
                            let (rect, _) = ui.allocate_exact_size(
                                egui::vec2(modules as f32 * scale, modules as f32 * scale),
                                egui::Sense::hover(),
                            );
                            ui.painter().rect_filled(rect, 0, egui::Color32::WHITE);
                            for y in 0..qr.width() {
                                for x in 0..qr.width() {
                                    if qr[(x, y)] == qrcode::Color::Dark {
                                        ui.painter().rect_filled(
                                            egui::Rect::from_min_size(
                                                rect.min
                                                    + egui::vec2(
                                                        (x + quiet) as f32 * scale,
                                                        (y + quiet) as f32 * scale,
                                                    ),
                                                egui::vec2(scale, scale),
                                            ),
                                            0,
                                            egui::Color32::BLACK,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                if ui.button("Revoke all pairings").clicked() {
                    if let Some(task) = self.relay.take() {
                        task.abort();
                    }
                    match pairing::Identity::generate() {
                        Ok(i) => {
                            self.identity = Some(i);
                            *self.relay_status.lock().unwrap() =
                                "Pairings revoked. Enable relay and pair again.".into();
                        }
                        Err(e) => *self.notice.lock().unwrap() = e,
                    }
                }
            }
            _ => {}
        }
        ui.label(self.notice.lock().unwrap().clone());
    }
}
impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        TitleBar::new("privaxy.title", "Privaxy")
            .frameless(self.chrome.frameless)
            .show(ui, |_, _| {});
        egui::CentralPanel::default().show(ui, |ui| self.content(ui));
        picker::window(ui.ctx(), &mut self.picker, &*self.store);
        if self.chrome.frameless {
            egui_theme_kit::title_bar::window_edges(ui);
        }
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(250));
    }
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        egui_theme_kit::save(&self.ctx, storage);
    }
}
fn main() -> eframe::Result {
    env_logger::init();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let chrome = chrome::resolve_from_process("privaxy");
    let viewport = chrome::viewport(
        egui::ViewportBuilder::default()
            .with_inner_size([1100., 780.])
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

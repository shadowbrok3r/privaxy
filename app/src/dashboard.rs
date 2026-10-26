//! The desktop workspace: operations and activity together, detailed traffic one click away.
use super::*;
use egui::{Color32, RichText, Stroke};
use egui_theme_kit::{Tokens, controls::toggle};
use num_format::{Locale, ToFormattedString};

const CONNECTION_HELP: &str = "Relay: TCP 8101 on every interface. No route to host on Android means the connection never reached the relay: check the selected address, Wi-Fi client isolation and the desktop firewall.\n\nWith a Tailscale exit node on this desktop, allow LAN access in Tailscale so it can reply to the phone.\n\nAndroid runs one VPN at a time: use LAN for Capture all traffic. With the Tailscale Android VPN, keep capture off and use proxy-only mode.\n\nPaired phones receive the inspection CA automatically; install it on the phone under Pairing > Install desktop CA.";

fn card_frame(ui: &egui::Ui) -> egui::Frame {
    let t = Tokens::get(ui.ctx());
    egui::Frame::new()
        .fill(t.raised)
        .stroke(Stroke::new(1., t.card_border))
        .corner_radius(t.radius_md)
        .inner_margin(16)
}
/// A card title with `actions` laid out from the right edge.
fn title_row(ui: &mut egui::Ui, title: &str, actions: impl FnOnce(&mut egui::Ui)) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(title).size(17.).strong());
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), actions);
    });
    ui.add_space(10.);
}
fn panel<R>(ui: &mut egui::Ui, title: &str, content: impl FnOnce(&mut egui::Ui) -> R) -> R {
    card_frame(ui)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            title_row(ui, title, |_| {});
            content(ui)
        })
        .inner
}
/// A card that fills the rest of `ui`.
fn card<R>(ui: &mut egui::Ui, content: impl FnOnce(&mut egui::Ui) -> R) -> R {
    card_frame(ui)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.set_height(ui.available_height());
            content(ui)
        })
        .inner
}
/// Runs `add` in a child Ui confined to `rect`.
fn region<R>(
    ui: &mut egui::Ui,
    id: &str,
    rect: egui::Rect,
    add: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    let mut child = ui.new_child(
        egui::UiBuilder::new()
            .id_salt(id)
            .max_rect(rect)
            .layout(egui::Layout::top_down(egui::Align::Min)),
    );
    child.set_clip_rect(rect.intersect(ui.clip_rect()));
    add(&mut child)
}
/// A multiline text field filling the rest of `ui`; it scrolls once the text outgrows it.
fn fill_text(ui: &mut egui::Ui, id: &str, text: &mut String, hint: &str) {
    let height = ui.available_height();
    egui::ScrollArea::vertical()
        .id_salt(id)
        .max_height(height)
        .auto_shrink(false)
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(text)
                    .hint_text(hint)
                    .desired_width(f32::INFINITY)
                    .min_size(egui::vec2(0., height - 2.)),
            );
        });
}
/// The enabled filter lists, grouped; regional lists start collapsed.
fn filter_lists(ui: &mut egui::Ui, filters: &mut [privaxy::configuration::Filter]) {
    use privaxy::configuration::FilterGroup;
    let enabled = filters.iter().filter(|filter| filter.enabled).count();
    let total = filters.len();
    title_row(ui, "Filter lists", |ui| {
        ui.weak(format!("{enabled} of {total} enabled"));
    });
    egui::ScrollArea::vertical()
        .id_salt("filter_lists")
        .auto_shrink(false)
        .show(ui, |ui| {
            ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Truncate);
            for (group, name) in [
                (FilterGroup::Default, "Default"),
                (FilterGroup::Ads, "Ads"),
                (FilterGroup::Privacy, "Privacy"),
                (FilterGroup::Malware, "Malware"),
                (FilterGroup::Social, "Social"),
                (FilterGroup::Regional, "Regional"),
            ] {
                let mut lists: Vec<_> = filters
                    .iter_mut()
                    .filter(|filter| filter.group == group)
                    .collect();
                if lists.is_empty() {
                    continue;
                }
                let on = lists.iter().filter(|filter| filter.enabled).count();
                egui::CollapsingHeader::new(format!("{name}  {on}/{}", lists.len()))
                    .id_salt(name)
                    .default_open(group != FilterGroup::Regional)
                    .show(ui, |ui| {
                        let columns = if ui.available_width() >= 360. { 2 } else { 1 };
                        let width = ((ui.available_width() - 12. * (columns - 1) as f32)
                            / columns as f32)
                            .max(60.);
                        egui::Grid::new(name)
                            .num_columns(columns)
                            .spacing([12., 4.])
                            .min_col_width(width)
                            .max_col_width(width)
                            .show(ui, |ui| {
                                for (index, filter) in lists.iter_mut().enumerate() {
                                    ui.checkbox(&mut filter.enabled, &filter.title)
                                        .on_hover_text(&filter.title);
                                    if (index + 1) % columns == 0 {
                                        ui.end_row();
                                    }
                                }
                            });
                    });
            }
        });
}
/// Paints the pairing QR code for `code`, at most `max` points wide.
fn pairing_qr(ui: &mut egui::Ui, code: &str, max: f32) {
    let Ok(qr) = qrcode::QrCode::new(code.as_bytes()) else {
        return;
    };
    let quiet = 4;
    let modules = qr.width() + quiet * 2;
    let scale = (ui.available_width().min(max) / modules as f32).floor().max(1.);
    let (rect, _) = ui.allocate_exact_size(
        egui::Vec2::splat(modules as f32 * scale),
        egui::Sense::hover(),
    );
    ui.painter().rect_filled(rect, 0, Color32::WHITE);
    for y in 0..qr.width() {
        for x in 0..qr.width() {
            if qr[(x, y)] == qrcode::Color::Dark {
                ui.painter().rect_filled(
                    egui::Rect::from_min_size(
                        rect.min + egui::vec2((x + quiet) as f32 * scale, (y + quiet) as f32 * scale),
                        egui::vec2(scale, scale),
                    ),
                    0,
                    Color32::BLACK,
                );
            }
        }
    }
}
fn status(ui: &mut egui::Ui, text: &str, color: Color32) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(egui::vec2(9., 9.), egui::Sense::hover());
        ui.painter().circle_filled(rect.center(), 3.5, color);
        ui.label(RichText::new(text).color(color));
    });
}
fn metric(ui: &mut egui::Ui, label: &str, value: u64, color: Color32) {
    ui.label(
        RichText::new(value.to_formatted_string(&Locale::en))
            .size(27.)
            .color(color),
    );
    ui.label(
        RichText::new(label)
            .small()
            .color(Tokens::get(ui.ctx()).text_dim),
    );
}
fn request_header(ui: &mut egui::Ui) {
    for (width, label) in [(66., "Time"), (62., "Method"), (60., "Decision")] {
        ui.add_sized([width, 23.], egui::Label::new(RichText::new(label).weak()));
    }
    ui.weak("URL");
}
fn request_row(ui: &mut egui::Ui, event: &Event, selected: &mut Option<Event>) {
    let t = Tokens::get(ui.ctx());
    ui.horizontal(|ui| {
        ui.add_sized(
            [66., 23.],
            egui::Label::new(
                RichText::new(
                    event
                        .now
                        .with_timezone(&chrono::Local)
                        .format("%H:%M:%S")
                        .to_string(),
                )
                .small()
                .color(t.text_dim),
            ),
        );
        ui.add_sized(
            [62., 23.],
            egui::Label::new(RichText::new(&event.method).monospace()),
        );
        ui.add_sized(
            [60., 23.],
            egui::Label::new(
                RichText::new(if event.is_request_blocked {
                    "Blocked"
                } else {
                    "Allowed"
                })
                .color(if event.is_request_blocked {
                    t.warn
                } else {
                    t.success
                }),
            ),
        );
        if ui
            .add(
                egui::Label::new(&event.url)
                    .truncate()
                    .sense(egui::Sense::click()),
            )
            .on_hover_text(&event.url)
            .clicked()
        {
            *selected = Some(event.clone());
        }
    });
}
/// Domains passed through after refusing the inspection certificate, minus those since excluded.
fn passed_through(server: &PrivaxyServer) -> Vec<privaxy::inspection::Rejection> {
    let mut rejected = server.inspection.rejected();
    rejected.retain(|rejection| !server.local_exclusion_store.contains(&rejection.domain));
    rejected
}
/// Appends `pattern` to the exclusion draft unless a line already names it.
fn add_exclusion(draft: &mut String, pattern: &str) {
    if draft.lines().any(|line| line.trim().eq_ignore_ascii_case(pattern)) {
        return;
    }
    if !draft.is_empty() && !draft.ends_with('\n') {
        draft.push('\n');
    }
    draft.push_str(pattern);
}
fn chart(ui: &mut egui::Ui, events: &[Event]) {
    let t = Tokens::get(ui.ctx());
    let now = chrono::Utc::now().timestamp();
    let mut allowed = [0_u64; 60];
    let mut blocked = [0_u64; 60];
    for event in events {
        let age = now - event.now.timestamp();
        if (0..60).contains(&age) {
            let bin = 59 - age as usize;
            if event.is_request_blocked {
                blocked[bin] += 1;
            } else {
                allowed[bin] += 1;
            }
        }
    }
    let peak = (0..60).map(|i| allowed[i] + blocked[i]).max().unwrap_or(0);
    let max = peak.max(1);
    ui.horizontal(|ui| {
        ui.label("Requests / second");
        ui.weak("Last 60 seconds");
    });
    let (rect, response) =
        ui.allocate_exact_size(egui::vec2(ui.available_width(), 142.), egui::Sense::hover());
    let plot = rect.shrink2(egui::vec2(6., 18.));
    ui.painter().rect_filled(rect, t.radius_sm, t.sunken);
    for step in 0..=2 {
        let y = plot.bottom() - plot.height() * step as f32 / 2.;
        ui.painter().line_segment(
            [egui::pos2(plot.left(), y), egui::pos2(plot.right(), y)],
            Stroke::new(1., t.separator),
        );
    }
    let width = plot.width() / 60.;
    for bin in 0..60 {
        let x = plot.left() + width * bin as f32;
        let a = plot.height() * allowed[bin] as f32 / max as f32;
        let b = plot.height() * blocked[bin] as f32 / max as f32;
        if a > 0. {
            ui.painter().rect_filled(
                egui::Rect::from_min_max(
                    egui::pos2(x, plot.bottom() - a),
                    egui::pos2(x + width.max(2.) - 1., plot.bottom()),
                ),
                1,
                t.primary,
            );
        }
        if b > 0. {
            ui.painter().rect_filled(
                egui::Rect::from_min_max(
                    egui::pos2(x, plot.bottom() - a - b),
                    egui::pos2(x + width.max(2.) - 1., plot.bottom() - a),
                ),
                1,
                t.warn,
            );
        }
    }
    ui.painter().text(
        rect.left_bottom() + egui::vec2(6., -2.),
        egui::Align2::LEFT_BOTTOM,
        "60s ago",
        egui::FontId::proportional(11.),
        t.text_dim,
    );
    ui.painter().text(
        rect.right_bottom() + egui::vec2(-6., -2.),
        egui::Align2::RIGHT_BOTTOM,
        "Now",
        egui::FontId::proportional(11.),
        t.text_dim,
    );
    if let Some(pos) = response.hover_pos() {
        let bin = ((pos.x - plot.left()) / width).floor().clamp(0., 59.) as usize;
        response.on_hover_text(format!(
            "{}s ago: {} allowed, {} blocked",
            59 - bin,
            allowed[bin],
            blocked[bin]
        ));
    }
    ui.horizontal(|ui| {
        status(ui, "Allowed", t.primary);
        status(ui, "Blocked", t.warn);
        ui.weak(format!("Peak {peak}/s"));
    });
}

impl App {
    pub(super) fn dashboard(
        &mut self,
        ui: &mut egui::Ui,
        server: Option<&PrivaxyServer>,
        events: &[Event],
    ) {
        let t = Tokens::get(ui.ctx());
        ui.horizontal(|ui| {
            ui.label(RichText::new("Network overview").size(23.).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if icons::button(ui, svg::PALETTE, "Appearance").clicked() {
                    self.picker.open = true;
                }
                ui.weak("Live session");
            });
        });
        ui.add_space(14.);
        let width = ui.available_width();
        let left = (width * 0.40).max(340.);
        ui.horizontal_top(|ui| {
            ui.vertical(|ui| {
                ui.set_width(left);
                panel(ui, "Desktop proxy", |ui| {
                    let state = server.map(|s| s.listener.status()).unwrap_or(ListenerStatus::Starting);
                    match &state {
                        ListenerStatus::Listening(_) => status(ui, "Running", t.success),
                        ListenerStatus::Starting => status(ui, "Starting…", t.warn),
                        ListenerStatus::Stopping => status(ui, "Stopping…", t.warn),
                        ListenerStatus::Stopped => status(ui, "Stopped", t.text_dim),
                        ListenerStatus::Failed(reason) => { status(ui, "Listener failed", t.error); ui.label(reason); }
                    }
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("127.0.0.1:8100").size(22.).monospace()).on_hover_text("Use this HTTP/HTTPS proxy in your desktop browser or system network settings.");
                        if icons::small_button(ui, svg::COPY, "Copy").clicked() { ui.ctx().copy_text("127.0.0.1:8100".into()); }
                    });
                    ui.add_space(8.);
                    ui.horizontal_wrapped(|ui| {
                        if ui.add_enabled(server.is_some() && !state.is_changing(), icons::button_widget(ui, if state.is_running() { svg::STOP } else { svg::PLAY }, if state.is_running() { "Stop proxy" } else { "Start proxy" })).clicked() {
                            let server = server.unwrap();
                            if state.is_running() { self.stop_relay(); server.listener.stop(); } else { server.listener.start(); }
                        }
                        if ui.add_enabled(state.is_running() && !self.checking_proxy.load(std::sync::atomic::Ordering::Relaxed), icons::button_widget(ui, svg::PLUGS_CONNECTED, "Test proxy")).clicked() { self.check_proxy(); }
                    });
                    ui.add_space(8.);
                    ui.separator();
                    if let Some(server) = server {
                        self.capture_controls(ui, server);
                        ui.separator();
                    }
                    if let Some(server) = server {
                        let mut observe_only = !server.blocking_disabled_store.is_enabled();
                        if icons::checkbox(ui, &mut observe_only, svg::EYE, "Observe only · no blocking").on_hover_text(if observe_only { "Requests are recorded without ad blocking or HTML injection. HTTPS still requires the inspection CA." } else { "Ad, tracker and cosmetic filters are active." }).changed() {
                            server.blocking_disabled_store.set(!observe_only);
                            let config = {
                                let mut config = self.config.lock().unwrap();
                                config.as_mut().map(|cfg| { cfg.observe_only = observe_only; cfg.clone() })
                            };
                            if let Some(config) = config { self.save_settings(config, server); }
                            log::info!("Observe only mode {}", if observe_only { "enabled" } else { "disabled" });
                        }
                    }
                    let counts = self.config.lock().unwrap().as_ref().map(|c| (c.filters.iter().filter(|f| f.enabled).count(), c.filters.len()));
                    if let Some((enabled, total)) = counts {
                        ui.horizontal_wrapped(|ui| {
                            ui.weak(format!("{enabled} of {total} filter lists enabled"));
                            if ui.link("Manage").clicked() { self.tab = Tab::Settings; }
                        });
                    }
                    let passed = server.map_or(0, |server| passed_through(server).len());
                    if passed > 0 {
                        ui.horizontal_wrapped(|ui| {
                            ui.colored_label(t.warn, if passed == 1 { "1 domain passes through encrypted".to_owned() } else { format!("{passed} domains pass through encrypted") }).on_hover_text("Their clients refused the inspection certificate this session.");
                            if ui.link("Review").clicked() { self.tab = Tab::Settings; }
                        });
                    }
                });
                ui.add_space(12.);
                panel(ui, "Android connection", |ui| self.android(ui, server));
            });
            ui.add_space(6.);
            ui.vertical(|ui| {
                ui.set_width((width-left-24.).max(320.));
                panel(ui, "Traffic activity", |ui| {
                    if let Some(server) = server {
                        let stats = server.statistics.get_serialized();
                        ui.columns(3, |ui| {
                            metric(&mut ui[0], "Forwarded", stats.proxied_requests, t.primary);
                            metric(&mut ui[1], "Blocked", stats.blocked_requests, t.warn);
                            metric(&mut ui[2], "Modified responses", stats.modified_responses, t.secondary);
                        });
                        let total = stats.proxied_requests + stats.blocked_requests;
                        ui.add_space(8.);
                        ui.add(egui::ProgressBar::new(if total>0 {stats.blocked_requests as f32/total as f32} else {0.})
                            .fill(t.warn).text(if total>0 {format!("{:.1}% blocked",100.*stats.blocked_requests as f64/total as f64)} else {"No requests processed yet".into()}));
                    }
                    ui.add_space(12.);
                    chart(ui, events);
                    if events.is_empty() {
                        ui.add_space(6.);
                        ui.label("Waiting for requests. Connect a browser above, or enable desktop routing on a paired phone.");
                    }
                });
                ui.add_space(12.);
                panel(ui, "Top destinations", |ui| {
                    let mut hosts = std::collections::HashMap::<String, u64>::new();
                    for event in events {
                        let authority = event.url.split("://").nth(1).unwrap_or(&event.url).split('/').next().unwrap_or("");
                        *hosts.entry(authority.to_owned()).or_default() += 1;
                    }
                    let mut hosts: Vec<_> = hosts.into_iter().collect();
                    hosts.sort_by(|a,b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                    if hosts.is_empty() { ui.weak("Destinations will appear as traffic passes through the proxy."); }
                    let max = hosts.first().map(|h| h.1).unwrap_or(1);
                    for (host, count) in hosts.iter().take(4) {
                        ui.horizontal(|ui| {
                            if ui.add(egui::Label::new(host).truncate().sense(egui::Sense::click())).clicked() { self.traffic.search(host.clone()); self.tab=Tab::Traffic; }
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| { ui.label(count.to_formatted_string(&Locale::en)); });
                        });
                        ui.add(egui::ProgressBar::new(*count as f32/max as f32).desired_height(4.).fill(t.secondary));
                        ui.add_space(4.);
                    }
                    if !hosts.is_empty() { ui.weak("From the most recent 5,000 logged requests."); }
                });
            });
        });
        ui.add_space(14.);
        panel(ui, "Recent requests", |ui| {
            ui.horizontal(|ui| {
                request_header(ui);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if icons::button(ui, svg::ARROWS_DOWN_UP, "Open traffic log").clicked() {
                        self.tab = Tab::Traffic;
                    }
                });
            });
            ui.separator();
            if events.is_empty() {
                ui.label(
                    "No requests yet. Test proxy sends a real request through the local listener.",
                );
            }
            for event in events.iter().rev().take(6) {
                let mut selected = None;
                request_row(ui, event, &mut selected);
                if let Some(event) = selected {
                    self.traffic.select(event);
                    self.tab = Tab::Traffic;
                }
            }
        });
    }
    pub(super) fn settings(&mut self, ui: &mut egui::Ui, server: Option<&PrivaxyServer>) {
        let mut config = self.config.lock().unwrap().clone();
        let mut save = false;
        ui.horizontal(|ui| {
            ui.label(RichText::new("Settings").size(23.).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                save = ui
                    .add_enabled(
                        server.is_some() && config.is_some(),
                        icons::button_widget(ui, svg::FLOPPY_DISK, "Save and reload filters"),
                    )
                    .on_hover_text("Applies the inspection settings, exclusions and custom rules, and reloads the enabled filter lists.")
                    .clicked();
            });
        });
        ui.add_space(10.);
        let Some(cfg) = config.as_mut() else {
            panel(ui, "Appearance", |ui| self.appearance(ui));
            return;
        };
        if !self.drafts_loaded {
            self.custom = cfg.custom_filters.join("\n");
            self.exclusions = cfg
                .exclusions
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            self.ports = cfg
                .inspected_ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            self.decrypted_apps = cfg.decrypted_apps.iter().cloned().collect::<Vec<_>>().join("\n");
            self.lan_clients = cfg.lan_clients.iter().cloned().collect::<Vec<_>>().join("\n");
            self.drafts_loaded = true;
        }
        let full = ui.available_rect_before_wrap();
        let gap = 12.;
        let rules = (full.height() * 0.25).clamp(140., 240.);
        let top = egui::Rect::from_min_max(
            full.min,
            egui::pos2(full.right(), full.bottom() - rules - gap),
        );
        let split = full.left() + (full.width() * 0.6).clamp(380., (full.width() - 300. - gap).max(380.));
        region(
            ui,
            "settings_inspection",
            egui::Rect::from_min_max(top.min, egui::pos2(split, top.bottom())),
            |ui| self.inspection_settings(ui, cfg, server),
        );
        region(
            ui,
            "settings_side",
            egui::Rect::from_min_max(egui::pos2(split + gap, top.top()), top.max),
            |ui| {
                panel(ui, "Appearance", |ui| self.appearance(ui));
                ui.add_space(gap);
                card(ui, |ui| filter_lists(ui, &mut cfg.filters));
            },
        );
        region(
            ui,
            "settings_rules",
            egui::Rect::from_min_max(
                egui::pos2(full.left(), top.bottom() + gap),
                egui::pos2(split, full.bottom()),
            ),
            |ui| {
                card(ui, |ui| {
                    let count = self.custom.lines().filter(|line| !line.trim().is_empty()).count();
                    title_row(ui, "Custom rules", |ui| {
                        ui.weak(if count == 1 { "1 rule".to_owned() } else { format!("{count} rules") });
                    });
                    fill_text(ui, "custom_rules", &mut self.custom, "One adblock rule per line, e.g. ||ads.example.com^");
                })
            },
        );
        region(
            ui,
            "settings_lan",
            egui::Rect::from_min_max(egui::pos2(split + gap, top.bottom() + gap), full.max),
            |ui| self.lan_settings(ui, cfg, server),
        );
        ui.allocate_rect(full, egui::Sense::hover());
        if save {
            let ports: Result<std::collections::BTreeSet<u16>, _> = self
                .ports
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|port| !port.is_empty())
                .map(str::parse)
                .collect();
            match ports.ok().filter(|ports| !ports.contains(&0)) {
                Some(ports) => {
                    cfg.inspected_ports = ports;
                    cfg.custom_filters = self
                        .custom
                        .lines()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect();
                    cfg.exclusions = self
                        .exclusions
                        .lines()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect();
                    for (draft, set) in [
                        (&self.decrypted_apps, &mut cfg.decrypted_apps),
                        (&self.lan_clients, &mut cfg.lan_clients),
                    ] {
                        *set = draft
                            .lines()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned)
                            .collect();
                    }
                    self.save_settings(cfg.clone(), server.unwrap());
                }
                None => {
                    *self.notice.lock().unwrap() =
                        "Inspect ports must be numbers from 1 to 65535, separated by commas.".into()
                }
            }
        }
        *self.config.lock().unwrap() = config;
    }
    /// Ways to send this desktop's apps and LAN devices through the proxy.
    fn capture_controls(&mut self, ui: &mut egui::Ui, server: &PrivaxyServer) {
        ui.horizontal_wrapped(|ui| {
            let mut system = self.system_proxy.load(std::sync::atomic::Ordering::Relaxed);
            if toggle(ui, &mut system, "System proxy")
                .on_hover_text("Points the KDE and GNOME proxy settings at 127.0.0.1:8100, so apps that follow the desktop setting use Privaxy. Your earlier settings come back when you switch it off or quit.")
                .changed()
            {
                self.set_system_proxy(system, server);
            }
            if cfg!(target_os = "linux") {
                let (mut on, starting) = match *self.network_capture.lock().unwrap() {
                    Capture::Off => (false, false),
                    Capture::Starting => (true, true),
                    Capture::On(_) => (true, false),
                };
                let label = if starting { "Network capture…" } else { "Network capture" };
                let response = ui
                    .add_enabled_ui(!starting, |ui| toggle(ui, &mut on, label))
                    .inner
                    .on_hover_text("Firewall rules send this user's web connections to Privaxy, including apps that ignore proxy settings. QUIC is refused so apps fall back to TCP. Asks for the administrator password; the rules go away when you switch it off or quit.");
                if response.changed() {
                    self.set_network_capture(on, server);
                }
            }
            let mut lan = self
                .config
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|cfg| cfg.lan_proxy);
            if toggle(ui, &mut lan, "LAN devices")
                .on_hover_text("Serves the proxy on every interface, port 8100, to the addresses under Settings > LAN devices. Point a device's Wi-Fi proxy at this computer, port 8100, and install the CA from http://<this computer>:8100/privaxy-ca.crt.")
                .changed()
            {
                self.set_lan_proxy(lan, server);
            }
        });
        ui.horizontal_wrapped(|ui| {
            if icons::button(ui, svg::BROWSER, "Inspected browser")
                .on_hover_text("Opens Chromium in its own profile, already using the proxy and trusting the inspection CA. Nothing is installed in your system or browser.")
                .clicked()
            {
                *self.notice.lock().unwrap() = match connect::open_inspected_browser(&server.ca_spki_sha256) {
                    Ok(name) => format!("Opened {name} with its own profile, through the proxy."),
                    Err(error) => error,
                };
            }
            if icons::button(ui, svg::TERMINAL_WINDOW, "Copy terminal setup")
                .on_hover_text("Copies export lines for a shell: the proxy variables, and CA bundles for curl, Python, Git and Node. Paste them into a terminal to send its tools through Privaxy.")
                .clicked()
            {
                match connect::terminal_setup(&server.ca_certificate_pem) {
                    Ok(lines) => {
                        ui.ctx().copy_text(lines);
                        *self.notice.lock().unwrap() = "Terminal setup copied. Paste it into a terminal; it lasts for that shell.".into();
                    }
                    Err(error) => *self.notice.lock().unwrap() = error,
                }
            }
            if icons::button(ui, svg::CERTIFICATE, "Export CA")
                .on_hover_text("Saves the inspection CA. Clients must trust it for HTTPS to be inspected.")
                .clicked()
            {
                self.export_ca(server);
            }
        });
    }
    fn appearance(&mut self, ui: &mut egui::Ui) {
        let controls = |ui: &mut egui::Ui| {
            if icons::button(ui, svg::PALETTE, "Theme presets and templates").clicked() {
                self.picker.open = true;
            }
            chrome::toggle_row(ui, &mut self.chrome, "Custom title bar");
        };
        if ui.available_width() >= 360. {
            ui.horizontal(controls);
        } else {
            ui.vertical(controls);
        }
    }
    fn inspection_settings(
        &mut self,
        ui: &mut egui::Ui,
        cfg: &mut privaxy::configuration::Configuration,
        server: Option<&PrivaxyServer>,
    ) {
        card(ui, |ui| {
            title_row(ui, "HTTPS inspection", |ui| {
                if ui
                    .add_enabled(server.is_some(), icons::button_widget(ui, svg::CERTIFICATE, "Export inspection CA"))
                    .on_hover_text("Clients must trust this desktop's CA for HTTPS to be inspected. Excluded hosts, other ports and refusing domains pass through encrypted.")
                    .clicked()
                {
                    self.export_ca(server.unwrap());
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.label("Inspect ports")
                    .on_hover_text("CONNECT tunnels to other ports pass through encrypted.");
                ui.add(egui::TextEdit::singleline(&mut self.ports).desired_width(110.).hint_text("443, 8443"));
                ui.add_space(12.);
                ui.checkbox(&mut cfg.pass_through_rejected, "Pass through domains that refuse the certificate")
                    .on_hover_text("A client that refuses the inspection certificate, with an alert, by hanging up or by not answering, sends its whole domain through encrypted for the rest of the session. Apps that pin certificates, such as Instagram, need this.");
            });
            ui.add_space(10.);
            let area = ui.available_rect_before_wrap();
            let column = (area.width() - 16.) / 2.;
            let half = (area.height() - 12.) / 2.;
            region(
                ui,
                "never_intercept",
                egui::Rect::from_min_size(area.min, egui::vec2(column, half)),
                |ui| {
                    ui.label("Never intercept").on_hover_text("One host per line. *.example.com covers example.com and every subdomain. Saved with the settings.");
                    ui.add_space(4.);
                    fill_text(ui, "exclusions", &mut self.exclusions, "*.example.com");
                },
            );
            region(
                ui,
                "decrypted_apps",
                egui::Rect::from_min_size(
                    egui::pos2(area.left(), area.top() + half + 12.),
                    egui::vec2(column, half),
                ),
                |ui| {
                    ui.label("Decrypt these Android apps").on_hover_text("Package names, one per line; * matches anything. Connections from other apps on a paired phone pass through encrypted from the start, since Android apps other than browsers refuse user-installed CAs. Saved with the settings.");
                    ui.add_space(4.);
                    fill_text(ui, "decrypted_apps", &mut self.decrypted_apps, "com.android.chrome");
                },
            );
            region(
                ui,
                "passed_through",
                egui::Rect::from_min_max(egui::pos2(area.right() - column, area.top()), area.max),
                |ui| self.passed_through_list(ui, server),
            );
            ui.allocate_rect(area, egui::Sense::hover());
        });
    }
    fn lan_settings(
        &mut self,
        ui: &mut egui::Ui,
        cfg: &mut privaxy::configuration::Configuration,
        server: Option<&PrivaxyServer>,
    ) {
        card(ui, |ui| {
            let mut lan = cfg.lan_proxy;
            let mut changed = false;
            title_row(ui, "LAN devices", |ui| {
                changed = ui
                    .add_enabled_ui(server.is_some(), |ui| toggle(ui, &mut lan, "Share proxy"))
                    .inner
                    .on_hover_text("Serves the proxy on every interface, port 8100, to the addresses below. Point a device's Wi-Fi proxy at this computer, port 8100, and install the CA from http://<this computer>:8100/privaxy-ca.crt.")
                    .changed();
            });
            if changed && let Some(server) = server {
                cfg.lan_proxy = lan;
                let invalid = server.listener.serve_lan(lan, &cfg.lan_clients);
                if !invalid.is_empty() {
                    *self.notice.lock().unwrap() = format!(
                        "Ignored LAN clients that are not addresses or ranges: {}",
                        invalid.join(", ")
                    );
                }
                self.save_config(cfg.clone(), server);
            }
            ui.horizontal_wrapped(|ui| {
                ui.weak("Wi-Fi proxy").on_hover_text("This computer's LAN addresses, for a device's Wi-Fi proxy settings.");
                for entry in &self.addresses.lan {
                    ui.monospace(format!("{}:8100", entry.ip));
                }
            });
            ui.label("Allowed addresses").on_hover_text("One address or CIDR range per line. Loopback is always allowed. Saved with the settings.");
            ui.add_space(4.);
            fill_text(ui, "lan_clients", &mut self.lan_clients, "192.168.1.0/24");
        });
    }
    fn passed_through_list(&mut self, ui: &mut egui::Ui, server: Option<&PrivaxyServer>) {
        let t = Tokens::get(ui.ctx());
        let passed = server.map(passed_through).unwrap_or_default();
        ui.horizontal(|ui| {
            ui.label(format!("Passed through ({})", passed.len()))
                .on_hover_text("Domains whose clients refused the inspection certificate this session. They stay encrypted until you retry.");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(!passed.is_empty(), icons::button_widget(ui, svg::ARROWS_CLOCKWISE, "Retry").small())
                    .on_hover_text("Inspect these domains again on their next connection.")
                    .clicked()
                {
                    server.unwrap().inspection.retry();
                }
            });
        });
        ui.add_space(4.);
        egui::Frame::new()
            .fill(t.sunken)
            .corner_radius(t.radius_sm)
            .inner_margin(6)
            .show(ui, |ui| {
                ui.set_min_size(ui.available_size());
                egui::ScrollArea::vertical()
                    .id_salt("passed_through_scroll")
                    .auto_shrink(false)
                    .show(ui, |ui| {
                        if passed.is_empty() {
                            ui.weak("No domain has refused the certificate this session.");
                        }
                        for rejection in &passed {
                            ui.horizontal(|ui| {
                                if icons::icon_button(ui, svg::SHIELD_SLASH, "Never intercept: adds it to the list on the left; save to keep it").clicked() {
                                    add_exclusion(&mut self.exclusions, &rejection.exclusion());
                                }
                                ui.add(
                                    egui::Label::new(RichText::new(format!("{}:{}", rejection.domain, rejection.port)).monospace())
                                        .truncate()
                                        .selectable(false),
                                )
                                .on_hover_text(format!(
                                    "{}:{} refused at {} ({})",
                                    rejection.host,
                                    rejection.port,
                                    rejection.at.with_timezone(&chrono::Local).format("%H:%M:%S"),
                                    rejection.reason
                                ));
                            });
                        }
                    });
            });
    }
    fn android(&mut self, ui: &mut egui::Ui, server: Option<&PrivaxyServer>) {
        let t = Tokens::get(ui.ctx());
        let count = self.connections.count();
        let (connection, color) = match count {
            0 if self.connections.verified() => ("Waiting for the phone to reconnect".to_owned(), t.warn),
            0 => ("No phone connected".to_owned(), t.text_dim),
            1 => ("1 phone connected".to_owned(), t.success),
            count => (format!("{count} phones connected"), t.success),
        };
        let relay = self.relay_status.lock().unwrap().clone();
        ui.scope(|ui| status(ui, &connection, color))
            .response
            .on_hover_text(format!("{relay}\nA phone counts once it authenticates and answers heartbeats; a saved pairing alone does not."));
        ui.add_space(6.);
        self.address_picker(ui);
        let code = self.identity.as_ref().map(|identity| identity.code(&self.host));
        if let Some(Err(reason)) = &code {
            ui.colored_label(t.warn, *reason);
        }
        ui.add_space(8.);
        ui.horizontal_wrapped(|ui| {
            let running = self.relay.is_some();
            let relay_button = icons::button_widget(
                ui,
                if running { svg::STOP } else { svg::PLUGS_CONNECTED },
                if running { "Stop relay" } else { "Start relay" },
            );
            if ui
                .add_enabled(server.is_some() && self.identity.is_some(), relay_button)
                .on_hover_text("Paired phones connect over encrypted TCP 8101 on every interface.")
                .clicked()
            {
                if running {
                    self.stop_relay();
                } else {
                    self.start_relay(server.unwrap());
                }
            }
            if ui
                .add_enabled(matches!(code, Some(Ok(_))), icons::button_widget(ui, svg::LINK, "Copy link"))
                .on_hover_text("Copies the pairing link; paste it into Privaxy on Android under Pairing.")
                .clicked()
                && let Some(Ok(code)) = &code
            {
                ui.ctx().copy_text(code.clone());
            }
            if icons::button(ui, svg::QR_CODE, if self.pairing_qr { "Hide QR" } else { "Show QR" })
                .on_hover_text("Scan with the phone camera to open Privaxy, then tap Pair desktop. A paired phone only needs Save address after this address changes.")
                .clicked()
            {
                self.pairing_qr = !self.pairing_qr;
            }
            if icons::icon_button(ui, svg::SHIELD_SLASH, "Revoke all pairings…").clicked() {
                self.revoke_confirm = true;
            }
            icons::icon_button(ui, svg::QUESTION, CONNECTION_HELP);
        });
        if self.pairing_qr
            && let Some(Ok(code)) = &code
        {
            ui.add_space(8.);
            pairing_qr(ui, code, 300.);
        }
    }
    fn address_picker(&mut self, ui: &mut egui::Ui) {
        egui::Grid::new("relay_addresses")
            .num_columns(2)
            .spacing([10., 6.])
            .show(ui, |ui| {
                for (kind, hint, addresses) in [
                    ("Tailscale", "Reachable from a phone on the same tailnet. Capture all traffic cannot run alongside the Tailscale Android VPN.", &self.addresses.tailscale),
                    ("LAN", "Reachable from a phone on the same network; use it for Capture all traffic.", &self.addresses.lan),
                    ("Other", "VPN, VM and container interfaces, rarely reachable from a phone.", &self.addresses.other),
                ] {
                    if addresses.is_empty() {
                        continue;
                    }
                    ui.weak(kind).on_hover_text(hint);
                    ui.horizontal_wrapped(|ui| {
                        for entry in addresses {
                            let address = entry.ip.to_string();
                            if ui
                                .selectable_label(
                                    self.host.trim() == address,
                                    format!("{}  {address}", entry.interface),
                                )
                                .clicked()
                            {
                                self.host = address;
                            }
                        }
                    });
                    ui.end_row();
                }
                ui.weak("Address").on_hover_text("The address the phone dials, carried in the pairing code. The relay listens on every interface.");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.host)
                            .hint_text("Desktop IPv4 or hostname")
                            .desired_width(180.),
                    );
                    if icons::icon_button(ui, svg::ARROWS_CLOCKWISE, "Refresh addresses").clicked() {
                        self.addresses = network::Addresses::detect();
                        if self.host.trim().is_empty() {
                            self.host = self.addresses.preferred_host();
                        }
                    }
                });
                ui.end_row();
            });
    }
    pub(super) fn dialogs(&mut self, ctx: &egui::Context) {
        if self.revoke_confirm {
            let modal=egui::Modal::new(egui::Id::unique("revoke_pairings")).show(ctx,|ui| {
                ui.set_width(360.); ui.heading("Revoke all desktop pairings?");
                ui.label("This disconnects every phone and replaces the pairing credentials. Each phone will need to scan a new code.");
                ui.horizontal(|ui|(icons::button(ui, svg::X, "Cancel").clicked(),icons::button(ui, svg::TRASH, "Revoke pairings").clicked())).inner
            });
            if modal.inner.0 || modal.should_close() {
                self.revoke_confirm = false;
            } else if modal.inner.1 {
                self.revoke_confirm = false;
                self.stop_relay();
                match pairing::Identity::generate() {
                    Ok(identity) => {
                        self.identity = Some(identity);
                        self.connections = Arc::default();
                        *self.notice.lock().unwrap() =
                            "Pairings revoked. Pair each phone again.".into();
                    }
                    Err(error) => *self.notice.lock().unwrap() = error,
                }
            }
        }
    }
}

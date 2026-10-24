//! The desktop workspace: operations and activity together, detailed traffic one click away.
use super::*;
use egui::{Color32, RichText, Stroke};
use egui_theme_kit::Tokens;
use num_format::{Locale, ToFormattedString};

fn panel<R>(ui: &mut egui::Ui, title: &str, content: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let t = Tokens::get(ui.ctx());
    egui::Frame::new()
        .fill(t.raised)
        .stroke(Stroke::new(1., t.card_border))
        .corner_radius(t.radius_md)
        .inner_margin(16)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(title).size(17.).strong());
            ui.add_space(10.);
            content(ui)
        })
        .inner
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
                if ui.button("Appearance").clicked() {
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
                        ui.label(RichText::new("127.0.0.1:8100").size(22.).monospace());
                        if ui.small_button("Copy").clicked() { ui.ctx().copy_text("127.0.0.1:8100".into()); }
                    });
                    ui.label("Use this HTTP/HTTPS proxy in your desktop browser or system network settings.");
                    ui.add_space(8.);
                    ui.horizontal_wrapped(|ui| {
                        if ui.add_enabled(server.is_some() && !state.is_changing(), egui::Button::new(if state.is_running() { "Stop proxy" } else { "Start proxy" })).clicked() {
                            let server = server.unwrap();
                            if state.is_running() { self.stop_relay(); server.listener.stop(); } else { server.listener.start(); }
                        }
                        if ui.button("Connect this computer").clicked() { self.setup_open = true; }
                        if ui.add_enabled(state.is_running() && !self.checking_proxy.load(std::sync::atomic::Ordering::Relaxed), egui::Button::new("Test proxy")).clicked() { self.check_proxy(); }
                    });
                    ui.add_space(8.);
                    ui.separator();
                    if let Some(server) = server {
                        let mut filtering = !*server.blocking_disabled_store.0.read().unwrap();
                        if ui.checkbox(&mut filtering, "Ad and tracker filtering").changed() {
                            *server.blocking_disabled_store.0.write().unwrap() = !filtering;
                        }
                    }
                    let counts = self.config.lock().unwrap().as_ref().map(|c| (c.filters.iter().filter(|f| f.enabled).count(), c.filters.len()));
                    if let Some((enabled, total)) = counts { ui.weak(format!("{enabled} of {total} filter lists enabled")); }
                    ui.horizontal_wrapped(|ui| {
                        if ui.link("Manage filters").clicked() { self.tab = Tab::Settings; }
                        if ui.add_enabled(server.is_some(), egui::Button::new("Export inspection CA").frame(false)).clicked() { self.export_ca(server.unwrap()); }
                    });
                });
                ui.add_space(12.);
                panel(ui, "Android connection", |ui| {
                    let count = self.connections.count();
                    let connection = match count {
                        0 => "No phone connected".into(),
                        1 => "1 phone connected and authenticated".into(),
                        count => format!("{count} phones connected and authenticated"),
                    };
                    status(ui, &connection, if count>0 {t.success} else {t.text_dim});
                    if count == 0 && self.connections.verified() { ui.weak("A phone connected earlier. Waiting for it to reconnect."); }
                    ui.label(RichText::new(if self.host.is_empty() { "Select a desktop address".into() } else { format!("{}:8101", self.host) }).monospace());
                    ui.label(self.relay_status.lock().unwrap().clone());
                    ui.horizontal_wrapped(|ui| {
                        let label = if self.relay.is_some() { "Stop Android relay" } else { "Start Android relay" };
                        if ui.add_enabled(server.is_some() && self.identity.is_some(), egui::Button::new(label)).clicked() {
                            if self.relay.is_some() { self.stop_relay(); } else { self.start_relay(server.unwrap()); }
                        }
                        if ui.button("Pair phone / addresses").clicked() { self.pairing_open = true; }
                    });
                    ui.add_space(6.);
                    ui.weak("Saved pairing is separate from a live connection. A phone appears here only after an authenticated heartbeat.");
                });
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
                            if ui.add(egui::Label::new(host).truncate().sense(egui::Sense::click())).clicked() { self.query=host.clone(); self.tab=Tab::Traffic; }
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
                    if ui.button("Open traffic log").clicked() {
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
                request_row(ui, event, &mut self.selected_event);
            }
        });
    }
    pub(super) fn traffic(&mut self, ui: &mut egui::Ui, events: &[Event]) {
        ui.heading("Traffic");
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.query)
                    .hint_text("Search URL or method")
                    .desired_width(380.),
            );
            for (i, label) in [(0, "All"), (1, "Allowed"), (2, "Blocked")] {
                ui.selectable_value(&mut self.traffic_filter, i, label);
            }
            if ui.button("Clear view").clicked() {
                self.events.lock().unwrap().clear();
            }
        });
        ui.weak(
            "Allowed and blocked describe the filter decision. Select a URL to inspect or copy it.",
        );
        ui.add_space(8.);
        let query = self.query.to_lowercase();
        let rows: Vec<_> = events
            .iter()
            .rev()
            .filter(|e| {
                (query.is_empty()
                    || e.url.to_lowercase().contains(&query)
                    || e.method.to_lowercase().contains(&query))
                    && match self.traffic_filter {
                        1 => !e.is_request_blocked,
                        2 => e.is_request_blocked,
                        _ => true,
                    }
            })
            .collect();
        ui.label(format!("{} matching requests", rows.len()));
        ui.horizontal(request_header);
        ui.separator();
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show_rows(ui, 23., rows.len(), |ui, range| {
                for index in range {
                    request_row(ui, rows[index], &mut self.selected_event);
                }
            });
    }
    pub(super) fn settings(&mut self, ui: &mut egui::Ui, server: Option<&PrivaxyServer>) {
        ui.heading("Settings");
        ui.add_space(10.);
        panel(ui, "Appearance", |ui| {
            ui.horizontal_wrapped(|ui| {
                if ui.button("Theme presets and templates").clicked() {
                    self.picker.open = true;
                }
                chrome::toggle_row(ui, &mut self.chrome, "Custom title bar");
            });
        });
        let mut config = self.config.lock().unwrap().clone();
        let Some(cfg) = config.as_mut() else {
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
            self.drafts_loaded = true;
        }
        ui.add_space(12.);
        panel(ui, "Filter lists", |ui| {
            ui.label("Choose which lists block ads, trackers, and unwanted requests.");
            egui::Grid::new("filter_lists")
                .num_columns(2)
                .spacing([24., 8.])
                .max_col_width((ui.available_width() - 24.) / 2.)
                .show(ui, |ui| {
                    for (index, filter) in cfg.filters.iter_mut().enumerate() {
                        ui.checkbox(&mut filter.enabled, &filter.title);
                        if index % 2 == 1 {
                            ui.end_row();
                        }
                    }
                });
        });
        ui.add_space(12.);
        ui.columns(2,|columns| {
            panel(&mut columns[0],"Custom rules",|ui| { ui.label("One adblock rule per line."); ui.add(egui::TextEdit::multiline(&mut self.custom).desired_width(f32::INFINITY).desired_rows(6).hint_text("||example.com^")); });
            panel(&mut columns[1],"HTTPS inspection",|ui| {
                ui.label("Never intercept these hosts (one per line).");
                ui.add(egui::TextEdit::multiline(&mut self.exclusions).desired_width(f32::INFINITY).desired_rows(4).hint_text("*.example.com"));
                if ui.add_enabled(server.is_some(),egui::Button::new("Export inspection CA")).clicked(){self.export_ca(server.unwrap());}
                ui.weak("Clients must trust this desktop's CA to inspect HTTPS. Excluded hosts pass through encrypted.");
            });
        });
        ui.add_space(12.);
        if ui
            .add_enabled(
                server.is_some(),
                egui::Button::new("Save settings and reload filters"),
            )
            .clicked()
        {
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
            self.save_settings(cfg.clone(), server.unwrap());
        }
        *self.config.lock().unwrap() = config;
    }
    fn address_picker(&mut self, ui: &mut egui::Ui) {
        ui.label("Choose the address reachable from the phone. Ethernet and Wi-Fi can be different networks.");
        for (kind, addresses) in [
            ("Tailscale", &self.addresses.tailscale),
            ("LAN", &self.addresses.lan),
            ("Other interfaces", &self.addresses.other),
        ] {
            if addresses.is_empty() {
                continue;
            }
            ui.horizontal_wrapped(|ui| {
                ui.weak(kind);
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
        }
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.host)
                    .hint_text("Desktop IPv4 address or hostname")
                    .desired_width(300.),
            );
            if ui.button("Refresh addresses").clicked() {
                self.addresses = network::Addresses::detect();
                if self.host.trim().is_empty() {
                    self.host = self.addresses.preferred_host();
                }
            }
        });
    }
    pub(super) fn dialogs(&mut self, ctx: &egui::Context, server: Option<&PrivaxyServer>) {
        if self.setup_open {
            let mut open = true;
            egui::Window::new("Connect this computer").open(&mut open).default_width(520.).show(ctx,|ui| {
                ui.heading("Use Privaxy as your desktop proxy");
                ui.label("The proxy starts when Privaxy opens. In your browser or operating system network settings, configure both HTTP and HTTPS proxy fields:");
                ui.add_space(8.);
                ui.monospace("Host: 127.0.0.1     Port: 8100");
                ui.horizontal_wrapped(|ui| {
                    if ui.button("Copy proxy URL").clicked(){ui.ctx().copy_text("http://127.0.0.1:8100".into());}
                    if ui.button("Copy test command").clicked(){ui.ctx().copy_text("curl --proxy http://127.0.0.1:8100 http://example.com".into());}
                    if ui.add_enabled(server.is_some(),egui::Button::new("Export inspection CA")).clicked(){self.export_ca(server.unwrap());}
                });
                ui.add_space(10.);
                ui.label("Trust the exported inspection CA in the browser or system certificate store to inspect HTTPS. Android pairing is optional; this computer can use the proxy on its own.");
                ui.weak("On Firefox: Settings → Network Settings → Manual proxy configuration. Use this proxy for HTTPS as well.");
            });
            self.setup_open = open;
        }
        if self.pairing_open {
            let mut open = true;
            egui::Window::new("Android connection and pairing").open(&mut open).default_width(650.).vscroll(true).show(ctx,|ui| {
                ui.label(self.connection_label());
                ui.label(self.relay_status.lock().unwrap().clone());
                ui.add_space(8.);
                self.address_picker(ui);
                ui.add_space(8.);
                ui.horizontal_wrapped(|ui| {
                    if ui.add_enabled(server.is_some() && self.identity.is_some(),egui::Button::new(if self.relay.is_some(){"Stop Android relay"}else{"Start Android relay"})).clicked(){if self.relay.is_some(){self.stop_relay();}else{self.start_relay(server.unwrap());}}
                    if let Some(identity)=&self.identity { if let Ok(code)=identity.code(&self.host) { if ui.button("Copy pairing link").clicked(){ui.ctx().copy_text(code);} } }
                });
                ui.label("Scan to open Privaxy on Android, then tap Pair desktop. For an existing pairing, change Desktop IP or hostname and tap Save address on the phone.");
                if let Some(identity)=&self.identity {
                    match identity.code(&self.host) {
                        Ok(code)=>{ if let Ok(qr)=qrcode::QrCode::new(code.as_bytes()) {
                            let quiet=4; let modules=qr.width()+quiet*2;
                            let scale=(ui.available_width().min(320.)/modules as f32).floor().max(1.);
                            let (rect,_)=ui.allocate_exact_size(egui::vec2(modules as f32*scale,modules as f32*scale),egui::Sense::hover());
                            ui.painter().rect_filled(rect,0,Color32::WHITE);
                            for y in 0..qr.width(){for x in 0..qr.width(){if qr[(x,y)]==qrcode::Color::Dark {ui.painter().rect_filled(egui::Rect::from_min_size(rect.min+egui::vec2((x+quiet)as f32*scale,(y+quiet)as f32*scale),egui::vec2(scale,scale)),0,Color32::BLACK);}}}
                        } },
                        Err(reason)=>{ui.colored_label(Tokens::get(ctx).warn,reason);}
                    }
                }
                ui.add_space(8.);
                egui::CollapsingHeader::new("Connection help").default_open(true).show(ui,|ui| {
                    ui.label("Relay: TCP 8101. If Android reports No route to host, its connection did not reach the relay. Check the selected Wi-Fi address, guest/client isolation, and the desktop firewall for this LAN.");
                    ui.label("If this desktop uses a Tailscale exit node, allow LAN access in Tailscale so it can reply to the phone. A saved pairing does not prove network reachability.");
                    ui.label("Android supports one VPN at a time: use LAN for Capture all traffic. With the Tailscale Android VPN, keep capture off and use proxy-only mode with supported apps.");
                });
                if ui.button("Revoke all pairings…").clicked(){self.revoke_confirm=true;}
            });
            self.pairing_open = open;
        }
        if self.revoke_confirm {
            let modal=egui::Modal::new(egui::Id::unique("revoke_pairings")).show(ctx,|ui| {
                ui.set_width(360.); ui.heading("Revoke all desktop pairings?");
                ui.label("This disconnects every phone and replaces the pairing credentials. Each phone will need to scan a new code.");
                ui.horizontal(|ui|(ui.button("Cancel").clicked(),ui.button("Revoke pairings").clicked())).inner
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
        if let Some(event) = self.selected_event.clone() {
            let mut open = true;
            egui::Window::new("Request details")
                .open(&mut open)
                .default_width(620.)
                .show(ctx, |ui| {
                    ui.label(format!(
                        "{}  {}",
                        event.method,
                        event
                            .now
                            .with_timezone(&chrono::Local)
                            .format("%Y-%m-%d %H:%M:%S")
                    ));
                    ui.label(if event.is_request_blocked {
                        "Blocked by filters"
                    } else {
                        "Allowed by filters"
                    });
                    ui.add(egui::Label::new(&event.url).wrap());
                    if ui.button("Copy URL").clicked() {
                        ui.ctx().copy_text(event.url);
                    }
                });
            if !open {
                self.selected_event = None;
            }
        }
    }
}

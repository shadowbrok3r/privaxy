//! A session table and docked inspector. Row identity is independent of filtering and sorting.
use eframe::egui::{self, RichText};
use egui_data_table::{
    DataTable, Renderer, RowViewer,
    viewer::{CellWriteContext, DecodeErrorBehavior, RowCodec, TableColumnConfig},
};
use egui_json_tree::{DefaultExpand, JsonTree};
use egui_theme_kit::Tokens;
use privaxy::{capture::Exchange, events::Event, storage::BodySnapshot};
use std::{
    borrow::Cow,
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

const COLUMNS: [&str; 12] = [
    "Status",
    "Method",
    "Host",
    "Path / query",
    "Received",
    "Duration",
    "Time",
    "Content type",
    "Sent",
    "Client",
    "Protocol",
    "ID",
];
const PAGE: usize = 64 * 1024;
const JSON_LIMIT: u64 = 8 * 1024 * 1024;

#[derive(Clone)]
struct Row {
    event: Event,
    values: [String; 12],
    status: u16,
    duration: u64,
    received: u64,
    sent: u64,
    failed: bool,
    search: String,
}
impl Row {
    fn new(event: Event) -> Self {
        let details = event.exchange.lock().unwrap();
        let parsed = url::Url::parse(&event.url).ok();
        let host = parsed
            .as_ref()
            .and_then(|u| u.host_str())
            .unwrap_or(&event.url)
            .to_owned();
        let path = parsed
            .as_ref()
            .map(|u| {
                format!(
                    "{}{}",
                    u.path(),
                    u.query().map(|q| format!("?{q}")).unwrap_or_default()
                )
            })
            .unwrap_or_default();
        let received = details.response_body.seen();
        let sent = details.request_body.seen();
        let mime = details
            .response_headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        let status = details.status.unwrap_or(0);
        let duration = details.duration_ms.unwrap_or(0);
        let values = [
            if details.error.is_some() {
                "Error".into()
            } else if event.is_request_blocked {
                format!("{status} blocked")
            } else {
                details
                    .status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "Pending".into())
            },
            event.method.clone(),
            host,
            path,
            bytes(received),
            details
                .duration_ms
                .map(|d| format!("{d} ms"))
                .unwrap_or_else(|| "…".into()),
            event
                .now
                .with_timezone(&chrono::Local)
                .format("%H:%M:%S%.3f")
                .to_string(),
            mime,
            bytes(sent),
            details.client.to_string(),
            format!("{:?}", details.request_version),
            event.id.to_string(),
        ];
        let search = format!("{} {}", event.url, values.join(" ")).to_lowercase();
        let failed = details.error.is_some();
        drop(details);
        Self {
            event,
            values,
            status,
            duration,
            received,
            sent,
            failed,
            search,
        }
    }
    fn empty() -> Self {
        Self::new(Event {
            id: 0,
            now: chrono::Utc::now(),
            method: String::new(),
            url: String::new(),
            is_request_blocked: false,
            exchange: Arc::new(Mutex::new(Exchange::default())),
        })
    }
}

#[derive(Default)]
struct Viewer {
    query: String,
    filter: u8,
    tunnels: bool,
    selected: Option<Event>,
}
struct Clipboard;
impl RowCodec<Row> for Clipboard {
    type DeserializeError = ();
    fn create_empty_decoded_row(&mut self) -> Row {
        Row::empty()
    }
    fn encode_column(&mut self, row: &Row, column: usize, out: &mut String) {
        out.push_str(&row.values[column]);
    }
    fn decode_column(&mut self, _: &str, _: usize, _: &mut Row) -> Result<(), DecodeErrorBehavior> {
        Err(DecodeErrorBehavior::Abort)
    }
}
impl RowViewer<Row> for Viewer {
    fn num_columns(&mut self) -> usize {
        COLUMNS.len()
    }
    fn column_name(&mut self, column: usize) -> Cow<'static, str> {
        COLUMNS[column].into()
    }
    fn column_render_config(&mut self, column: usize, _: bool) -> TableColumnConfig {
        let width = [
            72., 58., 145., 230., 86., 82., 105., 145., 80., 120., 85., 60.,
        ][column];
        TableColumnConfig::initial(width)
            .at_least(40.)
            .resizable(true)
            .clip(true)
    }
    fn show_cell_view(&mut self, ui: &mut egui::Ui, row: &Row, column: usize) {
        let tokens = Tokens::get(ui.ctx());
        let color = if column == 0 && row.failed {
            tokens.error
        } else if column == 0 && (row.event.is_request_blocked || row.status >= 400) {
            tokens.warn
        } else {
            tokens.text
        };
        if ui
            .add(
                egui::Label::new(RichText::new(&row.values[column]).color(color))
                    .truncate()
                    .sense(egui::Sense::click()),
            )
            .on_hover_text(&row.values[column])
            .clicked()
        {
            self.selected = Some(row.event.clone());
        }
    }
    fn on_cell_view_response(
        &mut self,
        row: &Row,
        _: usize,
        response: &egui::Response,
    ) -> Option<Box<Row>> {
        if response.clicked() {
            self.selected = Some(row.event.clone());
        }
        None
    }
    fn on_highlight_cell(&mut self, row: &Row, _: usize) {
        self.selected = Some(row.event.clone());
    }
    fn is_sortable_column(&mut self, _: usize) -> bool {
        true
    }
    fn compare_cell(&self, a: &Row, b: &Row, column: usize) -> std::cmp::Ordering {
        match column {
            0 => a.status.cmp(&b.status),
            4 => a.received.cmp(&b.received),
            5 => a.duration.cmp(&b.duration),
            6 => a.event.now.cmp(&b.event.now),
            8 => a.sent.cmp(&b.sent),
            11 => a.event.id.cmp(&b.event.id),
            _ => a.values[column].cmp(&b.values[column]),
        }
    }
    fn row_filter_hash(&mut self) -> &impl std::hash::Hash {
        &self.query
    }
    fn filter_row(&mut self, row: &Row) -> bool {
        (self.tunnels || row.event.method != "CONNECT" || row.failed)
            && (self.query.is_empty() || row.search.contains(&self.query.to_lowercase()))
            && match self.filter {
                1 => row.failed || row.status >= 400,
                2 => row.event.is_request_blocked,
                _ => true,
            }
    }
    fn is_editable_cell(&mut self, _: usize, _: usize, _: &Row) -> bool {
        false
    }
    fn allow_row_insertions(&mut self) -> bool {
        false
    }
    fn allow_row_deletions(&mut self) -> bool {
        false
    }
    fn confirm_cell_write_by_ui(
        &mut self,
        _: &Row,
        _: &Row,
        _: usize,
        _: CellWriteContext,
    ) -> bool {
        false
    }
    fn show_cell_editor(
        &mut self,
        _: &mut egui::Ui,
        _: &mut Row,
        _: usize,
    ) -> Option<egui::Response> {
        None
    }
    fn set_cell_value(&mut self, _: &Row, _: &mut Row, _: usize) {}
    fn new_empty_row(&mut self) -> Row {
        Row::empty()
    }
    fn clone_row(&mut self, row: &Row) -> Row {
        row.clone()
    }
    fn try_create_codec(&mut self, encoding: bool) -> Option<impl RowCodec<Row>> {
        encoding.then_some(Clipboard)
    }
    fn persist_ui_state(&self) -> bool {
        true
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Side {
    Request,
    #[default]
    Response,
    Overview,
}
#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Content {
    Headers,
    #[default]
    Body,
}
#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Format {
    #[default]
    Json,
    Text,
    Hex,
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct LoadKey {
    id: u64,
    request: bool,
    length: u64,
    complete: bool,
    page: u64,
}
struct BodyView {
    text: Option<String>,
    json: Option<serde_json::Value>,
    pretty: Option<String>,
    hex: String,
}
struct BodyLoad {
    key: LoadKey,
    rx: Option<mpsc::Receiver<Result<BodyView, String>>>,
    value: Option<Result<BodyView, String>>,
}

pub(super) struct Traffic {
    table: DataTable<Row>,
    viewer: Viewer,
    refreshed: Instant,
    split: f32,
    side: Side,
    content: Content,
    format: Format,
    page: u64,
    search_json: String,
    body: Option<BodyLoad>,
    previous_selection: Option<u64>,
}
impl Default for Traffic {
    fn default() -> Self {
        Self {
            table: DataTable::new(),
            viewer: Viewer::default(),
            refreshed: Instant::now() - Duration::from_secs(1),
            split: 0.55,
            side: Side::default(),
            content: Content::default(),
            format: Format::default(),
            page: 0,
            search_json: String::new(),
            body: None,
            previous_selection: None,
        }
    }
}
impl Traffic {
    pub fn select(&mut self, event: Event) {
        self.viewer.selected = Some(event);
    }
    pub fn search(&mut self, query: String) {
        self.viewer.query = query;
    }
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        server: Option<&privaxy::PrivaxyServer>,
        events: &[Event],
        notice: Arc<Mutex<String>>,
    ) {
        let mut cleared = false;
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.viewer.query)
                    .hint_text("Search host, URL, method, status…")
                    .desired_width(240.),
            );
            for (index, label) in [(0, "All"), (1, "Errors"), (2, "Blocked")] {
                ui.selectable_value(&mut self.viewer.filter, index, label);
            }
            ui.checkbox(&mut self.viewer.tunnels, "CONNECT");
            if ui.button("Clear session").clicked() {
                if let Some(server) = server {
                    if let Err(error) = server.capture.clear() {
                        *notice.lock().unwrap() = error.to_string();
                    }
                }
                cleared = true;
                self.table.replace(vec![]);
                self.viewer.selected = None;
                self.body = None;
            }
        });
        if cleared {
            return;
        }
        let filtered = self
            .table
            .iter()
            .filter(|row| {
                (self.viewer.tunnels || row.event.method != "CONNECT" || row.failed)
                    && row.search.contains(&self.viewer.query.to_lowercase())
                    && match self.viewer.filter {
                        1 => row.failed || row.status >= 400,
                        2 => row.event.is_request_blocked,
                        _ => true,
                    }
            })
            .count();
        ui.horizontal_wrapped(|ui| {
            ui.weak(format!("{filtered} sessions · {} captured",bytes(server.map_or(0,|s|s.capture.used()))));
            ui.weak("Right-click headers to choose columns. Drag headers or borders to reorder or resize.");
        });
        if let Some(problem) = server.and_then(|s| s.capture.problem()) {
            ui.colored_label(Tokens::get(ui.ctx()).warn, problem);
        }
        ui.add_space(6.);
        if self.refreshed.elapsed() >= Duration::from_millis(350)
            || self.table.len() != events.len()
        {
            self.table
                .replace(events.iter().cloned().map(Row::new).collect());
            self.refreshed = Instant::now();
        }
        // Revalidate when either filter changes, even when no new network traffic arrives.
        let filter_key = (
            self.viewer.query.clone(),
            self.viewer.filter,
            self.viewer.tunnels,
        );
        let key = ui.scope_id().with("filter");
        let changed = ui.ctx().data_mut(|d| {
            let old = d.get_temp::<(String, u8, bool)>(key);
            d.insert_temp(key, filter_key.clone());
            old.as_ref() != Some(&filter_key)
        });
        if changed {
            let rows = self.table.take();
            self.table.replace(rows);
        }
        let full = ui.available_rect_before_wrap();
        let selected = self.viewer.selected.clone();
        let table_rect = if selected.is_some() {
            let min = (full.width() * 0.35).min(340.);
            let width = (full.width() * self.split).clamp(min, (full.width() - min - 8.).max(min));
            let divider = egui::Rect::from_min_size(
                full.min + egui::vec2(width, 0.),
                egui::vec2(7., full.height()),
            );
            let drag = ui.interact(
                divider,
                ui.scope_id().with("inspector_split"),
                egui::Sense::drag(),
            );
            if drag.dragged() {
                self.split = ((width + drag.drag_delta().x) / full.width()).clamp(0.25, 0.75);
            }
            drag.on_hover_cursor(egui::CursorIcon::ResizeHorizontal);
            ui.painter().vline(
                divider.center().x,
                divider.y_range(),
                egui::Stroke::new(1., Tokens::get(ui.ctx()).separator),
            );
            let right =
                egui::Rect::from_min_max(egui::pos2(divider.right() + 8., full.top()), full.max);
            let mut child = ui.new_child(
                egui::UiBuilder::new()
                    .id_salt("session_inspector")
                    .max_rect(right),
            );
            child.set_clip_rect(right.intersect(ui.clip_rect()));
            self.inspector(&mut child, selected.unwrap(), notice);
            egui::Rect::from_min_max(full.min, egui::pos2(divider.left() - 4., full.bottom()))
        } else {
            full
        };
        let mut table_ui = ui.new_child(
            egui::UiBuilder::new()
                .id_salt("sessions_table")
                .max_rect(table_rect),
        );
        table_ui.set_clip_rect(table_rect.intersect(ui.clip_rect()));
        if events.is_empty() {
            table_ui.label(
                "No sessions yet. Send traffic through the desktop proxy or a paired phone.",
            );
        }
        Renderer::new(&mut self.table, &mut self.viewer)
            .with_table_row_height(ui.spacing().interact_size.y.max(24.))
            .with_style_modify(|style| style.auto_shrink = egui::Vec2b::FALSE)
            .show(&mut table_ui);
        ui.allocate_rect(full, egui::Sense::hover());
    }

    fn inspector(&mut self, ui: &mut egui::Ui, event: Event, notice: Arc<Mutex<String>>) {
        if self.previous_selection != Some(event.id) {
            self.previous_selection = Some(event.id);
            self.page = 0;
            self.body = None;
            self.search_json.clear();
        }
        let details = event.exchange.lock().unwrap().clone();
        ui.horizontal(|ui| {
            ui.strong(format!("{} · Session {}", event.method, event.id));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Close").clicked() {
                    self.viewer.selected = None;
                }
                if ui.button("Copy URL").clicked() {
                    ui.ctx().copy_text(event.url.clone());
                }
            });
        });
        ui.add(egui::Label::new(&event.url).truncate())
            .on_hover_text(&event.url);
        ui.horizontal(|ui| {
            for (side, label) in [
                (Side::Request, "Request"),
                (Side::Response, "Response"),
                (Side::Overview, "Overview"),
            ] {
                if ui.selectable_value(&mut self.side, side, label).changed() {
                    self.page = 0;
                    self.body = None;
                }
            }
        });
        ui.separator();
        if let Some(error) = &details.error {
            ui.colored_label(Tokens::get(ui.ctx()).error, error);
        }
        if self.side == Side::Overview {
            egui::ScrollArea::vertical()
                .id_salt("overview")
                .show(ui, |ui| {
                    egui::Grid::new("exchange_overview")
                        .num_columns(2)
                        .spacing([16., 8.])
                        .show(ui, |ui| {
                            for (label, value) in [
                                (
                                    "Started",
                                    event.now.with_timezone(&chrono::Local).to_rfc3339(),
                                ),
                                ("Client", details.client.to_string()),
                                (
                                    "Status",
                                    details
                                        .status
                                        .map(|s| s.to_string())
                                        .unwrap_or_else(|| "Pending".into()),
                                ),
                                (
                                    "Decision",
                                    if event.is_request_blocked {
                                        "Blocked"
                                    } else {
                                        "Allowed"
                                    }
                                    .into(),
                                ),
                                ("Request protocol", format!("{:?}", details.request_version)),
                                (
                                    "Response protocol",
                                    details
                                        .response_version
                                        .map(|v| format!("{v:?}"))
                                        .unwrap_or_default(),
                                ),
                                (
                                    "Response headers after",
                                    details
                                        .response_started_ms
                                        .map(|v| format!("{v} ms"))
                                        .unwrap_or_else(|| "Pending".into()),
                                ),
                                (
                                    "Total duration",
                                    details
                                        .duration_ms
                                        .map(|v| format!("{v} ms"))
                                        .unwrap_or_else(|| "In progress".into()),
                                ),
                                ("Request body", bytes(details.request_body.seen())),
                                ("Response body", bytes(details.response_body.seen())),
                            ] {
                                ui.weak(label);
                                ui.label(value);
                                ui.end_row();
                            }
                        });
                    if let Some(note) = &details.note {
                        ui.add_space(12.);
                        ui.label(note);
                    }
                });
            return;
        }
        let request = self.side == Side::Request;
        let headers = if request {
            &details.request_headers
        } else {
            &details.response_headers
        };
        let trailers = if request {
            &details.request_trailers
        } else {
            &details.response_trailers
        };
        ui.horizontal(|ui| {
            ui.selectable_value(
                &mut self.content,
                Content::Headers,
                format!("Headers ({})", headers.len()),
            );
            ui.selectable_value(&mut self.content, Content::Body, "Body");
        });
        if self.content == Content::Headers {
            if ui.button("Copy headers").clicked() {
                ui.ctx().copy_text(
                    headers
                        .iter()
                        .chain(trailers)
                        .map(|(k, v)| format!("{k}: {v}\r\n"))
                        .collect(),
                );
            }
            egui::ScrollArea::both()
                .id_salt(("headers", request))
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    header_rows(ui, headers);
                    if !trailers.is_empty() {
                        ui.separator();
                        ui.strong("Trailers");
                        ui.push_id("trailers", |ui| header_rows(ui, trailers));
                    }
                    if headers.is_empty() {
                        ui.weak("No headers received yet.");
                    }
                });
            return;
        }
        let snapshot = if request {
            details.request_body.snapshot()
        } else {
            details.response_body.snapshot()
        };
        if let Some(error) = &snapshot.error {
            ui.colored_label(Tokens::get(ui.ctx()).warn, error);
        }
        if let Some(note) = &details.note {
            ui.label(note);
        }
        self.body_view(
            ui,
            &event,
            snapshot,
            request,
            if request {
                details.request_complete
            } else {
                details.finished_at.is_some()
            },
            notice,
        );
    }

    fn body_view(
        &mut self,
        ui: &mut egui::Ui,
        event: &Event,
        snapshot: BodySnapshot,
        request: bool,
        complete: bool,
        notice: Arc<Mutex<String>>,
    ) {
        let pages = snapshot.len.div_ceil(PAGE as u64).max(1);
        self.page = self.page.min(pages - 1);
        let key = LoadKey {
            id: event.id,
            request,
            length: snapshot.len,
            complete,
            page: self.page,
        };
        if self
            .body
            .as_ref()
            .is_none_or(|b| b.key != key && b.rx.is_none())
        {
            let (tx, rx) = mpsc::channel();
            let data = snapshot.clone();
            std::thread::spawn(move || {
                let _ = tx.send(load_body(&data, key));
            });
            self.body = Some(BodyLoad {
                key,
                rx: Some(rx),
                value: None,
            });
        }
        let loaded = self.body.as_mut().unwrap();
        if let Some(rx) = &loaded.rx {
            match rx.try_recv() {
                Ok(result) => {
                    loaded.value = Some(result);
                    loaded.rx = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    loaded.value = Some(Err("Body reader stopped".into()));
                    loaded.rx = None;
                }
                _ => {}
            }
        }
        ui.horizontal_wrapped(|ui| {
            for (mode, label) in [
                (Format::Json, "JSON"),
                (Format::Text, "Text"),
                (Format::Hex, "Hex"),
            ] {
                ui.selectable_value(&mut self.format, mode, label);
            }
            ui.weak(format!("{} received", bytes(snapshot.len)));
            if ui
                .add_enabled(snapshot.len > 0, egui::Button::new("Export body"))
                .clicked()
            {
                let filename = format!(
                    "privaxy-{}-{}.bin",
                    event.id,
                    if request { "request" } else { "response" }
                );
                if let Some(path) = rfd::FileDialog::new().set_file_name(filename).save_file() {
                    let body = snapshot.clone();
                    let notice = notice.clone();
                    std::thread::spawn(move || {
                        *notice.lock().unwrap() = match body.copy_to(&path) {
                            Ok(()) => format!(
                                "Exported {} captured bytes to {}",
                                body.len,
                                path.display()
                            ),
                            Err(e) => format!("Body export failed: {e}"),
                        };
                    });
                }
            }
        });
        if !complete {
            ui.weak("Receiving… body and timing update as traffic arrives.");
        }
        let Some(value) = loaded.value.as_ref() else {
            ui.spinner();
            return;
        };
        let data = match value {
            Ok(data) => data,
            Err(error) => {
                ui.colored_label(Tokens::get(ui.ctx()).error, error);
                return;
            }
        };
        if snapshot.len == 0 {
            ui.weak(if complete {
                "Empty body."
            } else {
                "Waiting for body bytes…"
            });
            return;
        }
        if self.format == Format::Json
            && let Some(json) = &data.json
        {
            ui.horizontal_wrapped(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.search_json)
                        .hint_text("Find JSON keys or values")
                        .desired_width(180.),
                );
                if ui.button("Copy formatted JSON").clicked() {
                    ui.ctx().copy_text(data.pretty.clone().unwrap_or_default());
                }
            });
            egui::ScrollArea::both()
                .id_salt(("json_body", event.id, request))
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    let expand = if self.search_json.is_empty() {
                        DefaultExpand::ToLevel(2)
                    } else {
                        DefaultExpand::SearchResults(&self.search_json)
                    };
                    JsonTree::new(("body_tree", event.id, request), json)
                        .default_expand(expand)
                        .show(ui);
                });
        } else {
            if self.format == Format::Json {
                ui.weak(if snapshot.len > JSON_LIMIT {
                    "Large body: paged text view. Export preserves the complete captured body."
                } else if !complete {
                    "JSON tree becomes available when the response completes."
                } else {
                    "Not valid JSON; displaying text or hexadecimal bytes."
                });
            }
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(self.page > 0, egui::Button::new("Previous"))
                    .clicked()
                {
                    self.page -= 1;
                }
                ui.label(format!("Page {} / {pages}", self.page + 1));
                if ui
                    .add_enabled(self.page + 1 < pages, egui::Button::new("Next"))
                    .clicked()
                {
                    self.page += 1;
                }
                if ui.button("Copy page").clicked() {
                    ui.ctx().copy_text(if self.format == Format::Hex {
                        data.hex.clone()
                    } else {
                        data.text.clone().unwrap_or_else(|| data.hex.clone())
                    });
                }
            });
            let text = if self.format == Format::Hex {
                &data.hex
            } else {
                data.text.as_ref().unwrap_or(&data.hex)
            };
            egui::ScrollArea::both()
                .id_salt(("text_body", event.id, request, self.page))
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    let mut read_only = text.as_str();
                    ui.add(
                        egui::TextEdit::multiline(&mut read_only)
                            .code_editor()
                            .desired_width(f32::INFINITY)
                            .desired_rows(1),
                    );
                });
        }
    }
}

fn header_rows(ui: &mut egui::Ui, headers: &[(String, String)]) {
    egui::Grid::new(ui.scope_id().with("header_values"))
        .num_columns(2)
        .spacing([14., 7.])
        .striped(true)
        .show(ui, |ui| {
            for (name, value) in headers {
                ui.label(RichText::new(name).strong());
                ui.add(egui::Label::new(value).wrap());
                ui.end_row();
            }
        });
}
fn bytes(value: u64) -> String {
    if value >= 1024 * 1024 {
        format!("{:.2} MiB", value as f64 / 1048576.)
    } else if value >= 1024 {
        format!("{:.1} KiB", value as f64 / 1024.)
    } else {
        format!("{value} B")
    }
}

fn load_body(snapshot: &BodySnapshot, key: LoadKey) -> Result<BodyView, String> {
    let offset = key.page * PAGE as u64;
    // Read a few neighbouring bytes so UTF-8 code points are never split by pagination.
    let bytes = snapshot
        .read_range(offset.saturating_sub(3), PAGE + 6)
        .map_err(|e| e.to_string())?;
    let start = (offset - offset.saturating_sub(3)) as usize;
    let end = (start + PAGE).min(bytes.len());
    let mut lo = start;
    let mut hi = end;
    while lo > 0 && lo < bytes.len() && bytes[lo] & 0xc0 == 0x80 {
        lo -= 1;
    }
    while hi > 0 && hi < bytes.len() && bytes[hi] & 0xc0 == 0x80 {
        hi -= 1;
    }
    let text = std::str::from_utf8(&bytes[lo..hi])
        .ok()
        .filter(|s| !s.chars().any(|c| c == '\0'))
        .map(str::to_owned);
    let hex = bytes[start..end]
        .chunks(16)
        .enumerate()
        .map(|(row, chunk)| {
            let encoded = chunk
                .iter()
                .map(|b| format!("{b:02x} "))
                .collect::<String>();
            let ascii = chunk
                .iter()
                .map(|&b| {
                    if b.is_ascii_graphic() || b == b' ' {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect::<String>();
            format!(
                "{:08x}  {:48}  {}\n",
                offset + row as u64 * 16,
                encoded,
                ascii
            )
        })
        .collect();
    let json = if key.complete && snapshot.error.is_none() && snapshot.len <= JSON_LIMIT {
        let all = snapshot
            .read_range(0, snapshot.len as usize)
            .map_err(|e| e.to_string())?;
        serde_json::from_slice::<serde_json::Value>(&all).ok()
    } else {
        None
    };
    let pretty = json
        .as_ref()
        .and_then(|value| serde_json::to_string_pretty(value).ok());
    Ok(BodyView {
        text,
        json,
        pretty,
        hex,
    })
}

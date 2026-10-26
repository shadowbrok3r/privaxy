//! A session table and docked inspector. Row identity is independent of filtering and sorting.
pub(crate) mod icons;
mod presentation;

use eframe::egui::{self, RichText};
use egui_data_table::{
    DataTable, Renderer, RowViewer,
    viewer::{CellWriteContext, DecodeErrorBehavior, RowCodec, TableColumnConfig},
};
use egui_json_tree::{DefaultExpand, JsonTree};
use egui_theme_kit::Tokens;
use icons::{svg, widgets};
use presentation::{Code, Language, Palette};
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
    bodies: [BodySnapshot; 2],
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
            details
                .app
                .clone()
                .unwrap_or_else(|| details.client.to_string()),
            format!("{:?}", details.request_version),
            event.id.to_string(),
        ];
        let mut search = format!("{} {}", event.url, values.join(" "));
        for (name, value) in details
            .request_headers
            .iter()
            .chain(&details.response_headers)
            .chain(&details.request_trailers)
            .chain(&details.response_trailers)
        {
            search.push_str(&format!("\n{name}: {value}"));
        }
        for note in [&details.error, &details.note].into_iter().flatten() {
            search.push('\n');
            search.push_str(note);
        }
        let search = search.to_lowercase();
        let bodies = [
            details.request_body.snapshot(),
            details.response_body.snapshot(),
        ];
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
            bodies,
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

#[derive(Default, Clone, PartialEq, Eq, Hash)]
struct Filters {
    query: String,
    preset: Preset,
    tunnels: bool,
    columns: [String; 12],
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Hash)]
enum Preset {
    #[default]
    All,
    HideErrors,
    Errors,
    Blocked,
    Slow,
    Pending,
    Json,
}
impl Preset {
    const ALL: [Self; 7] = [
        Self::All,
        Self::HideErrors,
        Self::Errors,
        Self::Blocked,
        Self::Slow,
        Self::Pending,
        Self::Json,
    ];
    fn label(self) -> &'static str {
        match self {
            Self::All => "All requests",
            Self::HideErrors => "Hide errors",
            Self::Errors => "Errors",
            Self::Blocked => "Blocked",
            Self::Slow => "Slow (≥ 1 s)",
            Self::Pending => "Pending",
            Self::Json => "JSON responses",
        }
    }
    fn icon(self) -> icons::Icon {
        match self {
            Self::All => svg::LIST_BULLETS,
            Self::HideErrors => svg::SHIELD_CHECK,
            Self::Errors => svg::WARNING_CIRCLE,
            Self::Blocked => svg::PROHIBIT,
            Self::Slow => svg::CLOCK,
            Self::Pending => svg::HOURGLASS,
            Self::Json => svg::BRACKETS_CURLY,
        }
    }
    fn tooltip(self) -> &'static str {
        match self {
            Self::All => "All captured requests matching search and column filters.",
            Self::HideErrors => {
                "Hide transport failures and HTTP 4xx / 5xx responses; keep pending and successful requests."
            }
            Self::Errors => "Transport failures or HTTP status 400 and above.",
            Self::Blocked => "Requests blocked by a filter rule.",
            Self::Slow => "Requests with a recorded duration of at least 1,000 ms.",
            Self::Pending => "Requests still waiting for a response status, excluding failures.",
            Self::Json => "Responses with a JSON or +json content type.",
        }
    }
    fn matches(self, row: &Row) -> bool {
        let error = row.failed || row.status >= 400;
        match self {
            Self::All => true,
            Self::HideErrors => !error,
            Self::Errors => error,
            Self::Blocked => row.event.is_request_blocked,
            Self::Slow => row.duration >= 1000,
            Self::Pending => row.status == 0 && !row.failed,
            Self::Json => Language::detect(&row.values[7], "") == Language::Json,
        }
    }
}

/// Follow newly observed requests, without changing selection or chasing body updates.
struct Follow {
    enabled: bool,
    was_enabled: bool,
    latest: Option<u64>,
}
impl Default for Follow {
    fn default() -> Self {
        Self {
            enabled: true,
            was_enabled: false,
            latest: None,
        }
    }
}
impl Follow {
    fn update(&mut self, observed: Option<u64>, matching: Option<u64>) -> bool {
        let new_match = matching.is_some_and(|id| self.latest.is_none_or(|seen| id > seen));
        let scroll = self.enabled && matching.is_some() && (!self.was_enabled || new_match);
        self.was_enabled = self.enabled;
        // Advance through *all* observed IDs, including rows currently hidden by a filter.
        // A later status/body update making an old row match must not count as an arrival.
        self.latest = observed;
        scroll
    }
}

#[derive(Default)]
struct Viewer {
    filters: Filters,
    body_search: crate::traffic_search::BodySearch,
    selected: Option<Event>,
    scroll_to_end: bool,
    chronological: bool,
}
impl Viewer {
    fn matches(&self, row: &Row) -> bool {
        let f = &self.filters;
        (f.tunnels || row.event.method != "CONNECT" || row.failed)
            && (f.query.trim().is_empty()
                || row.search.contains(&f.query.trim().to_lowercase())
                || self.body_search.matches(row.event.id, &row.bodies))
            && f.columns.iter().zip(&row.values).all(|(query, value)| {
                query.trim().is_empty()
                    || value.to_lowercase().contains(&query.trim().to_lowercase())
            })
            && f.preset.matches(row)
    }
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
        if std::mem::take(&mut self.scroll_to_end) {
            // The pinned data-table does not expose TableBuilder::stick_to_bottom.
            // Issue a one-shot public egui scroll request *inside* its virtualized body.
            // This reaches off-screen rows without touching private table state or selection.
            ui.scroll_with_delta_animation(
                egui::vec2(0., -1.0e9),
                egui::style::ScrollAnimation::none(),
            );
        }
        let tokens = Tokens::get(ui.ctx());
        let color = if column == 0 && row.failed {
            tokens.error
        } else if column == 0 && (row.event.is_request_blocked || row.status >= 400) {
            tokens.warn
        } else {
            tokens.text
        };
        ui.add(
            egui::Label::new(RichText::new(&row.values[column]).color(color))
                .truncate()
                .selectable(false),
        )
        .on_hover_text(&row.values[column]);
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
        !self.chronological
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
        &self.filters
    }
    fn filter_row(&mut self, row: &Row) -> bool {
        self.matches(row)
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
        !self.chronological
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
    Pretty,
    Json,
    Text,
    Hex,
}
#[derive(Clone, Copy, PartialEq)]
struct LoadKey {
    id: u64,
    request: bool,
    length: u64,
    complete: bool,
    page: u64,
    language: Language,
    palette: Palette,
}
struct BodyView {
    text: Option<Code>,
    hex: Code,
}
struct DocumentView {
    json: Option<serde_json::Value>,
    pretty: Option<String>,
    formatted: presentation::Formatted,
}
struct BodyLoad<T> {
    key: LoadKey,
    rx: Option<mpsc::Receiver<Result<T, String>>>,
    value: Option<Result<T, String>>,
}
impl<T> BodyLoad<T> {
    fn poll(&mut self) {
        if let Some(rx) = &self.rx {
            match rx.try_recv() {
                Ok(result) => {
                    self.value = Some(result);
                    self.rx = None;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.value = Some(Err("Body worker stopped".into()));
                    self.rx = None;
                }
                _ => {}
            }
        }
    }
}

pub(super) struct Traffic {
    table: DataTable<Row>,
    parked_table: DataTable<Row>,
    table_following: bool,
    viewer: Viewer,
    refreshed: Instant,
    split: f32,
    side: Side,
    content: Content,
    format: Format,
    page: u64,
    search_json: String,
    body: Option<BodyLoad<BodyView>>,
    document: Option<BodyLoad<DocumentView>>,
    previous_selection: Option<u64>,
    follow: Follow,
}
impl Default for Traffic {
    fn default() -> Self {
        Self {
            table: DataTable::new(),
            parked_table: DataTable::new(),
            table_following: true,
            viewer: Viewer::default(),
            refreshed: Instant::now() - Duration::from_secs(1),
            split: 0.55,
            side: Side::default(),
            content: Content::default(),
            format: Format::default(),
            page: 0,
            search_json: String::new(),
            body: None,
            document: None,
            previous_selection: None,
            follow: Follow::default(),
        }
    }
}
impl Traffic {
    pub fn select(&mut self, event: Event) {
        self.viewer.selected = Some(event);
    }
    pub fn search(&mut self, query: String) {
        self.viewer.filters.query = query;
    }
    pub fn show(
        &mut self,
        ui: &mut egui::Ui,
        server: Option<&privaxy::PrivaxyServer>,
        events: &[Event],
        notice: Arc<Mutex<String>>,
    ) {
        icons::install(ui.ctx());
        let old_filters = self.viewer.filters.clone();
        let mut cleared = false;
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.viewer.filters.query)
                    .hint_text("Search all traffic…")
                    .char_limit(1024)
                    .desired_width(240.),
            ).on_hover_text("Search all columns, URLs, request/response headers, trailers, errors and complete captured bodies. Case-insensitive text; encrypted or uncaptured payloads cannot be searched.");
            let preset = self.viewer.filters.preset;
            widgets::menu_button(ui, preset.icon(), preset.label(), |ui| {
                ui.weak("Presets combine with search and column filters.");
                for preset in Preset::ALL {
                    if widgets::selectable_button(ui, preset.icon(), self.viewer.filters.preset == preset, preset.label())
                        .on_hover_text(preset.tooltip()).clicked() {
                        self.viewer.filters.preset = preset;
                        ui.close();
                    }
                }
            }).response.on_hover_text(preset.tooltip());
            let active = self.viewer.filters.columns.iter().filter(|q| !q.trim().is_empty()).count();
            let filter_button = widgets::button(ui, svg::FUNNEL, format!("Column filters ({active})"))
                .on_hover_text("Filter any column. Fields apply immediately and combine with the selected preset.");
            egui::Popup::menu(&filter_button)
                .id(ui.make_persistent_id("traffic_column_filter_popup"))
                .close_behavior(egui::PopupCloseBehavior::CloseOnClickOutside)
                .show(|ui| {
                ui.label("Match every filled field, including hidden columns.");
                egui::Grid::new("traffic_column_filters").num_columns(2).show(ui, |ui| {
                    for (column, name) in COLUMNS.iter().enumerate() {
                        let label = ui.label(*name);
                        ui.add(egui::TextEdit::singleline(&mut self.viewer.filters.columns[column])
                            .id_salt(("traffic_column", column))
                            .hint_text(format!("Filter {name}"))
                            .char_limit(256)
                            .desired_width(210.)).labelled_by(label.id);
                        ui.end_row();
                    }
                });
                ui.separator();
                ui.horizontal(|ui| {
                    if widgets::button(ui, svg::ARROW_COUNTER_CLOCKWISE, "Clear columns").clicked() {
                        self.viewer.filters.columns = Default::default();
                    }
                    if widgets::button(ui, svg::CHECK_CIRCLE, "Done").clicked() { ui.close(); }
                });
            });
            widgets::checkbox(ui, &mut self.follow.enabled, svg::ARROW_LINE_DOWN, "Follow new requests")
                .on_hover_text("Show requests in chronological order, oldest first, and reveal new matching arrivals. Sorting is disabled while following. Turn off to restore your manual table order; the inspector stays on your selected request.");
            widgets::checkbox(ui, &mut self.viewer.filters.tunnels, svg::PLUGS_CONNECTED, "CONNECT")
                .on_hover_text("Include successful HTTPS tunnel sessions. Failed tunnels remain visible unless excluded by a filter.");
            if widgets::button(ui, svg::ARROW_COUNTER_CLOCKWISE, "Reset filters").on_hover_text("Clear search, column filters and presets.").clicked() {
                self.viewer.filters = Filters::default();
            }
            if widgets::button(ui, svg::TRASH, "Clear session").on_hover_text("Remove all captured sessions and body files.").clicked() {
                if let Some(server) = server {
                    if let Err(error) = server.capture.clear() {
                        *notice.lock().unwrap() = error.to_string();
                    }
                }
                cleared = true;
                self.table.replace(vec![]);
                self.viewer.selected = None;
                self.body = None;
                self.document = None;
                self.viewer.body_search = Default::default();
                self.follow.latest = None;
            }
        });
        if cleared {
            return;
        }
        self.sync_follow_order();
        if self.refreshed.elapsed() >= Duration::from_millis(350)
            || self.table.len() != events.len()
        {
            self.table
                .replace(events.iter().cloned().map(Row::new).collect());
            self.refreshed = Instant::now();
        }
        let search_changed = self.viewer.body_search.update(
            &self.viewer.filters.query.trim().to_lowercase(),
            self.table
                .iter()
                .map(|row| (row.event.id, row.bodies.clone())),
            ui.ctx(),
        );
        if search_changed || old_filters != self.viewer.filters {
            let rows = self.table.take();
            self.table.replace(rows);
        }
        let filtered = self
            .table
            .iter()
            .filter(|row| self.viewer.matches(row))
            .count();
        self.viewer.scroll_to_end = self.follow.update(
            events.last().map(|event| event.id),
            self.table
                .iter()
                .rev()
                .find(|row| self.viewer.matches(row))
                .map(|row| row.event.id),
        );
        ui.horizontal_wrapped(|ui| {
            ui.weak(format!("{filtered} / {} sessions · {} captured", events.len(), bytes(server.map_or(0,|s|s.capture.used()))));
            if self.follow.enabled {
                widgets::label(ui, svg::CLOCK, "Chronological · oldest first")
                    .on_hover_text("Follow is on. Turn it off to sort by any column.");
            }
            if self.viewer.body_search.searching() {
                ui.spinner();
                ui.weak("Searching captured bodies…");
            }
            ui.weak("Right-click headers to choose columns. Drag headers or borders to reorder or resize.");
        });
        let errors = self.viewer.body_search.errors();
        if errors > 0 {
            ui.colored_label(Tokens::get(ui.ctx()).warn, format!("{errors} sessions have unreadable body files; their metadata is still searchable."));
        }
        if let Some(problem) = server.and_then(|s| s.capture.problem()) {
            ui.colored_label(Tokens::get(ui.ctx()).warn, problem);
        }
        ui.add_space(6.);
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
                .id_salt(if self.follow.enabled {
                    "follow_sessions_table"
                } else {
                    "sessions_table"
                })
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
            .with_style_modify(|style| {
                style.auto_shrink = egui::Vec2b::FALSE;
                style.scroll_bar_visibility = egui::scroll_area::ScrollBarVisibility::AlwaysVisible;
            })
            .show(&mut table_ui);
        ui.allocate_rect(full, egui::Sense::hover());
    }

    fn sync_follow_order(&mut self) {
        if self.table_following != self.follow.enabled {
            // Keep the manually sorted table's opaque UI state intact. The separate follow
            // table never loads persisted sorting and never permits sorting. Swapping back
            // restores manual sorting/column choices; dropping its rows avoids two body indexes.
            std::mem::swap(&mut self.table, &mut self.parked_table);
            self.parked_table.take();
            self.table_following = self.follow.enabled;
            self.refreshed = Instant::now() - Duration::from_secs(1);
        }
        self.viewer.chronological = self.follow.enabled;
    }

    fn inspector(&mut self, ui: &mut egui::Ui, event: Event, notice: Arc<Mutex<String>>) {
        if self.previous_selection != Some(event.id) {
            self.previous_selection = Some(event.id);
            self.page = 0;
            self.body = None;
            self.document = None;
            self.search_json.clear();
        }
        let details = event.exchange.lock().unwrap().clone();
        ui.horizontal(|ui| {
            ui.strong(format!("{} · Session {}", event.method, event.id));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if widgets::button(ui, svg::X_CIRCLE, "Close")
                    .on_hover_text("Close the session inspector.")
                    .clicked()
                {
                    self.viewer.selected = None;
                }
                if widgets::button(ui, svg::COPY, "Copy URL")
                    .on_hover_text("Copy the complete request URL.")
                    .clicked()
                {
                    ui.ctx().copy_text(event.url.clone());
                }
            });
        });
        ui.add(egui::Label::new(&event.url).truncate())
            .on_hover_text(&event.url);
        ui.horizontal(|ui| {
            for (side, icon, label) in [
                (Side::Request, svg::ARROW_UP, "Request"),
                (Side::Response, svg::ARROW_DOWN, "Response"),
                (Side::Overview, svg::INFO, "Overview"),
            ] {
                if widgets::selectable_button(ui, icon, self.side == side, label).clicked()
                    && self.side != side
                {
                    self.side = side;
                    self.page = 0;
                    self.body = None;
                    self.document = None;
                }
            }
        });
        ui.separator();
        if let Some(error) = &details.error {
            ui.colored_label(Tokens::get(ui.ctx()).error, error);
        }
        if self.side == Side::Overview {
            egui::ScrollArea::vertical()
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
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
                                (
                                    "Client",
                                    match &details.app {
                                        Some(app) => format!("{app} via {}", details.client),
                                        None => details.client.to_string(),
                                    },
                                ),
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
            if widgets::selectable_button(
                ui,
                svg::LIST_BULLETS,
                self.content == Content::Headers,
                format!("Headers ({})", headers.len()),
            )
            .clicked()
            {
                self.content = Content::Headers;
            }
            if widgets::selectable_button(ui, svg::FILE_CODE, self.content == Content::Body, "Body")
                .clicked()
            {
                self.content = Content::Body;
            }
        });
        if self.content == Content::Headers {
            if widgets::button(ui, svg::COPY, "Copy headers")
                .on_hover_text("Copy all headers and trailers.")
                .clicked()
            {
                ui.ctx().copy_text(
                    headers
                        .iter()
                        .chain(trailers)
                        .map(|(k, v)| format!("{k}: {v}\r\n"))
                        .collect(),
                );
            }
            egui::ScrollArea::both()
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
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
            Language::detect(
                headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
                    .map(|(_, v)| v.as_str())
                    .unwrap_or_default(),
                &event.url,
            ),
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
        language: Language,
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
            language,
            palette: Palette::from_ui(ui),
        };
        if self
            .body
            .as_ref()
            .is_none_or(|b| b.key != key && b.rx.is_none())
        {
            let (tx, rx) = mpsc::channel();
            let data = snapshot.clone();
            let ctx = ui.ctx().clone();
            std::thread::spawn(move || {
                let _ = tx.send(load_body(&data, key));
                ctx.request_repaint();
            });
            self.body = Some(BodyLoad {
                key,
                rx: Some(rx),
                value: None,
            });
        }
        // A separate page-independent cache: a whole-document formatter must never receive
        // a 64 KiB fragment, nor run again just because a raw/hex page changed.
        let document_key = LoadKey { page: 0, ..key };
        if self
            .document
            .as_ref()
            .is_none_or(|d| d.key != document_key && d.rx.is_none())
        {
            let (tx, rx) = mpsc::channel();
            let data = snapshot.clone();
            let ctx = ui.ctx().clone();
            std::thread::spawn(move || {
                let _ = tx.send(load_document(&data, document_key));
                ctx.request_repaint();
            });
            self.document = Some(BodyLoad {
                key: document_key,
                rx: Some(rx),
                value: None,
            });
        }
        let document = self.document.as_mut().unwrap();
        document.poll();
        let document_value = (document.key == document_key)
            .then_some(document.value.as_ref())
            .flatten();
        let document_data = document_value.and_then(|v| v.as_ref().ok());
        let loaded = self.body.as_mut().unwrap();
        loaded.poll();
        ui.horizontal_wrapped(|ui| {
            for (mode, icon, label) in [
                (Format::Pretty, svg::CODE_BLOCK, "Pretty"),
                (Format::Json, svg::BRACKETS_CURLY, "JSON tree"),
                (Format::Text, svg::FILE_CODE, "Source"),
                (Format::Hex, svg::HASH, "Hex"),
            ] {
                if widgets::selectable_button(ui, icon, self.format == mode, label).clicked() { self.format = mode; }
            }
            let kind = if loaded.value.as_ref().and_then(|v| v.as_ref().ok()).is_some_and(|data| data.text.is_none()) {
                "Binary"
            } else { language.name() };
            ui.weak(format!("{kind} · {}", bytes(snapshot.len)));
            let copy = widgets::button_widget(ui, svg::COPY, "Copy body");
            if ui.add_enabled(snapshot.len > 0, copy)
                .on_hover_text("Copy the complete captured UTF-8 body, including all pages, without formatting. Use Export body for binary data.").clicked() {
                let body = snapshot.clone();
                let ctx = ui.ctx().clone();
                let notice = notice.clone();
                std::thread::spawn(move || {
                    let result = body.read_range(0, body.len as usize).map_err(|e| e.to_string())
                        .and_then(|bytes| String::from_utf8(bytes).map_err(|_| "Binary body: use Export body to save every byte.".to_owned()));
                    *notice.lock().unwrap() = match result {
                        Ok(text) => { ctx.copy_text(text); format!("Copied {} captured bytes.", body.len) },
                        Err(error) => error,
                    };
                    ctx.request_repaint();
                });
            }
            let export = widgets::button_widget(ui, svg::DOWNLOAD_SIMPLE, "Export body");
            if ui
                .add_enabled(snapshot.len > 0, export)
                .on_hover_text("Save every captured byte to a file, including all pages. Source bytes are never reformatted.")
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
            ui.weak("Preparing body preview…");
            ui.ctx().request_repaint_after(Duration::from_millis(40));
            return;
        };
        if loaded.key != key {
            ui.spinner();
            ui.weak("Refreshing body preview…");
            ui.ctx().request_repaint();
            return;
        }
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
        if matches!(self.format, Format::Pretty | Format::Json) {
            if document_value.is_none() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.weak("Preparing complete document… showing source preview.");
                });
                ui.ctx().request_repaint_after(Duration::from_millis(40));
            } else if let Some(Err(error)) = document_value {
                ui.colored_label(Tokens::get(ui.ctx()).warn, error);
            }
        }
        if matches!(self.format, Format::Json | Format::Pretty)
            && let Some(json) = document_data.and_then(|doc| doc.json.as_ref())
        {
            ui.horizontal_wrapped(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.search_json)
                        .hint_text("Find JSON keys or values")
                        .desired_width(180.),
                );
                if widgets::button(ui, svg::COPY, "Copy formatted JSON")
                    .on_hover_text("Copy the complete formatted JSON document.")
                    .clicked()
                {
                    ui.ctx().copy_text(
                        document_data
                            .and_then(|doc| doc.pretty.clone())
                            .unwrap_or_default(),
                    );
                }
            });
            egui::ScrollArea::both()
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
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
            if self.format == Format::Json && document_value.is_some() {
                ui.weak(if snapshot.len > JSON_LIMIT {
                    "Large body: paged text view. Export preserves the complete captured body."
                } else if !complete {
                    "JSON tree becomes available when the response completes."
                } else {
                    "Not valid JSON; displaying text or hexadecimal bytes."
                });
            }
            if self.format == Format::Pretty
                && let Some(note) = document_data.and_then(|doc| doc.formatted.note.as_ref())
            {
                ui.add(
                    egui::Label::new(RichText::new(note).color(Tokens::get(ui.ctx()).text_dim))
                        .wrap(),
                );
            }
            if self.format == Format::Hex || data.text.is_none() {
                let tokens = Tokens::get(ui.ctx());
                ui.horizontal_wrapped(|ui| {
                    ui.weak("Offset / bytes / ASCII");
                    ui.colored_label(tokens.text_dim, "Zero");
                    ui.colored_label(tokens.warn, "Control");
                    ui.colored_label(tokens.secondary, "Non-ASCII");
                    ui.colored_label(tokens.success, "Printable");
                });
            }
            let code = if self.format == Format::Hex {
                &data.hex
            } else if self.format == Format::Pretty {
                document_data
                    .and_then(|doc| doc.formatted.code.as_ref())
                    .or(data.text.as_ref())
                    .unwrap_or(&data.hex)
            } else {
                data.text.as_ref().unwrap_or(&data.hex)
            };
            let full_document = self.format == Format::Pretty
                && document_data.is_some_and(|doc| doc.formatted.code.is_some());
            if full_document {
                ui.horizontal_wrapped(|ui| {
                    ui.weak(format!("Complete formatted body · {} · {} lines", bytes(code.text.len() as u64), code.line_count()));
                    if widgets::button(ui, svg::COPY, "Copy formatted body").on_hover_text("Copy the complete formatted document. Copy body and Export body preserve the original bytes.").clicked() {
                        ui.ctx().copy_text(code.text.clone());
                    }
                });
            } else {
                ui.horizontal_wrapped(|ui| {
                let previous = widgets::button_widget(ui, svg::ARROW_LEFT, "Previous");
                if ui
                    .add_enabled(self.page > 0, previous)
                    .clicked()
                {
                    self.page -= 1;
                }
                ui.label(format!("Page {} / {pages}", self.page + 1));
                let next = widgets::button_widget(ui, svg::ARROW_RIGHT, "Next");
                if ui
                    .add_enabled(self.page + 1 < pages, next)
                    .clicked()
                {
                    self.page += 1;
                }
                if widgets::button(ui, svg::COPY, "Copy page").on_hover_text("Copy this displayed preview. Copy body copies the complete captured source.").clicked() {
                    ui.ctx().copy_text(code.text.clone());
                }
            });
            }
            code.show(
                ui,
                (
                    "text_body",
                    event.id,
                    request,
                    if full_document { 0 } else { loaded.key.page },
                    self.format as u8,
                ),
            );
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
    let hex = Code::hex(&bytes[start..end], offset, key.palette);
    let text = text.map(|text| Code::highlight(text, key.language, key.palette));
    Ok(BodyView { text, hex })
}

fn load_document(snapshot: &BodySnapshot, key: LoadKey) -> Result<DocumentView, String> {
    let fallback = |note: &str| DocumentView {
        json: None,
        pretty: None,
        formatted: presentation::Formatted {
            code: None,
            note: Some(note.into()),
        },
    };
    if !key.complete || snapshot.error.is_some() {
        return Ok(fallback(
            "Incomplete body: showing source pages. Formatting starts when capture completes.",
        ));
    }
    if snapshot.len > JSON_LIMIT {
        return Ok(fallback(
            "Body exceeds the 2 MiB formatting / 8 MiB JSON tree limits; showing source pages. Copy body / Export body preserve all captured bytes.",
        ));
    }
    // The existing JSON tree keeps its 8 MiB bound. Other formatters receive at most
    // 2 MiB, checked before parsing, and every read/parse/highlight runs on a worker.
    let all = snapshot
        .read_range(0, snapshot.len as usize)
        .map_err(|e| e.to_string())?;
    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&all) {
        let pretty = serde_json::to_string_pretty(&json).ok();
        return Ok(DocumentView {
            json: Some(json),
            pretty,
            formatted: Default::default(),
        });
    }
    if snapshot.len > presentation::FORMAT_INPUT_LIMIT as u64 {
        return Ok(fallback(
            "Body exceeds the 2 MiB formatting limit; showing source pages. Copy body / Export body preserve all captured bytes.",
        ));
    }
    let formatted = match std::str::from_utf8(&all)
        .ok()
        .filter(|text| !text.contains('\0'))
    {
        Some(text) => presentation::prepare(text, key.language, true, key.palette),
        None => presentation::Formatted::default(),
    };
    Ok(DocumentView {
        json: None,
        pretty: None,
        formatted,
    })
}

#[cfg(test)]
mod filter_tests {
    use super::*;

    fn palette() -> Palette {
        let ctx = egui::Context::default();
        let mut palette = None;
        let mut output = ctx.run_ui(Default::default(), |ui| {
            palette = Some(Palette::from_ui(ui))
        });
        output.textures_delta.clear();
        palette.unwrap()
    }

    fn sample() -> Row {
        let mut event = Row::empty().event;
        event.method = "POST".into();
        event.url = "https://example.test/api?limit=20".into();
        {
            let mut exchange = event.exchange.lock().unwrap();
            exchange.status = Some(403);
            exchange
                .request_headers
                .push(("Authorization".into(), "fixture-request-token".into()));
            exchange
                .response_headers
                .push(("X-Result".into(), "response-marker".into()));
            exchange
                .response_trailers
                .push(("X-Trailer".into(), "trailer-marker".into()));
            exchange.error = Some("CertificateUnknown".into());
            exchange.note = Some("fixture capture note".into());
        }
        Row::new(event)
    }

    #[test]
    fn search_includes_headers_trailers_errors_and_notes() {
        let row = sample();
        let mut viewer = Viewer::default();
        for query in [
            "fixture-request-token",
            "response-marker",
            "trailer-marker",
            "CERTIFICATEUNKNOWN",
            "fixture capture note",
            "limit=20",
        ] {
            viewer.filters.query = query.into();
            assert!(viewer.matches(&row), "query {query}");
        }
        viewer.filters.query = "not-in-this-session".into();
        assert!(!viewer.matches(&row));
    }

    #[test]
    fn every_column_can_filter_and_filters_combine() {
        let row = sample();
        let mut viewer = Viewer::default();
        for (column, value) in row.values.iter().enumerate() {
            viewer.filters.columns = Default::default();
            viewer.filters.columns[column] = value.to_uppercase();
            assert!(viewer.matches(&row), "column {column}");
            viewer.filters.columns[column] = "does-not-match".into();
            assert!(!viewer.matches(&row), "column {column}");
        }
        viewer.filters.columns = Default::default();
        viewer.filters.columns[1] = "post".into();
        viewer.filters.columns[2] = "example.test".into();
        viewer.filters.query = "response-marker".into();
        viewer.filters.preset = Preset::Errors;
        assert!(viewer.matches(&row));
        viewer.filters.preset = Preset::Blocked;
        assert!(!viewer.matches(&row));
        viewer.filters = Filters::default();
        assert!(viewer.matches(&row));
    }

    #[test]
    fn presets_classify_transport_http_pending_blocked_slow_and_json() {
        for (status, failed, blocked, duration, mime, expected) in [
            (
                200,
                false,
                false,
                999,
                "text/html",
                vec![Preset::All, Preset::HideErrors],
            ),
            (
                302,
                false,
                false,
                1000,
                "application/problem+json; charset=utf-8",
                vec![Preset::All, Preset::HideErrors, Preset::Slow, Preset::Json],
            ),
            (404, false, false, 20, "", vec![Preset::All, Preset::Errors]),
            (503, false, false, 20, "", vec![Preset::All, Preset::Errors]),
            (0, true, false, 20, "", vec![Preset::All, Preset::Errors]),
            (
                0,
                false,
                false,
                0,
                "",
                vec![Preset::All, Preset::HideErrors, Preset::Pending],
            ),
            (
                403,
                false,
                true,
                20,
                "",
                vec![Preset::All, Preset::Errors, Preset::Blocked],
            ),
        ] {
            let mut event = Row::empty().event;
            event.is_request_blocked = blocked;
            {
                let mut details = event.exchange.lock().unwrap();
                details.status = (status > 0).then_some(status);
                details.error = failed.then(|| "TLS failed".into());
                details.duration_ms = Some(duration);
                details
                    .response_headers
                    .push(("Content-Type".into(), mime.into()));
            }
            let row = Row::new(event);
            for preset in Preset::ALL {
                assert_eq!(
                    preset.matches(&row),
                    expected.contains(&preset),
                    "{}: status {status}, failed {failed}",
                    preset.label()
                );
            }
        }
    }

    #[test]
    fn hide_errors_combines_with_columns_query_and_connect_visibility() {
        let mut row = sample();
        row.failed = false;
        row.status = 200;
        let mut viewer = Viewer::default();
        viewer.filters.preset = Preset::HideErrors;
        viewer.filters.query = "response-marker".into();
        viewer.filters.columns[2] = "example.test".into();
        assert!(viewer.matches(&row));
        row.event.method = "CONNECT".into();
        assert!(!viewer.matches(&row));
        viewer.filters.tunnels = true;
        assert!(viewer.matches(&row));
        row.failed = true;
        assert!(!viewer.matches(&row));
        viewer.filters.preset = Preset::Errors;
        viewer.filters.tunnels = false;
        assert!(viewer.matches(&row));
        viewer.filters.columns[2] = "different.test".into();
        assert!(!viewer.matches(&row));
    }

    #[test]
    fn follow_tracks_only_new_matching_ids_and_resumes_without_new_traffic() {
        let mut follow = Follow::default();
        assert!(!follow.update(None, None));
        assert!(follow.update(Some(1), Some(1)));
        assert!(
            !follow.update(Some(1), Some(1)),
            "body refresh must not jump"
        );
        assert!(
            !follow.update(Some(2), Some(1)),
            "a new hidden request must not jump"
        );
        assert!(
            !follow.update(Some(2), Some(2)),
            "completion making an existing row match must not jump"
        );
        assert!(follow.update(Some(3), Some(3)));
        follow.enabled = false;
        assert!(!follow.update(Some(4), Some(4)));
        follow.enabled = true;
        assert!(
            follow.update(Some(4), Some(4)),
            "resume scrolls without an arrival"
        );
        assert!(!follow.update(Some(4), Some(4)));
        assert!(
            !follow.update(Some(4), Some(3)),
            "editing filters must not jump"
        );
        assert!(
            !follow.update(None, None),
            "clearing the session must not scroll"
        );
        assert!(
            follow.update(Some(1), Some(1)),
            "a new capture may restart IDs"
        );
    }

    #[test]
    fn utf8_pages_reassemble_and_full_copy_export_preserve_all_bytes() {
        let store =
            privaxy::storage::BodyStore::new(&std::env::temp_dir(), (PAGE * 4) as u64).unwrap();
        let body = store.body();
        let source = format!("{}🦀{}日本語", "a".repeat(PAGE - 1), "b".repeat(PAGE - 4));
        body.push(source.as_bytes());
        let snapshot = body.snapshot();
        let ctx = egui::Context::default();
        let mut palette = None;
        let mut output = ctx.run_ui(Default::default(), |ui| {
            palette = Some(Palette::from_ui(ui))
        });
        output.textures_delta.clear();
        let mut reassembled = String::new();
        for page in 0..snapshot.len.div_ceil(PAGE as u64) {
            let view = load_body(
                &snapshot,
                LoadKey {
                    id: 1,
                    request: false,
                    length: snapshot.len,
                    complete: true,
                    page,
                    language: Language::Text,
                    palette: palette.unwrap(),
                },
            )
            .unwrap();
            let text = &view.text.unwrap().text;
            assert!(text.len() <= PAGE + 3);
            assert!(
                view.hex
                    .text
                    .starts_with(&format!("{:08x}", page * PAGE as u64))
            );
            reassembled.push_str(text);
        }
        assert_eq!(reassembled, source);
        assert_eq!(
            snapshot.read_range(0, snapshot.len as usize).unwrap(),
            source.as_bytes()
        );
        let path = std::env::temp_dir().join(format!(
            "privaxy-traffic-export-{}-{}.bin",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        snapshot.copy_to(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), source.as_bytes());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn complete_javascript_above_one_page_formats_whole_and_preserves_capture() {
        let source: String = (0..3000)
            .map(|i| format!("const value{i}={{id:{i},text:\"literal;a{{b}}\"}};\n"))
            .collect();
        assert!(source.len() > PAGE);
        let store =
            privaxy::storage::BodyStore::new(&std::env::temp_dir(), 4 * 1024 * 1024).unwrap();
        let body = store.body();
        body.push(source.as_bytes());
        let snapshot = body.snapshot();
        let key = LoadKey {
            id: 2,
            request: false,
            length: snapshot.len,
            complete: true,
            page: 0,
            language: Language::JavaScript,
            palette: palette(),
        };
        let started = Instant::now();
        let document = load_document(&snapshot, key).unwrap();
        let formatted = document.formatted.code.unwrap();
        assert!(
            formatted
                .text
                .contains("const value0 = { id: 0, text: \"literal;a{b}\" };")
        );
        assert!(
            formatted
                .text
                .contains("const value2999 = { id: 2999, text: \"literal;a{b}\" };")
        );
        assert_eq!(formatted.text.matches("literal;a{b}").count(), 3000);
        assert!(formatted.text.len() > PAGE);
        assert!(formatted.text.len() <= presentation::FORMAT_OUTPUT_LIMIT);
        let raw_page = load_body(&snapshot, LoadKey { page: 1, ..key }).unwrap();
        assert!(raw_page.text.unwrap().text.len() <= PAGE + 3);
        assert!(
            load_document(
                &snapshot,
                LoadKey {
                    complete: false,
                    ..key
                }
            )
            .unwrap()
            .formatted
            .code
            .is_none()
        );
        assert_eq!(
            snapshot.read_range(0, snapshot.len as usize).unwrap(),
            source.as_bytes()
        );
        let path = std::env::temp_dir().join(format!(
            "privaxy-js-export-{}-{}.js",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap()
        ));
        snapshot.copy_to(&path).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), source.as_bytes());
        std::fs::remove_file(path).unwrap();
        eprintln!(
            "whole JS: {} input bytes, {} formatted bytes, {} lines in {:?}",
            source.len(),
            formatted.text.len(),
            formatted.line_count(),
            started.elapsed()
        );
    }
}

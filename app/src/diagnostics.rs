use eframe::egui;
use egui_icon_pack::{phosphor_regular as svg, widgets as icons};
use egui_theme_kit::Tokens;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub(super) struct LogView {
    query: String,
    paused: bool,
    frozen: Vec<privaxy_diagnostics::Entry>,
}
impl LogView {
    pub fn show(&mut self, ui: &mut egui::Ui, notice: Arc<Mutex<String>>) {
        ui.heading("Diagnostic logs");
        ui.horizontal_wrapped(|ui| {
            let mut level = privaxy_diagnostics::level();
            egui::ComboBox::from_id_salt("capture_log_level")
                .selected_text(format!("Level: {level}"))
                .show_ui(ui, |ui| {
                    for choice in privaxy_diagnostics::LEVELS {
                        ui.selectable_value(&mut level, choice, choice.to_string());
                    }
                });
            if level != privaxy_diagnostics::level() {
                privaxy_diagnostics::set_level(level);
            }
            ui.add(
                egui::TextEdit::singleline(&mut self.query)
                    .hint_text("Search message or source")
                    .desired_width(230.),
            );
            if icons::checkbox(ui, &mut self.paused, svg::PAUSE, "Pause view").changed()
                && self.paused
            {
                self.frozen = privaxy_diagnostics::entries();
            }
            if icons::button(ui, svg::TRASH, "Clear view").clicked() {
                privaxy_diagnostics::clear_view();
                self.frozen.clear();
            }
            if icons::button(ui, svg::DOWNLOAD_SIMPLE, "Export logs").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .set_file_name("privaxy-desktop.log")
                    .save_file()
                {
                    std::thread::spawn(move || {
                        *notice.lock().unwrap() = match privaxy_diagnostics::export_text()
                            .and_then(|text| std::fs::write(&path, text))
                        {
                            Ok(()) => format!("Logs exported to {}", path.display()),
                            Err(error) => format!("Log export failed: {error}"),
                        };
                    });
                }
            }
        });
        ui.weak("Selected level and higher severity. Trace includes connection stages and heartbeat timing. Files retain the latest 10 MiB across restarts.");
        if let Some(path) = privaxy_diagnostics::file_path() {
            ui.label(
                egui::RichText::new(path.display().to_string())
                    .small()
                    .monospace(),
            );
        }
        if let Some(error) = privaxy_diagnostics::file_error() {
            ui.colored_label(Tokens::get(ui.ctx()).error, error);
        }
        let entries = if self.paused {
            self.frozen.clone()
        } else {
            privaxy_diagnostics::entries()
        };
        let query = self.query.to_lowercase();
        let entries: Vec<_> = entries
            .iter()
            .filter(|e| {
                e.level <= privaxy_diagnostics::level()
                    && (query.is_empty()
                        || e.message.to_lowercase().contains(&query)
                        || e.target.to_lowercase().contains(&query))
            })
            .collect();
        ui.horizontal(|ui| {
            ui.weak(format!(
                "{} visible · {} disk queue drops",
                entries.len(),
                privaxy_diagnostics::dropped_lines()
            ));
            if icons::button(ui, svg::COPY, "Copy visible").clicked() {
                ui.ctx()
                    .copy_text(entries.iter().map(|e| e.line()).collect());
            }
        });
        ui.separator();
        let height = ui.spacing().interact_size.y.max(24.);
        egui::ScrollArea::both()
            .id_salt("diagnostic_rows")
            .stick_to_bottom(!self.paused)
            .auto_shrink([false, false])
            .show_rows(ui, height, entries.len(), |ui, range| {
                for row in range {
                    let entry = entries[row];
                    let tokens = Tokens::get(ui.ctx());
                    let color = match entry.level {
                        log::Level::Error => tokens.error,
                        log::Level::Warn => tokens.warn,
                        log::Level::Debug | log::Level::Trace => tokens.text_dim,
                        _ => tokens.text,
                    };
                    ui.horizontal(|ui| {
                        ui.add_sized(
                            [94., height],
                            egui::Label::new(
                                egui::RichText::new(
                                    entry
                                        .time
                                        .with_timezone(&chrono::Local)
                                        .format("%H:%M:%S%.3f")
                                        .to_string(),
                                )
                                .monospace()
                                .color(tokens.text_dim),
                            ),
                        );
                        ui.add_sized(
                            [42., height],
                            egui::Label::new(
                                egui::RichText::new(entry.level.to_string()).color(color),
                            ),
                        );
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(format!("{}  {}", entry.target, entry.message))
                                    .monospace(),
                            )
                            .truncate(),
                        )
                        .on_hover_text(entry.line());
                    });
                }
            });
    }
}

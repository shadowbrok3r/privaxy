//! Theme roles for text and controls, so keys, values, actions and states read apart.
use eframe::egui::{self, Color32, RichText, Stroke};
use egui_icon_pack::{Icon, widgets::IconSize};
use egui_theme_kit::Tokens;

/// Tertiary, or warn when tertiary shares the primary or secondary hue.
pub fn third(t: &Tokens) -> Color32 {
    let hue = |color: Color32| egui::ecolor::Hsva::from(color).h;
    let near = |a: Color32, b: Color32| {
        let distance = (hue(a) - hue(b)).abs();
        distance.min(1. - distance) < 0.06
    };
    if near(t.tertiary, t.primary) || near(t.tertiary, t.secondary) {
        t.warn
    } else {
        t.tertiary
    }
}

/// The color of an HTTP status: success, redirect, client error, server error or failure.
pub fn status(t: &Tokens, status: u16, failed: bool, blocked: bool) -> Color32 {
    if failed {
        return t.error;
    }
    if blocked {
        return t.warn;
    }
    match status {
        0 => t.text_dim,
        100..=299 => t.success,
        300..=399 => third(t),
        400..=499 => t.warn,
        _ => t.error,
    }
}

/// The color of a request method; tunnels and unusual methods stay dim.
pub fn method(t: &Tokens, method: &str) -> Color32 {
    match method {
        "GET" | "HEAD" => t.primary,
        "POST" => t.secondary,
        "PUT" | "PATCH" => third(t),
        "DELETE" => t.error,
        _ => t.text_dim,
    }
}

/// Icon-then-text button builder with the icon drawn in `color`.
pub fn action_widget(
    ui: &egui::Ui,
    icon: Icon,
    text: impl Into<egui::WidgetText>,
    color: Color32,
) -> egui::Button<'static> {
    egui::Button::new((icon.image(IconSize::Md.px(ui)).tint(color), text.into())).gap(5.)
}

/// Icon-then-text button with the icon drawn in `color`.
pub fn action(
    ui: &mut egui::Ui,
    icon: Icon,
    text: impl Into<egui::WidgetText>,
    color: Color32,
) -> egui::Response {
    let widget = action_widget(ui, icon, text, color);
    ui.add(widget)
}

/// A tab whose icon carries `color`; the selected tab is drawn in it over a wash.
pub fn tab(
    ui: &mut egui::Ui,
    icon: Icon,
    selected: bool,
    text: impl Into<String>,
    color: Color32,
) -> egui::Response {
    let t = Tokens::get(ui.ctx());
    let ink = if selected { color } else { t.text };
    let mut button = egui::Button::new((
        icon.image(IconSize::Md.px(ui)).tint(color),
        RichText::new(text).color(ink),
    ))
    .gap(5.);
    if selected {
        button = button
            .fill(color.gamma_multiply(0.16))
            .stroke(Stroke::new(1., color.gamma_multiply(0.75)));
    }
    ui.add(button)
}

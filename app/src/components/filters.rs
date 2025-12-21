use crate::use_privaxy_server;
use dioxus::prelude::*;
use privaxy::configuration::{Configuration, Filter};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum FilterGroup {
    Default,
    Regional,
    Ads,
    Privacy,
    Malware,
    Social,
}

impl FilterGroup {
    fn display_name(&self) -> &'static str {
        match self {
            FilterGroup::Default => "Default",
            FilterGroup::Regional => "Regional",
            FilterGroup::Ads => "Ads",
            FilterGroup::Privacy => "Privacy",
            FilterGroup::Malware => "Malware",
            FilterGroup::Social => "Social",
        }
    }

    fn description(&self) -> &'static str {
        match self {
            FilterGroup::Default => "Essential filters enabled by default",
            FilterGroup::Regional => "Language and region-specific filters",
            FilterGroup::Ads => "Block advertisements and trackers",
            FilterGroup::Privacy => "Enhance your privacy protection",
            FilterGroup::Malware => "Block malicious content and domains",
            FilterGroup::Social => "Block social media trackers and widgets",
        }
    }

    fn icon_color(&self) -> &'static str {
        match self {
            FilterGroup::Default => "text-cosmic-blue",
            FilterGroup::Regional => "text-comet-gold",
            FilterGroup::Ads => "text-nebula-pink",
            FilterGroup::Privacy => "text-aurora-purple",
            FilterGroup::Malware => "text-warning-red",
            FilterGroup::Social => "text-stellar-blue",
        }
    }
}

#[component]
pub fn Filters() -> Element {
    let mut filters = use_signal(Vec::<Filter>::new);
    let mut saved = use_signal(|| false);
    let mut has_changes = use_signal(|| false);
    let mut loading = use_signal(|| true);

    // Load current filters configuration
    use_effect(move || {
        spawn(async move {
            let http_client = reqwest::Client::new();
            if let Ok(config) = Configuration::read_from_home(http_client).await {
                filters.set(config.filters);
            }
            loading.set(false);
        });
    });

    let toggle_filter = move |file_name: String| {
        filters.write().iter_mut().for_each(|f| {
            if f.file_name == file_name {
                f.enabled = !f.enabled;
            }
        });
        has_changes.set(true);
        saved.set(false);
    };

    let save_filters = move |_| {
        let current_filters = filters.read().clone();
        spawn(async move {
            if let Some(server) = use_privaxy_server() {
                let server = server.read().await;
                let http_client = reqwest::Client::new();
                
                if let Ok(mut config) = Configuration::read_from_home(http_client.clone()).await {
                    let _guard = server.configuration_save_lock.lock().await;
                    
                    // Update each filter's enabled status
                    for filter in &current_filters {
                        let _ = config.set_filter_enabled_status(&filter.file_name, filter.enabled).await;
                    }
                    
                    if server.configuration_updater_sender.send(config).await.is_ok() {
                        saved.set(true);
                        has_changes.set(false);
                    }
                }
            }
        });
    };

    let groups = [
        FilterGroup::Default,
        FilterGroup::Ads,
        FilterGroup::Privacy,
        FilterGroup::Malware,
        FilterGroup::Social,
        FilterGroup::Regional,
    ];

    rsx! {
        div { class: "space-y-8",
            // Header
            div {
                h1 { class: "text-2xl font-bold text-star-white", "Filters" }
                p { class: "mt-2 text-stardust",
                    "Manage your filter lists to control what gets blocked"
                }
            }

            // Loading state
            if *loading.read() {
                div { class: "space-y-4",
                    for _ in 0..3 {
                        div { class: "card-cosmic p-6 animate-pulse",
                            div { class: "h-6 bg-nebula-purple/20 rounded w-1/4 mb-4" }
                            div { class: "space-y-3",
                                div { class: "h-4 bg-nebula-purple/10 rounded" }
                                div { class: "h-4 bg-nebula-purple/10 rounded" }
                            }
                        }
                    }
                }
            } else {
                // Success banner
                if *saved.read() {
                    div { class: "flex items-center gap-3 p-4 rounded-xl bg-alien-green/10 border border-alien-green/30",
                        svg {
                            class: "w-6 h-6 text-alien-green flex-shrink-0",
                            fill: "none",
                            stroke: "currentColor",
                            view_box: "0 0 24 24",
                            path {
                                stroke_linecap: "round",
                                stroke_linejoin: "round",
                                stroke_width: "2",
                                d: "M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                            }
                        }
                        span { class: "text-alien-green font-medium", "Changes saved successfully" }
                    }
                }

                // Save button
                button {
                    class: if *has_changes.read() { "btn-nebula flex items-center gap-2" } else { "btn-nebula flex items-center gap-2 opacity-50 cursor-not-allowed" },
                    disabled: !*has_changes.read(),
                    onclick: save_filters,
                    svg {
                        class: "w-5 h-5",
                        fill: "none",
                        stroke: "currentColor",
                        view_box: "0 0 24 24",
                        path {
                            stroke_linecap: "round",
                            stroke_linejoin: "round",
                            stroke_width: "2",
                            d: "M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"
                        }
                    }
                    "Save Changes"
                }

                // Filter groups
                for group in groups {
                    FilterGroupSection {
                        group,
                        filters: filters.read().iter().filter(|f| matches_group(f, group)).cloned().collect(),
                        on_toggle: toggle_filter
                    }
                }
            }
        }
    }
}

fn matches_group(filter: &Filter, group: FilterGroup) -> bool {
    let group_str = format!("{:?}", filter.group);
    let target_str = format!("{:?}", group);
    group_str == target_str
}

#[component]
fn FilterGroupSection(
    group: FilterGroup,
    filters: Vec<Filter>,
    on_toggle: EventHandler<String>,
) -> Element {
    if filters.is_empty() {
        return rsx! {};
    }

    rsx! {
        div { class: "card-cosmic overflow-hidden",
            // Group header
            div { class: "px-6 py-4 border-b border-nebula-purple/20",
                div { class: "flex items-center gap-3",
                    span { class: "{group.icon_color()}",
                        GroupIcon { group }
                    }
                    div {
                        h3 { class: "text-lg font-semibold text-star-white",
                            "{group.display_name()}"
                        }
                        p { class: "text-sm text-stardust",
                            "{group.description()}"
                        }
                    }
                }
            }

            // Filters list
            div { class: "divide-y divide-nebula-purple/10",
                for filter in filters {
                    FilterItem {
                        filter: filter.clone(),
                        on_toggle: on_toggle
                    }
                }
            }
        }
    }
}

#[component]
fn GroupIcon(group: FilterGroup) -> Element {
    match group {
        FilterGroup::Default => rsx! {
            svg {
                class: "w-6 h-6",
                fill: "none",
                stroke: "currentColor",
                view_box: "0 0 24 24",
                path {
                    stroke_linecap: "round",
                    stroke_linejoin: "round",
                    stroke_width: "2",
                    d: "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                }
            }
        },
        FilterGroup::Ads => rsx! {
            svg {
                class: "w-6 h-6",
                fill: "none",
                stroke: "currentColor",
                view_box: "0 0 24 24",
                path {
                    stroke_linecap: "round",
                    stroke_linejoin: "round",
                    stroke_width: "2",
                    d: "M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"
                }
            }
        },
        FilterGroup::Privacy => rsx! {
            svg {
                class: "w-6 h-6",
                fill: "none",
                stroke: "currentColor",
                view_box: "0 0 24 24",
                path {
                    stroke_linecap: "round",
                    stroke_linejoin: "round",
                    stroke_width: "2",
                    d: "M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                }
                path {
                    stroke_linecap: "round",
                    stroke_linejoin: "round",
                    stroke_width: "2",
                    d: "M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"
                }
            }
        },
        FilterGroup::Malware => rsx! {
            svg {
                class: "w-6 h-6",
                fill: "none",
                stroke: "currentColor",
                view_box: "0 0 24 24",
                path {
                    stroke_linecap: "round",
                    stroke_linejoin: "round",
                    stroke_width: "2",
                    d: "M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                }
            }
        },
        FilterGroup::Social => rsx! {
            svg {
                class: "w-6 h-6",
                fill: "none",
                stroke: "currentColor",
                view_box: "0 0 24 24",
                path {
                    stroke_linecap: "round",
                    stroke_linejoin: "round",
                    stroke_width: "2",
                    d: "M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"
                }
            }
        },
        FilterGroup::Regional => rsx! {
            svg {
                class: "w-6 h-6",
                fill: "none",
                stroke: "currentColor",
                view_box: "0 0 24 24",
                path {
                    stroke_linecap: "round",
                    stroke_linejoin: "round",
                    stroke_width: "2",
                    d: "M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                }
            }
        },
    }
}

#[component]
fn FilterItem(filter: Filter, on_toggle: EventHandler<String>) -> Element {
    let file_name = filter.file_name.clone();

    rsx! {
        div { class: "flex items-center justify-between px-6 py-4 hover:bg-nebula-purple/5 transition-colors",
            div { class: "flex-1 min-w-0",
                label {
                    class: "text-moonlight select-none cursor-pointer",
                    r#for: "{filter.file_name}",
                    "{filter.title}"
                }
            }
            label { class: "toggle-cosmic",
                input {
                    r#type: "checkbox",
                    id: "{filter.file_name}",
                    checked: filter.enabled,
                    onchange: move |_| on_toggle.call(file_name.clone())
                }
                span { class: "toggle-slider" }
            }
        }
    }
}

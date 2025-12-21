use crate::use_privaxy_server;
use dioxus::prelude::*;
use privaxy::configuration::Configuration;

use crate::Route;

#[component]
pub fn Settings() -> Element {
    let route: Route = use_route();

    let is_filters = matches!(route, Route::Filters {});
    let is_exclusions = matches!(route, Route::Exclusions {});
    let is_custom_filters = matches!(route, Route::CustomFilters {});

    rsx! {
        div { class: "flex flex-col md:flex-row gap-8",
            // Sidebar
            aside { class: "md:w-64 flex-shrink-0",
                nav { class: "settings-sidebar",
                    Link {
                        to: Route::Filters {},
                        class: if is_filters { "settings-link active" } else { "settings-link" },
                        div { class: "flex items-center gap-3",
                            svg {
                                class: "w-5 h-5",
                                fill: "none",
                                stroke: "currentColor",
                                view_box: "0 0 24 24",
                                path {
                                    stroke_linecap: "round",
                                    stroke_linejoin: "round",
                                    stroke_width: "2",
                                    d: "M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z"
                                }
                            }
                            "Filters"
                        }
                    }
                    Link {
                        to: Route::Exclusions {},
                        class: if is_exclusions { "settings-link active" } else { "settings-link" },
                        div { class: "flex items-center gap-3",
                            svg {
                                class: "w-5 h-5",
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
                            "Exclusions"
                        }
                    }
                    Link {
                        to: Route::CustomFilters {},
                        class: if is_custom_filters { "settings-link active" } else { "settings-link" },
                        div { class: "flex items-center gap-3",
                            svg {
                                class: "w-5 h-5",
                                fill: "none",
                                stroke: "currentColor",
                                view_box: "0 0 24 24",
                                path {
                                    stroke_linecap: "round",
                                    stroke_linejoin: "round",
                                    stroke_width: "2",
                                    d: "M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"
                                }
                            }
                            "Custom Filters"
                        }
                    }
                }
            }

            // Content
            div { class: "flex-1",
                Outlet::<Route> {}
            }
        }
    }
}

#[component]
pub fn Exclusions() -> Element {
    let mut exclusions = use_signal(String::new);
    let mut saved = use_signal(|| false);
    let mut has_changes = use_signal(|| false);
    let mut loading = use_signal(|| true);

    // Load current exclusions
    use_effect(move || {
        spawn(async move {
            let http_client = reqwest::Client::new();
            if let Ok(config) = Configuration::read_from_home(http_client).await {
                let exclusions_text = config.exclusions.into_iter().collect::<Vec<_>>().join("\n");
                exclusions.set(exclusions_text);
            }
            loading.set(false);
        });
    });

    let save_exclusions = move |_| {
        let exclusions_text = exclusions.read().clone();
        spawn(async move {
            if let Some(server) = use_privaxy_server() {
                let server = server.read().await;
                let http_client = reqwest::Client::new();
                
                if let Ok(mut config) = Configuration::read_from_home(http_client.clone()).await {
                    let _guard = server.configuration_save_lock.lock().await;
                    
                    if config.set_exclusions(&exclusions_text, server.local_exclusion_store.clone()).await.is_ok() {
                        if server.configuration_updater_sender.send(config).await.is_ok() {
                            saved.set(true);
                            has_changes.set(false);
                        }
                    }
                }
            }
        });
    };

    rsx! {
        div { class: "space-y-6",
            // Header
            div {
                h1 { class: "text-2xl font-bold text-star-white", "Exclusions" }
                p { class: "mt-2 text-stardust",
                    "Exclusions are hosts or domains that are not passed through the MITM pipeline. "
                    "Excluded entries will be transparently tunneled."
                }
            }

            // Pattern help
            div { class: "card-cosmic p-4 text-sm text-moonlight space-y-1",
                p {
                    span { class: "inline-block px-2 py-0.5 rounded bg-nebula-purple/20 text-aurora-purple font-mono mr-2",
                        "?"
                    }
                    "matches exactly one occurrence of any character."
                }
                p {
                    span { class: "inline-block px-2 py-0.5 rounded bg-nebula-purple/20 text-aurora-purple font-mono mr-2",
                        "*"
                    }
                    "matches arbitrary many (including zero) occurrences of any character."
                }
            }

            // Success banner
            if *saved.read() {
                SuccessBanner { message: "Changes saved successfully" }
            }

            // Save button
            button {
                class: if *has_changes.read() { "btn-nebula flex items-center gap-2" } else { "btn-nebula flex items-center gap-2 opacity-50 cursor-not-allowed" },
                disabled: !*has_changes.read(),
                onclick: save_exclusions,
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

            // Textarea
            div {
                label { class: "block text-sm font-medium text-moonlight mb-2",
                    "Insert one entry per line"
                }
                if *loading.read() {
                    div { class: "w-full h-64 bg-nebula-purple/10 rounded-xl animate-pulse" }
                } else {
                    textarea {
                        class: "w-full h-64",
                        placeholder: "example.com\n*.google.com\napi.*.service.com",
                        value: "{exclusions}",
                        oninput: move |e| {
                            exclusions.set(e.value());
                            has_changes.set(true);
                            saved.set(false);
                        }
                    }
                }
            }
        }
    }
}

#[component]
pub fn CustomFilters() -> Element {
    let mut custom_filters = use_signal(String::new);
    let mut saved = use_signal(|| false);
    let mut has_changes = use_signal(|| false);
    let mut loading = use_signal(|| true);

    // Load current custom filters
    use_effect(move || {
        spawn(async move {
            let http_client = reqwest::Client::new();
            if let Ok(config) = Configuration::read_from_home(http_client).await {
                let filters_text = config.custom_filters.join("\n");
                custom_filters.set(filters_text);
            }
            loading.set(false);
        });
    });

    let save_filters = move |_| {
        let filters_text = custom_filters.read().clone();
        spawn(async move {
            if let Some(server) = use_privaxy_server() {
                let server = server.read().await;
                let http_client = reqwest::Client::new();
                
                if let Ok(mut config) = Configuration::read_from_home(http_client.clone()).await {
                    let _guard = server.configuration_save_lock.lock().await;
                    
                    if config.set_custom_filters(&filters_text).await.is_ok() {
                        if server.configuration_updater_sender.send(config).await.is_ok() {
                            saved.set(true);
                            has_changes.set(false);
                        }
                    }
                }
            }
        });
    };

    rsx! {
        div { class: "space-y-6",
            // Header
            div {
                h1 { class: "text-2xl font-bold text-star-white", "Custom Filters" }
                p { class: "mt-2 text-stardust",
                    "Insert EasyList compatible filters. Comment filters by prefixing lines with "
                    span { class: "font-mono px-1.5 py-0.5 rounded bg-nebula-purple/20 text-aurora-purple",
                        "!"
                    }
                    "."
                }
            }

            // Success banner
            if *saved.read() {
                SuccessBanner { message: "Changes saved successfully" }
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

            // Textarea
            div {
                label { class: "block text-sm font-medium text-moonlight mb-2",
                    "Insert one filter per line"
                }
                if *loading.read() {
                    div { class: "w-full h-64 bg-nebula-purple/10 rounded-xl animate-pulse" }
                } else {
                    textarea {
                        class: "w-full h-64",
                        placeholder: "! This is a comment\n||ads.example.com^\n@@||allowed.example.com^",
                        value: "{custom_filters}",
                        oninput: move |e| {
                            custom_filters.set(e.value());
                            has_changes.set(true);
                            saved.set(false);
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn SuccessBanner(message: &'static str) -> Element {
    rsx! {
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
            span { class: "text-alien-green font-medium", "{message}" }
        }
    }
}

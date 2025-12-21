use crate::use_privaxy_server;
use dioxus::prelude::*;
use num_format::{Locale, ToFormattedString};
use privaxy::statistics::SerializableStatistics;

#[component]
pub fn Dashboard() -> Element {
    let mut stats = use_signal(|| SerializableStatistics {
        proxied_requests: 0,
        blocked_requests: 0,
        modified_responses: 0,
        top_blocked_paths: Vec::new(),
        top_clients: Vec::new(),
    });

    let mut blocking_enabled = use_signal(|| true);

    // Poll statistics from the privaxy server
    use_effect(move || {
        spawn(async move {
            loop {
                if let Some(server) = use_privaxy_server() {
                    let server = server.read().await;
                    let new_stats = server.statistics.get_serialized();
                    stats.set(new_stats);

                    let enabled = server.blocking_disabled_store.is_enabled();
                    blocking_enabled.set(enabled);
                }
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        });
    });

    let toggle_blocking = move |_| {
        spawn(async move {
            if let Some(server) = use_privaxy_server() {
                let server = server.read().await;
                let current = server.blocking_disabled_store.is_enabled();
                server.blocking_disabled_store.set(!current);
                blocking_enabled.set(!current);
            }
        });
    };

    let save_ca_certificate = move |_| {
        spawn(async move {
            if let Some(server) = use_privaxy_server() {
                let server = server.read().await;
                let pem = server.ca_certificate_pem.clone();
                
                // Use rfd for file dialog
                if let Some(path) = rfd::AsyncFileDialog::new()
                    .set_file_name("privaxy_ca_cert.pem")
                    .add_filter("PEM Certificate", &["pem"])
                    .save_file()
                    .await
                {
                    if let Err(e) = tokio::fs::write(path.path(), &pem).await {
                        log::error!("Failed to save CA certificate: {}", e);
                    } else {
                        log::info!("CA certificate saved successfully");
                    }
                }
            }
        });
    };

    let current_stats = stats.read();

    rsx! {
        div { class: "space-y-8",
            // Header
            div { class: "flex flex-col md:flex-row md:items-center md:justify-between gap-4",
                div {
                    h1 { class: "text-3xl font-bold text-star-white flex items-center gap-3",
                        "Dashboard"
                        span { class: "live-indicator",
                            span { class: "live-dot" }
                            span { class: "text-sm text-alien-green font-medium", "Live" }
                        }
                    }
                    p { class: "mt-2 text-stardust",
                        "Monitor your proxy statistics in real-time"
                    }
                }

                // Action buttons
                div { class: "flex items-center gap-3",
                    // Save CA Certificate button
                    button {
                        class: "btn-cosmic flex items-center gap-2",
                        onclick: save_ca_certificate,
                        svg {
                            class: "w-5 h-5",
                            fill: "none",
                            stroke: "currentColor",
                            view_box: "0 0 24 24",
                            path {
                                stroke_linecap: "round",
                                stroke_linejoin: "round",
                                stroke_width: "2",
                                d: "M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
                            }
                        }
                        "Save CA Certificate"
                    }

                    // Blocking toggle button
                    if *blocking_enabled.read() {
                        button {
                            class: "btn-danger flex items-center gap-2",
                            onclick: toggle_blocking,
                            svg {
                                class: "w-5 h-5",
                                fill: "none",
                                stroke: "currentColor",
                                view_box: "0 0 24 24",
                                path {
                                    stroke_linecap: "round",
                                    stroke_linejoin: "round",
                                    stroke_width: "2",
                                    d: "M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z"
                                }
                            }
                            "Pause Blocking"
                        }
                    } else {
                        button {
                            class: "btn-success flex items-center gap-2",
                            onclick: toggle_blocking,
                            svg {
                                class: "w-5 h-5",
                                fill: "none",
                                stroke: "currentColor",
                                view_box: "0 0 24 24",
                                path {
                                    stroke_linecap: "round",
                                    stroke_linejoin: "round",
                                    stroke_width: "2",
                                    d: "M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"
                                }
                                path {
                                    stroke_linecap: "round",
                                    stroke_linejoin: "round",
                                    stroke_width: "2",
                                    d: "M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                                }
                            }
                            "Resume Blocking"
                        }
                    }
                }
            }

            // Stats Grid
            div { class: "stats-grid",
                StatCard {
                    label: "Proxied Requests",
                    value: current_stats.proxied_requests,
                    icon: rsx! {
                        svg {
                            class: "w-8 h-8",
                            fill: "none",
                            stroke: "currentColor",
                            view_box: "0 0 24 24",
                            path {
                                stroke_linecap: "round",
                                stroke_linejoin: "round",
                                stroke_width: "2",
                                d: "M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"
                            }
                        }
                    }
                }
                StatCard {
                    label: "Blocked Requests",
                    value: current_stats.blocked_requests,
                    icon: rsx! {
                        svg {
                            class: "w-8 h-8",
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
                    }
                }
                StatCard {
                    label: "Modified Responses",
                    value: current_stats.modified_responses,
                    icon: rsx! {
                        svg {
                            class: "w-8 h-8",
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
                    }
                }
            }

            // Top Lists Grid
            div { class: "grid md:grid-cols-2 gap-6",
                // Top Blocked Paths
                div { class: "card-cosmic p-6",
                    h3 { class: "text-lg font-semibold text-star-white mb-4 flex items-center gap-2",
                        svg {
                            class: "w-5 h-5 text-nebula-pink",
                            fill: "none",
                            stroke: "currentColor",
                            view_box: "0 0 24 24",
                            path {
                                stroke_linecap: "round",
                                stroke_linejoin: "round",
                                stroke_width: "2",
                                d: "M13 7h8m0 0v8m0-8l-8 8-4-4-6 6"
                            }
                        }
                        "Top Blocked Paths"
                    }
                    if current_stats.top_blocked_paths.is_empty() {
                        p { class: "text-stardust text-center py-8",
                            "No blocked paths yet"
                        }
                    } else {
                        ul { class: "list-cosmic",
                            for (path, count) in current_stats.top_blocked_paths.iter().take(10) {
                                li { key: "{path}",
                                    span { class: "truncate text-moonlight", "{path}" }
                                    span { class: "text-aurora-purple font-semibold",
                                        "{count.to_formatted_string(&Locale::en)}"
                                    }
                                }
                            }
                        }
                    }
                }

                // Top Clients
                div { class: "card-cosmic p-6",
                    h3 { class: "text-lg font-semibold text-star-white mb-4 flex items-center gap-2",
                        svg {
                            class: "w-5 h-5 text-cosmic-blue",
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
                        "Top Clients"
                    }
                    if current_stats.top_clients.is_empty() {
                        p { class: "text-stardust text-center py-8",
                            "No client data yet"
                        }
                    } else {
                        ul { class: "list-cosmic",
                            for (client, count) in current_stats.top_clients.iter().take(10) {
                                li { key: "{client}",
                                    span { class: "truncate text-moonlight", "{client}" }
                                    span { class: "text-cosmic-blue font-semibold",
                                        "{count.to_formatted_string(&Locale::en)}"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn StatCard(label: &'static str, value: u64, icon: Element) -> Element {
    let formatted_value = value.to_formatted_string(&Locale::en);

    rsx! {
        div { class: "card-stat",
            div { class: "flex items-start justify-between",
                div {
                    p { class: "stat-value", "{formatted_value}" }
                    p { class: "stat-label", "{label}" }
                }
                div { class: "text-aurora-purple opacity-60",
                    {icon}
                }
            }
        }
    }
}

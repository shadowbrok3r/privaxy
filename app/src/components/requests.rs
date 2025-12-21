use crate::use_privaxy_server;
use dioxus::prelude::*;
use privaxy::events::Event;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_REQUESTS_SHOWN: usize = 500;

// Global signal to persist requests across navigation
static REQUESTS: GlobalSignal<Vec<RequestEvent>> = Signal::global(Vec::new);
// Track if we've already started the listener
static LISTENER_STARTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone)]
pub struct RequestEvent {
    pub now: String,
    pub method: String,
    pub url: String,
    pub is_request_blocked: bool,
}

impl From<Event> for RequestEvent {
    fn from(event: Event) -> Self {
        Self {
            now: event.now.format("%H:%M:%S%.3f").to_string(),
            method: event.method,
            url: event.url,
            is_request_blocked: event.is_request_blocked,
        }
    }
}

// Start the global event listener (call this from main layout)
pub fn start_request_listener() {
    // Only start once
    if LISTENER_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }

    spawn(async move {
        // Wait for server to be available
        loop {
            if let Some(server) = use_privaxy_server() {
                let server = server.read().await;
                let mut receiver = server.requests_broadcast_sender.subscribe();
                drop(server);

                while let Ok(event) = receiver.recv().await {
                    let request_event: RequestEvent = event.into();
                    REQUESTS.write().insert(0, request_event);
                    REQUESTS.write().truncate(MAX_REQUESTS_SHOWN);
                }
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    });
}

#[component]
pub fn Requests() -> Element {
    rsx! {
        div { class: "space-y-6",
            // Header
            div {
                h1 { class: "text-3xl font-bold text-star-white flex items-center gap-3",
                    "Requests Feed"
                    span { class: "live-indicator",
                        span { class: "live-dot" }
                        span { class: "text-sm text-alien-green font-medium", "Live" }
                    }
                }
                p { class: "mt-2 text-stardust",
                    "Real-time view of proxied requests"
                }
            }

            // Requests Table
            div { class: "card-cosmic overflow-hidden",
                div { class: "overflow-x-auto",
                    table { class: "table-cosmic",
                        thead {
                            tr {
                                th { "Timestamp" }
                                th { "Method" }
                                th { "URL" }
                                th { "Status" }
                            }
                        }
                        tbody {
                            if REQUESTS.read().is_empty() {
                                tr {
                                    td {
                                        colspan: "4",
                                        class: "text-center py-12",
                                        div { class: "flex flex-col items-center gap-4",
                                            svg {
                                                class: "w-16 h-16 text-stardust opacity-50",
                                                fill: "none",
                                                stroke: "currentColor",
                                                view_box: "0 0 24 24",
                                                path {
                                                    stroke_linecap: "round",
                                                    stroke_linejoin: "round",
                                                    stroke_width: "1.5",
                                                    d: "M13 10V3L4 14h7v7l9-11h-7z"
                                                }
                                            }
                                            p { class: "text-stardust",
                                                "Waiting for requests..."
                                            }
                                            p { class: "text-sm text-stardust opacity-60",
                                                "Configure your browser to use http://127.0.0.1:8100 as proxy"
                                            }
                                        }
                                    }
                                }
                            } else {
                                for (idx, request) in REQUESTS.read().iter().enumerate().take(MAX_REQUESTS_SHOWN) {
                                    tr {
                                        key: "{idx}",
                                        class: if request.is_request_blocked { "blocked" } else { "" },
                                        td { class: "text-sm font-mono text-stardust whitespace-nowrap",
                                            "{request.now}"
                                        }
                                        td {
                                            span { class: "badge badge-method",
                                                "{request.method}"
                                            }
                                        }
                                        td { class: "max-w-md truncate text-moonlight",
                                            "{request.url}"
                                        }
                                        td {
                                            if request.is_request_blocked {
                                                span { class: "badge badge-blocked",
                                                    "Blocked"
                                                }
                                            } else {
                                                span { class: "badge badge-success",
                                                    "Passed"
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

            // Info footer
            if !REQUESTS.read().is_empty() {
                div { class: "text-center text-sm text-stardust",
                    "Showing up to {MAX_REQUESTS_SHOWN} most recent requests"
                }
            }
        }
    }
}

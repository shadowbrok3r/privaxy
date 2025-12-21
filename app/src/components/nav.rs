use crate::Route;
use dioxus::prelude::*;

#[component]
pub fn Navigation() -> Element {
    let route: Route = use_route();

    let is_dashboard = matches!(route, Route::Dashboard {});
    let is_requests = matches!(route, Route::Requests {});
    let is_settings = matches!(
        route,
        Route::Filters {} | Route::Exclusions {} | Route::CustomFilters {}
    );

    rsx! {
        nav { class: "nav-cosmic sticky top-0 z-50 backdrop-blur-xl border-b border-nebula-purple/20",
            div { class: "max-w-7xl mx-auto px-4 sm:px-6 lg:px-8",
                div { class: "flex items-center justify-between h-16",
                    // Logo
                    Link {
                        to: Route::Dashboard {},
                        class: "flex items-center space-x-3 group",
                        div { class: "logo-glow",
                            svg {
                                class: "w-9 h-9",
                                fill: "none",
                                stroke: "url(#logo-gradient)",
                                stroke_width: "1.5",
                                view_box: "0 0 24 24",
                                defs {
                                    linearGradient {
                                        id: "logo-gradient",
                                        x1: "0%",
                                        y1: "0%",
                                        x2: "100%",
                                        y2: "100%",
                                        stop { offset: "0%", stop_color: "#a855f7" }
                                        stop { offset: "50%", stop_color: "#ec4899" }
                                        stop { offset: "100%", stop_color: "#3b82f6" }
                                    }
                                }
                                path {
                                    stroke_linecap: "round",
                                    stroke_linejoin: "round",
                                    d: "M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z"
                                }
                            }
                        }
                        span { class: "text-xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-nebula-purple via-nebula-pink to-cosmic-blue group-hover:opacity-80 transition-opacity",
                            "Privaxy"
                        }
                    }

                    // Navigation links
                    div { class: "flex items-center space-x-1",
                        Link {
                            to: Route::Dashboard {},
                            class: if is_dashboard { "nav-link active" } else { "nav-link" },
                            svg {
                                class: "w-5 h-5",
                                fill: "none",
                                stroke: "currentColor",
                                view_box: "0 0 24 24",
                                path {
                                    stroke_linecap: "round",
                                    stroke_linejoin: "round",
                                    stroke_width: "2",
                                    d: "M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"
                                }
                            }
                            "Dashboard"
                        }
                        Link {
                            to: Route::Requests {},
                            class: if is_requests { "nav-link active" } else { "nav-link" },
                            svg {
                                class: "w-5 h-5",
                                fill: "none",
                                stroke: "currentColor",
                                view_box: "0 0 24 24",
                                path {
                                    stroke_linecap: "round",
                                    stroke_linejoin: "round",
                                    stroke_width: "2",
                                    d: "M13 10V3L4 14h7v7l9-11h-7z"
                                }
                            }
                            "Requests"
                        }
                        Link {
                            to: Route::Filters {},
                            class: if is_settings { "nav-link active" } else { "nav-link" },
                            svg {
                                class: "w-5 h-5",
                                fill: "none",
                                stroke: "currentColor",
                                view_box: "0 0 24 24",
                                path {
                                    stroke_linecap: "round",
                                    stroke_linejoin: "round",
                                    stroke_width: "2",
                                    d: "M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
                                }
                                path {
                                    stroke_linecap: "round",
                                    stroke_linejoin: "round",
                                    stroke_width: "2",
                                    d: "M15 12a3 3 0 11-6 0 3 3 0 016 0z"
                                }
                            }
                            "Settings"
                        }
                    }
                }
            }
        }
    }
}

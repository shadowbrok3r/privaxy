use chrono::{DateTime, Utc};
use serde::Serialize;

#[derive(Debug, Serialize, Clone)]
pub struct Event {
    pub id: u64,
    pub now: DateTime<Utc>,
    pub method: String,
    pub url: String,
    pub is_request_blocked: bool,
    #[serde(skip)]
    pub exchange: std::sync::Arc<std::sync::Mutex<crate::capture::Exchange>>,
}

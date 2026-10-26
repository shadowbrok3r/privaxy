//! Bounded session metadata and disk-backed request/response bodies.
use crate::{
    events::Event,
    storage::{Body, BodyStore, CAPTURE_BUDGET},
};
use chrono::{DateTime, Utc};
use std::{
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

pub const MAX_REQUESTS: usize = 5_000;
pub type Headers = Vec<(String, String)>;

pub fn header_pairs(headers: &http::HeaderMap) -> Headers {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct Exchange {
    pub request_headers: Headers,
    pub response_headers: Headers,
    pub request_trailers: Headers,
    pub response_trailers: Headers,
    pub request_version: http::Version,
    pub request_complete: bool,
    pub response_version: Option<http::Version>,
    pub status: Option<u16>,
    pub client: IpAddr,
    /// The Android app a paired phone attributed the connection to.
    pub app: Option<String>,
    /// That app's package name, when the phone sent it.
    pub app_package: Option<String>,
    pub request_body: Body,
    pub response_body: Body,
    pub response_started_ms: Option<u64>,
    pub duration_ms: Option<u64>,
    pub finished_at: Option<DateTime<Utc>>,
    pub note: Option<String>,
    pub error: Option<String>,
    pub(crate) started: Instant,
}

impl Default for Exchange {
    fn default() -> Self {
        Self {
            request_headers: vec![],
            response_headers: vec![],
            request_trailers: vec![],
            response_trailers: vec![],
            request_version: http::Version::HTTP_11,
            request_complete: false,
            response_version: None,
            status: None,
            client: std::net::Ipv4Addr::LOCALHOST.into(),
            app: None,
            app_package: None,
            request_body: Body::default(),
            response_body: Body::default(),
            response_started_ms: None,
            duration_ms: None,
            finished_at: None,
            note: None,
            error: None,
            started: Instant::now(),
        }
    }
}

impl Exchange {
    pub fn response(&mut self, status: u16, version: http::Version, headers: &http::HeaderMap) {
        self.status = Some(status);
        self.response_version = Some(version);
        self.response_headers = header_pairs(headers);
        self.response_started_ms
            .get_or_insert(self.started.elapsed().as_millis() as u64);
    }
    pub fn finish(&mut self) {
        if self.finished_at.is_none() {
            self.finished_at = Some(Utc::now());
            self.duration_ms = Some(self.started.elapsed().as_millis() as u64);
        }
    }
    pub fn fail(&mut self, message: impl Into<String>) {
        self.error.get_or_insert(message.into());
        self.finish();
    }
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        let storage = BodyStore::temporary(CAPTURE_BUDGET);
        Self {
            request_body: storage.body(),
            response_body: storage.body(),
            ..Self::default()
        }
    }
}

#[derive(Clone, Debug)]
pub struct CaptureStore(Arc<Store>);
#[derive(Debug)]
struct Store {
    session: Mutex<Session>,
    next_id: AtomicU64,
}
#[derive(Debug)]
struct Session {
    storage: BodyStore,
    events: Vec<Event>,
}

impl CaptureStore {
    pub fn new(root: &std::path::Path) -> std::io::Result<Self> {
        Ok(Self(Arc::new(Store {
            session: Mutex::new(Session {
                storage: BodyStore::new(root, CAPTURE_BUDGET)?,
                events: vec![],
            }),
            next_id: AtomicU64::new(1),
        })))
    }

    pub fn begin(
        &self,
        method: String,
        url: String,
        blocked: bool,
        mut exchange: Exchange,
    ) -> Event {
        let mut session = self.0.session.lock().unwrap();
        let retain = session.events.len() < MAX_REQUESTS;
        if retain && session.storage.problem().is_none() {
            exchange.request_body = session.storage.body();
            exchange.response_body = session.storage.body();
        } else {
            exchange.note = Some("Capture limit reached. Clear the session to record more bodies; proxy traffic continues.".into());
        }
        let event = Event {
            id: self.0.next_id.fetch_add(1, Ordering::Relaxed),
            now: Utc::now(),
            method,
            url,
            is_request_blocked: blocked,
            exchange: Arc::new(Mutex::new(exchange)),
        };
        if retain {
            session.events.push(event.clone());
        }
        event
    }

    pub fn events(&self) -> Vec<Event> {
        self.0.session.lock().unwrap().events.clone()
    }
    pub fn used(&self) -> u64 {
        self.0.session.lock().unwrap().storage.used()
    }
    pub fn problem(&self) -> Option<String> {
        let session = self.0.session.lock().unwrap();
        if session.events.len() >= MAX_REQUESTS {
            Some(format!(
                "Capture contains {MAX_REQUESTS} sessions. Clear the session to resume recording."
            ))
        } else {
            session.storage.problem()
        }
    }
    pub fn clear(&self) -> std::io::Result<()> {
        let mut session = self.0.session.lock().unwrap();
        session.storage = session.storage.reset()?;
        session.events.clear();
        Ok(())
    }
}

/// Records cancellation while upstream headers are still pending. Once the response is
/// returned, CaptureBody owns completion and cancellation tracking instead.
pub(crate) struct PendingResponse(pub Option<Arc<Mutex<Exchange>>>);
impl PendingResponse {
    pub fn disarm(&mut self) {
        self.0 = None;
    }
}
impl Drop for PendingResponse {
    fn drop(&mut self) {
        if let Some(exchange) = &self.0 {
            exchange
                .lock()
                .unwrap()
                .fail("Request cancelled before its response completed");
        }
    }
}

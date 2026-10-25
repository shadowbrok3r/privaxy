//! Search complete captured body prefixes off the UI thread, with bounded memory.
use privaxy::storage::BodySnapshot;
use std::{
    collections::HashMap,
    io::{self, Read},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
};

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct Key(u64, u64, u64);
type ResultEntry = (Key, Result<bool, String>);

#[derive(Default)]
pub(super) struct BodySearch {
    query: String,
    generation: Arc<AtomicU64>,
    receiver: Option<mpsc::Receiver<ResultEntry>>,
    results: HashMap<Key, Result<bool, String>>,
}

impl BodySearch {
    /// Returns true when a filter needs re-evaluating, including when stale results are cleared.
    pub fn update(
        &mut self,
        query: &str,
        bodies: impl Iterator<Item = (u64, [BodySnapshot; 2])>,
        ctx: &eframe::egui::Context,
    ) -> bool {
        let mut changed = false;
        if self.query != query {
            self.generation.fetch_add(1, Ordering::Relaxed);
            self.receiver = None;
            self.results.clear();
            self.query = query.to_owned();
            changed = true;
        }
        if query.is_empty() {
            return changed;
        }
        if let Some(rx) = &self.receiver {
            loop {
                match rx.try_recv() {
                    Ok((key, result)) => {
                        self.results.insert(key, result);
                        changed = true;
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.receiver = None;
                        break;
                    }
                }
            }
        }
        if self.receiver.is_none() {
            let bodies: Vec<_> = bodies
                .map(|(id, b)| (Key(id, b[0].len, b[1].len), b))
                .collect();
            let live: std::collections::HashSet<_> = bodies.iter().map(|(key, _)| *key).collect();
            self.results.retain(|key, _| live.contains(key));
            let pending: Vec<_> = bodies
                .into_iter()
                .filter(|(key, _)| !self.results.contains_key(key))
                .collect();
            if !pending.is_empty() {
                let generation = self.generation.clone();
                let ticket = generation.load(Ordering::Relaxed);
                let needle = query.to_owned();
                let (tx, rx) = mpsc::channel();
                self.receiver = Some(rx);
                let ctx = ctx.clone();
                std::thread::spawn(move || {
                    let cancelled = || generation.load(Ordering::Relaxed) != ticket;
                    for (key, bodies) in pending {
                        if cancelled() {
                            break;
                        }
                        let mut result = Ok(false);
                        for body in bodies {
                            match body.reader().and_then(|r| contains(r, &needle, &cancelled)) {
                                Ok(true) => {
                                    result = Ok(true);
                                    break;
                                }
                                Err(e) => result = Err(e.to_string()),
                                Ok(false) => {}
                            }
                        }
                        if cancelled() || tx.send((key, result)).is_err() {
                            break;
                        }
                        ctx.request_repaint();
                    }
                });
            }
        }
        changed
    }

    pub fn matches(&self, id: u64, bodies: &[BodySnapshot; 2]) -> bool {
        matches!(
            self.results.get(&Key(id, bodies[0].len, bodies[1].len)),
            Some(Ok(true))
        )
    }
    pub fn searching(&self) -> bool {
        self.receiver.is_some()
    }
    pub fn errors(&self) -> usize {
        self.results.values().filter(|r| r.is_err()).count()
    }
}

impl Drop for BodySearch {
    fn drop(&mut self) {
        self.generation.fetch_add(1, Ordering::Relaxed);
    }
}

fn contains(
    mut reader: impl Read,
    needle: &str,
    cancelled: &impl Fn() -> bool,
) -> io::Result<bool> {
    if needle.is_empty() {
        return Ok(true);
    }
    let mut block = [0; 64 * 1024];
    let mut overlap = Vec::new();
    loop {
        if cancelled() {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "Search changed"));
        }
        let count = reader.read(&mut block)?;
        if count == 0 {
            return Ok(false);
        }
        overlap.extend_from_slice(&block[..count]);
        if String::from_utf8_lossy(&overlap)
            .to_lowercase()
            .contains(needle)
        {
            return Ok(true);
        }
        // Preserve both the query and a UTF-8 character straddling the read boundary.
        let keep = needle.len().saturating_mul(3).saturating_add(4);
        if overlap.len() > keep {
            overlap.drain(..overlap.len() - keep);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn new_query_discards_old_results_and_growing_bodies_are_searched() {
        let store = privaxy::storage::BodyStore::new(&std::env::temp_dir(), 4096).unwrap();
        let body = store.body();
        body.push(b"first marker");
        let mut search = BodySearch::default();
        let ctx = eframe::egui::Context::default();
        let run = |search: &mut BodySearch, query: &str| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            loop {
                search.update(
                    query,
                    [(
                        1,
                        [
                            body.snapshot(),
                            privaxy::storage::Body::default().snapshot(),
                        ],
                    )]
                    .into_iter(),
                    &ctx,
                );
                if !search.searching() {
                    break;
                }
                assert!(std::time::Instant::now() < deadline, "search timed out");
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        };
        run(&mut search, "marker");
        assert!(search.matches(
            1,
            &[
                body.snapshot(),
                privaxy::storage::Body::default().snapshot()
            ]
        ));
        run(&mut search, "later");
        assert!(!search.matches(
            1,
            &[
                body.snapshot(),
                privaxy::storage::Body::default().snapshot()
            ]
        ));
        body.push(b" later");
        run(&mut search, "later");
        assert!(search.matches(
            1,
            &[
                body.snapshot(),
                privaxy::storage::Body::default().snapshot()
            ]
        ));
        run(&mut search, "");
        assert!(!search.matches(
            1,
            &[
                body.snapshot(),
                privaxy::storage::Body::default().snapshot()
            ]
        ));
    }
    #[test]
    fn searches_past_preview_and_across_utf8_read_boundaries() {
        let mut bytes = vec![b'x'; 2 * 1024 * 1024 - 1];
        bytes.extend_from_slice("Évidence-最後".as_bytes());
        assert!(contains(&bytes[..], "évidence-最後", &|| false).unwrap());
        assert!(!contains(&bytes[..], "absent", &|| false).unwrap());
    }
    #[test]
    fn cancelled_search_does_not_read_body() {
        struct MustNotRead;
        impl Read for MustNotRead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("cancelled reader called")
            }
        }
        assert_eq!(
            contains(MustNotRead, "test", &|| true).unwrap_err().kind(),
            io::ErrorKind::Interrupted
        );
    }
}

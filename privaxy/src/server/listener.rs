//! Controllable listener shared by the GUI and the headless proxy.
use std::{
    future::Future,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListenerStatus {
    Starting,
    Listening(SocketAddr),
    Stopping,
    Stopped,
    Failed(String),
}
impl ListenerStatus {
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Listening(_))
    }
    pub fn is_changing(&self) -> bool {
        matches!(self, Self::Starting | Self::Stopping)
    }
}

#[derive(Clone, Debug)]
pub struct ProxyListener {
    enabled: watch::Sender<bool>,
    status: Arc<Mutex<ListenerStatus>>,
}
impl ProxyListener {
    pub fn status(&self) -> ListenerStatus {
        self.status.lock().unwrap().clone()
    }
    pub fn start(&self) {
        if !self.status().is_running() {
            *self.status.lock().unwrap() = ListenerStatus::Starting;
            let _ = self.enabled.send(true);
        }
    }
    pub fn stop(&self) {
        *self.status.lock().unwrap() = ListenerStatus::Stopping;
        let _ = self.enabled.send(false);
    }
    pub(crate) fn spawn<F, Fut>(address: SocketAddr, serve: F) -> Self
    where
        F: Fn(TcpStream, SocketAddr, CancellationToken) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (enabled, mut desired) = watch::channel(true);
        let status = Arc::new(Mutex::new(ListenerStatus::Starting));
        let shared = status.clone();
        tokio::spawn(async move {
            loop {
                if !*desired.borrow_and_update() {
                    *shared.lock().unwrap() = ListenerStatus::Stopped;
                    if desired.changed().await.is_err() {
                        break;
                    }
                    continue;
                }
                *shared.lock().unwrap() = ListenerStatus::Starting;
                let listener = match TcpListener::bind(address).await {
                    Ok(listener) => listener,
                    Err(error) => {
                        log::error!("Cannot listen on {address}: {error}");
                        *shared.lock().unwrap() =
                            ListenerStatus::Failed(format!("Cannot listen on {address}: {error}"));
                        if !*desired.borrow() {
                            continue;
                        }
                        if desired.changed().await.is_err() {
                            break;
                        }
                        continue;
                    }
                };
                let cancellation = CancellationToken::new();
                let guard = cancellation.clone().drop_guard();
                let mut tasks = JoinSet::new();
                *shared.lock().unwrap() = ListenerStatus::Listening(listener.local_addr().unwrap());
                log::info!(
                    "Proxy available at http://{}",
                    listener.local_addr().unwrap()
                );
                loop {
                    tokio::select! {
                        biased;
                        _ = desired.changed() => break,
                        Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                        accepted = listener.accept() => match accepted {
                            Ok((stream, peer)) if tasks.len() < 1024 => {
                                let cancel = cancellation.clone();
                                let request = serve(stream, peer, cancel.clone());
                                tasks.spawn(async move {
                                    tokio::select! { biased; _ = cancel.cancelled() => {}, _ = request => {} }
                                });
                            }
                            Ok(_) => {},
                            Err(error) => {
                                log::warn!("Proxy accept failed: {error}");
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            }
                        }
                    }
                }
                drop(listener);
                drop(guard); // Also cancels upgraded CONNECT streams outside the HTTP task.
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                if desired.has_changed().is_err() {
                    break;
                }
            }
            *shared.lock().unwrap() = ListenerStatus::Stopped;
        });
        Self { enabled, status }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    async fn wait(listener: &ProxyListener, predicate: impl Fn(&ListenerStatus) -> bool) {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while !predicate(&listener.status()) {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn reports_port_conflict_retries_and_closes_connections_on_stop() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = occupied.local_addr().unwrap();
        let listener = ProxyListener::spawn(address, |mut stream, _, cancel| async move {
            // Model an upgraded stream outliving its initial HTTP request.
            tokio::spawn(async move {
                stream.write_all(b"ready").await.unwrap();
                cancel.cancelled().await;
                drop(stream);
            });
        });
        wait(&listener, |s| matches!(s, ListenerStatus::Failed(_))).await;
        drop(occupied);
        for _ in 0..3 {
            listener.start();
            wait(&listener, ListenerStatus::is_running).await;
            let mut stream = TcpStream::connect(address).await.unwrap();
            let mut ready = [0; 5];
            stream.read_exact(&mut ready).await.unwrap();
            assert_eq!(&ready, b"ready");
            listener.stop();
            wait(&listener, |s| *s == ListenerStatus::Stopped).await;
            assert!(TcpStream::connect(address).await.is_err());
            let end =
                tokio::time::timeout(std::time::Duration::from_secs(1), stream.read(&mut ready))
                    .await
                    .unwrap();
            assert!(matches!(end, Ok(0)), "active stream must close: {end:?}");
        }
    }
}

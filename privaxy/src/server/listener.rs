//! Controllable listener shared by the GUI and the headless proxy.
use ipnet::IpNet;
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex, RwLock},
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

/// Whether the listener runs, and where.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Desired {
    enabled: bool,
    address: SocketAddr,
}

/// Addresses beyond loopback that may connect; loopback always may.
#[derive(Clone, Debug, Default)]
pub struct Allowlist(Arc<RwLock<Vec<IpNet>>>);
impl Allowlist {
    /// Replaces the allowed ranges with `entries`, CIDR ranges or single addresses; returns the entries that are neither.
    pub fn replace<'a>(&self, entries: impl IntoIterator<Item = &'a String>) -> Vec<String> {
        let mut invalid = Vec::new();
        let mut ranges = Vec::new();
        for entry in entries {
            let entry = entry.trim();
            match entry
                .parse::<IpNet>()
                .or_else(|_| entry.parse::<IpAddr>().map(IpNet::from))
            {
                Ok(range) => ranges.push(range),
                Err(_) => invalid.push(entry.to_owned()),
            }
        }
        *self.0.write().unwrap() = ranges;
        invalid
    }
    pub fn allows(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        ip.is_loopback()
            || self
                .0
                .read()
                .unwrap()
                .iter()
                .any(|range| range.contains(&ip))
    }
}

#[derive(Clone, Debug)]
pub struct ProxyListener {
    desired: watch::Sender<Desired>,
    status: Arc<Mutex<ListenerStatus>>,
    allowlist: Allowlist,
}
impl ProxyListener {
    pub fn status(&self) -> ListenerStatus {
        self.status.lock().unwrap().clone()
    }
    pub fn start(&self) {
        if !self.status().is_running() {
            *self.status.lock().unwrap() = ListenerStatus::Starting;
            self.desired.send_modify(|desired| desired.enabled = true);
        }
    }
    pub fn stop(&self) {
        *self.status.lock().unwrap() = ListenerStatus::Stopping;
        self.desired.send_modify(|desired| desired.enabled = false);
    }
    /// Listens on every interface for `clients` when `lan` is set, otherwise on loopback only.
    ///
    /// Returns the client entries that are not addresses or CIDR ranges.
    pub fn serve_lan<'a>(
        &self,
        lan: bool,
        clients: impl IntoIterator<Item = &'a String>,
    ) -> Vec<String> {
        let invalid = self.allowlist.replace(clients);
        let ip = if lan {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        };
        self.desired.send_if_modified(|desired| {
            let address = SocketAddr::new(ip, desired.address.port());
            let changed = desired.address != address;
            desired.address = address;
            changed
        });
        invalid
    }
    pub(crate) fn spawn<F, Fut>(address: SocketAddr, serve: F) -> Self
    where
        F: Fn(TcpStream, SocketAddr, CancellationToken) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self::spawn_with(address, true, serve)
    }
    /// A listener that starts listening only once `enabled`.
    pub(crate) fn spawn_with<F, Fut>(address: SocketAddr, enabled: bool, serve: F) -> Self
    where
        F: Fn(TcpStream, SocketAddr, CancellationToken) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (sender, mut desired) = watch::channel(Desired { enabled, address });
        let status = Arc::new(Mutex::new(if enabled {
            ListenerStatus::Starting
        } else {
            ListenerStatus::Stopped
        }));
        let shared = status.clone();
        let allowlist = Allowlist::default();
        let allowed = allowlist.clone();
        tokio::spawn(async move {
            loop {
                let Desired { enabled, address } = *desired.borrow_and_update();
                if !enabled {
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
                        if !desired.borrow().enabled {
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
                            Ok((_, peer)) if !address.ip().is_loopback() && !allowed.allows(peer.ip()) => {
                                log::debug!("Proxy refused {peer}: not on the LAN client list");
                            }
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
        Self {
            desired: sender,
            status,
            allowlist,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_allowlist_takes_ranges_and_addresses_and_always_admits_loopback() {
        let allowlist = Allowlist::default();
        let invalid = allowlist.replace(&[
            "192.168.4.0/24".to_owned(),
            " 10.0.0.7 ".to_owned(),
            "fe80::/10".to_owned(),
            "not an address".to_owned(),
        ]);
        assert_eq!(invalid, ["not an address"]);
        for ip in [
            "192.168.4.32",
            "10.0.0.7",
            "fe80::1",
            "127.0.0.1",
            "::1",
            "::ffff:192.168.4.9",
        ] {
            assert!(allowlist.allows(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["192.168.5.1", "10.0.0.8", "8.8.8.8", "2001:db8::1"] {
            assert!(!allowlist.allows(ip.parse().unwrap()), "{ip}");
        }
    }

    #[tokio::test]
    async fn lan_mode_rebinds_on_every_interface_and_back() {
        let free = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = free.local_addr().unwrap();
        drop(free);
        let listener = ProxyListener::spawn(address, |mut stream, _, _| async move {
            let _ = stream.write_all(b"ok").await;
        });
        wait(&listener, ListenerStatus::is_running).await;
        listener.serve_lan(true, &["192.168.0.0/16".to_owned()]);
        wait(
            &listener,
            |s| matches!(s, ListenerStatus::Listening(bound) if bound.ip().is_unspecified()),
        )
        .await;
        let mut stream = TcpStream::connect(address).await.unwrap();
        let mut reply = [0; 2];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ok");
        listener.serve_lan(false, &[]);
        wait(
            &listener,
            |s| matches!(s, ListenerStatus::Listening(bound) if bound.ip().is_loopback()),
        )
        .await;
        listener.stop();
        wait(&listener, |s| *s == ListenerStatus::Stopped).await;
    }
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

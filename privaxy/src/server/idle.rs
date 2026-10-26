//! Connection lifetimes counted from the last byte moved instead of from the start.
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::Instant,
};

/// When bytes last moved through the [`Watched`] streams sharing it.
#[derive(Clone)]
pub(crate) struct Activity {
    start: Instant,
    last_ms: Arc<AtomicU64>,
}

impl Activity {
    pub(crate) fn new() -> Self {
        Self {
            start: Instant::now(),
            last_ms: Arc::default(),
        }
    }

    fn touch(&self) {
        self.last_ms
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    fn last(&self) -> Instant {
        self.start + Duration::from_millis(self.last_ms.load(Ordering::Relaxed))
    }

    /// Runs `work` to its end, or until nothing has moved for `limit`; `None` when it went idle.
    pub(crate) async fn until_idle<F: Future>(
        &self,
        limit: Duration,
        work: F,
    ) -> Option<F::Output> {
        tokio::pin!(work);
        loop {
            tokio::select! {
                output = &mut work => return Some(output),
                () = tokio::time::sleep_until(self.last() + limit) => {
                    if self.last() + limit <= Instant::now() {
                        return None;
                    }
                }
            }
        }
    }
}

/// A stream that records its reads and writes in an [`Activity`].
pub(crate) struct Watched<T> {
    inner: T,
    activity: Activity,
}

impl<T> Watched<T> {
    pub(crate) fn new(inner: T, activity: Activity) -> Self {
        Self { inner, activity }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Watched<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(poll, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.activity.touch();
        }
        poll
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Watched<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, data);
        if matches!(poll, Poll::Ready(Ok(written)) if written > 0) {
            self.activity.touch();
        }
        poll
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write_vectored(cx, data);
        if matches!(poll, Poll::Ready(Ok(written)) if written > 0) {
            self.activity.touch();
        }
        poll
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn traffic_keeps_a_connection_open_past_the_limit_and_silence_ends_it() {
        let limit = Duration::from_millis(150);
        let (client, mut server) = tokio::io::duplex(64);
        let activity = Activity::new();
        let mut watched = Watched::new(client, activity.clone());
        let started = std::time::Instant::now();
        let chatty = activity
            .until_idle(limit, async {
                let mut byte = [0];
                for _ in 0..8 {
                    server.write_all(b"x").await.unwrap();
                    watched.read_exact(&mut byte).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await;
        assert!(chatty.is_some());
        assert!(started.elapsed() >= Duration::from_millis(400));

        let silent = activity
            .until_idle(limit, std::future::pending::<()>())
            .await;
        assert!(silent.is_none());
    }

    #[tokio::test]
    async fn writes_count_as_traffic() {
        let (client, mut server) = tokio::io::duplex(64);
        let activity = Activity::new();
        let mut watched = Watched::new(client, activity.clone());
        tokio::time::sleep(Duration::from_millis(30)).await;
        let before = activity.last();
        watched.write_all(b"ping").await.unwrap();
        assert!(activity.last() > before);
        let mut echo = [0; 4];
        server.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");
    }
}

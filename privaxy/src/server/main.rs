use privaxy::start_privaxy;
use std::time::Duration;

const RUST_LOG_ENV_KEY: &str = "RUST_LOG";

#[tokio::main]
async fn main() {
    if std::env::var(RUST_LOG_ENV_KEY).is_err() {
        // SAFETY: We're setting this env var before any threads are spawned,
        // at the very start of main. This is safe as there's no concurrent access.
        unsafe {
            std::env::set_var(RUST_LOG_ENV_KEY, "privaxy=info");
        }
    }

    env_logger::init();

    start_privaxy().await;

    loop {
        tokio::time::sleep(Duration::from_secs(3600 * 24 * 30 * 365)).await
    }
}

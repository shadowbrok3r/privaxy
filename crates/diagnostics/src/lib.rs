//! App diagnostics, independent of the UI and networking runtimes.
pub use log::LevelFilter;
use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicU8, AtomicU64, Ordering},
        mpsc,
    },
};

pub const LEVELS: [LevelFilter; 5] = [
    LevelFilter::Error,
    LevelFilter::Warn,
    LevelFilter::Info,
    LevelFilter::Debug,
    LevelFilter::Trace,
];
const MAX_ENTRIES: usize = 5_000;
const FILE_LIMIT: u64 = 5 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Entry {
    pub time: chrono::DateTime<chrono::Utc>,
    pub level: log::Level,
    pub target: String,
    pub message: String,
}
impl Entry {
    pub fn line(&self) -> String {
        format!(
            "{} {:5} {} {}\n",
            self.time
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            self.level,
            self.target,
            self.message.replace('\n', " ")
        )
    }
}
enum WriteCommand {
    Line(String),
    Flush(mpsc::SyncSender<io::Result<()>>),
    Export(mpsc::SyncSender<io::Result<String>>),
}
struct State {
    entries: Mutex<VecDeque<Entry>>,
    level: AtomicU8,
    writer: Mutex<Option<(PathBuf, mpsc::SyncSender<WriteCommand>)>>,
    sink: OnceLock<Box<dyn log::Log>>,
    dropped: AtomicU64,
    file_error: Mutex<Option<String>>,
}
fn state() -> &'static State {
    static STATE: OnceLock<State> = OnceLock::new();
    STATE.get_or_init(|| State {
        entries: Mutex::default(),
        level: AtomicU8::new(3),
        writer: Mutex::default(),
        sink: OnceLock::new(),
        dropped: AtomicU64::new(0),
        file_error: Mutex::default(),
    })
}
struct Logger;
static LOGGER: Logger = Logger;

/// Install before the Android host installs its default logger. Dependency warnings/errors
/// are retained, while verbose third-party protocol dumps are excluded from exported logs.
pub fn init(sink: Option<Box<dyn log::Log>>) -> Result<(), log::SetLoggerError> {
    if let Some(sink) = sink {
        let _ = state().sink.set(sink);
    }
    log::set_logger(&LOGGER)?;
    log::set_max_level(LevelFilter::Trace);
    Ok(())
}
pub fn level() -> LevelFilter {
    match state().level.load(Ordering::Relaxed) {
        1 => LevelFilter::Error,
        2 => LevelFilter::Warn,
        4 => LevelFilter::Debug,
        5 => LevelFilter::Trace,
        _ => LevelFilter::Info,
    }
}
pub fn set_level(level: LevelFilter) {
    state().level.store(level as u8, Ordering::Relaxed);
    log::set_max_level(LevelFilter::Trace);
    if let Some(path) = file_path() {
        if let Err(error) = std::fs::write(path.with_extension("level"), level.to_string()) {
            *state().file_error.lock().unwrap() = Some(format!("Cannot save log level: {error}"));
        }
    }
    log::info!(target: "privaxy::diagnostics", "Capture level changed to {level}");
}
pub fn entries() -> Vec<Entry> {
    state().entries.lock().unwrap().iter().cloned().collect()
}
pub fn clear_view() {
    state().entries.lock().unwrap().clear();
}
pub fn dropped_lines() -> u64 {
    state().dropped.load(Ordering::Relaxed)
}
pub fn file_error() -> Option<String> {
    state().file_error.lock().unwrap().clone()
}
pub fn file_path() -> Option<PathBuf> {
    state().writer.lock().unwrap().as_ref().map(|w| w.0.clone())
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        metadata.level() <= level()
            && (metadata.target().starts_with("privaxy") || metadata.level() <= log::Level::Warn)
    }
    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let mut message = record.args().to_string();
        if message.len() > 8192 {
            let mut boundary = 8192;
            while !message.is_char_boundary(boundary) {
                boundary -= 1;
            }
            message.truncate(boundary);
            message.push_str(" [log message shortened]");
        }
        let entry = Entry {
            time: chrono::Utc::now(),
            level: record.level(),
            target: record.target().into(),
            message,
        };
        let line = entry.line();
        let mut entries = state().entries.lock().unwrap();
        entries.push_back(entry);
        while entries.len() > MAX_ENTRIES {
            entries.pop_front();
        }
        drop(entries);
        if let Some((_, writer)) = state().writer.lock().unwrap().as_ref() {
            if writer.try_send(WriteCommand::Line(line.clone())).is_err() {
                state().dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
        if let Some(sink) = state().sink.get() {
            sink.log(record);
        }
        #[cfg(not(target_os = "android"))]
        if state().sink.get().is_none() {
            eprint!("{line}");
        }
    }
    fn flush(&self) {
        let _ = flush_file();
    }
}

fn open_log(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}
fn previous(path: &Path) -> PathBuf {
    path.with_extension("log.1")
}

pub fn attach_file(path: &Path) -> io::Result<()> {
    let mut writer = state().writer.lock().unwrap();
    if writer.as_ref().is_some_and(|w| w.0 == path) {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    let mut file = RollingFile::new(path.to_owned(), FILE_LIMIT)?;
    if let Ok(saved) = std::fs::read_to_string(path.with_extension("level")) {
        if let Ok(level) = saved.trim().parse::<LevelFilter>() {
            if level != LevelFilter::Off {
                state().level.store(level as u8, Ordering::Relaxed);
            }
        }
    }
    log::set_max_level(LevelFilter::Trace);
    let (sender, receiver) = mpsc::sync_channel::<WriteCommand>(2048);
    let history: Vec<_> = entries().iter().map(Entry::line).collect();
    for line in history {
        file.write(&line)?;
    }
    std::thread::Builder::new()
        .name("privaxy-logs".into())
        .spawn(move || {
            while let Ok(command) = receiver.recv() {
                let result = match command {
                    WriteCommand::Line(line) => file.write(&line),
                    WriteCommand::Flush(done) => {
                        let _ = done.send(file.file.flush());
                        Ok(())
                    }
                    WriteCommand::Export(done) => {
                        let _ = done.send(file.export());
                        Ok(())
                    }
                };
                if let Err(error) = result {
                    *state().file_error.lock().unwrap() = Some(error.to_string());
                }
            }
        })?;
    *writer = Some((path.to_owned(), sender));
    drop(writer);
    log::info!(target: "privaxy::diagnostics", "Diagnostic file attached; level={}", level());
    Ok(())
}
fn flush_file() -> io::Result<()> {
    let writer = state().writer.lock().unwrap().as_ref().map(|w| w.1.clone());
    if let Some(writer) = writer {
        let (done, wait) = mpsc::sync_channel(1);
        writer
            .try_send(WriteCommand::Flush(done))
            .map_err(|_| io::Error::other("Log writer is busy; retry shortly"))?;
        wait.recv_timeout(std::time::Duration::from_secs(5))
            .map_err(io::Error::other)??;
    }
    Ok(())
}
/// Call on a worker; includes the current file and its preceding rotation, including prior runs.
pub fn export_text() -> io::Result<String> {
    let writer = state().writer.lock().unwrap().as_ref().map(|w| w.1.clone());
    let mut text = if let Some(writer) = writer {
        let (done, wait) = mpsc::sync_channel(1);
        writer
            .try_send(WriteCommand::Export(done))
            .map_err(|_| io::Error::other("Log writer is busy; retry shortly"))?;
        wait.recv_timeout(std::time::Duration::from_secs(5))
            .map_err(io::Error::other)??
    } else {
        entries().iter().map(Entry::line).collect()
    };
    if let Some(error) = file_error() {
        text.push_str(&format!("\nLog file error: {error}\n"));
    }
    text.push_str(&format!(
        "\nDisk queue dropped lines: {}\n",
        dropped_lines()
    ));
    Ok(text)
}

struct RollingFile {
    path: PathBuf,
    file: File,
    size: u64,
    limit: u64,
}
impl RollingFile {
    fn new(path: PathBuf, limit: u64) -> io::Result<Self> {
        let file = open_log(&path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            path,
            file,
            size,
            limit,
        })
    }
    fn write(&mut self, line: &str) -> io::Result<()> {
        if self.size + line.len() as u64 > self.limit {
            self.file.flush()?;
            let old = previous(&self.path);
            if old.exists() {
                std::fs::remove_file(&old)?;
            }
            std::fs::rename(&self.path, old)?;
            self.file = open_log(&self.path)?;
            self.size = 0;
        }
        self.file.write_all(line.as_bytes())?;
        self.size += line.len() as u64;
        Ok(())
    }
    fn export(&mut self) -> io::Result<String> {
        self.file.flush()?;
        let mut text = match std::fs::read_to_string(previous(&self.path)) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error),
        };
        text.push_str(&std::fs::read_to_string(&self.path)?);
        Ok(text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rotation_export_retains_previous_run_and_exact_order() {
        let path =
            std::env::temp_dir().join(format!("privaxy-logs-test-{}.log", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(previous(&path));
        let mut file = RollingFile::new(path.clone(), 12).unwrap();
        file.write("first\n").unwrap();
        file.write("second\n").unwrap();
        assert_eq!(file.export().unwrap(), "first\nsecond\n");
        drop(file);
        let mut file = RollingFile::new(path.clone(), 12).unwrap();
        file.write("third\n").unwrap();
        assert_eq!(file.export().unwrap(), "second\nthird\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(file);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(previous(&path)).unwrap();
    }
    #[test]
    fn levels_retain_app_trace_but_exclude_verbose_protocol_dumps() {
        use log::Log;
        for level in LEVELS {
            state().level.store(level as u8, Ordering::Relaxed);
            for severity in [
                log::Level::Error,
                log::Level::Warn,
                log::Level::Info,
                log::Level::Debug,
                log::Level::Trace,
            ] {
                let meta = log::Metadata::builder()
                    .target("privaxy_android::pairing")
                    .level(severity)
                    .build();
                assert_eq!(LOGGER.enabled(&meta), severity <= level);
                let meta = log::Metadata::builder()
                    .target("hyper::headers")
                    .level(severity)
                    .build();
                assert_eq!(
                    LOGGER.enabled(&meta),
                    severity <= level && severity <= log::Level::Warn
                );
            }
        }
    }
}

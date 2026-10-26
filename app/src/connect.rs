//! Ways to point this desktop's own apps at the proxy: system proxy settings, an inspected browser and terminal variables.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const PROXY_URL: &str = "http://127.0.0.1:8100";
const KDE_GROUP: &str = "Proxy Settings";
const KDE_KEYS: [&str; 4] = ["ProxyType", "httpProxy", "httpsProxy", "NoProxyFor"];
/// GNOME proxy settings as (schema, key), the ones Privaxy changes.
const GNOME_KEYS: [(&str, &str); 5] = [
    ("org.gnome.system.proxy", "mode"),
    ("org.gnome.system.proxy.http", "host"),
    ("org.gnome.system.proxy.http", "port"),
    ("org.gnome.system.proxy.https", "host"),
    ("org.gnome.system.proxy.https", "port"),
];
/// Chromium-based browsers, most likely first.
const BROWSERS: [&str; 8] = [
    "chromium",
    "google-chrome-stable",
    "google-chrome",
    "brave",
    "brave-browser",
    "microsoft-edge-stable",
    "vivaldi-stable",
    "thorium-browser",
];
/// System CA bundles across distributions.
const SYSTEM_BUNDLES: [&str; 4] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/ca-certificates/extracted/tls-ca-bundle.pem",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
];

/// `~/.privaxy`, where the configuration and the files below live.
fn privaxy_dir() -> Result<PathBuf, String> {
    Ok(dirs::home_dir()
        .ok_or("No home directory")?
        .join(".privaxy"))
}

/// The first `name` found on `PATH`.
pub fn which(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|directory| directory.join(name))
        .find(|path| path.is_file())
}

fn output(program: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("{}: {e}", program.display()))?;
    if !output.status.success() {
        return Err(format!(
            "{} failed: {}",
            program.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// The desktop proxy settings in place before Privaxy's, to put back when it lets go.
#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
struct SavedProxy {
    kde: Vec<(String, String)>,
    /// GVariant text, as `gsettings get` prints it.
    gnome: Vec<(String, String, String)>,
}

/// The desktop's proxy settings: KDE's `kioslaverc` and GNOME's GSettings, whichever exist.
pub struct SystemProxy {
    kreadconfig: Option<PathBuf>,
    kwriteconfig: Option<PathBuf>,
    gsettings: Option<PathBuf>,
    backup: PathBuf,
}

impl SystemProxy {
    pub fn detect() -> Result<Self, String> {
        let kde = |names: [&str; 2]| names.iter().find_map(|name| which(name));
        let proxy = Self {
            kreadconfig: kde(["kreadconfig6", "kreadconfig5"]),
            kwriteconfig: kde(["kwriteconfig6", "kwriteconfig5"]),
            gsettings: which("gsettings").filter(|gsettings| {
                output(gsettings, &["list-keys", "org.gnome.system.proxy"]).is_ok()
            }),
            backup: privaxy_dir()?.join("system-proxy-backup.json"),
        };
        if proxy.kwriteconfig.is_none() && proxy.gsettings.is_none() {
            return Err(
                "Neither KDE (kwriteconfig6) nor GNOME (gsettings) proxy settings are available."
                    .into(),
            );
        }
        Ok(proxy)
    }

    fn kde_read(&self, key: &str) -> Option<String> {
        let read = self.kreadconfig.as_ref()?;
        output(
            read,
            &["--file", "kioslaverc", "--group", KDE_GROUP, "--key", key],
        )
        .ok()
    }

    fn kde_write(&self, key: &str, value: &str) -> Result<(), String> {
        let Some(write) = &self.kwriteconfig else {
            return Ok(());
        };
        output(
            write,
            &[
                "--file",
                "kioslaverc",
                "--group",
                KDE_GROUP,
                "--key",
                key,
                value,
            ],
        )
        .map(drop)
    }

    fn gnome(&self, args: &[&str]) -> Result<String, String> {
        match &self.gsettings {
            Some(gsettings) => output(gsettings, args),
            None => Ok(String::new()),
        }
    }

    /// Whether either desktop points at Privaxy.
    pub fn is_active(&self) -> bool {
        let kde = self.kde_read("ProxyType").as_deref() == Some("1")
            && self
                .kde_read("httpProxy")
                .is_some_and(|proxy| proxy.contains("127.0.0.1") && proxy.contains("8100"));
        let gnome = self.gsettings.is_some()
            && self
                .gnome(&["get", "org.gnome.system.proxy", "mode"])
                .as_deref()
                == Ok("'manual'")
            && self
                .gnome(&["get", "org.gnome.system.proxy.http", "host"])
                .is_ok_and(|host| host == "'127.0.0.1'")
            && self
                .gnome(&["get", "org.gnome.system.proxy.http", "port"])
                .is_ok_and(|port| port == "8100");
        kde || gnome
    }

    /// Points the desktop at Privaxy, keeping the earlier settings for [`Self::restore`].
    pub fn apply(&self) -> Result<(), String> {
        if !self.backup.exists() {
            let saved = SavedProxy {
                kde: KDE_KEYS
                    .iter()
                    .filter_map(|key| Some((key.to_string(), self.kde_read(key)?)))
                    .collect(),
                gnome: GNOME_KEYS
                    .iter()
                    .filter_map(|(schema, key)| {
                        let value = self.gnome(&["get", schema, key]).ok()?;
                        (!value.is_empty()).then(|| (schema.to_string(), key.to_string(), value))
                    })
                    .collect(),
            };
            std::fs::create_dir_all(self.backup.parent().unwrap()).map_err(|e| e.to_string())?;
            std::fs::write(
                &self.backup,
                serde_json::to_vec_pretty(&saved).map_err(|e| e.to_string())?,
            )
            .map_err(|e| format!("Cannot save the current proxy settings: {e}"))?;
        }
        for (key, value) in [
            ("ProxyType", "1"),
            ("httpProxy", PROXY_URL),
            ("httpsProxy", PROXY_URL),
            ("NoProxyFor", "localhost,127.0.0.1,::1"),
        ] {
            self.kde_write(key, value)?;
        }
        for args in [
            ["set", "org.gnome.system.proxy.http", "host", "127.0.0.1"],
            ["set", "org.gnome.system.proxy.http", "port", "8100"],
            ["set", "org.gnome.system.proxy.https", "host", "127.0.0.1"],
            ["set", "org.gnome.system.proxy.https", "port", "8100"],
            ["set", "org.gnome.system.proxy", "mode", "manual"],
        ] {
            self.gnome(&args)?;
        }
        self.notify_kde();
        Ok(())
    }

    /// Puts back the settings [`Self::apply`] replaced, or turns the proxy off when none were kept.
    pub fn restore(&self) -> Result<(), String> {
        let saved: SavedProxy = std::fs::read(&self.backup)
            .ok()
            .and_then(|raw| serde_json::from_slice(&raw).ok())
            .unwrap_or_default();
        if saved.kde.is_empty() {
            self.kde_write("ProxyType", "0")?;
        }
        for (key, value) in &saved.kde {
            self.kde_write(key, value)?;
        }
        if saved.gnome.is_empty() {
            self.gnome(&["set", "org.gnome.system.proxy", "mode", "none"])?;
        }
        for (schema, key, value) in &saved.gnome {
            self.gnome(&["set", schema, key, value])?;
        }
        self.notify_kde();
        let _ = std::fs::remove_file(&self.backup);
        Ok(())
    }

    /// Restores the earlier settings if Privaxy replaced them.
    pub fn release(&self) -> Result<(), String> {
        if self.backup.exists() {
            self.restore()
        } else {
            Ok(())
        }
    }

    /// Asks running KDE apps to reread their proxy settings.
    fn notify_kde(&self) {
        if self.kwriteconfig.is_none() {
            return;
        }
        let Some(dbus) = which("dbus-send") else {
            return;
        };
        for member in ["reparseSlaveConfiguration", "reparseWorkerConfiguration"] {
            let _ = Command::new(&dbus)
                .args([
                    "--type=signal",
                    "/KIO/Scheduler",
                    &format!("org.kde.KIO.Scheduler.{member}"),
                    "string:",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

/// Opens a Chromium-based browser in its own profile that uses the proxy and trusts the inspection CA.
///
/// `spki` is the CA's public key hash, so nothing is installed in any system or browser store.
pub fn open_inspected_browser(spki: &str) -> Result<String, String> {
    let (name, browser) = BROWSERS
        .iter()
        .find_map(|name| Some((*name, which(name)?)))
        .ok_or(
            "No Chromium-based browser found: install Chromium, Chrome, Brave, Edge or Vivaldi.",
        )?;
    let profile = dirs::cache_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("privaxy/inspected-browser");
    std::fs::create_dir_all(&profile).map_err(|e| e.to_string())?;
    let mut child = Command::new(browser)
        .arg(format!("--user-data-dir={}", profile.display()))
        .arg(format!("--proxy-server={PROXY_URL}"))
        .arg("--proxy-bypass-list=<-loopback>")
        .arg(format!("--ignore-certificate-errors-spki-list={spki}"))
        .args(["--no-first-run", "--no-default-browser-check"])
        .arg(format!("{PROXY_URL}/"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("Cannot start {name}: {e}"))?;
    std::thread::spawn(move || child.wait());
    Ok(name.to_owned())
}

/// Shell lines that send a terminal's tools through the proxy and make them trust the inspection CA.
///
/// Writes the CA, and the system bundle with the CA appended, under `~/.privaxy`.
pub fn terminal_setup(ca_pem: &str) -> Result<String, String> {
    let directory = privaxy_dir()?;
    std::fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    let ca = directory.join("privaxy-ca.pem");
    std::fs::write(&ca, ca_pem).map_err(|e| format!("Cannot write {}: {e}", ca.display()))?;
    let system = SYSTEM_BUNDLES
        .iter()
        .find_map(|path| std::fs::read_to_string(path).ok())
        .ok_or("No system CA bundle found")?;
    let bundle = directory.join("ca-bundle.pem");
    std::fs::write(
        &bundle,
        format!("{}\n{}\n", system.trim_end(), ca_pem.trim()),
    )
    .map_err(|e| format!("Cannot write {}: {e}", bundle.display()))?;
    Ok(terminal_lines(&ca, &bundle))
}

fn terminal_lines(ca: &Path, bundle: &Path) -> String {
    let quote = |path: &Path| format!("'{}'", path.display().to_string().replace('\'', r"'\''"));
    let (ca, bundle) = (quote(ca), quote(bundle));
    format!(
        "export http_proxy={PROXY_URL} https_proxy={PROXY_URL} no_proxy=localhost,127.0.0.1,::1\n\
         export HTTP_PROXY=$http_proxy HTTPS_PROXY=$https_proxy NO_PROXY=$no_proxy\n\
         export SSL_CERT_FILE={bundle} CURL_CA_BUNDLE={bundle} REQUESTS_CA_BUNDLE={bundle} GIT_SSL_CAINFO={bundle}\n\
         export NODE_EXTRA_CA_CERTS={ca} DENO_CERT={ca}\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_lines_quote_paths_and_cover_common_tools() {
        let lines = terminal_lines(
            Path::new("/home/a b/.privaxy/privaxy-ca.pem"),
            Path::new("/home/o'k/.privaxy/ca-bundle.pem"),
        );
        assert!(lines.starts_with("export http_proxy=http://127.0.0.1:8100 "));
        assert!(lines.contains("NODE_EXTRA_CA_CERTS='/home/a b/.privaxy/privaxy-ca.pem'"));
        assert!(lines.contains(r"SSL_CERT_FILE='/home/o'\''k/.privaxy/ca-bundle.pem'"));
        for variable in [
            "HTTPS_PROXY",
            "REQUESTS_CA_BUNDLE",
            "GIT_SSL_CAINFO",
            "CURL_CA_BUNDLE",
        ] {
            assert!(lines.contains(variable), "{variable}");
        }
    }

    #[test]
    fn saved_settings_survive_a_round_trip() {
        let saved = SavedProxy {
            kde: vec![("ProxyType".into(), "0".into())],
            gnome: vec![(
                "org.gnome.system.proxy".into(),
                "mode".into(),
                "'none'".into(),
            )],
        };
        let raw = serde_json::to_vec(&saved).unwrap();
        assert_eq!(serde_json::from_slice::<SavedProxy>(&raw).unwrap(), saved);
    }
}

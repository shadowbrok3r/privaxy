//! Network-level capture on Linux: nftables sends this user's web traffic to the proxy's loopback listener.
//!
//! A root helper, this binary run through pkexec, loads the rules as an nftables table owned by an
//! `nft -i` session it keeps open while Privaxy keeps the helper's stdin open. The kernel deletes an
//! owned table when its session ends, so the rules go away with Privaxy, the helper or `nft`, even
//! when one of them is killed.
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::Duration;

/// First argument that runs the binary as the capture helper instead of the app.
pub const HELPER_FLAG: &str = "--network-capture-helper";
const TABLE: &str = "privaxy_capture";
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const NFT_PATHS: [&str; 4] = ["/usr/bin/nft", "/usr/sbin/nft", "/sbin/nft", "/bin/nft"];

/// What the capture rules cover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rules {
    /// The user whose apps are captured.
    pub uid: u32,
    /// Privaxy's cgroup, relative to the cgroup root; its own connections are not redirected.
    pub cgroup: String,
    pub ports: Vec<u16>,
    pub redirect_to: u16,
}

impl Rules {
    fn args(&self) -> Vec<String> {
        let ports: Vec<_> = self.ports.iter().map(u16::to_string).collect();
        vec![
            "--uid".into(),
            self.uid.to_string(),
            "--cgroup".into(),
            self.cgroup.clone(),
            "--ports".into(),
            ports.join(","),
            "--to".into(),
            self.redirect_to.to_string(),
        ]
    }

    fn parse(args: &[String]) -> Result<Self, String> {
        let value = |flag: &str| {
            args.iter()
                .position(|arg| arg == flag)
                .and_then(|at| args.get(at + 1))
                .ok_or(format!("missing {flag}"))
        };
        let number = |flag: &str| -> Result<u64, String> {
            value(flag)?
                .parse()
                .map_err(|_| format!("{flag} is not a number"))
        };
        let cgroup = value("--cgroup")?.trim_matches('/').to_owned();
        let allowed = |c: char| c.is_ascii_alphanumeric() || "._@:+=,~-/".contains(c);
        if cgroup.is_empty() || cgroup.contains("..") || !cgroup.chars().all(allowed) {
            return Err(format!("unsupported cgroup path {cgroup:?}"));
        }
        let ports = value("--ports")?
            .split(',')
            .map(|port| port.parse::<u16>().ok().filter(|port| *port > 0))
            .collect::<Option<Vec<_>>>()
            .filter(|ports| !ports.is_empty())
            .ok_or("--ports must list ports from 1 to 65535")?;
        Ok(Self {
            uid: u32::try_from(number("--uid")?).map_err(|e| e.to_string())?,
            cgroup,
            ports,
            redirect_to: u16::try_from(number("--to")?).map_err(|e| e.to_string())?,
        })
    }

    /// One line of nftables: an owned table that redirects the user's TCP on `ports` and refuses
    /// their QUIC, leaving Privaxy's own sockets and loopback alone.
    fn ruleset(&self) -> String {
        let level = self.cgroup.split('/').count();
        let ports: Vec<_> = self.ports.iter().map(u16::to_string).collect();
        let exempt = format!(
            "socket cgroupv2 level {level} \"{}\" return; meta skuid != {} return;",
            self.cgroup, self.uid
        );
        format!(
            "table inet {TABLE} {{ flags owner; \
             chain capture_redirect {{ type nat hook output priority dstnat; policy accept; \
             {exempt} ip daddr 127.0.0.0/8 return; ip6 daddr ::1 return; \
             tcp dport {{ {} }} redirect to :{}; }}; \
             chain capture_quic {{ type filter hook output priority filter; policy accept; \
             {exempt} udp dport 443 reject; }}; }}",
            ports.join(", "),
            self.redirect_to,
        )
    }
}

/// Runs as root: loads the rules, prints `ready`, and ends their `nft` session once stdin closes.
pub fn run_helper(args: &[String]) -> i32 {
    let rules = match Rules::parse(args) {
        Ok(rules) => rules,
        Err(error) => {
            println!("error: {error}");
            return 2;
        }
    };
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        println!("error: the capture helper must run as root");
        return 2;
    }
    let Some(nft) = NFT_PATHS.iter().map(Path::new).find(|path| path.is_file()) else {
        println!("error: nft was not found; install nftables");
        return 1;
    };
    let ruleset = rules.ruleset();
    let checked = Command::new(nft)
        .args(["-c", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child.stdin.take().unwrap().write_all(ruleset.as_bytes())?;
            child.wait_with_output()
        });
    match checked {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            let reason = String::from_utf8_lossy(&output.stderr);
            println!(
                "error: nft rejected the rules: {}",
                reason.trim().replace('\n', " ")
            );
            return 1;
        }
        Err(error) => {
            println!("error: cannot run nft: {error}");
            return 1;
        }
    }
    let listed = || {
        Command::new(nft)
            .args(["list", "table", "inet", TABLE])
            .stderr(Stdio::null())
            .output()
            .is_ok_and(|output| {
                output.status.success()
                    && String::from_utf8_lossy(&output.stdout).contains("redirect to")
            })
    };
    // A table left by an older helper, which did not own its rules.
    if listed() {
        let _ = Command::new(nft)
            .args(["delete", "table", "inet", TABLE])
            .stderr(Stdio::null())
            .status();
    }
    let mut session = match Command::new(nft)
        .arg("-i")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(session) => session,
        Err(error) => {
            println!("error: cannot run nft: {error}");
            return 1;
        }
    };
    let mut commands = session.stdin.take().unwrap();
    if let Err(error) = writeln!(commands, "{ruleset}").and_then(|()| commands.flush()) {
        println!("error: cannot load the rules: {error}");
        return 1;
    }
    if !(0..50).any(|_| {
        std::thread::sleep(Duration::from_millis(100));
        listed()
    }) {
        drop(commands);
        let _ = session.wait();
        println!("error: the rules did not take effect; another Privaxy may be capturing already");
        return 1;
    }
    println!("ready");
    let _ = std::io::stdout().flush();
    let mut sink = [0_u8; 64];
    while std::io::stdin()
        .read(&mut sink)
        .is_ok_and(|count| count > 0)
    {}
    drop(commands);
    let _ = session.wait();
    0
}

/// Privaxy's cgroup, split off from whatever launched it so the rules exempt nothing else.
fn own_cgroup() -> Result<String, String> {
    let current = std::fs::read_to_string("/proc/self/cgroup")
        .map_err(|e| format!("Cannot read this process's cgroup: {e}"))?
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(|path| path.trim().trim_matches('/').to_owned())
        .filter(|path| !path.is_empty())
        .ok_or(
            "Network capture needs cgroup v2, and this process is not in a cgroup of its own.",
        )?;
    if current.ends_with("/privaxy") {
        return Ok(current);
    }
    let own = format!("{current}/privaxy");
    let directory = Path::new(CGROUP_ROOT).join(&own);
    let moved = match std::fs::create_dir(&directory) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error),
    }
    .and_then(|()| {
        std::fs::write(
            directory.join("cgroup.procs"),
            std::process::id().to_string(),
        )
    });
    match moved {
        Ok(()) => Ok(own),
        Err(error) => {
            log::warn!(
                "Cannot move Privaxy into {own}: {error}. Other processes in {current} are not captured either."
            );
            Ok(current)
        }
    }
}

/// Capture in effect: the helper holding the rules, and the pipe whose closing removes them.
pub struct NetworkCapture {
    child: Child,
    stdin: Option<ChildStdin>,
}

impl NetworkCapture {
    /// Starts the helper through pkexec, unless already root, and waits until the rules are in place.
    ///
    /// Blocks while pkexec asks for the administrator password.
    pub fn start(ports: &[u16], redirect_to: u16) -> Result<Self, String> {
        let rules = Rules {
            // SAFETY: getuid has no preconditions.
            uid: unsafe { libc::getuid() },
            cgroup: own_cgroup()?,
            ports: ports.to_vec(),
            redirect_to,
        };
        let executable = std::env::current_exe().map_err(|e| e.to_string())?;
        // SAFETY: geteuid has no preconditions.
        let mut command = if unsafe { libc::geteuid() } == 0 {
            Command::new(&executable)
        } else {
            let pkexec = crate::connect::which("pkexec")
                .ok_or("pkexec was not found; install polkit to grant capture rights")?;
            let mut command = Command::new(pkexec);
            command.arg(&executable);
            command
        };
        let mut child = command
            .arg(HELPER_FLAG)
            .args(rules.args())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("Cannot start the capture helper: {e}"))?;
        let mut line = String::new();
        let _ = BufReader::new(child.stdout.take().unwrap()).read_line(&mut line);
        if line.trim() == "ready" {
            let stdin = child.stdin.take();
            return Ok(Self { child, stdin });
        }
        drop(child.stdin.take());
        let status = child.wait().ok().and_then(|status| status.code());
        Err(match (line.trim().strip_prefix("error: "), status) {
            (Some(reason), _) => reason.to_owned(),
            (None, Some(126)) => "Administrator authorization was dismissed.".into(),
            (None, Some(127)) => "Administrator authorization failed.".into(),
            (None, status) => format!("The capture helper stopped ({status:?})."),
        })
    }
}

impl Drop for NetworkCapture {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> Rules {
        Rules {
            uid: 1000,
            cgroup:
                "user.slice/user-1000.slice/user@1000.service/app.slice/app-privaxy.scope/privaxy"
                    .into(),
            ports: vec![80, 443, 8443],
            redirect_to: 8103,
        }
    }

    #[test]
    fn arguments_round_trip_and_reject_unsafe_paths() {
        let rules = rules();
        let mut args = vec![HELPER_FLAG.to_owned()];
        args.extend(rules.args());
        assert_eq!(Rules::parse(&args).unwrap(), rules);
        for (flag, bad) in [
            ("--cgroup", "a\"; flush ruleset; \""),
            ("--cgroup", "../../escape"),
            ("--cgroup", "/"),
            ("--ports", "443,0"),
            ("--ports", "https"),
            ("--uid", "-1"),
        ] {
            let mut bad_args = args.clone();
            let at = bad_args.iter().position(|arg| arg == flag).unwrap();
            bad_args[at + 1] = bad.into();
            assert!(Rules::parse(&bad_args).is_err(), "{flag} {bad}");
        }
    }

    #[test]
    fn the_ruleset_exempts_privaxy_other_users_and_loopback() {
        let ruleset = rules().ruleset();
        assert!(!ruleset.contains('\n'));
        assert!(ruleset.starts_with("table inet privaxy_capture { flags owner; "));
        assert!(ruleset.contains(
            "socket cgroupv2 level 6 \"user.slice/user-1000.slice/user@1000.service/app.slice/app-privaxy.scope/privaxy\" return;"
        ));
        assert!(ruleset.contains("meta skuid != 1000 return;"));
        assert!(ruleset.contains("ip daddr 127.0.0.0/8 return;"));
        assert!(ruleset.contains("tcp dport { 80, 443, 8443 } redirect to :8103;"));
        assert!(ruleset.contains("udp dport 443 reject;"));
        let redirect = ruleset.find("redirect to").unwrap();
        assert!(ruleset.find("socket cgroupv2").unwrap() < redirect);
    }
}

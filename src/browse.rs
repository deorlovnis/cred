//! The sandboxed browser: one headless Chromium per site, driven by the runner (a small,
//! root-installed Playwright program) on cred's behalf. cred puts the site's session into
//! it (cookies and Local Storage from stored fields), hands it the site's rules, and answers
//! its questions about writes with Touch ID. The agent only gets page text, masked.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};

use crate::policy::{Approved, Mode};
use crate::{approve, keychain};

/// Where install.sh puts the runner, owned by root so nothing running as the user can change it.
const RUNNER_DIR: &str = "/usr/local/lib/cred/runner";

fn runner_dir() -> PathBuf {
    // Tests run a checkout's runner. Release builds don't contain this.
    #[cfg(debug_assertions)]
    if let Some(dir) = std::env::var_os("CRED_RUNNER_DIR") {
        return dir.into();
    }
    PathBuf::from(RUNNER_DIR)
}

pub struct Session {
    pub site: String,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Session {
    /// Start a browser for the site with its session in place, and open the start page.
    pub fn open(site: &str, approved: &Approved) -> Result<(Self, String)> {
        let browse = approved
            .policy
            .browse
            .as_ref()
            .ok_or_else(|| anyhow!("the policy for {site} doesn't allow browsing (no [browse] section)"))?;
        let value = |field: &str| keychain::get(site, field).ok_or_else(|| anyhow!("{site}/{field} isn't stored"));
        let mut cookies = Vec::new();
        for c in &browse.cookies {
            let host = c.domain.trim_start_matches('.');
            let cookie = if host == "localhost" || host.parse::<std::net::IpAddr>().is_ok() {
                // Local test servers: plain http, and no domain cookies on an IP.
                json!({ "name": c.name, "value": value(&c.field)?, "url": format!("http://{host}/"), "sameSite": "Lax" })
            } else {
                json!({ "name": c.name, "value": value(&c.field)?, "domain": format!(".{host}"), "path": "/", "secure": true, "sameSite": "Lax" })
            };
            cookies.push(cookie);
        }
        let mut storage = Vec::new();
        for s in &browse.local_storage {
            let origin = url::Url::parse(&s.origin)?.origin().ascii_serialization();
            storage.push(json!({ "origin": origin, "key": s.key, "value": value(&s.field)? }));
        }
        let writes = match browse.writes {
            Mode::Allow => "allow",
            Mode::Ask => "ask",
            Mode::Deny => "deny",
        };
        let config = json!({
            "origins": browse.origins(),
            "requests": browse.requests(),
            "writes": writes,
            "allow_writes": browse.allow_writes,
            "start": browse.start,
            "cookies": cookies,
            "storage": storage,
            "screenshots": browse.screenshots,
        });

        let script = runner_dir().join("runner.mjs");
        if !script.exists() {
            bail!("the browser runner isn't installed ({}): run install.sh", script.display());
        }
        let mut child = Command::new("node")
            .arg(&script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("starting the browser runner (node)")?;
        let stdin = child.stdin.take().expect("piped");
        let stdout = BufReader::new(child.stdout.take().expect("piped"));
        let mut session = Self { site: site.to_string(), child, stdin, stdout, next_id: 0 };
        let text = session.call(json!({ "cmd": "open", "config": config }))?;
        Ok((session, text))
    }

    /// Send one command and wait for its answer, answering the runner's write questions on the way.
    pub fn call(&mut self, mut command: Value) -> Result<String> {
        self.next_id += 1;
        command["id"] = json!(self.next_id);
        writeln!(self.stdin, "{command}")?;
        self.stdin.flush()?;
        loop {
            let mut line = String::new();
            if self.stdout.read_line(&mut line)? == 0 {
                bail!("the browser runner stopped");
            }
            let Ok(msg) = serde_json::from_str::<Value>(&line) else { continue };
            if let Some(ask) = msg.get("ask") {
                let method = msg["method"].as_str().unwrap_or("?");
                let url = msg["url"].as_str().unwrap_or("?");
                let allow = approve::confirm(&format!("let a {} page send {method} {url}", self.site)).is_ok();
                writeln!(self.stdin, "{}", json!({ "answer": ask, "allow": allow }))?;
                self.stdin.flush()?;
                continue;
            }
            if msg["id"] != json!(self.next_id) {
                continue;
            }
            return match msg["ok"].as_bool() {
                Some(true) => Ok(msg["text"].as_str().unwrap_or("").to_string()),
                _ => Err(anyhow!("{}", msg["error"].as_str().unwrap_or("the browser runner failed"))),
            };
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = writeln!(self.stdin, "{}", json!({ "id": 0, "cmd": "close" }));
        let _ = self.stdin.flush();
        // Give the browser a moment to close cleanly, then make sure it's gone.
        for _ in 0..30 {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

//! The sandboxed browser: one headless Chromium per site, driven by the runner (a small,
//! root-installed Playwright program) on cred's behalf. cred puts the site's session into
//! it (cookies and Local Storage from stored fields), hands it the site's rules, and answers
//! its questions about writes with Touch ID. The agent only gets page text, masked.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::fs;

use anyhow::{Context, Result, anyhow, bail};
use jiff::civil::Date;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::index::today;
use crate::policy::{Approved, Mode};
use crate::util::config_dir;
use crate::{approve, keychain};

/// Writes a site's pages tried without an `allow_writes` rule are remembered, up to this many per site.
const BLOCKED_LIMIT: usize = 50;

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
            if let Some(write) = msg.get("write") {
                record_write(&self.site, write["method"].as_str().unwrap_or("?"), write["url"].as_str().unwrap_or(""));
                continue;
            }
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

/// A write that pages tried, kept so `cred info` can show what to put in `allow_writes`.
#[derive(Serialize, Deserialize)]
struct WriteSeen {
    count: u32,
    last: Date,
}

fn blocked_path(site: &str) -> PathBuf {
    config_dir().join("blocked-writes").join(format!("{site}.json"))
}

/// Remember a write a page tried (method and URL without query, never a body). Best effort.
fn record_write(site: &str, method: &str, url: &str) {
    let Ok(mut url) = url::Url::parse(url) else { return };
    url.set_query(None);
    url.set_fragment(None);
    let _ = remember(&blocked_path(site), &format!("{method} {url}"));
}

fn remember(path: &Path, entry: &str) -> Result<()> {
    let mut seen = read_seen(path);
    if seen.len() >= BLOCKED_LIMIT && !seen.contains_key(entry) {
        return Ok(());
    }
    let item = seen.entry(entry.to_string()).or_insert(WriteSeen { count: 0, last: today() });
    (item.count, item.last) = (item.count + 1, today());
    fs::create_dir_all(path.parent().context("no folder")?)?;
    fs::write(path, serde_json::to_string(&seen)?)?;
    Ok(())
}

fn read_seen(path: &Path) -> BTreeMap<String, WriteSeen> {
    fs::read_to_string(path).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

/// Writes the site's pages tried that its policy doesn't allow outright: "METHOD URL", how
/// often, and when last.
pub fn blocked_writes(site: &str, allow_writes: &[String]) -> Vec<(String, u32, Date)> {
    list_writes(&blocked_path(site), allow_writes)
}

fn list_writes(path: &Path, allow_writes: &[String]) -> Vec<(String, u32, Date)> {
    read_seen(path)
        .into_iter()
        .filter(|(entry, _)| {
            let url = entry.split_once(' ').map_or("", |(_, u)| u);
            !allow_writes.iter().any(|prefix| url.starts_with(prefix.as_str()))
        })
        .map(|(entry, seen)| (entry, seen.count, seen.last))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::TempDir;

    #[test]
    fn remembers_writes_and_hides_allowed_ones() {
        let dir = TempDir::new("cred-test").unwrap();
        let path = dir.0.join("blocked-writes/app.json");
        let telemetry = "POST https://app.example.com/api/telemetry";
        for entry in [telemetry, telemetry, "DELETE https://app.example.com/api/items/1"] {
            remember(&path, entry).unwrap();
        }
        let all = list_writes(&path, &[]);
        assert_eq!(all.len(), 2);
        assert_eq!((all[1].0.as_str(), all[1].1), (telemetry, 2));
        let rest = list_writes(&path, &["https://app.example.com/api/telemetry".to_string()]);
        assert_eq!(rest.len(), 1);
        assert!(rest[0].0.starts_with("DELETE"));
        assert!(list_writes(&dir.0.join("none.json"), &[]).is_empty());
    }

    #[test]
    fn stops_remembering_new_writes_at_the_limit() {
        let dir = TempDir::new("cred-test").unwrap();
        let path = dir.0.join("app.json");
        for i in 0..BLOCKED_LIMIT + 5 {
            remember(&path, &format!("POST https://app.example.com/{i}")).unwrap();
        }
        assert_eq!(read_seen(&path).len(), BLOCKED_LIMIT);
        remember(&path, "POST https://app.example.com/0").unwrap();
        assert_eq!(read_seen(&path)["POST https://app.example.com/0"].count, 2);
    }
}

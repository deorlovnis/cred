//! The sandboxed browser: one headless Chromium per site, driven by the runner (a small,
//! root-installed Playwright program) on cred's behalf. cred puts the site's session into
//! it (cookies and Local Storage from stored fields), hands it the site's rules, and answers
//! its questions about writes with Touch ID. The agent only gets page text, masked.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;
use std::time::Duration;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::fs;

use anyhow::{Context, Result, anyhow, bail};
use jiff::civil::Date;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::index::today;
use crate::policy::{Approved, Browse, Mode, Policy};
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

/// What a box gives the browser tools: runners in its browser VM, and the sessions it keeps
/// sealed. `cred mcp` outside a box has none and runs the browser on the Mac.
pub trait BoxBrowser: Send + Sync {
    /// Start a runner for the site in the box's browser VM (starting the VM if it isn't up),
    /// with the token the door will accept from it as that site.
    fn runner(&self, site: &str) -> Result<(Child, String)>;
    /// The site's sealed session (a Playwright `storageState`, as JSON). `Ok(None)`: there is none,
    /// or the box doesn't keep sessions. `Err`: there is one and it doesn't open.
    fn sealed(&self, site: &str) -> Result<Option<String>>;
    /// Replace the site's sealed session. Does nothing if the box doesn't keep sessions.
    fn seal(&self, site: &str, state: &str) -> Result<()>;
}

/// Where Chromium's traffic goes inside the browser VM: the shim's proxy.
const BOX_PROXY: &str = "http://127.0.0.1:3128";

/// The runner on the Mac, for `cred mcp` outside a box and for signing in by hand.
pub fn mac_runner() -> Result<Child> {
    let script = runner_dir().join("runner.mjs");
    if !script.exists() {
        bail!("the browser runner isn't installed ({}): run install.sh", script.display());
    }
    Command::new("node")
        .arg(&script)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("starting the browser runner (node)")
}

pub struct Session {
    pub site: String,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
    closed: bool,
    /// Values of the session put into this browser from a sealed state, for masking.
    pub secrets: Vec<String>,
}

impl Session {
    /// Start a browser on the Mac for the site with its session in place (the Keychain fields
    /// its policy names), and open the start page.
    pub fn open(site: &str, approved: &Approved) -> Result<(Self, String)> {
        Self::open_with(site, approved, mac_runner()?, None, None)
    }

    /// The same over any runner process: `sealed` is the session to start from instead of the
    /// Keychain fields, `proxy` the (username, password) Chromium presents to the proxy in a box.
    pub fn open_with(site: &str, approved: &Approved, mut child: Child, sealed: Option<&Value>, proxy: Option<(&str, &str)>) -> Result<(Self, String)> {
        let mut config = config(site, &approved.policy, sealed)?;
        if let Some((user, password)) = proxy {
            config["proxy"] = json!({ "server": BOX_PROXY, "username": user, "password": password });
        }
        let stdin = child.stdin.take().expect("piped");
        let stdout = BufReader::new(child.stdout.take().expect("piped"));
        let secrets = sealed.map(state_values).unwrap_or_default();
        let mut session = Self { site: site.to_string(), child, stdin, stdout, next_id: 0, closed: false, secrets };
        let text = session.call(json!({ "cmd": "open", "config": config }))?;
        Ok((session, text))
    }

    /// Send one command and wait for its answer, answering the runner's write questions on the way.
    pub fn call(&mut self, command: Value) -> Result<String> {
        let reply = self.exchange(command)?;
        Ok(reply["text"].as_str().unwrap_or("").to_string())
    }

    fn exchange(&mut self, mut command: Value) -> Result<Value> {
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
                Some(true) => Ok(msg),
                _ => Err(anyhow!("{}", msg["error"].as_str().unwrap_or("the browser runner failed"))),
            };
        }
    }

    /// Close the browser and take back the session it ends with (cookies and Local Storage, as
    /// Playwright's `storageState`), if the runner gave one.
    pub fn close(mut self) -> Result<Option<Value>> {
        self.closed = true;
        Ok(closed_state(&self.exchange(json!({ "cmd": "close" }))?))
    }
}

/// The state in a runner's answer to `close`: beside the answer or inside its text.
fn closed_state(reply: &Value) -> Option<Value> {
    let inside = || serde_json::from_str::<Value>(reply["text"].as_str()?).ok()?.get("storageState").cloned();
    reply.get("storageState").cloned().or_else(inside).filter(Value::is_object)
}

/// What the runner needs to open a site: its rules and the session to start with.
fn config(site: &str, policy: &Policy, sealed: Option<&Value>) -> Result<Value> {
    let browse = policy
        .browse
        .as_ref()
        .ok_or_else(|| anyhow!("the policy for {site} doesn't allow browsing (no [browse] section)"))?;
    let (cookies, storage) = match sealed {
        Some(state) => state_parts(state),
        None => field_parts(site, browse)?,
    };
    let writes = match browse.writes {
        Mode::Allow => "allow",
        Mode::Ask => "ask",
        Mode::Deny => "deny",
    };
    Ok(json!({
        "origins": browse.origins(),
        "requests": browse.requests(),
        "writes": writes,
        "allow_writes": browse.allow_writes,
        "start": browse.start,
        "cookies": cookies,
        "storage": storage,
        "screenshots": browse.screenshots,
    }))
}

/// The cookies and Local Storage entries the policy builds from the site's stored fields.
fn field_parts(site: &str, browse: &Browse) -> Result<(Vec<Value>, Vec<Value>)> {
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
    Ok((cookies, storage))
}

/// The same from a `storageState`: its cookies as they are, its Local Storage as flat entries.
fn state_parts(state: &Value) -> (Vec<Value>, Vec<Value>) {
    let cookies = state["cookies"].as_array().cloned().unwrap_or_default();
    let storage = state["origins"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|o| {
            let origin = o["origin"].clone();
            o["localStorage"].as_array().into_iter().flatten().map(move |e| json!({ "origin": origin, "key": e["name"], "value": e["value"] }))
        })
        .collect();
    (cookies, storage)
}

/// Every cookie and Local Storage value of a state, which masking must hide from the agent.
pub fn state_values(state: &Value) -> Vec<String> {
    let (cookies, storage) = state_parts(state);
    cookies.iter().chain(&storage).filter_map(|e| e["value"].as_str().map(str::to_string)).collect()
}

/// Whether a state holds nothing: nobody signed in.
pub fn state_is_empty(state: &Value) -> bool {
    let (cookies, storage) = state_parts(state);
    cookies.is_empty() && storage.is_empty()
}

/// The page a person signs in on: the policy's `start`, or its first origin if that is one exact
/// address.
pub fn login_start(site: &str, policy: &Policy) -> Result<String> {
    let browse = policy.browse.as_ref().ok_or_else(|| anyhow!("the policy for {site} doesn't allow browsing (no [browse] section)"))?;
    let origin = browse.origins().into_iter().next().filter(|o| !o.contains('*'));
    browse.start.clone().or(origin).ok_or_else(|| anyhow!("the policy for {site} names no page to sign in on: set start in its [browse] section"))
}

/// How a person ends a sign-in by hand before the window is closed.
pub enum Stop {
    /// Take the session as it is now.
    Done,
    /// Give up on this site.
    Skip,
}

/// A browser for a person to sign in to the site by hand: an empty profile on `start`, in a
/// window if `headed`. Ends when the window is closed, or when `stop` (asked every 100 ms) says
/// so. Returns the session, or `None` if the person skipped or the runner gave none.
pub fn sign_in(site: &str, policy: &Policy, start: &str, mut child: Child, headed: bool, mut stop: impl FnMut() -> Option<Stop>) -> Result<Option<Value>> {
    let mut config = config(site, policy, Some(&json!({})))?;
    config["start"] = json!(start);
    config["login"] = json!(true);
    config["headed"] = json!(headed);
    let mut stdin = child.stdin.take().expect("piped");
    let stdout = BufReader::new(child.stdout.take().expect("piped"));
    let (tx, lines) = mpsc::channel();
    thread::spawn(move || {
        for line in stdout.lines().map_while(Result::ok) {
            if let Ok(msg) = serde_json::from_str::<Value>(&line)
                && tx.send(msg).is_err()
            {
                return;
            }
        }
    });
    let result = (|| -> Result<Option<Value>> {
        writeln!(stdin, "{}", json!({ "id": 1, "cmd": "open", "config": config }))?;
        let mut asked_to_close = false;
        loop {
            match lines.recv_timeout(Duration::from_millis(100)) {
                Ok(msg) if msg["closed"] == json!(true) => return Ok(closed_state(&msg)),
                Ok(msg) if msg["id"] == json!(1) && msg["ok"] != json!(true) => {
                    bail!("{}", msg["error"].as_str().unwrap_or("the browser runner failed"));
                }
                Ok(msg) if msg["id"] == json!(2) => return Ok(closed_state(&msg)),
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    // The runner went away without saying why (Ctrl-C reaches it too).
                    return match stop() {
                        Some(Stop::Skip) => Ok(None),
                        _ => bail!("the browser stopped before it gave back the session"),
                    };
                }
            }
            if asked_to_close {
                continue;
            }
            match stop() {
                Some(Stop::Skip) => return Ok(None),
                Some(Stop::Done) => {
                    asked_to_close = true;
                    writeln!(stdin, "{}", json!({ "id": 2, "cmd": "close" }))?;
                }
                None => {}
            }
        }
    })();
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    result
}

/// The command that types one of the site's stored fields into a page, as far as the approved
/// policy lets cred. The runner only types it on the policy's own origins.
pub fn fill_command(site: &str, approved: &Approved, element: &str, field: &str) -> Result<Value> {
    let allowed = approved.policy.browse.as_ref().is_some_and(|b| b.fill.iter().any(|f| f == field));
    if !allowed {
        bail!("the policy for {site} doesn't let cred type {field} into pages (list it in [browse] fill)");
    }
    let value = keychain::get(site, field).ok_or_else(|| anyhow!("{site}/{field} isn't stored"))?;
    Ok(json!({ "cmd": "fill", "ref": element, "value": value }))
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.closed {
            let _ = writeln!(self.stdin, "{}", json!({ "id": 0, "cmd": "close" }));
            let _ = self.stdin.flush();
        }
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

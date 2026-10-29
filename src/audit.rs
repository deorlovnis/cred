//! The audit log: an append-only record of every agent action through `cred mcp`, one JSON
//! line each, in ~/.config/cred/audit.log. It holds time, site, tool, method, a masked URL
//! and the decision — never values, headers or bodies.
//!
//! Each line carries an HMAC-SHA256 over its content and the previous line's MAC, with a key
//! kept in the Keychain (created on first use). Editing or removing a line other than the
//! last breaks the chain from there on, which `cred audit --verify` reports. Cutting off the
//! end of the log can't be seen: there is no later line to notice it.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
#[cfg(debug_assertions)]
use std::env;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::keychain;
use crate::mask::{MASK, Masker};
use crate::util::config_dir;

/// Keychain item of the HMAC key. Resource names can't start with "_".
const KEY_RES: &str = "_audit";
const KEY_FIELD: &str = "hmac";
/// The last line is looked for in this many bytes at the end of the file.
const TAIL: u64 = 8192;
/// Longest text kept for a site, tool or URL, so lines stay short.
const MAX_NAME: usize = 100;
const MAX_URL: usize = 300;
/// Query values and path segments at least this long, made of token characters, look like secrets.
const OPAQUE_LEN: usize = 20;
/// Query keys containing one of these have their value masked whatever it looks like.
const SENSITIVE_KEYS: [&str; 14] =
    ["token", "key", "secret", "pass", "pwd", "auth", "sig", "code", "session", "cred", "jwt", "bearer", "otp", "sid"];

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Debug)]
pub enum Decision {
    #[serde(rename = "allowed")]
    Allowed,
    #[serde(rename = "asked:yes")]
    AskedYes,
    #[serde(rename = "asked:no")]
    AskedNo,
    /// Refused, or failed before it got an answer.
    #[serde(rename = "blocked")]
    Blocked,
}

/// What one line says.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Body {
    pub time: String,
    pub site: String,
    pub tool: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub decision: Decision,
    /// The box the call came from, if it came through one.
    #[serde(default, rename = "box", skip_serializing_if = "Option::is_none")]
    pub boxed: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Record {
    #[serde(flatten)]
    body: Body,
    mac: String,
}

impl Body {
    /// The entry for an action happening now. The agent supplies every text, so each is
    /// clipped and cleaned of control characters; the URL is masked.
    pub fn new(site: &str, tool: &str, method: Option<&str>, url: Option<&str>, decision: Decision, masker: &Masker) -> Self {
        Self {
            time: Timestamp::from_second(Timestamp::now().as_second()).map(|t| t.to_string()).unwrap_or_default(),
            site: clip(site, MAX_NAME),
            tool: clip(tool, MAX_NAME),
            method: method.map(|m| clip(&m.to_ascii_uppercase(), 16)),
            url: url.map(|u| mask_url(u, masker)),
            decision,
            boxed: None,
        }
    }
}

/// The decision for a call, from how the user answered the prompts it caused and whether it
/// ended in an error.
pub fn decide(answers: &[bool], failed: bool) -> Decision {
    match (answers.is_empty(), answers.iter().all(|&a| a), failed) {
        (true, _, true) => Decision::Blocked,
        (true, _, false) => Decision::Allowed,
        (false, true, _) => Decision::AskedYes,
        (false, false, _) => Decision::AskedNo,
    }
}

fn clip(text: &str, max: usize) -> String {
    let clean: String = text.chars().map(|c| if c.is_control() { '?' } else { c }).collect();
    match clean.char_indices().nth(max) {
        Some((end, _)) => format!("{}…", &clean[..end]),
        None => clean,
    }
}

fn opaque(s: &str) -> bool {
    s.len() >= OPAQUE_LEN && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_.~=:".contains(c))
}

/// A URL fit for the log: no user, password or fragment; opaque path segments and query
/// values that could be secrets masked; then the site's stored values and JWTs masked too.
pub fn mask_url(raw: &str, masker: &Masker) -> String {
    let Ok(mut url) = Url::parse(raw) else {
        return clip(&masker.mask(raw.split(['?', '#']).next().unwrap_or("")), MAX_URL);
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_fragment(None);
    if url.path() != "/" {
        let path: Vec<&str> = url.path().split('/').skip(1).map(|s| if opaque(s) { MASK } else { s }).collect();
        url.set_path(&path.join("/"));
    }
    if let Some(query) = url.query() {
        let query: Vec<String> = query
            .split('&')
            .map(|pair| match pair.split_once('=') {
                Some((k, v)) => {
                    let lower = k.to_ascii_lowercase();
                    let secret = SENSITIVE_KEYS.iter().any(|s| lower.contains(s)) || opaque(v) || masker.mask(v) != v;
                    format!("{k}={}", if secret { MASK } else { v })
                }
                None => (if opaque(pair) { MASK } else { pair }).to_string(),
            })
            .collect();
        url.set_query(Some(&query.join("&")));
    }
    clip(&masker.mask(url.as_str()), MAX_URL)
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> String {
    let mut block = [0u8; 64];
    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(block.map(|b| b ^ 0x36));
    for part in parts {
        inner.update(part);
    }
    let mut outer = Sha256::new();
    outer.update(block.map(|b| b ^ 0x5c));
    outer.update(inner.finalize());
    outer.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// The MAC of a line: over the previous line's MAC ("" for the first) and its content.
fn chain_mac(key: &[u8], prev: &str, body: &Body) -> Result<String> {
    Ok(hmac_sha256(key, &[prev.as_bytes(), b"\n", serde_json::to_string(body)?.as_bytes()]))
}

fn keychain_key(create: bool) -> Result<Vec<u8>> {
    // Tests inject a key instead of touching the Keychain. Release builds don't contain this.
    #[cfg(debug_assertions)]
    if let Ok(key) = env::var("CRED_AUDIT_KEY") {
        return Ok(key.into_bytes());
    }
    if keychain::exists(KEY_RES, KEY_FIELD) {
        return keychain::get(KEY_RES, KEY_FIELD)
            .map(String::into_bytes)
            .ok_or_else(|| anyhow!("can't read the audit key from the Keychain"));
    }
    if !create {
        bail!("the audit key isn't in the Keychain, so the log can't be verified");
    }
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let key: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    keychain::set(KEY_RES, KEY_FIELD, &key)?;
    Ok(key.into_bytes())
}

pub struct Log {
    path: PathBuf,
    key_source: Box<dyn Fn() -> Result<Vec<u8>>>,
    key: Option<Vec<u8>>,
}

impl Log {
    pub fn new(path: PathBuf, key_source: impl Fn() -> Result<Vec<u8>> + 'static) -> Self {
        Self { path, key_source: Box::new(key_source), key: None }
    }

    /// The log in its usual place with its key in the Keychain, created on first use if `create_key`.
    pub fn standard(create_key: bool) -> Self {
        // Tests run with a log of their own. Release builds don't contain this.
        #[cfg(debug_assertions)]
        if let Some(path) = env::var_os("CRED_AUDIT") {
            return Self::new(path.into(), move || keychain_key(create_key));
        }
        Self::new(config_dir().join("audit.log"), move || keychain_key(create_key))
    }

    fn key(&mut self) -> Result<Vec<u8>> {
        if self.key.is_none() {
            self.key = Some((self.key_source)()?);
        }
        Ok(self.key.clone().expect("just set"))
    }

    /// Open the log for appending and take its lock, which other `cred mcp` processes wait on.
    fn lock(&self) -> Result<File> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&self.path)
            .with_context(|| format!("opening {}", self.path.display()))?;
        file.lock()?;
        Ok(file)
    }

    /// Make sure a line can be written: the log opens and its key is there (created if need be).
    pub fn ready(&mut self) -> Result<()> {
        let _lock = self.lock()?;
        self.key().map(|_| ())
    }

    pub fn append(&mut self, body: Body) -> Result<()> {
        let mut file = self.lock()?;
        let key = self.key()?;
        let len = file.metadata()?.len();
        file.seek(SeekFrom::Start(len.saturating_sub(TAIL)))?;
        let mut tail = Vec::new();
        file.read_to_end(&mut tail)?;
        let prev = match String::from_utf8_lossy(&tail).lines().rev().find(|l| !l.trim().is_empty()) {
            Some(line) => serde_json::from_str::<Record>(line).context("the last line of the audit log is damaged")?.mac,
            None => String::new(),
        };
        let mac = chain_mac(&key, &prev, &body)?;
        let line = serde_json::to_string(&Record { body, mac })?;
        file.write_all(format!("{line}\n").as_bytes())?;
        Ok(())
    }

    /// The non-empty lines with their line numbers.
    fn lines(&self) -> Result<Vec<(usize, String)>> {
        match fs::read_to_string(&self.path) {
            Ok(text) => Ok(text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()).map(|(i, l)| (i + 1, l.to_string())).collect()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e).with_context(|| format!("reading {}", self.path.display())),
        }
    }

    /// The last `n` entries, not checked against the chain.
    pub fn recent(&self, n: usize) -> Result<Vec<Body>> {
        let lines = self.lines()?;
        lines[lines.len().saturating_sub(n)..]
            .iter()
            .map(|(no, l)| Ok(serde_json::from_str::<Record>(l).with_context(|| format!("line {no} is not an audit entry"))?.body))
            .collect()
    }

    /// Check every line against the chain; the number of lines if it holds.
    pub fn verify(&mut self) -> Result<usize> {
        let lines = self.lines()?;
        let mut prev = String::new();
        for (no, line) in &lines {
            let record: Record = serde_json::from_str(line).with_context(|| format!("line {no} is not an audit entry"))?;
            if chain_mac(&self.key()?, &prev, &record.body)? != record.mac {
                bail!("the chain breaks at line {no}: that line, or one before it, was changed or removed");
            }
            prev = record.mac;
        }
        Ok(lines.len())
    }
}

/// `cred audit`: show the last `n` entries, or with `verify` check the whole chain.
pub fn show(n: usize, verify: bool) -> Result<()> {
    let mut log = Log::standard(false);
    if verify {
        println!("{} entries, chain intact", log.verify()?);
        return Ok(());
    }
    let entries = log.recent(n)?;
    if entries.is_empty() {
        println!("no entries");
    }
    for e in entries {
        let what = [e.method.as_deref(), e.url.as_deref()].into_iter().flatten().collect::<Vec<_>>().join(" ");
        let site = match &e.boxed {
            Some(b) => format!("{b}/{}", e.site),
            None => e.site.clone(),
        };
        println!("{}  {}  {}  {}  [{}]", e.time, site, e.tool, what, serde_json::to_value(e.decision)?.as_str().unwrap_or(""));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::TempDir;

    fn log(dir: &TempDir) -> Log {
        Log::new(dir.0.join("audit.log"), || Ok(b"test-key".to_vec()))
    }

    fn entry(tool: &str) -> Body {
        Body::new("app", tool, Some("get"), Some("https://api.example.com/items"), Decision::Allowed, &Masker::new([]))
    }

    #[test]
    fn hmac_matches_rfc_4231() {
        assert_eq!(
            hmac_sha256(b"Jefe", &[b"what do ya ", b"want for nothing?"]),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // A key longer than the block is hashed first (test case 6).
        assert_eq!(
            hmac_sha256(&[0xaa; 131], &[b"Test Using Larger Than Block-Size Key - Hash Key First"]),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn chain_verifies_and_survives_reopening() {
        let dir = TempDir::new("cred-audit").unwrap();
        log(&dir).append(entry("one")).unwrap();
        log(&dir).append(entry("two")).unwrap();
        let mut l = log(&dir);
        l.append(entry("three")).unwrap();
        assert_eq!(l.verify().unwrap(), 3);
        let recent = l.recent(2).unwrap();
        assert_eq!(recent.iter().map(|b| b.tool.as_str()).collect::<Vec<_>>(), ["two", "three"]);
        assert_eq!(recent[0].method.as_deref(), Some("GET"));
    }

    #[test]
    fn empty_log_verifies() {
        let dir = TempDir::new("cred-audit").unwrap();
        assert_eq!(log(&dir).verify().unwrap(), 0);
        assert!(log(&dir).recent(5).unwrap().is_empty());
    }

    #[test]
    fn edits_and_removals_show() {
        let dir = TempDir::new("cred-audit").unwrap();
        let mut l = log(&dir);
        for tool in ["one", "two", "three", "four"] {
            l.append(entry(tool)).unwrap();
        }
        let path = dir.0.join("audit.log");
        let original = fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = original.lines().collect();
        let breaks_at = |text: String, line: &str| {
            fs::write(&path, text).unwrap();
            let err = log(&dir).verify().unwrap_err().to_string();
            assert!(err.contains(line), "{err}");
        };

        breaks_at(original.replace("\"two\"", "\"2\""), "line 2");
        // A line removed from the middle: the next one no longer follows.
        breaks_at(format!("{}\n{}\n{}\n", lines[0], lines[2], lines[3]), "line 2");
        breaks_at(format!("{}\n{}\n{}\n", lines[1], lines[2], lines[3]), "line 1");
        breaks_at(format!("{}\n{}\n{}\n{}\n", lines[0], lines[2], lines[1], lines[3]), "line 2");
        // The wrong key.
        fs::write(&path, &original).unwrap();
        assert!(Log::new(path, || Ok(b"other".to_vec())).verify().is_err());
    }

    #[test]
    fn key_is_fetched_once_and_only_when_needed() {
        use std::cell::Cell;
        use std::rc::Rc;
        let dir = TempDir::new("cred-audit").unwrap();
        let calls = Rc::new(Cell::new(0));
        let counter = Rc::clone(&calls);
        let mut l = Log::new(dir.0.join("audit.log"), move || {
            counter.set(counter.get() + 1);
            Ok(b"k".to_vec())
        });
        assert_eq!(l.verify().unwrap(), 0);
        assert!(l.recent(1).unwrap().is_empty());
        assert_eq!(calls.get(), 0);
        l.ready().unwrap();
        l.append(entry("one")).unwrap();
        l.append(entry("two")).unwrap();
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn an_unavailable_key_stops_writing() {
        let dir = TempDir::new("cred-audit").unwrap();
        let mut l = Log::new(dir.0.join("audit.log"), || bail!("no key"));
        assert!(l.ready().is_err() && l.append(entry("one")).is_err());
    }

    #[test]
    fn lines_hold_no_values() {
        let dir = TempDir::new("cred-audit").unwrap();
        let masker = Masker::new(["s3cret-value".to_string()]);
        let url = "https://u:p@api.example.com/x?a=1&token=zqx-token&q=s3cret-value#frag";
        let body = Body::new("app", "fetch\u{1b}[2J", Some("post"), Some(url), Decision::AskedNo, &masker);
        log(&dir).append(body).unwrap();
        let text = fs::read_to_string(dir.0.join("audit.log")).unwrap();
        for leaked in ["s3cret-value", "zqx-token", "frag", "u:p", "\\u001b"] {
            assert!(!text.contains(leaked), "{leaked} in {text}");
        }
        assert!(text.contains("\"decision\":\"asked:no\"") && text.contains("a=1&token=********&q=********"));
    }

    #[test]
    fn masks_urls() {
        let m = Masker::new(["hunter2hunter2".to_string()]);
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl";
        let cases = [
            ("https://api.example.com/v1/items?page=2&sort=name", "https://api.example.com/v1/items?page=2&sort=name"),
            ("https://api.example.com/", "https://api.example.com/"),
            ("https://api.example.com/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/send", "https://api.example.com/********/send"),
            ("https://api.example.com/x?api_key=short&Access-Token=1&n=3", "https://api.example.com/x?api_key=********&Access-Token=********&n=3"),
            ("https://api.example.com/x?v=0123456789abcdef0123456789abcdef", "https://api.example.com/x?v=********"),
            ("https://api.example.com/x?name=hunter2hunter2", "https://api.example.com/x?name=********"),
            ("https://api.example.com/x?flag&session", "https://api.example.com/x?flag&session"),
            ("https://api.example.com/x?q=a+b%20c", "https://api.example.com/x?q=a+b%20c"),
            ("not a url?token=abc#x", "not a url"),
        ];
        for (raw, want) in cases {
            assert_eq!(mask_url(raw, &m), want, "{raw}");
        }
        assert!(!mask_url(&format!("https://a.example.com/{jwt}"), &m).contains("eyJ"));
        assert!(mask_url(&format!("https://a.example.com/{}", "x".repeat(500)), &m).chars().count() <= MAX_URL + 1);
    }

    #[test]
    fn decides_from_prompts_and_outcome() {
        assert_eq!(decide(&[], false), Decision::Allowed);
        assert_eq!(decide(&[], true), Decision::Blocked);
        assert_eq!(decide(&[true], false), Decision::AskedYes);
        assert_eq!(decide(&[true, true], true), Decision::AskedYes);
        assert_eq!(decide(&[true, false], false), Decision::AskedNo);
        assert_eq!(decide(&[false], true), Decision::AskedNo);
    }
}

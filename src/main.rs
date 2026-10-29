//! cred — macOS Keychain-backed secrets for humans and agents.
//!
//! Values live only in the login Keychain (service "cred:<NAME>").
//! Metadata (expiry, last update, resource link, description) lives in
//! ~/.config/cred/index.json — never values. NAME is the env var the secret
//! is injected as, e.g. GITHUB_TOKEN.

use std::collections::BTreeMap;
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::sync::Arc;
use std::{env, fs, thread};

use aho_corasick::{AhoCorasick, MatchKind};
use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::{Args, Parser, Subcommand};
use jiff::civil::Date;
use jiff::Timestamp;
use jiff::tz::TimeZone;
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};
use serde::{Deserialize, Serialize};

const PREFIX: &str = "cred:";
const MASK: &[u8] = b"********";
/// Set while a refresh command runs, so a `cred run` inside it doesn't refresh again and loop.
const REFRESHING: &str = "CRED_REFRESHING";
/// Auto-refresh a secret once it is this close to expiring.
const REFRESH_MARGIN_SECS: i64 = 3600;

#[derive(Parser)]
#[command(name = "cred", version, about = "Keychain-backed secrets for humans and agents")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Default)]
struct Meta {
    /// Where the token is issued/rotated
    #[arg(long)]
    url: Option<String>,
    /// What the token is for
    #[arg(long, visible_alias = "note")]
    desc: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Store or rotate a secret (hidden prompt); also asks for link and description while they're empty
    Set {
        #[arg(value_parser = parse_name)]
        name: String,
        #[arg(long, value_parser = parse_date)]
        expires: Option<Date>,
        #[command(flatten)]
        meta: Meta,
    },
    /// Replace NAME with the clipboard contents, then clear the clipboard
    #[command(visible_alias = "rotate")]
    Update {
        #[arg(value_parser = parse_name)]
        name: String,
        #[arg(long, value_parser = parse_date)]
        expires: Option<Date>,
        #[command(flatten)]
        meta: Meta,
    },
    /// Change link/description only ("" clears; no flags = prompt)
    Describe {
        #[arg(value_parser = parse_name)]
        name: String,
        #[command(flatten)]
        meta: Meta,
    },
    /// Turn automatic refresh on (--cmd) or off (--off) for NAME; no flags shows the setting
    Auto {
        #[arg(value_parser = parse_name)]
        name: String,
        /// Shell command that prints a fresh value on stdout
        #[arg(long, conflicts_with = "off")]
        cmd: Option<String>,
        #[arg(long)]
        off: bool,
    },
    /// Refresh auto-refreshing secrets due within the hour (all named ones with --force)
    Refresh {
        names: Vec<String>,
        #[arg(long)]
        force: bool,
    },
    /// Show NAME's details (never the value)
    Info { name: String },
    /// List names, expiry, age, description (never values)
    #[command(visible_alias = "list")]
    Ls,
    /// List expired/expiring secrets; exit 1 if any
    Check {
        /// Warning window in days [default: $CRED_WARN_DAYS or 14]
        days: Option<i64>,
    },
    /// Delete a secret
    #[command(visible_alias = "delete")]
    Rm { name: String },
    /// Copy a value to the clipboard (humans only)
    Copy { name: String },
    /// Run CMD with secrets as env vars, values masked in its output
    #[command(after_help = "Also loads names listed in ./.cred (one per line, # comments ok), \
                            searching upward from the current directory.")]
    Run {
        #[arg(short = 's', long = "secret", value_name = "NAME", value_parser = parse_name)]
        secrets: Vec<String>,
        #[arg(last = true, required = true, value_name = "CMD")]
        command: Vec<String>,
    },
}

fn parse_name(s: &str) -> Result<String, String> {
    let mut chars = s.chars();
    let ok = chars.next().is_some_and(|c| c.is_ascii_uppercase() || c == '_')
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if ok { Ok(s.to_string()) } else { Err("use ENV_VAR style, e.g. GITHUB_TOKEN".into()) }
}

fn parse_date(s: &str) -> Result<Date, String> {
    match s.parse::<Date>() {
        Ok(d) if s.len() == 10 => Ok(d),
        _ => Err("must be YYYY-MM-DD".into()),
    }
}

// --- index (metadata only, never values) ---

#[derive(Serialize, Deserialize, Default)]
struct Entry {
    #[serde(default)]
    url: String,
    #[serde(default, alias = "note")]
    description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    updated: Option<Date>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires: Option<Date>,
    /// Exact expiry, read from the value when it is a JWT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<Timestamp>,
    /// Shell command that prints a fresh value; set with `cred auto`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh: Option<String>,
}

impl Entry {
    fn apply(&mut self, meta: &Meta) {
        if let Some(u) = &meta.url {
            self.url = u.clone();
        }
        if let Some(d) = &meta.desc {
            self.description = d.clone();
        }
    }

    /// Due within the hour of an exact expiry, on the expiry date, or daily when expiry is unknown.
    fn due(&self) -> bool {
        match (self.expires_at, self.expires, self.updated) {
            (Some(t), _, _) => t.as_second() - Timestamp::now().as_second() < REFRESH_MARGIN_SECS,
            (None, Some(d), _) => days_left(d) <= 0,
            (None, None, Some(u)) => u < today(),
            (None, None, None) => true,
        }
    }

    fn expired(&self) -> bool {
        match (self.expires_at, self.expires) {
            (Some(t), _) => t <= Timestamp::now(),
            (None, Some(d)) => days_left(d) < 0,
            (None, None) => false,
        }
    }
}

struct Index {
    path: PathBuf,
    map: BTreeMap<String, Entry>,
}

impl Index {
    fn load() -> Result<Self> {
        let path = env::var_os("CRED_INDEX").map(PathBuf::from).unwrap_or_else(|| {
            PathBuf::from(env::var_os("HOME").unwrap_or_default()).join(".config/cred/index.json")
        });
        let map = match fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).with_context(|| format!("reading {}", path.display()))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Self { path, map })
    }

    fn save(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        // Write then rename, so a crash never leaves a half-written index.
        let tmp = self.path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_string_pretty(&self.map)? + "\n")?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

// --- keychain, clipboard, terminal ---

fn account() -> String {
    env::var("USER").unwrap_or_default()
}

fn kc_get(name: &str) -> Option<String> {
    get_generic_password(&format!("{PREFIX}{name}"), &account())
        .ok()
        .map(|v| String::from_utf8_lossy(&v).into_owned())
}

fn kc_set(name: &str, value: &str) -> Result<()> {
    // Updates in place if the item exists, so rotation keeps the same Keychain item.
    set_generic_password(&format!("{PREFIX}{name}"), &account(), value.as_bytes())
        .with_context(|| format!("storing {name} in Keychain"))
}

fn pbpaste() -> Result<String> {
    let out = Command::new("pbpaste").output().context("running pbpaste")?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn pbcopy(data: &str) -> Result<()> {
    let mut child = Command::new("pbcopy").stdin(Stdio::piped()).spawn().context("running pbcopy")?;
    child.stdin.take().expect("piped stdin").write_all(data.as_bytes())?;
    child.wait()?;
    Ok(())
}

fn interactive() -> bool {
    io::stdin().is_terminal()
}

fn ask(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn today() -> Date {
    jiff::Zoned::now().date()
}

fn days_left(d: Date) -> i64 {
    today().until(d).map(|s| s.get_days().into()).unwrap_or(0)
}

fn local_date(t: Timestamp) -> Date {
    t.to_zoned(TimeZone::system()).date()
}

fn local_time(t: Timestamp) -> String {
    t.to_zoned(TimeZone::system()).strftime("%Y-%m-%d %H:%M").to_string()
}

/// The `exp` claim when the value is a JWT, so its expiry is known without asking.
fn jwt_exp(value: &str) -> Option<Timestamp> {
    let parts: Vec<&str> = value.split('.').collect();
    let [_, payload, _] = parts.as_slice() else { return None };
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let exp = serde_json::from_slice::<serde_json::Value>(&bytes).ok()?.get("exp")?.as_f64()?;
    let secs = (if exp > 1e12 { exp / 1000.0 } else { exp }) as i64;
    Timestamp::from_second(secs).ok()
}

fn warn_days() -> i64 {
    env::var("CRED_WARN_DAYS").ok().and_then(|v| v.parse().ok()).unwrap_or(14)
}

// --- commands ---

enum Expiry {
    Keep,
    Set(Date),
    Clear,
}

/// Store the value and its metadata; returns " (expires …)" for the caller's message.
fn store(name: &str, value: &str, expiry: Expiry, meta: &Meta) -> Result<String> {
    kc_set(name, value)?;
    let mut idx = Index::load()?;
    let e = idx.map.entry(name.to_string()).or_default();
    e.apply(meta);
    e.updated = Some(today());
    // A JWT carries its own expiry; an explicit --expires still wins for the date.
    e.expires_at = jwt_exp(value);
    let suffix = match (expiry, e.expires_at) {
        (Expiry::Set(d), _) => {
            e.expires = Some(d);
            format!(" (expires {d})")
        }
        (_, Some(t)) => {
            e.expires = Some(local_date(t));
            format!(" (expires {})", local_time(t))
        }
        (Expiry::Keep, None) => String::new(),
        (Expiry::Clear, None) => {
            e.expires = None;
            String::new()
        }
    };
    idx.save()?;
    Ok(suffix)
}

fn cmd_set(name: &str, expires: Option<Date>, mut meta: Meta) -> Result<()> {
    if !interactive() {
        bail!("set needs an interactive terminal (value is read with hidden input)");
    }
    let value = rpassword::prompt_password(format!("Value for {name}: "))?;
    if value.is_empty() {
        bail!("empty value, nothing stored");
    }
    // Ask only for fields that are still empty, so rotating a described secret stays one prompt.
    let idx = Index::load()?;
    let current = idx.map.get(name);
    if meta.url.is_none() && current.is_none_or(|e| e.url.is_empty()) {
        meta.url = Some(ask("Resource link (Enter to leave empty): ")?);
    }
    if meta.desc.is_none() && current.is_none_or(|e| e.description.is_empty()) {
        meta.desc = Some(ask("Description (Enter to leave empty): ")?);
    }
    let suffix = store(name, &value, expires.map_or(Expiry::Keep, Expiry::Set), &meta)?;
    println!("stored {name}{suffix}");
    Ok(())
}

fn cmd_update(name: &str, expires: Option<Date>, meta: Meta) -> Result<()> {
    let Some(current) = kc_get(name) else {
        bail!("{name} is not stored yet (add it with: cred set {name})");
    };
    // Strip surrounding whitespace and newlines that come along when copying from a web page.
    let value = pbpaste()?.trim().to_string();
    if value.is_empty() {
        bail!("clipboard is empty — copy the new token first");
    }
    if value.contains(char::is_whitespace) {
        bail!("clipboard contains whitespace inside the value — copy just the token");
    }
    if value == current {
        bail!("clipboard matches the stored {name} — copy the new token first");
    }

    // A rotated token has a new expiry; the old date would be wrong, so ask instead of keeping it.
    let expiry = match expires {
        Some(d) => Expiry::Set(d),
        None if jwt_exp(&value).is_some() => Expiry::Keep,
        None if interactive() => {
            let old = Index::load()?
                .map
                .get(name)
                .and_then(|e| e.expires)
                .map_or("none".to_string(), |d| d.to_string());
            let answer =
                ask(&format!("New expiry for {name}, YYYY-MM-DD (was {old}; blank = no expiry): "))?;
            if answer.is_empty() {
                Expiry::Clear
            } else {
                Expiry::Set(parse_date(&answer).map_err(|e| anyhow::anyhow!("expiry {e}"))?)
            }
        }
        None => Expiry::Clear,
    };

    let suffix = store(name, &value, expiry, &meta)?;
    println!("stored {name}{suffix}");
    pbcopy("")?;
    println!("clipboard cleared");
    Ok(())
}

fn cmd_describe(name: &str, mut meta: Meta) -> Result<()> {
    if kc_get(name).is_none() {
        bail!("{name} is not stored (add it with: cred set {name})");
    }
    let mut idx = Index::load()?;
    let e = idx.map.entry(name.to_string()).or_default();
    if meta.url.is_none() && meta.desc.is_none() {
        if !interactive() {
            bail!("give --url and/or --desc, or run in a terminal to be prompted");
        }
        // Enter keeps the current value, "-" clears it.
        let keep_or_clear = |a: String| match a.as_str() {
            "" => None,
            "-" => Some(String::new()),
            _ => Some(a),
        };
        let shown = |s: &str| if s.is_empty() { "empty".to_string() } else { s.to_string() };
        eprintln!("Enter keeps the current value, a single - clears it.");
        meta.url = keep_or_clear(ask(&format!("Resource link [{}]: ", shown(&e.url)))?);
        meta.desc = keep_or_clear(ask(&format!("Description [{}]: ", shown(&e.description)))?);
    }
    e.apply(&meta);
    idx.save()?;
    println!("updated {name}");
    Ok(())
}

fn cmd_auto(name: &str, cmd: Option<String>, off: bool) -> Result<()> {
    let mut idx = Index::load()?;
    if cmd.is_none() && !off {
        match idx.map.get(name).and_then(|e| e.refresh.as_deref()) {
            Some(c) => println!("{name} refreshes with: {c}"),
            None => println!("{name} has no auto-refresh"),
        }
        return Ok(());
    }
    let e = idx.map.entry(name.to_string()).or_default();
    e.refresh = cmd;
    // Learn the exact expiry of a value stored before, so the first refresh happens on time.
    if e.refresh.is_some()
        && e.expires_at.is_none()
        && let Some(t) = kc_get(name).as_deref().and_then(jwt_exp)
    {
        e.expires_at = Some(t);
        e.expires = Some(local_date(t));
    }
    let on = e.refresh.is_some();
    idx.save()?;
    println!("auto-refresh {} for {name}", if on { "on" } else { "off" });
    Ok(())
}

/// Run NAME's refresh command and store what it prints. Messages go to stderr,
/// so a refresh inside `cred run` never mixes into the command's output.
fn refresh_one(name: &str, cmd: &str) -> Result<()> {
    let out = Command::new("sh")
        .args(["-c", cmd])
        .env(REFRESHING, name)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| format!("running refresh command for {name}"))?;
    if !out.status.success() {
        bail!("refresh command for {name} failed ({})", out.status);
    }
    let value = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if value.is_empty() || value.contains(char::is_whitespace) {
        bail!("refresh command for {name} must print exactly one value");
    }
    let suffix = store(name, &value, Expiry::Keep, &Meta::default())?;
    eprintln!("cred: refreshed {name}{suffix}");
    Ok(())
}

/// Refresh each auto-refreshing NAME that is due (or all with force). Returns false if any failed.
fn refresh_due(names: &[String], force: bool, verbose: bool) -> bool {
    if env::var_os(REFRESHING).is_some() {
        return true;
    }
    let Ok(idx) = Index::load() else { return false };
    let mut ok = true;
    for name in names {
        let Some(e) = idx.map.get(name) else { continue };
        let Some(cmd) = &e.refresh else { continue };
        if force || e.due() {
            if let Err(err) = refresh_one(name, cmd) {
                eprintln!("cred: {err:#}");
                ok = false;
            }
        } else if verbose {
            let until = e.expires_at.map_or(String::new(), |t| format!(" (expires {})", local_time(t)));
            eprintln!("cred: {name} is fresh{until}");
        }
    }
    ok
}

fn auto_names(idx: &Index) -> Vec<String> {
    idx.map.iter().filter(|(_, e)| e.refresh.is_some()).map(|(n, _)| n.clone()).collect()
}

fn cmd_refresh(names: Vec<String>, force: bool) -> Result<u8> {
    let idx = Index::load()?;
    let names = if names.is_empty() { auto_names(&idx) } else { names };
    if names.is_empty() {
        println!("no secrets have auto-refresh (set one with: cred auto NAME --cmd ...)");
        return Ok(0);
    }
    for n in &names {
        if idx.map.get(n).is_none_or(|e| e.refresh.is_none()) {
            bail!("{n} has no auto-refresh (set one with: cred auto {n} --cmd ...)");
        }
    }
    Ok(if refresh_due(&names, force, true) { 0 } else { 1 })
}

fn cmd_info(name: &str) -> Result<()> {
    let idx = Index::load()?;
    let Some(e) = idx.map.get(name) else { bail!("{name} is not in the index") };
    let opt = |d: Option<Date>| d.map(|d| d.to_string()).unwrap_or_default();
    let in_kc = if kc_get(name).is_some() { "yes" } else { "MISSING" };
    for (k, v) in [
        ("name", name.to_string()),
        ("in-keychain", in_kc.to_string()),
        ("expires", opt(e.expires)),
        ("expires-at", e.expires_at.map(local_time).unwrap_or_default()),
        ("updated", opt(e.updated)),
        ("refresh", e.refresh.clone().unwrap_or_default()),
        ("url", e.url.clone()),
        ("description", e.description.clone()),
    ] {
        println!("{k:<12} {v}");
    }
    Ok(())
}

fn cmd_ls() -> Result<()> {
    let idx = Index::load()?;
    let warn = warn_days();
    println!("{:<32} {:<12} {:<10} {:<11} DESCRIPTION", "NAME", "EXPIRES", "STATUS", "UPDATED");
    for (name, e) in &idx.map {
        let mut status = match e.expires.map(days_left) {
            _ if e.expired() => "EXPIRED".to_string(),
            _ if e.refresh.is_some() => "auto".to_string(),
            Some(d) if d < 0 => "EXPIRED".to_string(),
            Some(d) if d <= warn => format!("{d}d left"),
            _ => "ok".to_string(),
        };
        if kc_get(name).is_none() {
            status = "MISSING".into();
        }
        let dash = |d: Option<Date>| d.map_or("-".to_string(), |d| d.to_string());
        println!(
            "{name:<32} {:<12} {status:<10} {:<11} {}",
            dash(e.expires),
            dash(e.updated),
            e.description
        );
    }
    Ok(())
}

fn cmd_check(days: Option<i64>) -> Result<u8> {
    let within = days.unwrap_or_else(warn_days);
    // Renew what can renew itself first; those are only reported if still expired afterwards.
    refresh_due(&auto_names(&Index::load()?), false, false);
    let mut bad = 0;
    for (name, e) in &Index::load()?.map {
        let Some(exp) = e.expires else { continue };
        let d = days_left(exp);
        let msg = if e.refresh.is_some() {
            if !e.expired() {
                continue;
            }
            format!("{name} expired and auto-refresh failed (cred refresh {name})")
        } else if d < 0 {
            format!("{name} expired {}d ago ({exp})", -d)
        } else if d <= within {
            format!("{name} expires in {d}d ({exp})")
        } else {
            continue;
        };
        let rotate = if e.url.is_empty() { String::new() } else { format!(" — rotate at {}", e.url) };
        println!("{msg}{rotate}");
        bad = 1;
    }
    Ok(bad)
}

fn cmd_rm(name: &str) -> Result<()> {
    if delete_generic_password(&format!("{PREFIX}{name}"), &account()).is_err() {
        eprintln!("cred: {name} not in Keychain");
    }
    let mut idx = Index::load()?;
    idx.map.remove(name);
    idx.save()?;
    println!("removed {name}");
    Ok(())
}

fn cmd_copy(name: &str) -> Result<()> {
    let Some(v) = kc_get(name) else { bail!("{name} not found") };
    pbcopy(v.trim_end_matches('\n'))?;
    println!("copied {name} to clipboard");
    Ok(())
}

fn find_credfile() -> Option<PathBuf> {
    let mut dir = env::current_dir().ok()?;
    loop {
        let f = dir.join(".cred");
        if f.is_file() {
            return Some(f);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Copy src to dst line by line, replacing every secret value with ********.
fn pump(src: impl Read, mut dst: impl Write, ac: &AhoCorasick) {
    let reps = vec![MASK; ac.patterns_len()];
    let mut r = BufReader::new(src);
    let mut line = Vec::new();
    loop {
        line.clear();
        match r.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if dst.write_all(&ac.replace_all_bytes(&line, &reps)).and_then(|_| dst.flush()).is_err() {
            break;
        }
    }
}

fn cmd_run(mut names: Vec<String>, command: Vec<String>) -> Result<u8> {
    if let Some(f) = find_credfile() {
        for line in fs::read_to_string(&f)?.lines() {
            let n: String = line.split('#').next().unwrap_or("").split_whitespace().collect();
            if !n.is_empty() {
                names.push(parse_name(&n).map_err(|e| anyhow::anyhow!("{}: '{n}': {e}", f.display()))?);
            }
        }
    }
    if names.is_empty() {
        bail!("no secrets requested (use -s NAME or a .cred file)");
    }
    // A failed refresh is reported; the stored value is still tried.
    refresh_due(&names, false, false);

    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut masks = Vec::new();
    for n in &names {
        let Some(v) = kc_get(n) else { bail!("{n} not found in Keychain (add it with: cred set {n})") };
        cmd.env(n, &v);
        if !v.is_empty() {
            masks.push(v);
        }
    }
    let ac = Arc::new(AhoCorasick::builder().match_kind(MatchKind::LeftmostLongest).build(&masks)?);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cred: {}: {e}", command[0]);
            return Ok(127);
        }
    };
    // Mask stdout and stderr so a value never reaches a log or an agent transcript.
    let (out, err) = (child.stdout.take().expect("piped"), child.stderr.take().expect("piped"));
    let a = Arc::clone(&ac);
    let t_out = thread::spawn(move || pump(out, io::stdout(), &a));
    let t_err = thread::spawn(move || pump(err, io::stderr(), &ac));
    let status = child.wait()?;
    let _ = (t_out.join(), t_err.join());
    let code = status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
    Ok(code as u8)
}

fn main() -> ExitCode {
    let ok = |r: Result<()>| r.map(|_| 0);
    let result = match Cli::parse().cmd {
        Cmd::Set { name, expires, meta } => ok(cmd_set(&name, expires, meta)),
        Cmd::Update { name, expires, meta } => ok(cmd_update(&name, expires, meta)),
        Cmd::Describe { name, meta } => ok(cmd_describe(&name, meta)),
        Cmd::Auto { name, cmd, off } => ok(cmd_auto(&name, cmd, off)),
        Cmd::Refresh { names, force } => cmd_refresh(names, force),
        Cmd::Info { name } => ok(cmd_info(&name)),
        Cmd::Ls => ok(cmd_ls()),
        Cmd::Check { days } => cmd_check(days),
        Cmd::Rm { name } => ok(cmd_rm(&name)),
        Cmd::Copy { name } => ok(cmd_copy(&name)),
        Cmd::Run { secrets, command } => cmd_run(secrets, command),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("cred: {e:#}");
            ExitCode::FAILURE
        }
    }
}

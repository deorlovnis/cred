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
use clap::{Args, Parser, Subcommand};
use jiff::civil::Date;
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};
use serde::{Deserialize, Serialize};

const PREFIX: &str = "cred:";
const MASK: &[u8] = b"********";

#[derive(Parser)]
#[command(name = "cred", version, about = "Keychain-backed secrets for humans and agents")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args)]
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
    /// Store or rotate a secret (hidden prompt); a new NAME is also asked for link and description
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

fn warn_days() -> i64 {
    env::var("CRED_WARN_DAYS").ok().and_then(|v| v.parse().ok()).unwrap_or(14)
}

// --- commands ---

enum Expiry {
    Keep,
    Set(Date),
    Clear,
}

fn store(name: &str, value: &str, expiry: Expiry, meta: &Meta) -> Result<()> {
    kc_set(name, value)?;
    let mut idx = Index::load()?;
    let e = idx.map.entry(name.to_string()).or_default();
    e.apply(meta);
    e.updated = Some(today());
    let mut suffix = String::new();
    match expiry {
        Expiry::Keep => {}
        Expiry::Set(d) => {
            e.expires = Some(d);
            suffix = format!(" (expires {d})");
        }
        Expiry::Clear => e.expires = None,
    }
    idx.save()?;
    println!("stored {name}{suffix}");
    Ok(())
}

fn cmd_set(name: &str, expires: Option<Date>, mut meta: Meta) -> Result<()> {
    if !interactive() {
        bail!("set needs an interactive terminal (value is read with hidden input)");
    }
    let value = rpassword::prompt_password(format!("Value for {name}: "))?;
    if value.is_empty() {
        bail!("empty value, nothing stored");
    }
    // Only a new NAME is asked for its link and description; rotating via set keeps them.
    if kc_get(name).is_none() {
        if meta.url.is_none() {
            meta.url = Some(ask("Resource link (Enter to leave empty): ")?);
        }
        if meta.desc.is_none() {
            meta.desc = Some(ask("Description (Enter to leave empty): ")?);
        }
    }
    store(name, &value, expires.map_or(Expiry::Keep, Expiry::Set), &meta)
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

    store(name, &value, expiry, &meta)?;
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

fn cmd_info(name: &str) -> Result<()> {
    let idx = Index::load()?;
    let Some(e) = idx.map.get(name) else { bail!("{name} is not in the index") };
    let opt = |d: Option<Date>| d.map(|d| d.to_string()).unwrap_or_default();
    let in_kc = if kc_get(name).is_some() { "yes" } else { "MISSING" };
    for (k, v) in [
        ("name", name.to_string()),
        ("in-keychain", in_kc.to_string()),
        ("expires", opt(e.expires)),
        ("updated", opt(e.updated)),
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
    let mut bad = 0;
    for (name, e) in &Index::load()?.map {
        let Some(exp) = e.expires else { continue };
        let d = days_left(exp);
        let msg = if d < 0 {
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

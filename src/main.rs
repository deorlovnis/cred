//! cred — macOS Keychain-backed secrets for humans and agents.
//!
//! Secrets are grouped by resource: one thing you sign in to (GitHub, AWS, …).
//! A resource has fields — token, user, password, … — each its own Keychain item
//! (service "cred:<resource>/<field>"). `cred run` exports only fields mapped to an
//! env var; the rest (e.g. a login) stay inside cred and reach only the resource's
//! refresh command. Metadata lives in ~/.config/cred/index.json — never values.

mod browser;

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
use jiff::Timestamp;
use jiff::civil::Date;
use jiff::tz::TimeZone;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
use security_framework::passwords::{
    delete_generic_password, get_generic_password, set_generic_password,
};
use serde::{Deserialize, Serialize};

const PREFIX: &str = "cred:";
const MASK: &[u8] = b"********";
/// Set while a refresh command runs, so a `cred run` inside it doesn't refresh again and loop.
const REFRESHING: &str = "CRED_REFRESHING";
/// Auto-refresh a field once it is this close to expiring.
const REFRESH_MARGIN_SECS: i64 = 3600;

#[derive(Parser)]
#[command(name = "cred", version, about = "Keychain-backed secrets for humans and agents")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Default)]
struct Meta {
    /// Where the resource's credentials are issued/rotated
    #[arg(long)]
    url: Option<String>,
    /// What the resource is
    #[arg(long, visible_alias = "note")]
    desc: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Store or rotate a field (hidden prompt); creates the resource and asks for what's missing
    Set {
        #[arg(value_parser = parse_resource)]
        resource: String,
        #[arg(value_parser = parse_field)]
        field: String,
        /// Export this field to `cred run` as this env var
        #[arg(long, value_parser = parse_env)]
        env: Option<String>,
        #[arg(long, value_parser = parse_date)]
        expires: Option<Date>,
        #[command(flatten)]
        meta: Meta,
    },
    /// Replace a field with the clipboard contents, then clear the clipboard
    #[command(visible_alias = "rotate")]
    Update {
        #[arg(value_parser = parse_resource)]
        resource: String,
        #[arg(value_parser = parse_field)]
        field: String,
        #[arg(long, value_parser = parse_date)]
        expires: Option<Date>,
    },
    /// Export a field to `cred run` as VAR, or --off to keep it inside cred
    Env {
        #[arg(value_parser = parse_resource)]
        resource: String,
        #[arg(value_parser = parse_field)]
        field: String,
        #[arg(value_parser = parse_env, required_unless_present = "off", conflicts_with = "off")]
        var: Option<String>,
        #[arg(long)]
        off: bool,
    },
    /// Change a resource's link/description ("" clears; no flags = prompt)
    Describe {
        #[arg(value_parser = parse_resource)]
        resource: String,
        #[command(flatten)]
        meta: Meta,
    },
    /// Refresh a field automatically (--cmd or --from) or stop (--off); no flags shows the setting
    #[command(after_help = "A --cmd command must print the new value on stdout. It gets the \
                            resource's fields that stay inside cred as CRED_<FIELD>, e.g. CRED_USER and CRED_SESSION.\n\
                            --from reads a key the browser keeps for a site after you sign in there, \
                            e.g. firefox:https://app.example.com#session_token. The value never \
                            leaves cred.")]
    Auto {
        #[arg(value_parser = parse_resource)]
        resource: String,
        #[arg(value_parser = parse_field)]
        field: String,
        /// Shell command that prints a fresh value on stdout
        #[arg(long, conflicts_with_all = ["off", "from"])]
        cmd: Option<String>,
        /// Browser Local Storage to read: BROWSER:ORIGIN#KEY
        #[arg(long, conflicts_with = "off", value_parser = parse_source)]
        from: Option<String>,
        #[arg(long)]
        off: bool,
    },
    /// Refresh auto fields due within the hour (every auto field of the named resources with --force)
    Refresh {
        #[arg(value_parser = parse_resource)]
        resources: Vec<String>,
        #[arg(long)]
        force: bool,
    },
    /// Show a resource and its fields (never values)
    Info {
        #[arg(value_parser = parse_resource)]
        resource: String,
    },
    /// List resources (never values)
    #[command(visible_alias = "list")]
    Ls,
    /// List expired/expiring fields; exit 1 if any
    Check {
        /// Warning window in days [default: $CRED_WARN_DAYS or 14]
        days: Option<i64>,
    },
    /// Delete one field, or the whole resource
    #[command(visible_alias = "delete")]
    Rm {
        #[arg(value_parser = parse_resource)]
        resource: String,
        #[arg(value_parser = parse_field)]
        field: Option<String>,
    },
    /// Copy a field's value to the clipboard (humans only)
    Copy {
        #[arg(value_parser = parse_resource)]
        resource: String,
        #[arg(value_parser = parse_field)]
        field: String,
    },
    /// Run CMD with the resources' exported fields as env vars, values masked in its output
    #[command(after_help = "Also loads resource names listed in ./.cred (one per line, # comments ok), \
                            searching upward from the current directory.")]
    Run {
        #[arg(short = 's', long = "secret", value_name = "RESOURCE", value_parser = parse_resource)]
        resources: Vec<String>,
        #[arg(last = true, required = true, value_name = "CMD")]
        command: Vec<String>,
    },
}

fn parse_resource(s: &str) -> Result<String, String> {
    let mut chars = s.chars();
    let ok = chars.next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if ok { Ok(s.to_string()) } else { Err("use lowercase letters, digits and -, e.g. github".into()) }
}

fn parse_field(s: &str) -> Result<String, String> {
    let mut chars = s.chars();
    let ok = chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if ok { Ok(s.to_string()) } else { Err("use lowercase letters, digits and _, e.g. token".into()) }
}

fn parse_env(s: &str) -> Result<String, String> {
    let mut chars = s.chars();
    let ok = chars.next().is_some_and(|c| c.is_ascii_uppercase() || c == '_')
        && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if ok { Ok(s.to_string()) } else { Err("use ENV_VAR style, e.g. GITHUB_TOKEN".into()) }
}

fn parse_source(s: &str) -> Result<String, String> {
    browser::Source::parse(s).map(|_| s.to_string())
}

fn parse_date(s: &str) -> Result<Date, String> {
    match s.parse::<Date>() {
        Ok(d) if s.len() == 10 => Ok(d),
        _ => Err("must be YYYY-MM-DD".into()),
    }
}

// --- index (metadata only, never values) ---

#[derive(Serialize, Deserialize, Default)]
struct Resource {
    #[serde(default)]
    url: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    fields: BTreeMap<String, Field>,
}

#[derive(Serialize, Deserialize, Default)]
struct Field {
    /// Env var `cred run` exports this field as; unmapped fields never leave cred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    env: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    updated: Option<Date>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires: Option<Date>,
    /// Exact expiry, read from the value when it is a JWT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expires_at: Option<Timestamp>,
    /// Shell command that prints a fresh value; set with `cred auto --cmd`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh: Option<String>,
    /// Browser source the value is read from; set with `cred auto --from`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    from: Option<String>,
}

impl Resource {
    fn apply(&mut self, meta: &Meta) {
        if let Some(u) = &meta.url {
            self.url = u.clone();
        }
        if let Some(d) = &meta.desc {
            self.description = d.clone();
        }
    }

    fn has_auto(&self) -> bool {
        self.fields.values().any(Field::is_auto)
    }
}

impl Field {
    fn is_auto(&self) -> bool {
        self.refresh.is_some() || self.from.is_some()
    }

    fn auto_text(&self) -> Option<String> {
        self.from.as_ref().map(|s| format!("from {s}")).or_else(|| self.refresh.clone())
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

    /// When it expires, comparable across exact and date-only expiries.
    fn expiry_key(&self) -> Option<Timestamp> {
        self.expires_at
            .or_else(|| self.expires?.to_zoned(TimeZone::system()).ok().map(|z| z.timestamp()))
    }

    fn expiry_text(&self) -> Option<String> {
        self.expires_at.map(local_time).or_else(|| self.expires.map(|d| d.to_string()))
    }
}

struct Index {
    path: PathBuf,
    map: BTreeMap<String, Resource>,
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

    fn get(&self, res: &str) -> Result<&Resource> {
        self.map.get(res).with_context(|| format!("{res} doesn't exist (create it with: cred set {res} FIELD)"))
    }

    fn field_mut(&mut self, res: &str, field: &str) -> Result<&mut Field> {
        self.map
            .get_mut(res)
            .and_then(|r| r.fields.get_mut(field))
            .with_context(|| format!("{res}/{field} doesn't exist (add it with: cred set {res} {field})"))
    }
}

// --- keychain, clipboard, terminal ---

fn account() -> String {
    env::var("USER").unwrap_or_default()
}

fn service(res: &str, field: &str) -> String {
    format!("{PREFIX}{res}/{field}")
}

fn kc_get(res: &str, field: &str) -> Option<String> {
    get_generic_password(&service(res, field), &account())
        .ok()
        .map(|v| String::from_utf8_lossy(&v).into_owned())
}

/// Whether the item exists, without reading its value: only reading a value can make
/// macOS ask for Keychain access, so status checks never prompt.
fn kc_exists(res: &str, field: &str) -> bool {
    ItemSearchOptions::new()
        .class(ItemClass::generic_password())
        .service(&service(res, field))
        .account(&account())
        .load_attributes(true)
        .limit(Limit::Max(1))
        .search()
        .is_ok_and(|r| !r.is_empty())
}

fn kc_set(res: &str, field: &str, value: &str) -> Result<()> {
    // Updates in place if the item exists, so rotation keeps the same Keychain item.
    set_generic_password(&service(res, field), &account(), value.as_bytes())
        .with_context(|| format!("storing {res}/{field} in Keychain"))
}

fn kc_delete(res: &str, field: &str) -> bool {
    delete_generic_password(&service(res, field), &account()).is_ok()
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

// --- time ---

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

// --- storing ---

enum Expiry {
    Keep,
    Set(Date),
    Clear,
}

/// Store a field's value and metadata; returns " (expires …)" for the caller's message.
fn store(res: &str, field: &str, value: &str, expiry: Expiry, env: Option<String>, meta: &Meta) -> Result<String> {
    kc_set(res, field, value)?;
    let mut idx = Index::load()?;
    let r = idx.map.entry(res.to_string()).or_default();
    r.apply(meta);
    let f = r.fields.entry(field.to_string()).or_default();
    if env.is_some() {
        f.env = env;
    }
    f.updated = Some(today());
    // A JWT carries its own expiry; an explicit --expires still wins for the date.
    f.expires_at = jwt_exp(value);
    let suffix = match (expiry, f.expires_at) {
        (Expiry::Set(d), _) => {
            f.expires = Some(d);
            format!(" (expires {d})")
        }
        (_, Some(t)) => {
            f.expires = Some(local_date(t));
            format!(" (expires {})", local_time(t))
        }
        (Expiry::Keep, None) => String::new(),
        (Expiry::Clear, None) => {
            f.expires = None;
            String::new()
        }
    };
    idx.save()?;
    Ok(suffix)
}

// --- commands ---

fn cmd_set(res: &str, field: &str, mut env: Option<String>, expires: Option<Date>, mut meta: Meta) -> Result<()> {
    if !interactive() {
        bail!("set needs an interactive terminal (value is read with hidden input)");
    }
    let value = rpassword::prompt_password(format!("Value for {res}/{field}: "))?;
    if value.is_empty() {
        bail!("empty value, nothing stored");
    }
    // Ask only for what is still missing, so rotating a set-up field stays one prompt.
    let idx = Index::load()?;
    let r = idx.map.get(res);
    if meta.url.is_none() && r.is_none_or(|r| r.url.is_empty()) {
        meta.url = Some(ask(&format!("Resource link for {res} (Enter to leave empty): "))?);
    }
    if meta.desc.is_none() && r.is_none_or(|r| r.description.is_empty()) {
        meta.desc = Some(ask(&format!("Description of {res} (Enter to leave empty): "))?);
    }
    if env.is_none() && r.is_none_or(|r| !r.fields.contains_key(field)) {
        let var = ask(&format!("Export {res}/{field} to `cred run` as env var (Enter keeps it inside cred): "))?;
        if !var.is_empty() {
            env = Some(parse_env(&var).map_err(|e| anyhow::anyhow!("env var {e}"))?);
        }
    }
    let suffix = store(res, field, &value, expires.map_or(Expiry::Keep, Expiry::Set), env, &meta)?;
    println!("stored {res}/{field}{suffix}");
    Ok(())
}

fn cmd_update(res: &str, field: &str, expires: Option<Date>) -> Result<()> {
    let Some(current) = kc_get(res, field) else {
        bail!("{res}/{field} is not stored yet (add it with: cred set {res} {field})");
    };
    // Strip surrounding whitespace and newlines that come along when copying from a web page.
    let value = pbpaste()?.trim().to_string();
    if value.is_empty() {
        bail!("clipboard is empty — copy the new value first");
    }
    if value.contains(char::is_whitespace) {
        bail!("clipboard contains whitespace inside the value — copy just the token");
    }
    if value == current {
        bail!("clipboard matches the stored {res}/{field} — copy the new value first");
    }

    // A rotated token has a new expiry; the old date would be wrong, so ask instead of keeping it.
    let expiry = match expires {
        Some(d) => Expiry::Set(d),
        None if jwt_exp(&value).is_some() => Expiry::Keep,
        None if interactive() => {
            let old = Index::load()?
                .map
                .get(res)
                .and_then(|r| r.fields.get(field))
                .and_then(|f| f.expires)
                .map_or("none".to_string(), |d| d.to_string());
            let answer = ask(&format!(
                "New expiry for {res}/{field}, YYYY-MM-DD (was {old}; blank = no expiry): "
            ))?;
            if answer.is_empty() {
                Expiry::Clear
            } else {
                Expiry::Set(parse_date(&answer).map_err(|e| anyhow::anyhow!("expiry {e}"))?)
            }
        }
        None => Expiry::Clear,
    };

    let suffix = store(res, field, &value, expiry, None, &Meta::default())?;
    println!("stored {res}/{field}{suffix}");
    pbcopy("")?;
    println!("clipboard cleared");
    Ok(())
}

fn cmd_env(res: &str, field: &str, var: Option<String>) -> Result<()> {
    let mut idx = Index::load()?;
    let f = idx.field_mut(res, field)?;
    f.env = var;
    let msg = match &f.env {
        Some(v) => format!("cred run exports {res}/{field} as {v}"),
        None => format!("{res}/{field} stays inside cred"),
    };
    idx.save()?;
    println!("{msg}");
    Ok(())
}

fn cmd_describe(res: &str, mut meta: Meta) -> Result<()> {
    let mut idx = Index::load()?;
    idx.get(res)?;
    let r = idx.map.get_mut(res).expect("checked above");
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
        meta.url = keep_or_clear(ask(&format!("Resource link [{}]: ", shown(&r.url)))?);
        meta.desc = keep_or_clear(ask(&format!("Description [{}]: ", shown(&r.description)))?);
    }
    r.apply(&meta);
    idx.save()?;
    println!("updated {res}");
    Ok(())
}

fn cmd_auto(res: &str, field: &str, cmd: Option<String>, from: Option<String>, off: bool) -> Result<()> {
    let mut idx = Index::load()?;
    if cmd.is_none() && from.is_none() && !off {
        let current = idx.map.get(res).and_then(|r| r.fields.get(field)).and_then(Field::auto_text);
        match current {
            Some(c) => println!("{res}/{field} refreshes with: {c}"),
            None => println!("{res}/{field} has no auto-refresh"),
        }
        return Ok(());
    }
    // Auto-refresh may be set up before the first value exists; the first refresh creates it.
    let f = idx.map.entry(res.to_string()).or_default().fields.entry(field.to_string()).or_default();
    f.refresh = cmd;
    f.from = from;
    // Learn the exact expiry of a value stored before, so the first refresh happens on time.
    if f.is_auto()
        && f.expires_at.is_none()
        && let Some(t) = kc_get(res, field).as_deref().and_then(jwt_exp)
    {
        f.expires_at = Some(t);
        f.expires = Some(local_date(t));
    }
    let on = f.is_auto();
    idx.save()?;
    println!("auto-refresh {} for {res}/{field}", if on { "on" } else { "off" });
    Ok(())
}

/// Get a field's fresh value from its browser source or refresh command, and store it.
/// Messages go to stderr, so a refresh inside `cred run` never mixes into the command's output.
fn refresh_one(res: &str, r: &Resource, field: &str, f: &Field) -> Result<()> {
    let value = match (&f.from, &f.refresh) {
        (Some(spec), _) => browser::Source::parse(spec).map_err(anyhow::Error::msg)?.read()?,
        (None, Some(cmd)) => run_refresh_cmd(res, r, field, cmd)?,
        (None, None) => bail!("{res}/{field} has no auto-refresh"),
    };
    let value = value.trim();
    if value.is_empty() || value.contains(char::is_whitespace) {
        bail!("refresh of {res}/{field} must produce exactly one value");
    }
    let suffix = store(res, field, value, Expiry::Keep, None, &Meta::default())?;
    eprintln!("cred: refreshed {res}/{field}{suffix}");
    Ok(())
}

/// Run a refresh command with the resource's internal fields as CRED_<FIELD>; returns its stdout.
fn run_refresh_cmd(res: &str, r: &Resource, field: &str, cmd: &str) -> Result<String> {
    let mut command = Command::new("sh");
    // Inputs are the fields kept inside cred (login, session); exported fields are outputs,
    // and skipping them saves a Keychain read (and possibly an access prompt) each.
    for (name, _) in r.fields.iter().filter(|(_, f)| f.env.is_none()) {
        if let Some(v) = kc_get(res, name) {
            command.env(format!("CRED_{}", name.to_uppercase()), v);
        }
    }
    let out = command
        .args(["-c", cmd])
        .env(REFRESHING, res)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| format!("running refresh command for {res}/{field}"))?;
    if !out.status.success() {
        bail!("refresh command for {res}/{field} failed ({})", out.status);
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Refresh each auto field of the given resources that is due (or all with force).
/// Returns false if any refresh failed.
fn refresh_due(resources: &[String], force: bool, verbose: bool) -> bool {
    if env::var_os(REFRESHING).is_some() {
        return true;
    }
    let Ok(idx) = Index::load() else { return false };
    let mut ok = true;
    for res in resources {
        let Some(r) = idx.map.get(res) else { continue };
        let due: Vec<&String> = r.fields.iter().filter(|(_, f)| f.is_auto() && (force || f.due())).map(|(n, _)| n).collect();
        // Browser-sourced fields are cheap to re-read and usually feed the others (a session that
        // mints a token), so whenever anything is due they go first.
        let mut order: Vec<&String> = Vec::new();
        if !due.is_empty() {
            order.extend(r.fields.iter().filter(|(_, f)| f.from.is_some()).map(|(n, _)| n));
            order.extend(due.iter().copied().filter(|n| r.fields[*n].from.is_none()));
        }
        for field in &order {
            if let Err(err) = refresh_one(res, r, field, &r.fields[*field]) {
                eprintln!("cred: {err:#}");
                ok = false;
            }
        }
        if verbose {
            for (field, f) in r.fields.iter().filter(|(n, f)| f.is_auto() && !order.contains(n)) {
                let until = f.expiry_text().map_or(String::new(), |t| format!(" (expires {t})"));
                eprintln!("cred: {res}/{field} is fresh{until}");
            }
        }
    }
    ok
}

fn auto_resources(idx: &Index) -> Vec<String> {
    idx.map.iter().filter(|(_, r)| r.has_auto()).map(|(n, _)| n.clone()).collect()
}

fn cmd_refresh(resources: Vec<String>, force: bool) -> Result<u8> {
    let idx = Index::load()?;
    let resources = if resources.is_empty() { auto_resources(&idx) } else { resources };
    if resources.is_empty() {
        println!("nothing has auto-refresh (set it with: cred auto RESOURCE FIELD --cmd ...)");
        return Ok(0);
    }
    for res in &resources {
        if !idx.get(res)?.has_auto() {
            bail!("{res} has no auto-refresh field (set one with: cred auto {res} FIELD --cmd ...)");
        }
    }
    Ok(if refresh_due(&resources, force, true) { 0 } else { 1 })
}

fn cmd_info(res: &str) -> Result<()> {
    let idx = Index::load()?;
    let r = idx.get(res)?;
    println!("{:<12} {res}", "name");
    println!("{:<12} {}", "url", r.url);
    println!("{:<12} {}", "description", r.description);
    for (name, f) in &r.fields {
        let mut parts = vec![if kc_exists(res, name) { "stored" } else { "MISSING" }.to_string()];
        parts.push(f.env.as_ref().map_or("inside cred".to_string(), |v| format!("exported as {v}")));
        if let Some(t) = f.expiry_text() {
            parts.push(format!("expires {t}"));
        }
        if let Some(u) = f.updated {
            parts.push(format!("updated {u}"));
        }
        println!("{name:<12} {}", parts.join(", "));
        if let Some(auto) = f.auto_text() {
            println!("{:<12}   auto-refresh: {auto}", "");
        }
    }
    Ok(())
}

/// A field's status label and how urgent it is (higher = worse), for picking a resource's status.
fn field_status(res: &str, name: &str, f: &Field, warn: i64) -> (i64, String) {
    if !kc_exists(res, name) {
        return (i64::MAX, "MISSING".into());
    }
    if f.expired() {
        return (i64::MAX - 1, "EXPIRED".into());
    }
    if f.is_auto() {
        return (1, "auto".into());
    }
    match f.expires.map(days_left) {
        // Fewer days left is more urgent.
        Some(d) if d <= warn => (1000 - d, format!("{d}d left")),
        _ => (0, "ok".into()),
    }
}

fn cmd_ls() -> Result<()> {
    let idx = Index::load()?;
    let warn = warn_days();
    println!("{:<20} {:<9} {:<17} {:<34} DESCRIPTION", "RESOURCE", "STATUS", "EXPIRES", "FIELDS");
    for (res, r) in &idx.map {
        let status = r
            .fields
            .iter()
            .map(|(n, f)| field_status(res, n, f, warn))
            .max_by_key(|(rank, _)| *rank)
            .map_or("empty".to_string(), |(_, s)| s);
        let expires = r
            .fields
            .values()
            .filter_map(|f| Some((f.expiry_key()?, f.expiry_text()?)))
            .min_by_key(|(key, _)| *key)
            .map_or("-".to_string(), |(_, text)| text);
        let fields: Vec<String> = r
            .fields
            .iter()
            .map(|(n, f)| f.env.as_ref().map_or(n.clone(), |v| format!("{n}→{v}")))
            .collect();
        println!("{res:<20} {status:<9} {expires:<17} {:<34} {}", fields.join(", "), r.description);
    }
    Ok(())
}

fn cmd_check(days: Option<i64>) -> Result<u8> {
    let within = days.unwrap_or_else(warn_days);
    // Renew what can renew itself first; those are only reported if still expired afterwards.
    refresh_due(&auto_resources(&Index::load()?), false, false);
    let mut bad = 0;
    for (res, r) in &Index::load()?.map {
        for (name, f) in &r.fields {
            let Some(exp) = f.expires else { continue };
            let d = days_left(exp);
            let msg = if f.is_auto() {
                if !f.expired() {
                    continue;
                }
                format!("{res}/{name} expired and auto-refresh failed (cred refresh {res})")
            } else if d < 0 {
                format!("{res}/{name} expired {}d ago ({exp})", -d)
            } else if d <= within {
                format!("{res}/{name} expires in {d}d ({exp})")
            } else {
                continue;
            };
            let rotate = if r.url.is_empty() { String::new() } else { format!(" — rotate at {}", r.url) };
            println!("{msg}{rotate}");
            bad = 1;
        }
    }
    Ok(bad)
}

fn cmd_rm(res: &str, field: Option<String>) -> Result<()> {
    let mut idx = Index::load()?;
    let names: Vec<String> = match &field {
        Some(f) => vec![f.clone()],
        None => idx.get(res)?.fields.keys().cloned().collect(),
    };
    for name in &names {
        if !kc_delete(res, name) {
            eprintln!("cred: {res}/{name} not in Keychain");
        }
    }
    match field {
        Some(f) => {
            if let Some(r) = idx.map.get_mut(res) {
                r.fields.remove(&f);
            }
            println!("removed {res}/{f}");
        }
        None => {
            idx.map.remove(res);
            println!("removed {res}");
        }
    }
    idx.save()
}

fn cmd_copy(res: &str, field: &str) -> Result<()> {
    let Some(v) = kc_get(res, field) else { bail!("{res}/{field} not found") };
    pbcopy(v.trim_end_matches('\n'))?;
    println!("copied {res}/{field} to clipboard");
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

fn cmd_run(mut resources: Vec<String>, command: Vec<String>) -> Result<u8> {
    if let Some(f) = find_credfile() {
        for line in fs::read_to_string(&f)?.lines() {
            let n: String = line.split('#').next().unwrap_or("").split_whitespace().collect();
            if !n.is_empty() {
                resources.push(parse_resource(&n).map_err(|e| anyhow::anyhow!("{}: '{n}': {e}", f.display()))?);
            }
        }
    }
    if resources.is_empty() {
        bail!("no resources requested (use -s RESOURCE or a .cred file)");
    }
    // A failed refresh is reported; the stored value is still tried.
    refresh_due(&resources, false, false);

    let idx = Index::load()?;
    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut masks = Vec::new();
    for res in &resources {
        let r = idx.get(res)?;
        let exported: Vec<(&String, &String)> =
            r.fields.iter().filter_map(|(n, f)| f.env.as_ref().map(|v| (n, v))).collect();
        if exported.is_empty() {
            bail!("{res} exports no fields (map one with: cred env {res} FIELD VAR)");
        }
        for (name, var) in exported {
            let Some(v) = kc_get(res, name) else {
                bail!("{res}/{name} not found in Keychain (add it with: cred set {res} {name})")
            };
            cmd.env(var, &v);
            if !v.is_empty() {
                masks.push(v);
            }
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
        Cmd::Set { resource, field, env, expires, meta } => ok(cmd_set(&resource, &field, env, expires, meta)),
        Cmd::Update { resource, field, expires } => ok(cmd_update(&resource, &field, expires)),
        Cmd::Env { resource, field, var, off: _ } => ok(cmd_env(&resource, &field, var)),
        Cmd::Describe { resource, meta } => ok(cmd_describe(&resource, meta)),
        Cmd::Auto { resource, field, cmd, from, off } => ok(cmd_auto(&resource, &field, cmd, from, off)),
        Cmd::Refresh { resources, force } => cmd_refresh(resources, force),
        Cmd::Info { resource } => ok(cmd_info(&resource)),
        Cmd::Ls => ok(cmd_ls()),
        Cmd::Check { days } => cmd_check(days),
        Cmd::Rm { resource, field } => ok(cmd_rm(&resource, field)),
        Cmd::Copy { resource, field } => ok(cmd_copy(&resource, &field)),
        Cmd::Run { resources, command } => cmd_run(resources, command),
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("cred: {e:#}");
            ExitCode::FAILURE
        }
    }
}

//! cred — macOS Keychain-backed secrets for humans and agents.
//!
//! Secrets are grouped by resource: one thing you sign in to (GitHub, AWS, …). A resource has
//! fields — token, user, password, … — each its own Keychain item. What may happen to them is
//! decided by the resource's policy, which counts only once approved with Touch ID: which
//! fields `cred run` exports, how fields refresh, and what an agent may do through `cred mcp`.
//! Agents never get the credentials themselves.

mod approve;
mod audit;
mod boxes;
mod browse;
mod browser;
mod chain;
mod door;
mod engine;
mod fetch;
mod index;
mod keychain;
mod limits;
mod mask;
mod mcp;
mod policy;
mod refresh;
mod seal;
mod util;

use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::sync::Arc;
use std::{env, fs, thread};

use aho_corasick::{AhoCorasick, MatchKind};
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use jiff::civil::Date;

use index::{Expiry, Field, Index, Meta, days_left, jwt_exp, store, warn_days};
use policy::Mode;
use refresh::{auto_resources, refresh_due};

const MASK: &[u8] = b"********";

#[derive(Parser)]
#[command(name = "cred", version, about = "Keychain-backed secrets for humans and agents")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Store or rotate a field (hidden prompt); creates the resource and asks for what's missing
    Set {
        #[arg(value_parser = parse_resource)]
        resource: String,
        #[arg(value_parser = parse_field)]
        field: String,
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
    /// Change a resource's link/description ("" clears; no flags = prompt)
    Describe {
        #[arg(value_parser = parse_resource)]
        resource: String,
        #[command(flatten)]
        meta: Meta,
    },
    /// Show, edit or approve a resource's policy (what may happen to its secrets)
    Policy {
        #[command(subcommand)]
        action: PolicyCmd,
    },
    /// Refresh fields due within the hour, as the policies say (all of them with --force)
    Refresh {
        #[arg(value_parser = parse_resource)]
        resources: Vec<String>,
        #[arg(long)]
        force: bool,
    },
    /// Show a resource, its policy and its fields (never values)
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
    /// Copy a field's value to the clipboard (asks for Touch ID)
    Copy {
        #[arg(value_parser = parse_resource)]
        resource: String,
        #[arg(value_parser = parse_field)]
        field: String,
    },
    /// Run CMD with the fields the policies export, values masked in its output
    #[command(after_help = "Each resource's policy decides: [run] mode = allow, ask (Touch ID) or deny. \
                            Also loads resource names listed in ./.cred (one per line, # comments ok), \
                            searching upward from the current directory.")]
    Run {
        #[arg(short = 's', long = "secret", value_name = "RESOURCE", value_parser = parse_resource)]
        resources: Vec<String>,
        #[arg(last = true, required = true, value_name = "CMD")]
        command: Vec<String>,
    },
    /// Serve agents over MCP (stdio): requests and site tools, credentials added by cred
    Mcp,
    /// Show what agents did through `cred mcp` (never values); --verify checks nothing was altered
    Audit {
        /// How many of the latest entries to show
        #[arg(short = 'n', long, default_value_t = 20)]
        last: usize,
        /// Check the whole log against its Keychain-held HMAC chain
        #[arg(long)]
        verify: bool,
    },
    /// Re-create Keychain items so only the running cred may read them (after re-signing cred)
    Reseal {
        #[arg(value_parser = parse_resource)]
        resources: Vec<String>,
    },
    /// Boxes: isolated, encrypted places where an agent works, with cred as its only door
    #[command(name = "box")]
    Box {
        #[command(subcommand)]
        action: BoxCmd,
    },
}

#[derive(Subcommand)]
enum BoxCmd {
    /// Make a box: edit its policy from a template, create its key and an empty encrypted store
    New {
        #[arg(value_parser = boxes::parse_name)]
        name: String,
    },
    /// Open a box's policy in $EDITOR; shows what changed from the approved one
    Edit {
        #[arg(value_parser = boxes::parse_name)]
        name: String,
    },
    /// Approve box policies with one Touch ID (all of them if none named); until then they have no effect
    Approve {
        #[arg(value_parser = boxes::parse_name)]
        names: Vec<String>,
    },
    /// Open a box (Touch ID) and work in it; joins it if it runs already
    #[command(after_help = "Without CMD, runs the policy's `run` (claude). --temp makes a throwaway box with the \
                            same policy, shredded when it stops. Ctrl-C or closing the terminal stops the box.")]
    Run {
        /// A throwaway box: new store, key never written down, gone when it stops
        #[arg(long)]
        temp: bool,
        #[arg(value_parser = boxes::parse_name)]
        name: String,
        #[arg(last = true, value_name = "CMD")]
        command: Vec<String>,
    },
    /// List boxes: open or locked, policy status, size, sites, last used
    #[command(visible_alias = "list")]
    Ls,
    /// Show what went through a box's door (Touch ID unless it is open)
    Log {
        #[arg(value_parser = boxes::parse_name)]
        name: String,
        /// How many of the latest lines to show
        #[arg(short = 'n', long, default_value_t = 50)]
        last: usize,
        /// Check the whole log against its chain instead: fails at the first line that was changed or removed
        #[arg(long)]
        verify: bool,
    },
    /// Stop a running box and lock it
    Stop { name: String },
    /// Copy a file or folder out of a box (Touch ID); lists each file with its size and sha256
    Export {
        #[arg(value_parser = boxes::parse_name)]
        name: String,
        /// Path inside the box, e.g. work/report.md
        path: String,
        /// Folder on this Mac to copy it into
        #[arg(long, value_name = "DIR")]
        to: PathBuf,
    },
    /// Copy a file or folder into a box's work/ folder (box stopped)
    Import {
        #[arg(value_parser = boxes::parse_name)]
        name: String,
        path: String,
    },
    /// Sign in to a box's sites by hand, in a window on this Mac; cred seals each session into the box (Touch ID, box stopped)
    #[command(after_help = "Without SITE, goes through the box's sites that allow browsing and have no sealed session yet, one window after another. \
Closing a window (or Enter) takes the session; Ctrl-C skips that site. --all signs in again to the ones that have a session.")]
    Login {
        #[arg(value_parser = boxes::parse_name)]
        name: String,
        #[arg(value_parser = parse_resource)]
        site: Option<String>,
        /// Include sites that already have a sealed session
        #[arg(long)]
        all: bool,
    },
    /// Delete a box for good: its key first, then its store (Touch ID)
    Rm {
        #[arg(value_parser = boxes::parse_name)]
        name: String,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Print the policy and whether it is approved
    Show {
        #[arg(value_parser = parse_resource)]
        resource: String,
    },
    /// Open the policy in $EDITOR (a template if new); approve it afterwards
    Edit {
        #[arg(value_parser = parse_resource)]
        resource: String,
    },
    /// Approve policies with one Touch ID (all of them if none named); until then they have no effect
    Approve {
        #[arg(value_parser = parse_resource)]
        resources: Vec<String>,
    },
}

fn parse_resource(s: &str) -> Result<String, String> {
    let mut chars = s.chars();
    let ok = chars.next().is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if ok { Ok(s.to_string()) } else { Err("use lowercase letters, digits and -, e.g. github".into()) }
}

fn parse_field(s: &str) -> Result<String, String> {
    let mut chars = s.chars();
    let ok = chars.next().is_some_and(|c| c.is_ascii_lowercase()) && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    if ok { Ok(s.to_string()) } else { Err("use lowercase letters, digits and _, e.g. token".into()) }
}

fn parse_env(s: &str) -> Result<String, String> {
    let mut chars = s.chars();
    let ok = chars.next().is_some_and(|c| c.is_ascii_uppercase() || c == '_') && chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if ok { Ok(s.to_string()) } else { Err("use ENV_VAR style, e.g. GITHUB_TOKEN".into()) }
}

fn parse_date(s: &str) -> Result<Date, String> {
    match s.parse::<Date>() {
        Ok(d) if s.len() == 10 => Ok(d),
        _ => Err("must be YYYY-MM-DD".into()),
    }
}

// --- clipboard, terminal ---

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

// --- commands ---

fn cmd_set(res: &str, field: &str, expires: Option<Date>, mut meta: Meta) -> Result<()> {
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
    let suffix = store(res, field, &value, expires.map_or(Expiry::Keep, Expiry::Set), &meta)?;
    println!("stored {res}/{field}{suffix}");
    if policy::path(res).exists() {
        return Ok(());
    }
    println!("{res} has no policy, so nothing can use it yet (cred policy edit {res})");
    Ok(())
}

fn cmd_update(res: &str, field: &str, expires: Option<Date>) -> Result<()> {
    let Some(current) = keychain::get(res, field) else {
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
            let old = Index::load()?.map.get(res).and_then(|r| r.fields.get(field)).and_then(|f| f.expires).map_or("none".to_string(), |d| d.to_string());
            let answer = ask(&format!("New expiry for {res}/{field}, YYYY-MM-DD (was {old}; blank = no expiry): "))?;
            if answer.is_empty() { Expiry::Clear } else { Expiry::Set(parse_date(&answer).map_err(|e| anyhow::anyhow!("expiry {e}"))?) }
        }
        None => Expiry::Clear,
    };

    let suffix = store(res, field, &value, expiry, &Meta::default())?;
    println!("stored {res}/{field}{suffix}");
    pbcopy("")?;
    println!("clipboard cleared");
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

fn cmd_refresh(resources: Vec<String>, force: bool) -> Result<u8> {
    let resources = if resources.is_empty() { auto_resources() } else { resources };
    if resources.is_empty() {
        println!("nothing refreshes (add a [refresh.FIELD] section to a policy)");
        return Ok(0);
    }
    for res in &resources {
        if policy::load(res)?.policy.refresh.is_empty() {
            bail!("the policy for {res} refreshes nothing (add a [refresh.FIELD] section)");
        }
    }
    Ok(if refresh_due(&resources, force, true) { 0 } else { 1 })
}

fn cmd_info(res: &str) -> Result<()> {
    let idx = Index::load()?;
    let r = idx.get(res)?;
    let approved = policy::load(res).ok();
    println!("{:<12} {res}", "name");
    println!("{:<12} {}", "url", r.url);
    println!("{:<12} {}", "description", r.description);
    let status = policy::status(res);
    println!("{:<12} {} ({})", "policy", status.text(), policy::path(res).display());
    match &approved {
        // Lines about what agents may do. Further ones (e.g. blocked browser writes) go here.
        Some(a) => {
            for (label, text) in a.policy.rules() {
                println!("  {label:<10} {text}");
            }
        }
        None if !matches!(status, policy::Status::Missing) => {
            println!("  nothing in it applies until approved (cred policy approve {res})");
        }
        None => {}
    }
    for (name, f) in &r.fields {
        let mut parts = vec![if keychain::exists(res, name) { "stored" } else { "MISSING" }.to_string()];
        let export = approved.as_ref().and_then(|a| a.policy.run.export.get(name));
        parts.push(export.map_or("inside cred".to_string(), |v| format!("exported as {v}")));
        if let Some(t) = f.expiry_text() {
            parts.push(format!("expires {t}"));
        }
        if let Some(u) = f.updated {
            parts.push(format!("updated {u}"));
        }
        println!("{name:<12} {}", parts.join(", "));
        if let Some(r) = approved.as_ref().and_then(|a| a.policy.refresh.get(name)) {
            let how = r.from.as_ref().map_or_else(|| format!("run {}", r.run.as_deref().unwrap_or("")), |f| format!("from {f}"));
            println!("{:<12}   auto-refresh: {how}", "");
        }
    }
    let allowed = approved.as_ref().and_then(|a| a.policy.browse.as_ref()).map_or(&[][..], |b| &b.allow_writes[..]);
    let writes = browse::blocked_writes(res, allowed);
    if !writes.is_empty() {
        println!("{:<12} writes pages tried without an allow_writes rule (add a URL prefix under [browse] to allow one):", "browser");
        for (what, count, last) in writes {
            println!("{:<12}   {what} (x{count}, last {last})", "");
        }
    }
    Ok(())
}

/// A field's status label and how urgent it is (higher = worse), for picking a resource's status.
fn field_status(res: &str, name: &str, f: &Field, auto: bool, warn: i64) -> (i64, String) {
    if !keychain::exists(res, name) {
        return (i64::MAX, "MISSING".into());
    }
    if f.expired() {
        return (i64::MAX - 1, "EXPIRED".into());
    }
    if auto {
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
    println!("{:<20} {:<9} {:<17} {:<34} {:<26} DESCRIPTION", "RESOURCE", "STATUS", "EXPIRES", "FIELDS", "POLICY");
    for (res, r) in &idx.map {
        let approved = policy::load(res).ok();
        let auto = |n: &str| approved.as_ref().is_some_and(|a| a.policy.refresh.contains_key(n));
        let status = r.fields.iter().map(|(n, f)| field_status(res, n, f, auto(n), warn)).max_by_key(|(rank, _)| *rank).map_or("empty".to_string(), |(_, s)| s);
        let expires = r.fields.values().filter_map(|f| Some((f.expiry_key()?, f.expiry_text()?))).min_by_key(|(key, _)| *key).map_or("-".to_string(), |(_, text)| text);
        let fields: Vec<String> = r
            .fields
            .keys()
            .map(|n| match approved.as_ref().and_then(|a| a.policy.run.export.get(n)) {
                Some(v) => format!("{n}→{v}"),
                None => n.clone(),
            })
            .collect();
        let policy = match &approved {
            Some(a) => a.policy.summary(),
            None => policy::status(res).text().to_string(),
        };
        println!("{res:<20} {status:<9} {expires:<17} {:<34} {policy:<26} {}", fields.join(", "), r.description);
    }
    Ok(())
}

fn cmd_check(days: Option<i64>) -> Result<u8> {
    let within = days.unwrap_or_else(warn_days);
    // Renew what can renew itself first; those are only reported if still expired afterwards.
    refresh_due(&auto_resources(), false, false);
    let mut bad = 0;
    for (res, r) in &Index::load()?.map {
        let approved = policy::load(res).ok();
        for (name, f) in &r.fields {
            let Some(exp) = f.expires else { continue };
            let d = days_left(exp);
            let msg = if approved.as_ref().is_some_and(|a| a.policy.refresh.contains_key(name)) {
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
        if !keychain::delete(res, name) {
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
            policy::revoke(res);
            println!("removed {res}");
        }
    }
    idx.save()
}

fn cmd_copy(res: &str, field: &str) -> Result<()> {
    let Some(v) = keychain::get(res, field) else { bail!("{res}/{field} not found") };
    approve::confirm(&format!("copy {res}/{field} to the clipboard"))?;
    pbcopy(v.trim_end_matches('\n'))?;
    println!("copied {res}/{field} to clipboard");
    Ok(())
}

fn cmd_reseal(resources: Vec<String>) -> Result<()> {
    let idx = Index::load()?;
    let resources = if resources.is_empty() { idx.map.keys().cloned().collect() } else { resources };
    for res in &resources {
        for name in idx.get(res)?.fields.keys() {
            // Reading may ask for Keychain access once; the new item needs no approval.
            let Some(value) = keychain::get(res, name) else {
                eprintln!("cred: {res}/{name} not in Keychain, skipped");
                continue;
            };
            keychain::replace(res, name, &value).with_context(|| format!("{res}/{name} was removed but not stored again: set it with cred set {res} {name}"))?;
            println!("resealed {res}/{name}");
        }
        // Approvals aren't carried over: one planted by another program must not become trusted.
        if policy::path(res).exists() && !matches!(policy::status(res), policy::Status::Approved) {
            println!("approve {res}'s policy again: cred policy approve {res}");
        }
    }
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

    let mut cmd = Command::new(&command[0]);
    cmd.args(&command[1..]).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut masks = Vec::new();
    for res in &resources {
        let approved = policy::load(res).with_context(|| format!("cred run needs an approved policy for {res}"))?;
        let run = &approved.policy.run;
        if run.export.is_empty() {
            bail!("the policy for {res} exports no fields to cred run");
        }
        let fields: Vec<&str> = run.export.keys().map(String::as_str).collect();
        match run.mode {
            Mode::Deny => bail!("the policy for {res} doesn't allow cred run (agents can use cred mcp)"),
            Mode::Ask => approve::confirm(&format!("run {} with {res}'s {}", command[0], fields.join(", ")))?,
            Mode::Allow => {}
        }
        for (name, var) in &run.export {
            let Some(v) = keychain::get(res, name) else { bail!("{res}/{name} not found in Keychain (add it with: cred set {res} {name})") };
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
    // Mask stdout and stderr so a value never reaches a log or an agent transcript by accident.
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
    util::blocking_stdio();
    let ok = |r: Result<()>| r.map(|_| 0);
    let result = match Cli::parse().cmd {
        Cmd::Set { resource, field, expires, meta } => ok(cmd_set(&resource, &field, expires, meta)),
        Cmd::Update { resource, field, expires } => ok(cmd_update(&resource, &field, expires)),
        Cmd::Describe { resource, meta } => ok(cmd_describe(&resource, meta)),
        Cmd::Policy { action } => ok(match action {
            PolicyCmd::Show { resource } => policy::show(&resource),
            PolicyCmd::Edit { resource } => policy::edit(&resource),
            PolicyCmd::Approve { resources } => policy::approve(&resources),
        }),
        Cmd::Refresh { resources, force } => cmd_refresh(resources, force),
        Cmd::Info { resource } => ok(cmd_info(&resource)),
        Cmd::Ls => ok(cmd_ls()),
        Cmd::Check { days } => cmd_check(days),
        Cmd::Rm { resource, field } => ok(cmd_rm(&resource, field)),
        Cmd::Copy { resource, field } => ok(cmd_copy(&resource, &field)),
        Cmd::Run { resources, command } => cmd_run(resources, command),
        Cmd::Mcp => ok(mcp::serve()),
        Cmd::Audit { last, verify } => ok(audit::show(last, verify)),
        Cmd::Reseal { resources } => ok(cmd_reseal(resources)),
        Cmd::Box { action } => match action {
            BoxCmd::Run { temp, name, command } => boxes::run(&name, temp, command),
            BoxCmd::New { name } => ok(boxes::new(&name)),
            BoxCmd::Edit { name } => ok(boxes::edit(&name)),
            BoxCmd::Approve { names } => ok(boxes::approve(&names)),
            BoxCmd::Ls => ok(boxes::ls()),
            BoxCmd::Log { name, last, verify } => ok(boxes::log(&name, last, verify)),
            BoxCmd::Stop { name } => ok(boxes::stop(&name)),
            BoxCmd::Export { name, path, to } => ok(boxes::export(&name, &path, &to)),
            BoxCmd::Import { name, path } => ok(boxes::import(&name, &path)),
            BoxCmd::Login { name, site, all } => ok(boxes::login(&name, site.as_deref(), all)),
            BoxCmd::Rm { name } => ok(boxes::rm(&name)),
        },
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("cred: {e:#}");
            ExitCode::FAILURE
        }
    }
}

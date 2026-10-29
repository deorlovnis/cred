//! Auto-refresh: renewing fields before they expire, using only what the resource's approved
//! policy names: a browser source, or a script whose bytes were pinned at approval.

use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::index::{Expiry, Index, Meta, store};
use crate::policy::{self, Approved};
use crate::util::TempDir;
use crate::{browser, keychain};

/// Set while a refresh script runs, so a `cred` inside it doesn't refresh again and loop.
const REFRESHING: &str = "CRED_REFRESHING";

/// Refresh every field of the given resources that is due (or all with force), as their
/// approved policies say. Returns false if anything failed.
pub fn refresh_due(resources: &[String], force: bool, verbose: bool) -> bool {
    if env::var_os(REFRESHING).is_some() {
        return true;
    }
    let Ok(idx) = Index::load() else { return false };
    let mut ok = true;
    for res in resources {
        let approved = match policy::load(res) {
            Ok(a) => a,
            Err(e) => {
                if verbose {
                    eprintln!("cred: {e:#}");
                }
                ok = false;
                continue;
            }
        };
        let refresh = &approved.policy.refresh;
        let meta = |name: &str| idx.map.get(res).and_then(|r| r.fields.get(name));
        let due: Vec<&String> = refresh.keys().filter(|n| force || meta(n).is_none_or(|f| f.due())).collect();
        // Browser sources are cheap to re-read and usually feed the others (a session that
        // mints a token), so whenever anything is due they go first.
        let mut order: Vec<&String> = Vec::new();
        if !due.is_empty() {
            order.extend(refresh.iter().filter(|(_, r)| r.from.is_some()).map(|(n, _)| n));
            order.extend(due.iter().copied().filter(|n| refresh[*n].from.is_none()));
        }
        for field in &order {
            if let Err(err) = refresh_one(res, &approved, field) {
                eprintln!("cred: {err:#}");
                ok = false;
            }
        }
        if verbose {
            for field in refresh.keys().filter(|n| !order.contains(n)) {
                let until = meta(field).and_then(|f| f.expiry_text()).map_or(String::new(), |t| format!(" (expires {t})"));
                eprintln!("cred: {res}/{field} is fresh{until}");
            }
        }
    }
    ok
}

/// Resources whose approved policy refreshes something.
pub fn auto_resources() -> Vec<String> {
    policy::names()
        .into_iter()
        .filter(|res| policy::load(res).is_ok_and(|a| !a.policy.refresh.is_empty()))
        .collect()
}

/// Get a field's fresh value and store it. Messages go to stderr, so a refresh inside
/// `cred run` never mixes into the command's output.
fn refresh_one(res: &str, approved: &Approved, field: &str) -> Result<()> {
    let value = match &approved.policy.refresh[field].from {
        Some(spec) => browser::Source::parse(spec).map_err(anyhow::Error::msg)?.read()?,
        None => run_script(res, approved, field)?,
    };
    let value = value.trim();
    if value.is_empty() || value.contains(char::is_whitespace) {
        bail!("refresh of {res}/{field} must produce exactly one value");
    }
    let suffix = store(res, field, value, Expiry::Keep, &Meta::default())?;
    eprintln!("cred: refreshed {res}/{field}{suffix}");
    Ok(())
}

/// Run a field's refresh script and return what it prints. The script gets the resource's
/// fields that aren't exported to `cred run` (login, session) as CRED_<FIELD>.
fn run_script(res: &str, approved: &Approved, field: &str) -> Result<String> {
    // Run the bytes that were checked, from a private copy: the script can't be swapped
    // between the check and the run.
    let bytes = approved.script(res, field)?;
    let dir = TempDir::new("cred-refresh")?;
    let script = dir.0.join("refresh");
    fs::write(&script, bytes)?;
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700))?;

    let mut command = Command::new(&script);
    // Read the index again: a field refreshed a moment ago (a new session) must be included.
    let idx = Index::load()?;
    let mut fields: BTreeSet<&String> = approved.policy.refresh.keys().collect();
    fields.extend(idx.map.get(res).into_iter().flat_map(|r| r.fields.keys()));
    let exported = &approved.policy.run.export;
    for name in fields.into_iter().filter(|n| !exported.contains_key(*n)) {
        if let Some(v) = keychain::get(res, name) {
            command.env(format!("CRED_{}", name.to_uppercase()), v);
        }
    }
    let out = command
        .env(REFRESHING, res)
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| format!("running the refresh script for {res}/{field}"))?;
    if !out.status.success() {
        bail!("refresh script for {res}/{field} failed ({})", out.status);
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

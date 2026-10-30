//! The index: metadata about resources and their fields (link, description, expiry), kept in
//! ~/.config/cred/index.json. Never values, and never rules: what may happen to a value is
//! decided by the resource's approved policy.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::{env, fs, io};

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Args;
use jiff::Timestamp;
use jiff::civil::Date;
use jiff::tz::TimeZone;
use serde::{Deserialize, Serialize};

use crate::keychain;
use crate::util::config_dir;

/// Auto-refresh a field once it is this close to its exact expiry. Short: some tokens only
/// live an hour, and a larger margin would renew them on every use.
const REFRESH_MARGIN_SECS: i64 = 300;

#[derive(Args, Default)]
pub struct Meta {
    /// Where the resource's credentials are issued/rotated
    #[arg(long)]
    pub url: Option<String>,
    /// What the resource is
    #[arg(long, visible_alias = "note")]
    pub desc: Option<String>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Resource {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub fields: BTreeMap<String, Field>,
}

#[derive(Serialize, Deserialize, Default)]
pub struct Field {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated: Option<Date>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<Date>,
    /// Exact expiry, read from the value when it is a JWT.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
}

impl Resource {
    pub fn apply(&mut self, meta: &Meta) {
        if let Some(u) = &meta.url {
            self.url = u.clone();
        }
        if let Some(d) = &meta.desc {
            self.description = d.clone();
        }
    }
}

impl Field {
    /// Due in the last minutes before an exact expiry, on the expiry date, or daily when expiry is unknown.
    pub fn due(&self) -> bool {
        match (self.expires_at, self.expires, self.updated) {
            (Some(t), _, _) => t.as_second() - Timestamp::now().as_second() < REFRESH_MARGIN_SECS,
            (None, Some(d), _) => days_left(d) <= 0,
            (None, None, Some(u)) => u < today(),
            (None, None, None) => true,
        }
    }

    pub fn expired(&self) -> bool {
        match (self.expires_at, self.expires) {
            (Some(t), _) => t <= Timestamp::now(),
            (None, Some(d)) => days_left(d) < 0,
            (None, None) => false,
        }
    }

    /// When it expires, comparable across exact and date-only expiries.
    pub fn expiry_key(&self) -> Option<Timestamp> {
        self.expires_at.or_else(|| self.expires?.to_zoned(TimeZone::system()).ok().map(|z| z.timestamp()))
    }

    pub fn expiry_text(&self) -> Option<String> {
        self.expires_at.map(local_time).or_else(|| self.expires.map(|d| d.to_string()))
    }
}

pub struct Index {
    path: PathBuf,
    pub map: BTreeMap<String, Resource>,
}

impl Index {
    pub fn load() -> Result<Self> {
        let path = env::var_os("CRED_INDEX").map(PathBuf::from).unwrap_or_else(|| config_dir().join("index.json"));
        let map = match fs::read_to_string(&path) {
            Ok(s) => serde_json::from_str(&s).with_context(|| format!("reading {}", path.display()))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Self { path, map })
    }

    pub fn save(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir)?;
        }
        // Write then rename, so a crash never leaves a half-written index.
        let tmp = self.path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_string_pretty(&self.map)? + "\n")?;
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    pub fn get(&self, res: &str) -> Result<&Resource> {
        self.map.get(res).with_context(|| format!("{res} doesn't exist (create it with: cred set {res} FIELD)"))
    }

    /// The stored values of a resource's fields, for masking them in output.
    pub fn values(&self, res: &str) -> Vec<String> {
        let Some(r) = self.map.get(res) else { return Vec::new() };
        r.fields.keys().filter_map(|n| keychain::get(res, n)).collect()
    }
}

// --- time ---

pub fn today() -> Date {
    jiff::Zoned::now().date()
}

pub fn days_left(d: Date) -> i64 {
    today().until(d).map(|s| s.get_days().into()).unwrap_or(0)
}

fn local_date(t: Timestamp) -> Date {
    t.to_zoned(TimeZone::system()).date()
}

pub fn local_time(t: Timestamp) -> String {
    t.to_zoned(TimeZone::system()).strftime("%Y-%m-%d %H:%M").to_string()
}

/// The `exp` claim when the value is a JWT, so its expiry is known without asking.
pub fn jwt_exp(value: &str) -> Option<Timestamp> {
    let parts: Vec<&str> = value.split('.').collect();
    let [_, payload, _] = parts.as_slice() else { return None };
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let exp = serde_json::from_slice::<serde_json::Value>(&bytes).ok()?.get("exp")?.as_f64()?;
    let secs = (if exp > 1e12 { exp / 1000.0 } else { exp }) as i64;
    Timestamp::from_second(secs).ok()
}

pub fn warn_days() -> i64 {
    env::var("CRED_WARN_DAYS").ok().and_then(|v| v.parse().ok()).unwrap_or(14)
}

// --- storing ---

pub enum Expiry {
    Keep,
    Set(Date),
    Clear,
}

/// Store a field's value and metadata; returns " (expires …)" for the caller's message.
pub fn store(res: &str, field: &str, value: &str, expiry: Expiry, meta: &Meta) -> Result<String> {
    keychain::set(res, field, value)?;
    let mut idx = Index::load()?;
    let r = idx.map.entry(res.to_string()).or_default();
    r.apply(meta);
    let f = r.fields.entry(field.to_string()).or_default();
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

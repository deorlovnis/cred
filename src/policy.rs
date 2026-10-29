//! Per-resource policies: what cred may do with a resource's secrets.
//!
//! A policy is a TOML file, ~/.config/cred/policy/<resource>.toml. It counts only once the user
//! approves it with Touch ID: the approval pins the file's sha256, and the sha256 of every
//! refresh script it names, in a Keychain item that cred reads without UI. A policy or script
//! changed afterwards, or an approval cred can't read silently (e.g. one planted by another
//! program), blocks the resource until it is approved again.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

use anyhow::{Context, Result, anyhow, bail};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use similar::TextDiff;
use url::{Host, Url};

use crate::util::{config_dir, expand_home, sha256_hex};
use crate::{approve, ask, boxes, browser, interactive, keychain, parse_env, parse_field, parse_resource};

/// Keychain field of a resource's approval record. Field names can't start with "_".
const APPROVAL: &str = "_policy";
pub const METHODS: [&str; 6] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];
/// What a tool parameter may contain unencoded: RFC 3986 unreserved characters.
const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC.remove(b'-').remove(b'_').remove(b'.').remove(b'~');

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    #[serde(default)]
    pub run: Run,
    #[serde(default)]
    pub refresh: BTreeMap<String, Refresh>,
    #[serde(default)]
    pub agent: Agent,
    pub fetch: Option<Fetch>,
    #[serde(default, rename = "tool")]
    pub tools: Vec<Tool>,
    pub browse: Option<Browse>,
}

/// What `cred run` may do.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Run {
    #[serde(default)]
    pub mode: Mode,
    /// field -> env var
    #[serde(default)]
    pub export: BTreeMap<String, String>,
}

#[derive(Deserialize, Default, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Allow,
    /// Touch ID each time.
    Ask,
    #[default]
    Deny,
}

impl Mode {
    pub fn text(self) -> &'static str {
        match self {
            Mode::Allow => "allow",
            Mode::Ask => "ask",
            Mode::Deny => "deny",
        }
    }
}

/// Where a field's fresh value comes from: an executable (pinned by hash) or a browser.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refresh {
    pub run: Option<String>,
    pub from: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    #[serde(default)]
    pub consent: Consent,
    /// How long a consent lasts, if the MCP server stays connected. 0: until it disconnects.
    #[serde(default = "default_consent_minutes")]
    pub consent_minutes: u64,
}

impl Default for Agent {
    fn default() -> Self {
        Self { consent: Consent::default(), consent_minutes: default_consent_minutes() }
    }
}

fn default_consent_minutes() -> u64 {
    240
}

#[derive(Deserialize, Default, Clone, Copy, PartialEq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Consent {
    /// Touch ID before an agent session first uses the resource.
    #[default]
    Session,
    None,
}

/// Requests cred makes for an agent, adding the resource's credentials itself.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fetch {
    pub hosts: Vec<String>,
    /// Requests other than GET and HEAD.
    #[serde(default)]
    pub writes: Mode,
    /// Header value with {field} placeholders, e.g. "Bearer {token}".
    pub auth: Option<String>,
    #[serde(default = "default_auth_header")]
    pub auth_header: String,
    /// Fixed, non-secret headers the site expects on every request, e.g. a client id.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

fn default_auth_header() -> String {
    "Authorization".into()
}

/// The sandboxed browser an agent may steer: which pages it may open, where those pages may
/// send requests, and the session cred puts into it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Browse {
    /// The only sites pages may be opened from.
    pub origins: Vec<String>,
    /// Further hosts the pages may load from or call (APIs, static files).
    #[serde(default)]
    pub requests: Vec<String>,
    /// Requests other than GET/HEAD/OPTIONS that pages send.
    #[serde(default)]
    pub writes: Mode,
    /// URL prefixes that may receive writes without asking.
    #[serde(default)]
    pub allow_writes: Vec<String>,
    /// The page opened first.
    pub start: Option<String>,
    #[serde(default)]
    pub cookies: Vec<BrowseCookie>,
    #[serde(default)]
    pub local_storage: Vec<BrowseStorage>,
    /// Lets the agent take screenshots. Masking can't reach text inside an image.
    #[serde(default)]
    pub screenshots: bool,
    /// The browser closes after this long without a call. 0: never.
    #[serde(default = "default_idle_minutes")]
    pub idle_minutes: u64,
    /// The browser closes this long after it opened, however busy. 0: never.
    #[serde(default = "default_max_minutes")]
    pub max_minutes: u64,
    /// Fields (a login's user and password) cred may type into pages on the origins, for
    /// sites without a session to inject. Off unless listed.
    #[serde(default)]
    pub fill: Vec<String>,
}

fn default_idle_minutes() -> u64 {
    10
}

fn default_max_minutes() -> u64 {
    60
}

/// A cookie set from a stored field, e.g. the session token.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowseCookie {
    pub name: String,
    pub field: String,
    pub domain: String,
}

/// A Local Storage entry set from a stored field, on one origin.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowseStorage {
    pub origin: String,
    pub key: String,
    pub field: String,
}

/// A site the browser may use: an exact origin, "https://*.example.com" (that domain and its
/// subdomains), or "*" (any https site).
pub enum Site {
    Any,
    Domain { scheme: String, domain: String },
    Exact(String),
}

impl Site {
    pub fn parse(entry: &str) -> Result<Self> {
        if entry == "*" {
            return Ok(Site::Any);
        }
        if let Some((scheme, rest)) = entry.split_once("://*.") {
            let domain = rest.trim_end_matches('/');
            if !matches!(scheme, "https" | "http") || !domain.contains('.') || domain.contains(['/', ':', '*', '@']) {
                bail!("must be like https://*.example.com");
            }
            return Ok(Site::Domain { scheme: scheme.into(), domain: domain.to_ascii_lowercase() });
        }
        Ok(Site::Exact(host_origin(entry)?))
    }

    /// The form the browser runner matches against.
    pub fn text(&self) -> String {
        match self {
            Site::Any => "*".into(),
            Site::Domain { scheme, domain } => format!("{scheme}://*.{domain}"),
            Site::Exact(origin) => origin.clone(),
        }
    }

    pub fn matches(&self, origin: &str) -> bool {
        match self {
            Site::Any => origin.starts_with("https://"),
            Site::Exact(o) => o == origin,
            Site::Domain { scheme, domain } => Url::parse(origin).is_ok_and(|u| {
                u.scheme() == scheme && u.host_str().is_some_and(|h| h == domain || h.ends_with(&format!(".{domain}")))
            }),
        }
    }

    /// Whether a cookie for this domain is meant for this site.
    fn covers_cookie(&self, cookie_domain: &str) -> bool {
        let inside = |host: &str| host == cookie_domain || host.ends_with(&format!(".{cookie_domain}"));
        match self {
            Site::Any => true,
            Site::Exact(o) => Url::parse(o).is_ok_and(|u| u.host_str().is_some_and(inside)),
            Site::Domain { domain, .. } => inside(domain) || cookie_domain.ends_with(&format!(".{domain}")),
        }
    }
}

fn sites(entries: &[String]) -> Vec<Site> {
    entries.iter().filter_map(|e| Site::parse(e).ok()).collect()
}

impl Browse {
    pub fn origins(&self) -> Vec<String> {
        sites(&self.origins).iter().map(Site::text).collect()
    }

    pub fn requests(&self) -> Vec<String> {
        sites(&self.requests).iter().map(Site::text).collect()
    }

    fn validate(&self) -> Result<()> {
        if self.origins.is_empty() {
            bail!("[browse] origins is empty");
        }
        for entry in self.origins.iter().chain(&self.requests) {
            Site::parse(entry).map_err(|e| anyhow!("[browse] '{entry}': {e}"))?;
        }
        let origins = sites(&self.origins);
        let all: Vec<Site> = sites(&self.origins).into_iter().chain(sites(&self.requests)).collect();
        let origin_of = |raw: &str| Url::parse(raw).map_err(|e| anyhow!("{e}")).and_then(|u| url_origin(&u));
        for prefix in &self.allow_writes {
            let origin = origin_of(prefix).map_err(|e| anyhow!("[browse] allow_writes '{prefix}': {e}"))?;
            if !all.iter().any(|s| s.matches(&origin)) {
                bail!("[browse] allow_writes '{prefix}' isn't on an allowed host");
            }
        }
        if let Some(start) = &self.start {
            let origin = origin_of(start).map_err(|e| anyhow!("[browse] start: {e}"))?;
            if !origins.iter().any(|s| s.matches(&origin)) {
                bail!("[browse] start must be on one of the origins");
            }
        }
        for c in &self.cookies {
            parse_field(&c.field).map_err(|e| anyhow!("[browse] cookie {}: field: {e}", c.name))?;
            if c.name.is_empty() || !c.name.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
                bail!("[browse] cookie name '{}' isn't valid", c.name);
            }
            // The cookie must be meant for the sites the browser may open.
            let domain = c.domain.trim_start_matches('.').to_ascii_lowercase();
            if !domain.contains('.') || !origins.iter().any(|s| s.covers_cookie(&domain)) {
                bail!("[browse] cookie {} domain '{}' doesn't cover one of the origins", c.name, c.domain);
            }
        }
        for field in &self.fill {
            parse_field(field).map_err(|e| anyhow!("[browse] fill '{field}': {e}"))?;
        }
        if !self.fill.is_empty() && origins.iter().any(|s| matches!(s, Site::Any)) {
            bail!("[browse] fill can't be used with origins = [\"*\"]: name the sites cred may type credentials into");
        }
        for s in &self.local_storage {
            parse_field(&s.field).map_err(|e| anyhow!("[browse] local_storage {}: field: {e}", s.key))?;
            let origin = host_origin(&s.origin).map_err(|e| anyhow!("[browse] local_storage origin: {e}"))?;
            if !origins.iter().any(|site| site.matches(&origin)) {
                bail!("[browse] local_storage origin '{}' isn't one of the origins", s.origin);
            }
        }
        Ok(())
    }
}

/// A named request an agent may make: "METHOD URL", {placeholders} only in the path or query.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub name: String,
    pub about: String,
    pub request: String,
}

impl Policy {
    /// What the policy allows in a few words, for listings: `run:ask fetch browse:ask`. The word
    /// after a colon is the mode of `cred run`, or of writes where requests can also be sent.
    pub fn summary(&self) -> String {
        let with_writes = |name: &str, writes: Mode| if writes == Mode::Deny { name.to_string() } else { format!("{name}:{}", writes.text()) };
        let mut parts = Vec::new();
        if self.run.mode != Mode::Deny && !self.run.export.is_empty() {
            parts.push(format!("run:{}", self.run.mode.text()));
        }
        parts.extend(self.fetch.as_ref().map(|f| with_writes("fetch", f.writes)));
        parts.extend(self.browse.as_ref().map(|b| with_writes("browse", b.writes)));
        if parts.is_empty() { "-".into() } else { parts.join(" ") }
    }

    /// What agents may do, as (label, text) lines for `cred info`.
    pub fn rules(&self) -> Vec<(&'static str, String)> {
        let consent = match (self.agent.consent, self.agent.consent_minutes) {
            (Consent::Session, 0) => "session (Touch ID on first use)".to_string(),
            (Consent::Session, m) => format!("session (Touch ID on first use, then every {m} min)"),
            (Consent::None, _) => "none".to_string(),
        };
        let mut lines = vec![("agent", format!("consent {consent}"))];
        if let Some(f) = &self.fetch {
            let auth = f.auth.as_ref().map_or(String::new(), |_| format!("; auth in {}", f.auth_header));
            lines.push(("fetch", format!("hosts {}; writes {}{auth}", f.hosts.join(", "), f.writes.text())));
        }
        for t in &self.tools {
            lines.push(("tool", format!("{}: {}", t.name, t.request)));
        }
        if let Some(b) = &self.browse {
            let mut text = format!("pages on {}", b.origins.join(", "));
            if !b.requests.is_empty() {
                text += &format!("; requests to {}", b.requests.join(", "));
            }
            text += &format!("; writes {}", b.writes.text());
            if !b.allow_writes.is_empty() {
                text += &format!(" (allowed: {})", b.allow_writes.join(", "));
            }
            text += if b.screenshots { "; screenshots" } else { "; no screenshots" };
            if !b.fill.is_empty() {
                text += &format!("; cred types {}", b.fill.join(", "));
            }
            let limit = |m: u64| if m == 0 { "none".to_string() } else { format!("{m} min") };
            text += &format!("; closes when idle {}, at most {}", limit(b.idle_minutes), limit(b.max_minutes));
            lines.push(("browse", text));
        }
        lines
    }

    pub fn parse(text: &str) -> Result<Self> {
        let policy: Policy = toml::from_str(text)?;
        policy.validate()?;
        Ok(policy)
    }

    fn validate(&self) -> Result<()> {
        let mut vars = BTreeSet::new();
        for (field, var) in &self.run.export {
            parse_field(field).map_err(|e| anyhow!("[run] export: field '{field}': {e}"))?;
            parse_env(var).map_err(|e| anyhow!("[run] export: '{var}': {e}"))?;
            if !vars.insert(var) {
                bail!("[run] exports two fields as {var}");
            }
        }
        for (field, r) in &self.refresh {
            parse_field(field).map_err(|e| anyhow!("[refresh.{field}]: {e}"))?;
            match (&r.run, &r.from) {
                (Some(run), None) if !run.trim().is_empty() => {}
                (None, Some(from)) => {
                    browser::Source::parse(from).map_err(|e| anyhow!("[refresh.{field}] from: {e}"))?;
                }
                _ => bail!("[refresh.{field}] needs exactly one of run or from"),
            }
        }
        if let Some(fetch) = &self.fetch {
            if fetch.hosts.is_empty() {
                bail!("[fetch] hosts is empty");
            }
            for host in &fetch.hosts {
                host_origin(host).map_err(|e| anyhow!("[fetch] host '{host}': {e}"))?;
            }
            if let Some(auth) = &fetch.auth {
                for name in placeholders(auth)? {
                    parse_field(&name).map_err(|e| anyhow!("[fetch] auth {{{name}}}: {e}"))?;
                }
            }
            let is_name = |h: &str| !h.is_empty() && h.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
            if !is_name(&fetch.auth_header) {
                bail!("[fetch] auth_header must be a header name");
            }
            for (name, value) in &fetch.headers {
                if !is_name(name) || value.contains(['\r', '\n']) {
                    bail!("[fetch] headers: '{name}' isn't a valid header");
                }
                // Values are fixed text: they can't carry a stored value or replace the credentials.
                if value.contains('{') || ["cookie", "host", &fetch.auth_header.to_ascii_lowercase()].contains(&name.to_ascii_lowercase().as_str()) {
                    bail!("[fetch] headers: '{name}' can't be set here");
                }
            }
        }
        if let Some(browse) = &self.browse {
            browse.validate()?;
        }
        let mut names = BTreeSet::new();
        for tool in &self.tools {
            let name = &tool.name;
            parse_field(name).map_err(|e| anyhow!("tool name '{name}': {e}"))?;
            if !names.insert(name) {
                bail!("two tools are named {name}");
            }
            let fetch = self.fetch.as_ref().ok_or_else(|| anyhow!("tool {name} needs a [fetch] section"))?;
            let (_, template) = tool.split()?;
            for p in placeholders(template)? {
                parse_field(&p).map_err(|e| anyhow!("tool {name}: {{{p}}}: {e}"))?;
            }
            // Placeholders may fill the path or query, never the scheme, host or port.
            let after_scheme = template.find("://").map_or(0, |i| i + 3);
            let authority_end = template[after_scheme..].find('/').map_or(template.len(), |i| after_scheme + i);
            if template[..authority_end].contains('{') {
                bail!("tool {name}: placeholders can't be in the host");
            }
            fetch.check_url(&fill(template, |_| Ok("x".into()))?).map_err(|e| anyhow!("tool {name}: {e}"))?;
        }
        Ok(())
    }
}

impl Fetch {
    /// Whether the policy lists this host (lower case, as the door knows it) among its https hosts.
    pub fn covers_host(&self, host: &str) -> bool {
        let authority = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
        let origin = format!("https://{authority}");
        self.hosts.iter().filter_map(|h| host_origin(h).ok()).any(|h| h == origin)
    }

    /// The URL, if it is on one of the policy's hosts.
    pub fn check_url(&self, raw: &str) -> Result<Url> {
        let url = Url::parse(raw).map_err(|e| anyhow!("'{raw}' isn't a URL: {e}"))?;
        let origin = url_origin(&url)?;
        if !self.hosts.iter().filter_map(|h| host_origin(h).ok()).any(|h| h == origin) {
            bail!("{origin} isn't one of this site's hosts ({})", self.hosts.join(", "));
        }
        Ok(url)
    }
}

impl Tool {
    fn split(&self) -> Result<(&str, &str)> {
        let (method, template) = self
            .request
            .trim()
            .split_once(' ')
            .ok_or_else(|| anyhow!("tool {}: request must be \"METHOD URL\"", self.name))?;
        if !METHODS.contains(&method) {
            bail!("tool {}: method must be one of {}", self.name, METHODS.join(", "));
        }
        Ok((method, template.trim()))
    }

    pub fn params(&self) -> Vec<String> {
        self.split().and_then(|(_, t)| placeholders(t)).unwrap_or_default()
    }

    /// The method and URL this tool requests with the agent's arguments, each percent-encoded.
    pub fn expand(&self, args: &Map<String, Value>) -> Result<(String, String)> {
        let (method, template) = self.split()?;
        let url = fill(template, |name| {
            let value = match args.get(name) {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Number(n)) => n.to_string(),
                Some(Value::Bool(b)) => b.to_string(),
                Some(_) => bail!("parameter {name} must be a string"),
                None => bail!("missing parameter {name}"),
            };
            // "." and ".." would climb out of the path the tool names.
            if value == "." || value == ".." {
                bail!("parameter {name} can't be '{value}'");
            }
            Ok(utf8_percent_encode(&value, COMPONENT).to_string())
        })?;
        Ok((method.to_string(), url))
    }
}

/// The names of the {placeholders} in a template.
pub fn placeholders(template: &str) -> Result<Vec<String>> {
    let mut names = Vec::new();
    fill(template, |name| {
        names.push(name.to_string());
        Ok(String::new())
    })?;
    Ok(names)
}

/// Replace each {name} in the template with lookup(name).
pub fn fill(template: &str, mut lookup: impl FnMut(&str) -> Result<String>) -> Result<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let close = rest[open..].find('}').ok_or_else(|| anyhow!("unclosed {{ in '{template}'"))? + open;
        out.push_str(&rest[..open]);
        out.push_str(&lookup(&rest[open + 1..close])?);
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// scheme://host[:port] of a URL that may carry credentials: https, or http to this machine.
fn url_origin(url: &Url) -> Result<String> {
    if !url.username().is_empty() || url.password().is_some() {
        bail!("URLs with a user or password aren't allowed");
    }
    let loopback = match url.host() {
        Some(Host::Domain(d)) => d == "localhost",
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        other => bail!("{other}:// isn't allowed (https only, or http to localhost)"),
    }
    Ok(url.origin().ascii_serialization())
}

fn host_origin(entry: &str) -> Result<String> {
    let url = Url::parse(entry).map_err(|e| anyhow!("{e}"))?;
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        bail!("must be just scheme://host[:port]");
    }
    url_origin(&url)
}

// --- files and approval ---

#[derive(Serialize, Deserialize)]
pub struct Approval {
    /// sha256 of the policy file
    policy: String,
    /// refresh script path -> sha256
    scripts: BTreeMap<String, String>,
    /// The approved text itself, so a later edit can be shown as a diff. Absent in older records.
    #[serde(default)]
    text: Option<String>,
}

impl Approval {
    /// The approval of a policy file with this text and no scripts, like a box policy.
    pub fn of(text: &str) -> Self {
        Self { policy: sha256_hex(text.as_bytes()), scripts: BTreeMap::new(), text: Some(text.to_string()) }
    }

    /// The first characters of the file's sha256, for showing.
    pub fn short(&self) -> &str {
        &self.policy[..12]
    }
}

/// A policy that is approved and unchanged since.
pub struct Approved {
    pub policy: Policy,
    scripts: BTreeMap<String, String>,
}

pub enum Status {
    Missing,
    Unapproved,
    Changed,
    Approved,
}

impl Status {
    pub fn text(&self) -> &'static str {
        match self {
            Status::Missing => "none",
            Status::Unapproved => "not approved",
            Status::Changed => "changed since approval",
            Status::Approved => "approved",
        }
    }
}

pub fn dir() -> PathBuf {
    env::var_os("CRED_POLICY_DIR").map(PathBuf::from).unwrap_or_else(|| config_dir().join("policy"))
}

pub fn path(res: &str) -> PathBuf {
    dir().join(format!("{res}.toml"))
}

/// Resources that have a policy file, approved or not.
pub fn names() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir())
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok()?.file_name().to_str()?.strip_suffix(".toml").map(str::to_string))
        .filter(|n| parse_resource(n).is_ok())
        .collect();
    names.sort();
    names
}

fn record(res: &str) -> Option<Approval> {
    serde_json::from_str(&keychain::get_silently(res, APPROVAL)?).ok()
}

pub fn status(res: &str) -> Status {
    status_of(res, &path(res))
}

/// The status of any approvable file (a resource's policy, a box's) whose approval record is
/// kept under this Keychain name.
pub fn status_of(key: &str, file: &Path) -> Status {
    let Ok(text) = fs::read(file) else { return Status::Missing };
    match record(key) {
        None => Status::Unapproved,
        Some(r) if r.policy == sha256_hex(&text) => Status::Approved,
        Some(_) => Status::Changed,
    }
}

/// The text of an approvable file, as long as it is approved and unchanged since; otherwise why not.
pub fn approved_at(key: &str, file: &Path) -> Result<String, Status> {
    let text = fs::read_to_string(file).map_err(|_| Status::Missing)?;
    match record(key) {
        None => Err(Status::Unapproved),
        Some(r) if r.policy == sha256_hex(text.as_bytes()) => Ok(text),
        Some(_) => Err(Status::Changed),
    }
}

pub fn load(res: &str) -> Result<Approved> {
    let p = path(res);
    let text = fs::read(&p).map_err(|_| anyhow!("{res} has no policy (write one with: cred policy edit {res})"))?;
    let record = record(res).ok_or_else(|| anyhow!("the policy for {res} isn't approved (cred policy approve {res})"))?;
    if record.policy != sha256_hex(&text) {
        bail!("the policy for {res} changed since it was approved (cred policy approve {res})");
    }
    let text = String::from_utf8(text).with_context(|| format!("{} isn't UTF-8", p.display()))?;
    let policy = Policy::parse(&text).with_context(|| p.display().to_string())?;
    Ok(Approved { policy, scripts: record.scripts })
}

impl Approved {
    /// The bytes of a field's refresh script, as long as they're the ones approved.
    pub fn script(&self, res: &str, field: &str) -> Result<Vec<u8>> {
        let run = self.policy.refresh.get(field).and_then(|r| r.run.as_deref());
        let p = expand_home(run.ok_or_else(|| anyhow!("{res}/{field} has no refresh script"))?);
        let bytes = fs::read(&p).with_context(|| format!("reading {}", p.display()))?;
        if self.scripts.get(&p.display().to_string()) != Some(&sha256_hex(&bytes)) {
            bail!("{} changed since the policy for {res} was approved (cred policy approve {res})", p.display());
        }
        Ok(bytes)
    }
}

/// The policy text as it was approved, if the approval record keeps it.
fn approved_text(key: &str) -> Option<String> {
    record(key)?.text
}

/// Forget an approval (a resource's, or a box's under its Keychain name); the file has no
/// effect until approved again.
pub fn revoke(key: &str) {
    keychain::delete(key, APPROVAL);
}

/// How an approval reads in messages: a resource's name, or "box NAME".
fn label(key: &str) -> String {
    key.strip_prefix(boxes::KEY_PREFIX).map_or_else(|| key.to_string(), |name| format!("box {name}"))
}

/// Read, check and print a policy for approval; what is printed is exactly what gets pinned.
fn prepare(res: &str) -> Result<Approval> {
    let p = path(res);
    let text = fs::read_to_string(&p).map_err(|_| anyhow!("{res} has no policy (write one with: cred policy edit {res})"))?;
    let policy = Policy::parse(&text).with_context(|| p.display().to_string())?;
    let mut scripts = BTreeMap::new();
    for (field, r) in &policy.refresh {
        if let Some(run) = &r.run {
            let script = expand_home(run);
            let bytes = fs::read(&script).with_context(|| format!("[refresh.{field}] reading {}", script.display()))?;
            scripts.insert(script.display().to_string(), sha256_hex(&bytes));
        }
    }
    let digest = sha256_hex(text.as_bytes());
    println!("Policy for {res} ({}):\n\n{}\n", p.display(), text.trim_end());
    for (script, hash) in &scripts {
        println!("pins {script} (sha256 {})", &hash[..12]);
    }
    println!("sha256 {}\n", &digest[..12]);
    Ok(Approval { policy: digest, scripts, text: Some(text) })
}

/// Approve the given resources' policies with one confirmation (all policies, boxes included,
/// when none given).
pub fn approve(resources: &[String]) -> Result<()> {
    let mut prepared = Vec::new();
    if resources.is_empty() {
        for res in names() {
            prepared.push((res.clone(), prepare(&res)?));
        }
        for name in boxes::names() {
            prepared.push(boxes::prepare(&name)?);
        }
    } else {
        for res in resources {
            prepared.push((res.clone(), prepare(res)?));
        }
    }
    if prepared.is_empty() {
        bail!("there are no policies (write one with: cred policy edit RESOURCE)");
    }
    approve_prepared(prepared)
}

/// Pin prepared approvals (Keychain name, record) after one confirmation.
pub fn approve_prepared(prepared: Vec<(String, Approval)>) -> Result<()> {
    let list: Vec<String> = prepared.iter().map(|(key, a)| format!("{} (sha256 {})", label(key), a.short())).collect();
    let what = if list.len() == 1 { "policy" } else { "policies" };
    approve::confirm(&format!("approve the cred {what} for {}", list.join(", ")))?;
    for (key, approval) in prepared {
        keychain::replace(&key, APPROVAL, &serde_json::to_string(&approval)?)?;
        println!("approved the policy for {}", label(&key));
    }
    Ok(())
}

pub fn show(res: &str) -> Result<()> {
    let p = path(res);
    println!("{} ({})", p.display(), status(res).text());
    match fs::read_to_string(&p) {
        Ok(text) => println!("\n{}", text.trim_end()),
        Err(_) => println!("\nno policy yet (write one with: cred policy edit {res})"),
    }
    Ok(())
}

/// What changed from the approved text to the current one, as a unified diff. Colored
/// (ANSI) for a terminal.
fn diff(old: &str, new: &str, color: bool) -> String {
    let body = TextDiff::from_lines(old, new).unified_diff().context_radius(3).to_string();
    let paint = |code: &str, line: &str| if color { format!("\x1b[{code}m{line}\x1b[0m\n") } else { format!("{line}\n") };
    let mut out = paint("1", "--- approved") + &paint("1", "+++ now");
    for line in body.lines() {
        out += &paint(
            match line.as_bytes().first() {
                Some(b'+') => "32",
                Some(b'-') => "31",
                Some(b'@') => "36",
                _ => "0",
            },
            line,
        );
    }
    out
}

pub fn edit(res: &str) -> Result<()> {
    let p = path(res);
    if !p.exists() {
        fs::create_dir_all(dir())?;
        fs::write(&p, TEMPLATE.replace("RES", res))?;
    }
    if edit_file(res, &p, |text| Policy::parse(text).map(drop))? {
        offer_approval(&p, &format!("cred policy approve {res}"), || approve(&[res.to_string()]))?;
    }
    Ok(())
}

/// Open an approvable file in $EDITOR and check what was saved. A file approved before shows
/// what the edit changed (false if nothing); a new one is shown whole when approved.
pub fn edit_file(key: &str, p: &Path, check: impl FnOnce(&str) -> Result<()>) -> Result<bool> {
    let editor = env::var("VISUAL").or_else(|_| env::var("EDITOR")).unwrap_or_else(|_| "vi".into());
    let status = Command::new("sh").args(["-c", &format!("{editor} \"$1\""), "sh"]).arg(p).status()?;
    if !status.success() {
        bail!("{editor} exited with {status}");
    }
    let text = fs::read_to_string(p)?;
    check(&text).with_context(|| p.display().to_string())?;
    if let Some(old) = approved_text(key) {
        if old == text {
            println!("no change from the approved policy for {}", label(key));
            return Ok(false);
        }
        println!("{}", diff(&old, &text, io::stdout().is_terminal()));
    }
    Ok(true)
}

/// Say that an edited file takes effect once approved, and offer to approve it now.
pub fn offer_approval(p: &Path, approve_cmd: &str, approve_now: impl FnOnce() -> Result<()>) -> Result<()> {
    println!("saved {} — it takes effect once approved: {approve_cmd}", p.display());
    if interactive() && ask("Approve it now? [y/N] ")?.eq_ignore_ascii_case("y") {
        approve_now()?;
    }
    Ok(())
}

const TEMPLATE: &str = r#"# cred policy for RES. It takes effect only once approved: cred policy approve RES

[run]
mode = "deny"          # cred run: allow | ask (Touch ID each time) | deny
export = {}            # field = "ENV_VAR", e.g. { token = "RES_TOKEN" }

[agent]
consent = "session"    # session: Touch ID once per agent session | none
consent_minutes = 240  # a session consent lapses after this long (0: only when the agent disconnects)

# [refresh.token]
# run = "~/.config/cred/refresh/RES.sh"     # prints a fresh value; gets the fields that
#                                           # aren't exported as CRED_<FIELD>
# from = "firefox:https://example.com#key"  # or: read it from Firefox Local Storage
#                                           # (firefox-cookie:… and chrome-cookie:… read a cookie)

# [fetch]
# hosts = ["https://api.example.com"]
# writes = "deny"                           # requests other than GET/HEAD: deny | ask | allow
# auth = "Bearer {token}"                   # header value, {field} placeholders
# auth_header = "Authorization"
# headers = { "x-client-id" = "web" }       # fixed, non-secret headers the site expects

# [[tool]]
# name = "item"
# about = "Get one item"
# request = "GET https://api.example.com/items/{id}"
"#;

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
        [run]
        mode = "ask"
        export = { token = "APP_TOKEN" }

        [refresh.session]
        from = "firefox:https://app.example.com#session_token"

        [refresh.token]
        run = "~/.config/cred/refresh/app.sh"

        [fetch]
        hosts = ["https://api.example.com", "http://127.0.0.1:8080"]
        writes = "ask"
        auth = "Bearer {token}"
        headers = { "x-client-id" = "web" }

        [[tool]]
        name = "item"
        about = "Get one item"
        request = "GET https://api.example.com/items/{id}?q={query}"

        [browse]
        origins = ["https://app.example.com"]
        requests = ["https://api.example.com"]
        writes = "ask"
        allow_writes = ["https://app.example.com/api/telemetry"]
        start = "https://app.example.com/home"
        cookies = [{ name = "session", field = "token", domain = ".example.com" }]
        local_storage = [{ origin = "https://app.example.com", key = "jwt", field = "token" }]
        fill = ["user", "password"]
    "#;

    #[test]
    fn parses_a_full_policy() {
        let p = Policy::parse(GOOD).unwrap();
        assert_eq!(p.run.mode, Mode::Ask);
        assert_eq!(p.agent.consent, Consent::Session);
        assert_eq!(p.tools[0].params(), ["id", "query"]);
        assert_eq!(Policy::parse("").unwrap().run.mode, Mode::Deny);
    }

    #[test]
    fn time_limits_default_and_can_be_set() {
        let p = Policy::parse(GOOD).unwrap();
        assert_eq!((p.agent.consent_minutes, p.browse.unwrap().idle_minutes), (240, 10));
        assert_eq!(Policy::parse("").unwrap().agent.consent_minutes, 240);
        let p = Policy::parse("[agent]\nconsent_minutes = 0\n[browse]\norigins = [\"*\"]\nidle_minutes = 3\nmax_minutes = 30").unwrap();
        let b = p.browse.unwrap();
        assert_eq!((p.agent.consent_minutes, b.idle_minutes, b.max_minutes), (0, 3, 30));
    }

    #[test]
    fn rejects_unsafe_policies() {
        let bad = [
            ("[run]\nmod = \"allow\"", "unknown field"),
            ("[run]\nexport = { a = \"X\", b = \"X\" }", "two fields"),
            ("[fetch]\nhosts = [\"http://api.example.com\"]", "https only"),
            ("[fetch]\nhosts = [\"https://api.example.com/v1\"]", "scheme://host"),
            ("[fetch]\nhosts = [\"https://u:p@api.example.com\"]", "user or password"),
            ("[refresh.token]\nrun = \"a\"\nfrom = \"firefox:https://a.b#k\"", "exactly one"),
            ("[fetch]\nhosts = [\"https://a.example.com\"]\n[[tool]]\nname = \"t\"\nabout = \"\"\nrequest = \"GET https://b.example.com/x\"", "isn't one of"),
            ("[fetch]\nhosts = [\"https://a.example.com\"]\n[[tool]]\nname = \"t\"\nabout = \"\"\nrequest = \"GET https://{h}.example.com/x\"", "host"),
            ("[[tool]]\nname = \"t\"\nabout = \"\"\nrequest = \"GET https://a.example.com/x\"", "[fetch]"),
            ("[fetch]\nhosts = [\"https://a.example.com\"]\nheaders = { authorization = \"x\" }", "can't be set"),
            ("[fetch]\nhosts = [\"https://a.example.com\"]\nheaders = { x-id = \"{token}\" }", "can't be set"),
            ("[fetch]\nhosts = [\"https://a.example.com\"]\nheaders = { cookie = \"a=b\" }", "can't be set"),
            ("[browse]\norigins = [\"https://a.example.com\"]\ncookies = [{ name = \"s\", field = \"token\", domain = \".com\" }]", "doesn't cover"),
            ("[browse]\norigins = [\"https://a.example.com\"]\ncookies = [{ name = \"s\", field = \"token\", domain = \"other.com\" }]", "doesn't cover"),
            ("[browse]\norigins = [\"https://a.example.com\"]\nstart = \"https://b.example.com/\"", "start"),
            ("[browse]\norigins = [\"https://a.example.com\"]\nallow_writes = [\"https://evil.com/x\"]", "allowed host"),
            ("[browse]\norigins = [\"https://*.com\"]", "like https://*.example.com"),
            ("[browse]\norigins = [\"ftp://*.example.com\"]", "like https://*.example.com"),
            ("[browse]\norigins = [\"*\"]\nfill = [\"password\"]", "name the sites"),
            ("[browse]\norigins = [\"https://a.example.com\"]\nfill = [\"_policy\"]", "fill '_policy'"),
        ];
        for (text, why) in bad {
            let err = format!("{:#}", Policy::parse(text).err().unwrap_or_else(|| panic!("accepted: {text}")));
            assert!(err.contains(why), "{text}: {err}");
        }
    }

    #[test]
    fn matches_browse_sites() {
        let any = Site::parse("*").unwrap();
        let dom = Site::parse("https://*.example.com").unwrap();
        assert!(any.matches("https://anything.org") && !any.matches("http://anything.org"));
        assert!(dom.matches("https://example.com") && dom.matches("https://a.b.example.com"));
        assert!(!dom.matches("https://notexample.com") && !dom.matches("http://a.example.com"));
        assert!(dom.covers_cookie("example.com") && dom.covers_cookie("app.example.com") && !dom.covers_cookie("other.com"));
        let p = Policy::parse("[browse]\norigins = [\"https://*.example.com\"]\nrequests = [\"*\"]\nstart = \"https://app.example.com/\"\nscreenshots = true\ncookies = [{ name = \"s\", field = \"token\", domain = \".example.com\" }]").unwrap();
        assert_eq!(p.browse.unwrap().requests(), ["*"]);
    }

    #[test]
    fn summarizes_what_a_policy_allows() {
        let p = Policy::parse(GOOD).unwrap();
        assert_eq!(p.summary(), "run:ask fetch:ask browse:ask");
        assert_eq!(Policy::parse("[run]\nexport = { token = \"T\" }\n[fetch]\nhosts = [\"https://a.example.com\"]").unwrap().summary(), "fetch");
        assert_eq!(Policy::parse("").unwrap().summary(), "-");
        let rules = p.rules();
        let line = |label: &str| rules.iter().find(|(l, _)| *l == label).map(|(_, t)| t.as_str()).unwrap();
        assert_eq!(line("fetch"), "hosts https://api.example.com, http://127.0.0.1:8080; writes ask; auth in Authorization");
        assert!(line("browse").contains("allowed: https://app.example.com/api/telemetry") && line("browse").contains("no screenshots"));
        assert_eq!(line("tool"), "item: GET https://api.example.com/items/{id}?q={query}");
    }

    #[test]
    fn diffs_against_the_approved_text() {
        let old = "[run]\nmode = \"ask\"\n";
        let new = "[run]\nmode = \"allow\"\n";
        let plain = diff(old, new, false);
        assert_eq!(plain, "--- approved\n+++ now\n@@ -1,2 +1,2 @@\n [run]\n-mode = \"ask\"\n+mode = \"allow\"\n");
        let colored = diff(old, new, true);
        assert!(colored.contains("\x1b[31m-mode = \"ask\"\x1b[0m\n") && colored.contains("\x1b[32m+mode = \"allow\"\x1b[0m\n"));
    }

    #[test]
    fn checks_urls_against_hosts() {
        let fetch = Policy::parse(GOOD).unwrap().fetch.unwrap();
        assert!(fetch.check_url("https://api.example.com/a?b=c").is_ok());
        assert!(fetch.check_url("http://127.0.0.1:8080/x").is_ok());
        assert!(fetch.check_url("https://api.example.com.evil.com/").is_err());
        assert!(fetch.check_url("https://evil.com/?https://api.example.com").is_err());
        assert!(fetch.check_url("https://x@api.example.com/").is_err());
        assert!(fetch.check_url("http://api.example.com/").is_err());
    }

    #[test]
    fn expands_tool_parameters_safely() {
        let p = Policy::parse(GOOD).unwrap();
        let args = |id: &str| serde_json::json!({ "id": id, "query": "a b&c=d/e" }).as_object().unwrap().clone();
        let (method, url) = p.tools[0].expand(&args("12/../x?y")).unwrap();
        assert_eq!(method, "GET");
        assert_eq!(url, "https://api.example.com/items/12%2F..%2Fx%3Fy?q=a%20b%26c%3Dd%2Fe");
        assert!(p.tools[0].expand(&args("..")).is_err());
        assert!(p.tools[0].expand(&serde_json::Map::new()).is_err());
    }
}

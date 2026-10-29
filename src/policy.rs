//! Per-resource policies: what cred may do with a resource's secrets.
//!
//! A policy is a TOML file, ~/.config/cred/policy/<resource>.toml. It counts only once the user
//! approves it with Touch ID: the approval pins the file's sha256, and the sha256 of every
//! refresh script it names, in a Keychain item that cred reads without UI. A policy or script
//! changed afterwards, or an approval cred can't read silently (e.g. one planted by another
//! program), blocks the resource until it is approved again.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;
use std::{env, fs};

use anyhow::{Context, Result, anyhow, bail};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use url::{Host, Url};

use crate::util::{config_dir, expand_home, sha256_hex};
use crate::{approve, browser, keychain, parse_env, parse_field, parse_resource};

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

/// Where a field's fresh value comes from: an executable (pinned by hash) or a browser.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Refresh {
    pub run: Option<String>,
    pub from: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Agent {
    #[serde(default)]
    pub consent: Consent,
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

/// A named request an agent may make: "METHOD URL", {placeholders} only in the path or query.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub name: String,
    pub about: String,
    pub request: String,
}

impl Policy {
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
struct Approval {
    /// sha256 of the policy file
    policy: String,
    /// refresh script path -> sha256
    scripts: BTreeMap<String, String>,
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
    let Ok(text) = fs::read(path(res)) else { return Status::Missing };
    match record(res) {
        None => Status::Unapproved,
        Some(r) if r.policy == sha256_hex(&text) => Status::Approved,
        Some(_) => Status::Changed,
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

/// Forget a resource's approval; its policy has no effect until approved again.
pub fn revoke(res: &str) {
    keychain::delete(res, APPROVAL);
}

pub fn approve(res: &str) -> Result<()> {
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
    // What is shown is exactly what gets pinned: the text and scripts read once, above.
    let digest = sha256_hex(text.as_bytes());
    println!("Policy for {res} ({}):\n\n{}\n", p.display(), text.trim_end());
    for (script, hash) in &scripts {
        println!("pins {script} (sha256 {})", &hash[..12]);
    }
    println!("sha256 {}", &digest[..12]);
    approve::confirm(&format!("approve the cred policy for {res} (sha256 {})", &digest[..12]))?;
    keychain::replace(res, APPROVAL, &serde_json::to_string(&Approval { policy: digest, scripts })?)?;
    println!("approved the policy for {res}");
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

pub fn edit(res: &str) -> Result<()> {
    let p = path(res);
    if !p.exists() {
        fs::create_dir_all(dir())?;
        fs::write(&p, TEMPLATE.replace("RES", res))?;
    }
    let editor = env::var("VISUAL").or_else(|_| env::var("EDITOR")).unwrap_or_else(|_| "vi".into());
    let status = Command::new("sh").args(["-c", &format!("{editor} \"$1\""), "sh"]).arg(&p).status()?;
    if !status.success() {
        bail!("{editor} exited with {status}");
    }
    Policy::parse(&fs::read_to_string(&p)?).with_context(|| p.display().to_string())?;
    println!("saved {} — it takes effect once approved: cred policy approve {res}", p.display());
    Ok(())
}

const TEMPLATE: &str = r#"# cred policy for RES. It takes effect only once approved: cred policy approve RES

[run]
mode = "deny"          # cred run: allow | ask (Touch ID each time) | deny
export = {}            # field = "ENV_VAR", e.g. { token = "RES_TOKEN" }

[agent]
consent = "session"    # session: Touch ID once per agent session | none

# [refresh.token]
# run = "~/.config/cred/refresh/RES.sh"     # prints a fresh value; gets the fields that
#                                           # aren't exported as CRED_<FIELD>
# from = "firefox:https://example.com#key"  # or: read it from Firefox Local Storage

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
        ];
        for (text, why) in bad {
            let err = format!("{:#}", Policy::parse(text).err().unwrap_or_else(|| panic!("accepted: {text}")));
            assert!(err.contains(why), "{text}: {err}");
        }
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

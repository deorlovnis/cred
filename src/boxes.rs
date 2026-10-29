//! Boxes: isolated, encrypted places where an agent works (`cred box`).
//!
//! A box has a policy, ~/.config/cred/box/<name>.toml, that counts only once approved with
//! Touch ID, exactly like a resource's policy (the same approval records, kept under the
//! Keychain name `box.<name>`: resource names can't contain a dot, so the two never collide).
//! Its data lives in an encrypted store (see `store`) whose key is one Keychain item,
//! `cred:box.<name>/_key`, read only to open the store. `run` (see `run`) opens the store, starts
//! the VM and the door, and tears it all down again.
//!
//! The door sees every request (see `door::inspect`): `[net] allow` says which hosts the box may
//! reach, `writes` and `allow_writes` what it may send them besides reads, and `standins` which
//! environment variables hold the stand-in for a site's credential. Fields of a later phase
//! (`[browser]`) are refused, not ignored.

mod run;
mod store;

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::{env, thread};

use anyhow::{Context, Result, anyhow, bail};
use jiff::Timestamp;
use jiff::tz::TimeZone;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::chain::{self, Chain};
use crate::door::inspect::parse_prefix;
use crate::policy::{self, Approval, Mode, Site, Status};
use crate::util::{config_dir, expand_home, home};
use crate::{approve, engine, keychain, parse_env, parse_resource};
use store::Layout;

/// Keychain names of box items start with this. Resource names can't contain a dot.
pub const KEY_PREFIX: &str = "box.";
/// The Keychain field of a box's store key. Field names can't start with "_".
const KEY_FIELD: &str = "_key";
/// The Keychain field of where the box's door log stood when it last stopped (`chain::Head`).
pub const LOG_HEAD_FIELD: &str = "_loghead";
/// A box's name also names its VM and its socket (104-byte limit), so it stays short.
const MAX_NAME: usize = 32;

pub fn key(name: &str) -> String {
    format!("{KEY_PREFIX}{name}")
}

pub fn parse_name(s: &str) -> Result<String, String> {
    let name = parse_resource(s).map_err(|_| "use lowercase letters, digits and -, e.g. research".to_string())?;
    if name.len() > MAX_NAME {
        return Err(format!("at most {MAX_NAME} characters"));
    }
    Ok(name)
}

pub fn dir() -> PathBuf {
    env::var_os("CRED_BOX_DIR").map(PathBuf::from).unwrap_or_else(|| config_dir().join("box"))
}

pub fn path(name: &str) -> PathBuf {
    dir().join(format!("{name}.toml"))
}

/// Boxes that have a policy file, approved or not.
pub fn names() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir())
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok()?.file_name().to_str()?.strip_suffix(".toml").map(str::to_string))
        .filter(|n| parse_name(n).is_ok())
        .collect();
    names.sort();
    names
}

// --- the policy ---

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoxPolicy {
    #[serde(default)]
    pub about: String,
    /// What `cred box run` starts inside.
    #[serde(default = "default_run")]
    pub run: Vec<String>,
    /// The system inside, pinned by digest: a new image is a policy change.
    pub image: Option<String>,
    /// Resource whose key cred adds to the agent's model calls.
    pub model: Option<String>,
    /// Resources the agent may use through cred; their own policies apply.
    #[serde(default)]
    pub sites: Vec<String>,
    /// Environment variables set to the stand-in `cred-managed` for tools that refuse to start
    /// without a token (`GH_TOKEN`). The door adds the real credential on the hosts of `sites`.
    #[serde(default)]
    pub standins: Vec<String>,
    /// false: the box is shredded when it stops.
    #[serde(default = "default_keep")]
    pub keep: bool,
    #[serde(default = "default_cpus")]
    pub cpus: u32,
    #[serde(default = "default_memory")]
    pub memory: String,
    /// Docker Engine inside the VM, with the extra capabilities it needs.
    #[serde(default)]
    pub docker: bool,
    #[serde(default)]
    pub net: Net,
    /// Phase 3. Any value is refused until the browser lives in the box.
    pub browser: Option<toml::Value>,
    #[serde(default, rename = "mount")]
    pub mounts: Vec<MountPolicy>,
}

/// Where the agent's own requests may go.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Net {
    /// "*" (any public https site) or patterns like "https://*.wikipedia.org". Empty: nowhere.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Requests other than reads (see `door::inspect`) to hosts no site covers: deny | ask | allow.
    #[serde(default)]
    pub writes: Mode,
    /// URL prefixes (`https://host/path`) that may receive writes whatever `writes` says.
    #[serde(default)]
    pub allow_writes: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MountPolicy {
    pub path: String,
    /// "clone": the agent works on its own copy in work/. "ro": the folder itself, read-only.
    #[serde(default = "default_mode")]
    pub mode: String,
}

fn default_run() -> Vec<String> {
    vec!["claude".into()]
}

fn default_keep() -> bool {
    true
}

fn default_cpus() -> u32 {
    4
}

fn default_memory() -> String {
    "8G".into()
}

fn default_mode() -> String {
    "clone".into()
}

impl MountPolicy {
    pub fn host(&self) -> PathBuf {
        expand_home(&self.path)
    }

    /// The folder's name, which is its name inside the box too.
    pub fn name(&self) -> String {
        self.host().file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
    }

    pub fn readonly(&self) -> bool {
        self.mode == "ro"
    }
}

/// Why a folder can't be handed to a box: it holds cred's own files, or everything.
pub fn mount_problem(path: &Path) -> Option<String> {
    if path == Path::new("/") || path == home() {
        return Some("is too broad".into());
    }
    [config_dir(), home().join("Library/Application Support/cred")]
        .iter()
        .any(|own| path.starts_with(own) || own.starts_with(path))
        .then(|| "holds cred's own files".into())
}

impl BoxPolicy {
    pub fn parse(text: &str) -> Result<Self> {
        let policy: BoxPolicy = toml::from_str(text)?;
        policy.validate()?;
        Ok(policy)
    }

    /// `[net] allow` in the form the door matches against.
    pub fn allow(&self) -> Vec<String> {
        self.net.allow.iter().filter_map(|e| Site::parse(e).ok()).map(|s| s.text()).collect()
    }

    fn validate(&self) -> Result<()> {
        if self.run.is_empty() || self.run.iter().any(|a| a.is_empty()) {
            bail!("run must be a command, e.g. [\"claude\"]");
        }
        if let Some(image) = &self.image {
            let pinned = image.split_once("@sha256:").is_some_and(|(name, digest)| {
                !name.is_empty()
                    && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._/-".contains(&b))
                    && digest.len() == 64
                    && digest.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
            });
            if !pinned {
                bail!("image must be pinned by digest, like cred-agent@sha256:<64 hex digits>");
            }
        }
        if let Some(model) = &self.model {
            parse_resource(model).map_err(|e| anyhow!("model '{model}': {e}"))?;
        }
        let mut seen = BTreeSet::new();
        for site in &self.sites {
            parse_resource(site).map_err(|e| anyhow!("sites: '{site}': {e}"))?;
            if !seen.insert(site) {
                bail!("sites lists {site} twice");
            }
        }
        let reserved: BTreeSet<String> = [true, false].into_iter().flat_map(engine::agent_env).map(|(name, _)| name).collect();
        for name in &self.standins {
            parse_env(name).map_err(|e| anyhow!("standins: '{name}': {e}"))?;
            if reserved.contains(name) {
                bail!("standins: {name} is set by cred already");
            }
            if self.standins.iter().filter(|n| *n == name).count() > 1 {
                bail!("standins lists {name} twice");
            }
        }
        if self.docker {
            bail!("docker = true isn't available yet: the agent image has no Docker Engine");
        }
        if !(1..=64).contains(&self.cpus) {
            bail!("cpus must be between 1 and 64");
        }
        let digits = self.memory.strip_suffix(['M', 'G']).unwrap_or("");
        if digits.is_empty() || digits.len() > 6 || !digits.bytes().all(|b| b.is_ascii_digit()) || digits.bytes().all(|b| b == b'0') {
            bail!("memory must be like 8G or 512M");
        }
        for entry in &self.net.allow {
            let site = Site::parse(entry).map_err(|e| anyhow!("[net] allow '{entry}': {e}"))?;
            // The door connects to port 443 only.
            let text = site.text();
            let https_only = text == "*" || (text.starts_with("https://") && url::Url::parse(&text).map_or(true, |u| u.port().is_none()));
            if !https_only {
                bail!("[net] allow '{entry}': https sites on the default port only");
            }
        }
        for entry in &self.net.allow_writes {
            parse_prefix(entry).map_err(|e| anyhow!("[net] allow_writes '{entry}': {e}"))?;
        }
        if self.browser.is_some() {
            bail!("[browser] arrives with phase 3 (the browser in the box): leave it out");
        }
        let mut names = BTreeSet::new();
        for m in &self.mounts {
            match m.mode.as_str() {
                "clone" | "ro" => {}
                "rw" => bail!("[[mount]] {}: rw isn't available, a box can't change your files; use clone and `cred box export`", m.path),
                other => bail!("[[mount]] {}: mode '{other}' isn't clone or ro", m.path),
            }
            let host = m.host();
            if !host.is_absolute() || host.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir)) {
                bail!("[[mount]] path '{}' must be absolute or start with ~/, without . or ..", m.path);
            }
            if let Some(why) = mount_problem(&host) {
                bail!("[[mount]] path '{}' {why}", m.path);
            }
            let name = m.name();
            if name.is_empty() || name.starts_with('.') || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)) {
                bail!("[[mount]] path '{}': the folder's name must be letters, digits, . _ - and not start with a dot", m.path);
            }
            if !names.insert(name.clone()) {
                bail!("two [[mount]] folders are named {name}");
            }
        }
        Ok(())
    }
}

fn template(name: &str, image: Option<&str>) -> String {
    let image = image.map_or_else(
        || "# image = \"cred-agent@sha256:...\"       # the system inside, pinned: build it with install.sh, then paste its digest".to_string(),
        |digest| format!("image = \"{digest}\"                  # the system inside, pinned: a new image is a policy change"),
    );
    format!(
        r#"# cred box policy for {name}. It takes effect only once approved: cred box approve {name}
about = ""
run = ["claude"]                        # what `cred box run {name}` starts
{image}
model = "anthropic"                     # resource whose key cred adds to the agent's model calls
sites = []                              # resources the agent may use through cred; their policies apply
# standins = ["GH_TOKEN"]               # variables set to "cred-managed" for tools that insist on a token; cred adds the real credential on the hosts of `sites`
keep = true                            # false: the box is shredded when it stops
cpus = 4
memory = "8G"

[net]                                   # where the agent's own requests may go; nothing else is reachable
allow = ["*"]                           # any public https site, reads only (see writes); or a list like ["https://*.wikipedia.org"], or [] for nowhere
writes = "deny"                         # anything but a read (GET, HEAD, OPTIONS, a fetch or clone) to a host no `sites` entry covers: deny | ask (Touch ID each) | allow
# allow_writes = ["https://api.example.com/search"]   # URL prefixes that may receive writes anyway

# [[mount]]                             # holes in the box: none unless listed
# path = "~/Git/project"
# mode = "clone"                        # clone: the agent works on its own copy in work/ | ro: read-only
"#
    )
}

// --- approval ---

/// The approved policy of a box and its text, or why there is none.
fn load(name: &str) -> Result<(BoxPolicy, String)> {
    let p = path(name);
    let text = policy::approved_at(&key(name), &p).map_err(|why| not_approved(name, &why))?;
    let policy = BoxPolicy::parse(&text).with_context(|| p.display().to_string())?;
    Ok((policy, text))
}

fn not_approved(name: &str, why: &Status) -> anyhow::Error {
    match why {
        Status::Missing => anyhow!("there is no box {name} (create it with: cred box new {name})"),
        Status::Unapproved => anyhow!("the policy for box {name} isn't approved (cred box approve {name})"),
        Status::Changed => anyhow!("the policy for box {name} changed since it was approved (cred box approve {name})"),
        Status::Approved => anyhow!("box {name} is approved"),
    }
}

/// Read, check and show a box policy for approval; what is shown is exactly what gets pinned.
pub fn prepare(name: &str) -> Result<(String, Approval)> {
    let p = path(name);
    let text = fs::read_to_string(&p).map_err(|_| not_approved(name, &Status::Missing))?;
    BoxPolicy::parse(&text).with_context(|| p.display().to_string())?;
    let approval = Approval::of(&text);
    println!("Policy for box {name} ({}):\n\n{}\n\nsha256 {}\n", p.display(), text.trim_end(), approval.short());
    Ok((key(name), approval))
}

pub fn approve(names_given: &[String]) -> Result<()> {
    let given = if names_given.is_empty() { names() } else { names_given.to_vec() };
    if given.is_empty() {
        bail!("there are no boxes (create one with: cred box new NAME)");
    }
    let prepared = given.iter().map(|n| prepare(n)).collect::<Result<_>>()?;
    policy::approve_prepared(prepared)
}

// --- commands ---

/// The box's store key, from the Keychain.
fn box_key(name: &str) -> Result<String> {
    keychain::get(&key(name), KEY_FIELD)
        .ok_or_else(|| anyhow!("the key of box {name} isn't in the Keychain, so its store can't be opened (cred box rm {name})"))
}

// STUB: replaced at merge by seal::derive (one key per purpose, derived from the box key)
fn derive(box_key: &[u8], purpose: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"cred box key derivation stub\0");
    hash.update(purpose.as_bytes());
    hash.update(b"\0");
    hash.update(box_key);
    hash.finalize().into()
}

/// The key that chains the box's log (`door.log`), derived from the box key; `key` is the box
/// key as the Keychain holds it.
fn log_key(key: &str) -> [u8; 32] {
    derive(key.as_bytes(), "log")
}

fn has_key(name: &str) -> bool {
    keychain::exists(&key(name), KEY_FIELD)
}

/// Make a box: its policy (edited from a template), a key in the Keychain and an empty store.
pub fn new(name: &str) -> Result<()> {
    let layout = Layout::real()?;
    let (p, bundle, k) = (path(name), layout.bundle(name), key(name));
    match (has_key(name), bundle.exists()) {
        (true, true) => bail!("box {name} exists (cred box edit {name} changes its policy)"),
        (false, true) => bail!("box {name} has a store but no key, so it can't be opened: remove it with cred box rm {name}"),
        _ => {}
    }
    if !p.exists() {
        fs::create_dir_all(dir())?;
        // The pinned image of the engine's agent system, if there is one yet.
        let image = engine::image_digest(engine::AGENT_IMAGE).ok();
        fs::write(&p, template(name, image.as_deref()))?;
    }
    let edited = policy::edit_file(&k, &p, |text| BoxPolicy::parse(text).map(drop))?;
    if BoxPolicy::parse(&fs::read_to_string(&p)?)?.keep {
        let created = !has_key(name);
        if created {
            keychain::set(&k, KEY_FIELD, &store::new_key()?)?;
        }
        let made = keychain::get(&k, KEY_FIELD).ok_or_else(|| anyhow!("the key of box {name} can't be read"));
        if let Err(e) = made.and_then(|key| store::create(&layout, &bundle, &key)) {
            if created {
                keychain::delete(&k, KEY_FIELD);
            }
            return Err(e);
        }
        println!("created box {name}: an empty encrypted store, its key in the Keychain");
    } else {
        println!("created box {name}: keep = false, so every run gets a new store that is shredded when it stops");
    }
    if edited || !matches!(policy::status_of(&k, &p), Status::Approved) {
        policy::offer_approval(&p, &format!("cred box approve {name}"), || approve(&[name.to_string()]))?;
    }
    Ok(())
}

pub fn edit(name: &str) -> Result<()> {
    let p = path(name);
    if !p.exists() {
        return Err(not_approved(name, &Status::Missing));
    }
    if policy::edit_file(&key(name), &p, |text| BoxPolicy::parse(text).map(drop))? {
        policy::offer_approval(&p, &format!("cred box approve {name}"), || approve(&[name.to_string()]))?;
    }
    Ok(())
}

/// `cred box run`: open the box (or join it if it runs), and work in it until it ends.
pub fn run(name: &str, temp: bool, command: Vec<String>) -> Result<u8> {
    let (policy, text) = load(name)?;
    let layout = Layout::real()?;
    let persistent = policy.keep && !temp;
    if persistent && !layout.bundle(name).exists() {
        bail!("box {name} has no store (create one with: cred box new {name})");
    }
    let id = if temp { format!("{name}-tmp-{}", &store::new_key()?[..8]) } else { name.to_string() };
    if temp {
        println!("temporary box {id}: shredded when it stops");
    }
    run::catch_signals();
    let request = run::Request {
        name,
        id,
        policy: &policy,
        policy_sha: crate::util::sha256_hex(text.as_bytes()),
        persistent,
        unique: temp,
        command: (!command.is_empty()).then_some(command),
        tty: crate::interactive(),
        stop: run::signalled(),
    };
    run::run(&layout, &run::Real, &request)
}

pub fn stop(name: &str) -> Result<()> {
    let layout = Layout::real()?;
    let vm = run::vm_name(name);
    let was_running = engine::running(&vm);
    if was_running {
        engine::stop(&vm)?;
    }
    let lock = layout.lock(name);
    if lock.exists() {
        // The cred that runs the box shuts it down; when it lets go, nothing is left to clean.
        // If it died, what it left (a mounted store) is cleaned here.
        for _ in 0..60 {
            if let Some(_held) = store::lock(&lock)? {
                run::sweep(&layout, name)?;
                break;
            }
            thread::sleep(std::time::Duration::from_millis(250));
        }
    }
    if was_running {
        println!("stopped box {name}");
        Ok(())
    } else {
        bail!("box {name} isn't running")
    }
}

/// Run `f` on the open store. A store that is closed is opened (and closed again) after Touch ID
/// and the key from the Keychain. One that a run has open can be read, not changed: `readonly`.
fn with_store<T>(name: &str, reason: &str, readonly: bool, f: impl FnOnce(&Path) -> Result<T>) -> Result<T> {
    let layout = Layout::real()?;
    layout.prepare()?;
    let bundle = layout.bundle(name);
    if !bundle.exists() {
        bail!("box {name} has no store (cred box new {name})");
    }
    let mnt = layout.mount_point(name);
    let Some(_lock) = store::lock(&layout.lock(name))? else {
        if !readonly {
            bail!("box {name} is running: stop it first (cred box stop {name}), so nothing changes a folder its VM has mounted");
        }
        if !store::is_mounted(&mnt) {
            bail!("box {name} is being opened or closed: try again in a moment");
        }
        return f(&mnt);
    };
    approve::confirm(reason)?;
    let key = box_key(name)?;
    let open = store::open(&bundle, &mnt, &key, readonly)?;
    f(open.path())
}

/// What the door and cred did for a box, latest last. With `verify`, checks the whole log
/// against its chain instead, and fails naming the first line that was changed or removed.
pub fn log(name: &str, last: usize, verify: bool) -> Result<()> {
    with_store(name, &format!("read the log of box {name}"), true, |mnt| {
        if verify {
            let chain = Chain::new(&store::door_log(mnt), log_key(&box_key(name)?));
            let found = chain.verify().with_context(|| format!("the log of box {name}"))?;
            let head = keychain::get_silently(&key(name), LOG_HEAD_FIELD).and_then(|h| serde_json::from_str::<chain::Head>(&h).ok());
            if let Some(head) = &head {
                found.check(head).with_context(|| format!("the log of box {name}"))?;
            }
            let before = if found.unchained > 0 { format!(" ({} older lines from before the log was chained can't be checked)", found.unchained) } else { String::new() };
            println!("{} lines, chain intact{before}", found.chained);
            return Ok(());
        }
        let text = fs::read_to_string(store::door_log(mnt)).unwrap_or_default();
        let lines: Vec<&str> = text.lines().collect();
        for line in &lines[lines.len().saturating_sub(last)..] {
            println!("{line}");
        }
        if lines.is_empty() {
            println!("nothing logged yet");
        }
        Ok(())
    })
}

/// A file taken out of a box.
struct Exported {
    file: PathBuf,
    size: u64,
    sha256: String,
}

fn sha256_file(path: &Path) -> Result<(String, u64)> {
    let mut file = File::open(path)?;
    let (mut hash, mut buf, mut size) = (Sha256::new(), vec![0u8; 1 << 16], 0);
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
        size += n as u64;
    }
    Ok((hash.finalize().iter().map(|b| format!("{b:02x}")).collect(), size))
}

/// A path inside the box, as typed: relative, going nowhere but down.
fn box_path(rel: &str) -> Result<PathBuf> {
    let rel = Path::new(rel);
    if rel.as_os_str().is_empty() || !rel.components().all(|c| matches!(c, Component::Normal(_))) {
        bail!("give a path inside the box, like work/report.md (no leading /, . or ..)");
    }
    Ok(rel.to_path_buf())
}

/// Copy `rel` out of the open store into `to`. A path that resolves outside the store (a link the
/// agent made) is refused, and links inside a folder are skipped.
fn export_from(mnt: &Path, rel: &str, to: &Path) -> Result<(Vec<Exported>, usize)> {
    let rel = box_path(rel)?;
    let src = mnt.join(&rel);
    let real = fs::canonicalize(&src).map_err(|_| anyhow!("{} isn't in the box", rel.display()))?;
    if !real.starts_with(fs::canonicalize(mnt)?) {
        bail!("{} leads out of the box", rel.display());
    }
    let to = fs::canonicalize(to).with_context(|| format!("{} isn't a folder", to.display()))?;
    if !to.is_dir() {
        bail!("{} isn't a folder", to.display());
    }
    let dst = to.join(rel.file_name().expect("a normal component"));
    let copied = store::copy_tree(&src, &dst)?;
    let single = src.is_file();
    let mut out = Vec::new();
    for file in copied.files {
        let (sha256, size) = sha256_file(&if single { dst.clone() } else { dst.join(&file) })?;
        out.push(Exported { file: if single { rel.clone() } else { rel.join(file) }, size, sha256 });
    }
    Ok((out, copied.skipped))
}

pub fn export(name: &str, rel: &str, to: &Path) -> Result<()> {
    box_path(rel)?;
    let reason = format!("export {rel} from box {name} to {}", to.display());
    with_store(name, &reason, false, |mnt| {
        let log_key = log_key(&box_key(name)?);
        let (files, skipped) = export_from(mnt, rel, to)?;
        let mut total = 0;
        for f in &files {
            println!("{:>10}  {}  {}", human(f.size), f.sha256, f.file.display());
            store::log_event(mnt, &log_key, "export", &f.file.display().to_string(), f.size, "allowed")?;
            total += f.size;
        }
        let links = if skipped > 0 { format!(" ({skipped} links and special files skipped)") } else { String::new() };
        println!("exported {} file(s), {}, to {}{links}", files.len(), human(total), to.display());
        Ok(())
    })
}

pub fn import(name: &str, from: &str) -> Result<()> {
    let src = expand_home(from);
    let file_name = src.file_name().map(|n| n.to_os_string()).ok_or_else(|| anyhow!("{from} isn't a file or folder"))?;
    with_store(name, &format!("import {} into box {name}", src.display()), false, |mnt| {
        let log_key = log_key(&box_key(name)?);
        let dst = mnt.join("work").join(&file_name);
        let copied = store::copy_tree(&src, &dst)?;
        let rel = Path::new("work").join(&file_name);
        store::log_event(mnt, &log_key, "import", &rel.display().to_string(), 0, "allowed")?;
        println!("imported {} file(s) into {}", copied.files.len(), rel.display());
        Ok(())
    })
}

pub fn rm(name: &str) -> Result<()> {
    let layout = Layout::real()?;
    let (p, bundle, k) = (path(name), layout.bundle(name), key(name));
    if !p.exists() && !bundle.exists() && !has_key(name) {
        bail!("there is no box {name}");
    }
    let lock = layout.lock(name);
    layout.prepare()?;
    let Some(_held) = store::lock(&lock)? else {
        bail!("box {name} is running: stop it first (cred box stop {name})");
    };
    approve::confirm(&format!("delete box {name}: its data can never be read again"))?;
    // The key goes first: without it the store is noise, whatever happens to the files.
    keychain::delete(&k, KEY_FIELD);
    keychain::delete(&k, LOG_HEAD_FIELD);
    policy::revoke(&k);
    store::shred(&bundle)?;
    run::sweep(&layout, name)?;
    println!("deleted box {name}: its key and its store");
    if p.exists() {
        println!("kept its policy {} (cred box new {name} makes a fresh box from it)", p.display());
    }
    println!(
        "Time Machine may still hold encrypted copies of the store (and APFS local snapshots for about a day). \
         They stay closed unless restored together with a Keychain from before this, which has the old key."
    );
    Ok(())
}

fn human(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let (mut value, mut unit) = (bytes as f64, 0);
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 { format!("{bytes} B") } else { format!("{value:.1} {}", UNITS[unit]) }
}

pub fn ls() -> Result<()> {
    let layout = Layout::real()?;
    println!("{:<20} {:<9} {:<22} {:>9}  {:<17} {:<24} ABOUT", "BOX", "STATE", "POLICY", "SIZE", "LAST USED", "SITES");
    let mut shown = names();
    // Stores whose policy file is gone.
    for entry in fs::read_dir(&layout.root).into_iter().flatten().flatten() {
        let file = entry.file_name().to_string_lossy().into_owned();
        if let Some(name) = file.strip_suffix(".sparsebundle").filter(|n| !shown.iter().any(|s| s == n)) {
            shown.push(name.to_string());
        }
    }
    for name in &shown {
        let bundle = layout.bundle(name);
        let parsed = fs::read_to_string(path(name)).ok().and_then(|t| BoxPolicy::parse(&t).ok());
        let held = store::is_held(&layout.lock(name));
        let state = match (held, bundle.exists(), parsed.as_ref().is_some_and(|p| !p.keep)) {
            (true, _, _) => "open",
            (false, true, _) => "locked",
            (false, false, true) => "shredded",
            (false, false, false) => "no store",
        };
        let status = if path(name).exists() { policy::status_of(&key(name), &path(name)).text() } else { "no policy" };
        let (bytes, used) = if bundle.exists() { store::usage(&bundle) } else { (0, None) };
        let used = used
            .and_then(|t| Timestamp::try_from(t).ok())
            .map_or("-".to_string(), |t| t.to_zoned(TimeZone::system()).strftime("%Y-%m-%d %H:%M").to_string());
        let sites = parsed.as_ref().map_or(String::new(), |p| p.sites.join(", "));
        let about = parsed.as_ref().map_or("", |p| p.about.as_str());
        let size = if bundle.exists() { human(bytes) } else { "-".into() };
        println!("{name:<20} {state:<9} {status:<22} {size:>9}  {used:<17} {sites:<24} {about}");
    }
    // Temporary boxes that are running.
    for entry in fs::read_dir(layout.open_dir()).into_iter().flatten().flatten() {
        let file = entry.file_name().to_string_lossy().into_owned();
        let Some(id) = file.strip_suffix(".lock").filter(|id| id.contains("-tmp-")) else { continue };
        if store::is_held(&entry.path()) {
            println!("{id:<20} {:<9} {:<22} {:>9}  {:<17} {:<24} temporary", "open", "-", "-", "-", "");
        }
    }
    if shown.is_empty() {
        println!("(no boxes: cred box new NAME)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_field;
    use crate::util::TempDir;

    const DIGEST: &str = "cred-agent@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn err(text: &str) -> String {
        format!("{:#}", BoxPolicy::parse(text).err().unwrap_or_else(|| panic!("accepted: {text}")))
    }

    #[test]
    fn parses_a_full_policy() {
        let p = BoxPolicy::parse(&format!(
            r#"
            about = "Market research"
            run = ["claude", "--dangerously-skip-permissions"]
            image = "{DIGEST}"
            model = "anthropic"
            sites = ["github", "app"]
            keep = false
            cpus = 2
            memory = "512M"

            standins = ["GH_TOKEN", "NPM_TOKEN"]

            [net]
            allow = ["*", "https://*.wikipedia.org", "https://docs.rs", "https://Example.com"]
            writes = "ask"
            allow_writes = ["https://api.example.com/search", "https://docs.rs"]

            [[mount]]
            path = "~/Git/cred"

            [[mount]]
            path = "/opt/data/"
            mode = "ro"
            "#
        ))
        .unwrap();
        assert_eq!((p.keep, p.cpus, p.memory.as_str(), p.docker), (false, 2, "512M", false));
        assert_eq!(p.allow(), ["*", "https://*.wikipedia.org", "https://docs.rs", "https://example.com"]);
        assert_eq!((p.net.writes, p.net.allow_writes.len(), p.standins.as_slice()), (Mode::Ask, 2, &["GH_TOKEN".to_string(), "NPM_TOKEN".to_string()][..]));
        assert_eq!(BoxPolicy::parse("[net]\nwrites = \"allow\"").unwrap().net.writes, Mode::Allow);
        assert_eq!((p.mounts[0].name(), p.mounts[0].readonly()), ("cred".to_string(), false));
        assert_eq!((p.mounts[1].name(), p.mounts[1].readonly()), ("data".to_string(), true));
    }

    #[test]
    fn an_empty_policy_is_a_closed_box() {
        let p = BoxPolicy::parse("").unwrap();
        assert!(p.net.writes == Mode::Deny && p.net.allow_writes.is_empty() && p.standins.is_empty());
        assert_eq!((p.run.as_slice(), p.keep, p.cpus, p.memory.as_str()), (&["claude".to_string()][..], true, 4, "8G"));
        assert!(p.allow().is_empty() && p.sites.is_empty() && p.mounts.is_empty() && p.image.is_none());
    }

    #[test]
    fn rejects_what_the_door_cannot_keep() {
        for (text, why) in [
            ("docker = true", "docker = true isn't available"),
            ("[browser]\nkeep_sessions = true", "phase 3"),
            ("[[mount]]\npath = \"/opt/data\"\nmode = \"rw\"", "rw isn't available"),
            ("[[mount]]\npath = \"/opt/data\"\nmode = \"x\"", "isn't clone or ro"),
        ] {
            let e = err(text);
            assert!(e.contains(why), "{text}: {e}");
        }
    }

    #[test]
    fn rejects_unsafe_or_malformed_policies() {
        for (text, why) in [
            ("nope = 1", "unknown field"),
            ("[net]\nalow = []", "unknown field"),
            ("run = []", "run must be"),
            ("run = [\"\"]", "run must be"),
            ("image = \"cred-agent\"", "pinned by digest"),
            ("image = \"cred-agent@sha256:abc\"", "pinned by digest"),
            ("model = \"Bad Name\"", "model"),
            ("sites = [\"github\", \"github\"]", "twice"),
            ("sites = [\"../x\"]", "sites"),
            ("cpus = 0", "cpus"),
            ("memory = \"8\"", "memory"),
            ("memory = \"0G\"", "memory"),
            ("memory = \"lots\"", "memory"),
            ("[net]\nwrites = \"sometimes\"", "unknown variant"),
            ("[net]\nallow_writes = [\"http://a.example.com/x\"]", "allow_writes"),
            ("[net]\nallow_writes = [\"a.example.com/x\"]", "allow_writes"),
            ("[net]\nallow_writes = [\"https://*.example.com/x\"]", "allow_writes"),
            ("[net]\nallow_writes = [\"https://a.example.com/x?y=1\"]", "allow_writes"),
            ("[net]\nallow_writes = [\"https://a.example.com:8443/x\"]", "allow_writes"),
            ("standins = [\"gh_token\"]", "standins"),
            ("standins = [\"GH TOKEN\"]", "standins"),
            ("standins = [\"HTTPS_PROXY\"]", "set by cred already"),
            ("standins = [\"ANTHROPIC_API_KEY\"]", "set by cred already"),
            ("standins = [\"CLAUDE_CODE_OAUTH_TOKEN\"]", "set by cred already"),
            ("standins = [\"GH_TOKEN\", \"GH_TOKEN\"]", "twice"),
            ("[net]\nallow = [\"http://a.example.com\"]", "https"),
            ("[net]\nallow = [\"http://localhost\"]", "https"),
            ("[net]\nallow = [\"https://a.example.com:8443\"]", "default port"),
            ("[net]\nallow = [\"https://a.example.com/path\"]", "scheme://host"),
            ("[net]\nallow = [\"https://*.com\"]", "like https://*.example.com"),
            ("[[mount]]\npath = \"relative/dir\"", "absolute"),
            ("[[mount]]\npath = \"/opt/../etc\"", "absolute"),
            ("[[mount]]\npath = \"/\"", "too broad"),
            ("[[mount]]\npath = \"/opt/.hidden\"", "must be letters"),
            ("[[mount]]\npath = \"/opt/a b\"", "must be letters"),
            ("[[mount]]\npath = \"/opt/a\"\n[[mount]]\npath = \"/srv/a\"", "two [[mount]]"),
            ("[[mount]]\npath = \"/opt/a\"\nmod = \"ro\"", "unknown field"),
        ] {
            let e = err(text);
            assert!(e.contains(why), "{text}: {e}");
        }
    }

    #[test]
    fn keeps_cred_s_own_folders_out_of_boxes() {
        for path in [home(), config_dir(), config_dir().join("policy"), home().join(".config"), home().join("Library/Application Support/cred/box/open/x"), home().join("Library/Application Support")] {
            let text = format!("[[mount]]\npath = \"{}\"", path.display());
            let e = err(&text);
            assert!(e.contains("too broad") || e.contains("cred's own"), "{text}: {e}");
        }
        assert!(BoxPolicy::parse(&format!("[[mount]]\npath = \"{}\"", home().join("Git/project").display())).is_ok());
    }

    #[test]
    fn the_templates_are_valid_policies() {
        assert!(BoxPolicy::parse(&template("research", None)).is_ok());
        let open = BoxPolicy::parse(&template("research", None)).unwrap();
        assert_eq!((open.allow(), open.net.writes), (vec!["*".to_string()], Mode::Deny), "the open web, reads only");
        let p = BoxPolicy::parse(&template("research", Some(DIGEST))).unwrap();
        assert_eq!((p.image.as_deref(), p.model.as_deref(), p.keep), (Some(DIGEST), Some("anthropic"), true));
        assert!(template("research", None).contains("cred box approve research"));
    }

    #[test]
    fn names_are_short_and_plain() {
        assert!(parse_name("research").is_ok() && parse_name("a-1").is_ok());
        assert!(parse_name("Research").is_err() && parse_name("a.b").is_err() && parse_name("").is_err());
        assert!(parse_name(&"a".repeat(MAX_NAME)).is_ok() && parse_name(&"a".repeat(MAX_NAME + 1)).is_err());
        assert_eq!(key("research"), "box.research");
        assert!(parse_resource(&key("research")).is_err(), "no resource can be named like a box key");
        assert!(parse_field(KEY_FIELD).is_err(), "no field can be named like the key");
    }

    #[test]
    fn says_why_a_box_is_not_approved() {
        let say = |s: Status| not_approved("research", &s).to_string();
        assert!(say(Status::Missing).contains("cred box new research"));
        assert!(say(Status::Unapproved).contains("isn't approved") && say(Status::Unapproved).contains("cred box approve research"));
        assert!(say(Status::Changed).contains("changed since"));
    }

    #[test]
    fn sizes_read_plainly() {
        assert_eq!((human(0), human(999), human(1500), human(25_000_000), human(3_200_000_000)), ("0 B".into(), "999 B".into(), "1.5 KB".into(), "25.0 MB".into(), "3.2 GB".into()));
    }

    #[test]
    fn exports_list_each_file_with_size_and_hash() {
        let dir = TempDir::new("cred-export").unwrap();
        let (mnt, to) = (dir.0.join("mnt"), dir.0.join("to"));
        fs::create_dir_all(mnt.join("work/out")).unwrap();
        fs::create_dir_all(&to).unwrap();
        fs::write(mnt.join("work/report.md"), "hello\n").unwrap();
        fs::write(mnt.join("work/out/a.csv"), "").unwrap();
        fs::write(dir.0.join("secret.txt"), "not in the box").unwrap();
        std::os::unix::fs::symlink(dir.0.join("secret.txt"), mnt.join("work/out/link")).unwrap();
        std::os::unix::fs::symlink(&dir.0, mnt.join("work/escape")).unwrap();

        let (files, skipped) = export_from(&mnt, "work/report.md", &to).unwrap();
        assert_eq!((files.len(), skipped), (1, 0));
        assert_eq!((files[0].file.as_path(), files[0].size), (Path::new("work/report.md"), 6));
        assert_eq!(files[0].sha256, crate::util::sha256_hex(b"hello\n"));
        assert_eq!(fs::read_to_string(to.join("report.md")).unwrap(), "hello\n");
        assert!(export_from(&mnt, "work/report.md", &to).is_err(), "never overwrites");

        let (files, skipped) = export_from(&mnt, "work/out", &to).unwrap();
        assert_eq!((files.iter().map(|f| f.file.clone()).collect::<Vec<_>>(), skipped), (vec![PathBuf::from("work/out/a.csv")], 1));
        assert!(to.join("out/a.csv").exists() && !to.join("out/link").exists());
    }

    #[test]
    fn exports_never_leave_the_box() {
        let dir = TempDir::new("cred-escape").unwrap();
        let (mnt, to) = (dir.0.join("mnt"), dir.0.join("to"));
        fs::create_dir_all(mnt.join("work")).unwrap();
        fs::create_dir_all(&to).unwrap();
        fs::write(dir.0.join("secret.txt"), "not in the box").unwrap();
        std::os::unix::fs::symlink(&dir.0, mnt.join("work/escape")).unwrap();
        std::os::unix::fs::symlink(dir.0.join("secret.txt"), mnt.join("work/file-link")).unwrap();

        for rel in ["../secret.txt", "/etc/passwd", "work/../../secret.txt", "", ".", "work/escape/secret.txt", "work/escape", "work/file-link", "work/missing"] {
            assert!(export_from(&mnt, rel, &to).is_err(), "exported {rel:?}");
        }
        assert!(fs::read_dir(&to).unwrap().next().is_none(), "nothing was written");
        assert!(export_from(&mnt, "work", &dir.0.join("nowhere")).is_err());
    }
}

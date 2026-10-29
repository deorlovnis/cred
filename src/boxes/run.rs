//! `cred box run`: open the box, start its VM and door, work in it, and put everything away.
//!
//! The order is the point. Opening needs a lock (one cred per open box), Touch ID, the key and
//! the store; then the folders are set up while no VM has them mounted, then the VM and the door
//! start. Ending runs the other way round: the VM stops first, then the door, then the store is
//! detached (and deleted, for a box that isn't kept). Each step is held by a guard object, so an
//! error, a panic or a signal (see `catch_signals`) unwinds the same way.
//!
//! Everything outside cred (Touch ID, the engine, the door) is reached through `World`, so the
//! sequence can be tested with fakes while the store is real.

use std::any::Any;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value, json};

use super::store::{self, Layout};
use super::{BoxPolicy, MountPolicy, mount_problem};
use crate::chain::{self, Chain};
use crate::{approve, door, engine, keychain, policy, seal};

/// Where the store's folders appear in the VM, and where `ro` folders go.
const GUEST_HOME: &str = "/home/agent";
const GUEST_WORK: &str = "/work";
const GUEST_DOWNLOADS: &str = "/downloads";
const GUEST_MOUNTS: &str = "/mnt";
/// How often a stop request (a signal) is looked for while the agent works.
const WATCH_EVERY: Duration = Duration::from_millis(100);

/// What a run needs from outside cred.
pub trait World: Sync {
    fn confirm(&self, reason: &str) -> Result<()>;
    fn available(&self) -> Result<()>;
    fn running(&self, vm: &str) -> bool;
    fn start_vm(&self, spec: &engine::VmSpec) -> Result<()>;
    /// Stop a VM; fine if it is gone already.
    fn stop_vm(&self, vm: &str);
    /// Start the door. It stops when the returned value is dropped.
    fn start_door(&self, cfg: door::Config) -> Result<Box<dyn Any>>;
    /// Make the box's CA trusted inside the VM (as root, before the agent starts).
    fn install_ca(&self, vm: &str, pem: &str) -> Result<()>;
    fn model_uses_bearer(&self, model: &str) -> Result<bool>;
    /// Fails unless the site has an approved policy.
    fn site_ready(&self, site: &str) -> Result<()>;
    /// The store key of a kept box.
    fn key(&self, name: &str) -> Result<String>;
    /// Keep where the box's log chain stands, outside the store.
    fn record_log_head(&self, name: &str, head: &chain::Head) -> Result<()>;
    fn exec(&self, vm: &str, env: &[(String, String)], cmd: &[String], tty: bool) -> Result<ExitStatus>;
}

/// The real thing.
pub struct Real;

impl World for Real {
    fn confirm(&self, reason: &str) -> Result<()> {
        approve::confirm(reason)
    }

    fn available(&self) -> Result<()> {
        engine::available()
    }

    fn running(&self, vm: &str) -> bool {
        engine::running(vm)
    }

    fn start_vm(&self, spec: &engine::VmSpec) -> Result<()> {
        engine::run(spec)
    }

    fn stop_vm(&self, vm: &str) {
        if let Err(e) = engine::stop(vm) {
            eprintln!("cred: stopping {vm}: {e:#}");
        }
    }

    fn start_door(&self, cfg: door::Config) -> Result<Box<dyn Any>> {
        Ok(Box::new(door::Door::start(cfg)?))
    }

    fn install_ca(&self, vm: &str, pem: &str) -> Result<()> {
        engine::install_ca(vm, pem)
    }

    fn model_uses_bearer(&self, model: &str) -> Result<bool> {
        door::model_uses_bearer(model)
    }

    fn site_ready(&self, site: &str) -> Result<()> {
        policy::load(site).map(drop)
    }

    fn key(&self, name: &str) -> Result<String> {
        keychain::get(&super::key(name), super::KEY_FIELD)
            .ok_or_else(|| anyhow!("the key of box {name} isn't in the Keychain, so its store can't be opened (cred box rm {name})"))
    }

    fn record_log_head(&self, name: &str, head: &chain::Head) -> Result<()> {
        keychain::set(&super::key(name), super::LOG_HEAD_FIELD, &serde_json::to_string(head)?)
    }

    fn exec(&self, vm: &str, env: &[(String, String)], cmd: &[String], tty: bool) -> Result<ExitStatus> {
        let status = engine::exec(vm, env, cmd, tty);
        // `container exec` shares the terminal and may leave it non-blocking.
        crate::util::blocking_stdio();
        status
    }
}

/// One run of a box.
pub struct Request<'a> {
    pub name: &'a str,
    /// What names the VM, socket, lock and mount: the box's name, or a unique one for `--temp`.
    pub id: String,
    pub policy: &'a BoxPolicy,
    /// The SHA-256 of the approved policy text: a join must run under the policy the box opened with.
    pub policy_sha: String,
    /// A kept box, whose store and key last; otherwise a store made for this run and shredded after.
    pub persistent: bool,
    /// The id belongs to this run alone, so its lock file goes with it.
    pub unique: bool,
    /// Run this instead of the policy's `run`.
    pub command: Option<Vec<String>>,
    pub tty: bool,
    /// Set (by a signal) to stop the box.
    pub stop: &'a AtomicBool,
}

pub fn vm_name(id: &str) -> String {
    format!("cred-box-{id}")
}

/// Run the box. Returns the exit code of the command inside.
pub fn run(layout: &Layout, world: &dyn World, req: &Request) -> Result<u8> {
    layout.prepare()?;
    let vm = vm_name(&req.id);
    let policy = req.policy;
    let agent_env = || -> Result<Vec<(String, String)>> {
        let bearer = policy.model.as_deref().map(|m| world.model_uses_bearer(m)).transpose()?.unwrap_or(false);
        let mut env = engine::agent_env(bearer);
        // For tools that won't start without a token; the door adds the real one on the sites' hosts.
        env.extend(policy.standins.iter().map(|name| (name.clone(), door::STANDIN.to_string())));
        Ok(env)
    };
    let command = guest_command(req.command.as_deref().unwrap_or(&policy.run));

    // Another cred has the box open: work in the same VM, through the same door.
    let Some(lock) = store::lock(&layout.lock(&req.id))? else {
        if !world.running(&vm) {
            bail!("box {} is being opened or closed by another cred: try again in a moment", req.name);
        }
        // The door of the open box keeps the rules it started with, so joining under a policy
        // approved since would promise rules nothing enforces.
        if fs::read_to_string(layout.opened_with(&req.id)).ok().as_deref() != Some(req.policy_sha.as_str()) {
            bail!(
                "box {} runs with the policy it was opened with, not the one approved since: stop it (cred box stop {}) and run it again",
                req.name,
                req.name
            );
        }
        return exit_code(world.exec(&vm, &agent_env()?, &command, req.tty)?);
    };
    fs::write(layout.opened_with(&req.id), &req.policy_sha).with_context(|| format!("noting the policy box {} opens with", req.name))?;

    // Holding the lock, whatever a crashed run left is ours to clear.
    sweep_temp(layout)?;
    sweep(layout, &req.id)?;
    if world.running(&vm) {
        world.stop_vm(&vm);
    }

    world.available()?;
    let image = policy.image.as_deref().ok_or_else(|| anyhow!("the policy of box {} names no image (set image = \"cred-agent@sha256:...\" and approve it)", req.name))?;
    let env = agent_env()?;
    for site in policy.model.iter().chain(&policy.sites) {
        world.site_ready(site).with_context(|| format!("box {} uses {site}", req.name))?;
    }
    let folders = resolve_mounts(&policy.mounts)?;

    let sites = if policy.sites.is_empty() { String::new() } else { format!(" and let it use {}", policy.sites.join(", ")) };
    world.confirm(&format!("open box {}{sites}", req.name))?;

    let mnt = layout.mount_point(&req.id);
    let (bundle, key) = if req.persistent {
        (layout.bundle(req.name), world.key(req.name)?)
    } else {
        let (bundle, key) = (layout.ephemeral_bundle(&req.id), store::new_key()?);
        store::create(layout, &bundle, &key)?;
        (bundle, key)
    };
    let log_key = super::log_key(&key);
    let mut store = store::open(&bundle, &mnt, &key, false).inspect_err(|_| {
        if !req.persistent {
            let _ = store::shred(&bundle);
        }
    })?;
    if !req.persistent {
        store.shred_on_close();
    }
    let ca = Arc::new(box_ca(&mnt, req.name, &key, req.persistent)?);
        let _ = store::log_event(&mnt, &log_key, "box", &req.id, 0, "started");

    // The folders are changed here, while no VM has them.
    prepare_home(&mnt.join("home"))?;
    let mut mounts = vec![
        engine::Mount { host: mnt.join("home"), guest: GUEST_HOME.into(), readonly: false },
        engine::Mount { host: mnt.join("work"), guest: GUEST_WORK.into(), readonly: false },
        engine::Mount { host: mnt.join("downloads"), guest: GUEST_DOWNLOADS.into(), readonly: false },
    ];
    for (mount, host) in &folders {
        if mount.readonly() {
            mounts.push(engine::Mount { host: host.clone(), guest: format!("{GUEST_MOUNTS}/{}", mount.name()), readonly: true });
        } else {
            clone_into(&mnt.join("work"), &mount.name(), host)?;
        }
    }

    let socket = layout.socket(&req.id);
    let _ = fs::remove_file(&socket);
    let spec = engine::VmSpec {
        name: vm.clone(),
        image: image.to_string(),
        cpus: policy.cpus,
        memory: policy.memory.clone(),
        socket: socket.clone(),
        mounts,
        docker: policy.docker,
    };
    let config = door::Config {
        name: req.id.clone(),
        socket: socket.clone(),
        allow: policy.allow(),
        model: policy.model.clone(),
        sites: policy.sites.clone(),
        net: door::inspect::Net { writes: policy.net.writes, allow_writes: policy.net.allow_writes.clone() },
        log: store::door_log(&mnt),
        ca: Some(ca.clone()),
        log_key,
    };

    // Declared in the order they start, so they drop in the order they must end: VM, door, store.
    let door: Box<dyn Any>;
    let vm_guard = VmGuard { world, vm: &vm, socket: &socket };
    world.start_vm(&spec)?;
    door = world.start_door(config)?;
    world.install_ca(&vm, &ca.cert_pem())?;

    let done = AtomicBool::new(false);
    let status = thread::scope(|scope| {
        scope.spawn(|| {
            while !done.load(Ordering::SeqCst) {
                if req.stop.load(Ordering::SeqCst) {
                    world.stop_vm(&vm);
                    return;
                }
                thread::sleep(WATCH_EVERY);
            }
        });
        let status = world.exec(&vm, &env, &command, req.tty);
        done.store(true, Ordering::SeqCst);
        status
    });

    let _ = store::log_event(&mnt, &log_key, "box", &req.id, 0, "stopped");
    drop(vm_guard);
    drop(door);
    if req.persistent {
        record_head(world, req.name, &mnt, log_key);
    }
    drop(store);
    if req.unique {
        let _ = fs::remove_file(layout.lock(&req.id));
    }
    drop(lock);
    exit_code(status?)
}

/// Note where the log's chain stands, so `cred box log --verify` can tell a log whose chain was
/// stripped or whose end was cut off. A log whose chain is already broken keeps the head it had.
fn record_head(world: &dyn World, name: &str, mnt: &Path, log_key: [u8; 32]) {
    match Chain::new(&store::door_log(mnt), log_key).verify() {
        Ok(found) => {
            if let Some(head) = found.head()
                && let Err(e) = world.record_log_head(name, &head)
            {
                eprintln!("cred: keeping where the log of box {name} stands: {e:#}");
            }
        }
        Err(e) => eprintln!("cred: the log of box {name}: {e:#}"),
    }
}

/// The VM stops when this is dropped, and its socket goes.
struct VmGuard<'a> {
    world: &'a dyn World,
    vm: &'a str,
    socket: &'a Path,
}

impl Drop for VmGuard<'_> {
    fn drop(&mut self) {
        self.world.stop_vm(self.vm);
        let _ = fs::remove_file(self.socket);
    }
}

/// The box's CA, which only its VM trusts. A kept box has it sealed in its store (with a key
/// derived from the box key), made on the first run that needs it, so a box from before the door
/// ended TLS gets one too. A box that isn't kept gets one for this run, in memory only.
fn box_ca(mnt: &Path, name: &str, box_key: &str, persistent: bool) -> Result<door::BoxCa> {
    if !persistent {
        return door::BoxCa::generate(name);
    }
    let key = seal::derive(box_key.as_bytes(), door::CA_PURPOSE);
    let file = store::ca_file(mnt);
    match fs::read(&file) {
        Ok(sealed) => door::BoxCa::from_sealed(&sealed, &key).with_context(|| format!("box {name}'s CA ({})", file.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let ca = door::BoxCa::generate(name)?;
            let tmp = file.with_extension("new");
            let mut out = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            out.write_all(&ca.to_sealed(&key)?)?;
            out.sync_all()?;
            fs::rename(&tmp, &file).with_context(|| format!("saving {}", file.display()))?;
            Ok(ca)
        }
        Err(e) => Err(e).with_context(|| format!("reading {}", file.display())),
    }
}

fn exit_code(status: ExitStatus) -> Result<u8> {
    Ok(status.code().unwrap_or_else(|| 128 + status.signal().unwrap_or(0)) as u8)
}

/// The command as the VM runs it: in the work folder, which is where the agent's files are.
fn guest_command(cmd: &[String]) -> Vec<String> {
    let mut full = vec!["sh".to_string(), "-c".to_string(), format!("cd {GUEST_WORK} && exec \"$0\" \"$@\"")];
    full.extend(cmd.iter().cloned());
    full
}

/// The mounts of the policy, checked to be folders that exist and can be shared, with their
/// real paths (a link is followed once, here, and the target is what gets checked and mounted).
fn resolve_mounts(mounts: &[MountPolicy]) -> Result<Vec<(&MountPolicy, PathBuf)>> {
    mounts
        .iter()
        .map(|m| {
            let real = fs::canonicalize(m.host()).map_err(|_| anyhow!("[[mount]] {} doesn't exist", m.path))?;
            if !real.is_dir() {
                bail!("[[mount]] {} isn't a folder", m.path);
            }
            if let Some(why) = mount_problem(&real) {
                bail!("[[mount]] {} ({}) {why}", m.path, real.display());
            }
            Ok((m, real))
        })
        .collect()
}

/// Copy a folder into work/<name> the first time. Later runs keep the agent's own copy.
fn clone_into(work: &Path, name: &str, host: &Path) -> Result<()> {
    let dst = work.join(name);
    if dst.exists() {
        return Ok(());
    }
    match store::copy_tree(host, &dst) {
        Ok(copied) => {
            if copied.skipped > 0 {
                eprintln!("cred: {} links and special files in {} weren't copied", copied.skipped, host.display());
            }
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&dst);
            Err(e.context(format!("copying {} into the box", host.display())))
        }
    }
}

/// What the agent needs in its home: Claude Code skips its web-fetch check (the door's rules take
/// its place), knows cred's tools, and doesn't stop at first-run screens. Merged into what is
/// there, so what the agent keeps in these files stays.
fn prepare_home(home: &Path) -> Result<()> {
    merge_json(&home.join(".claude/settings.json"), |o| {
        o.insert("skipWebFetchPreflight".into(), json!(true));
    })?;
    // User-scope MCP servers live in ~/.claude.json.
    merge_json(&home.join(".claude.json"), |o| {
        o.insert("hasCompletedOnboarding".into(), json!(true));
        let servers = o.entry("mcpServers").or_insert_with(|| json!({}));
        if let Some(servers) = servers.as_object_mut() {
            servers.insert("cred".into(), json!({ "type": "stdio", "command": "cred-shim", "args": ["mcp"], "env": {} }));
        }
    })
}

fn merge_json(path: &Path, change: impl FnOnce(&mut Map<String, Value>)) -> Result<()> {
    let mut value = fs::read_to_string(path).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()).filter(Value::is_object).unwrap_or_else(|| json!({}));
    change(value.as_object_mut().expect("an object"));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(&value)? + "\n").with_context(|| format!("writing {}", path.display()))
}

/// Clear what a crashed run left for an id: a mounted store, and a store made for one run.
pub fn sweep(layout: &Layout, id: &str) -> Result<()> {
    store::detach(&layout.mount_point(id))?;
    store::shred(&layout.ephemeral_bundle(id))
}

/// Clear the leftovers of runs that ended without cleaning up (no cred holds their lock any more):
/// stores made for one run have no key to open them again, so they go.
fn sweep_temp(layout: &Layout) -> Result<()> {
    for entry in fs::read_dir(layout.root.join("temp")).into_iter().flatten().flatten() {
        let file = entry.file_name().to_string_lossy().into_owned();
        let Some(id) = file.strip_suffix(".sparsebundle") else { continue };
        let lock = layout.lock(id);
        if let Some(_held) = store::lock(&lock)? {
            sweep(layout, id)?;
            if id.contains("-tmp-") {
                let _ = fs::remove_file(&lock);
            }
        }
    }
    Ok(())
}

// --- signals ---

static SIGNALLED: AtomicBool = AtomicBool::new(false);

/// Set once the process got SIGHUP, SIGINT or SIGTERM after `catch_signals`.
pub fn signalled() -> &'static AtomicBool {
    &SIGNALLED
}

extern "C" fn on_signal(_signal: i32) {
    SIGNALLED.store(true, Ordering::SeqCst);
}

unsafe extern "C" {
    fn signal(signal: i32, handler: usize) -> usize;
}

/// Have the signals that end a terminal session set a flag instead of killing cred, so the
/// box is put away properly. (A child gets the default again when it starts: a handler isn't
/// inherited across exec, so Ctrl-C still reaches a command that isn't on a terminal.)
pub fn catch_signals() {
    const SIGHUP: i32 = 1;
    const SIGINT: i32 = 2;
    const SIGTERM: i32 = 15;
    for sig in [SIGHUP, SIGINT, SIGTERM] {
        // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
        unsafe { signal(sig, on_signal as extern "C" fn(i32) as usize) };
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::{Condvar, Mutex};

    use super::*;
    use crate::util::TempDir;

    const DIGEST: &str = "cred-agent@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    type SpecSeen = (String, String, u32, String, PathBuf, Vec<(PathBuf, String, bool)>, bool);
    type DoorSeen = (Vec<String>, Option<String>, Vec<String>, PathBuf);
    type NetSeen = (policy::Mode, Vec<String>, [u8; 32]);
    type ExecSeen = (Vec<(String, String)>, Vec<String>, bool);
    type Hook = Box<dyn Fn(&Path) + Sync + Send>;

    #[derive(Default)]
    struct Seen {
        calls: Vec<String>,
        spec: Option<SpecSeen>,
        door: Option<DoorSeen>,
        /// The CA installed in the VM, as PEM, and whether the door was given one.
        ca: Option<String>,
        door_ca: Option<String>,
        net: Option<NetSeen>,
        /// The lines of the log head recorded when the box was put away.
        log_head: Option<usize>,
        exec: Option<ExecSeen>,
        /// Files of the box as the agent would find them, read when it starts.
        files: BTreeMap<String, String>,
        stopped: bool,
    }

    /// Records what a run does; `exec` can change files the way the agent would.
    #[derive(Default)]
    struct Fake {
        seen: Mutex<Seen>,
        wake: Condvar,
        running: Mutex<bool>,
        deny: bool,
        unavailable: bool,
        door_fails: bool,
        /// Block in exec until the VM is stopped (a signal's doing).
        block: bool,
        key: String,
        /// Runs in exec with the box's work folder.
        hook: Option<Hook>,
    }

    impl Fake {
        fn calls(&self) -> Vec<String> {
            self.seen.lock().unwrap().calls.clone()
        }

        fn note(&self, call: impl Into<String>) {
            self.seen.lock().unwrap().calls.push(call.into());
        }
    }

    impl World for Fake {
        fn confirm(&self, reason: &str) -> Result<()> {
            self.note(format!("confirm: {reason}"));
            if self.deny { bail!("not approved") } else { Ok(()) }
        }

        fn available(&self) -> Result<()> {
            self.note("available");
            if self.unavailable { bail!("container isn't installed") } else { Ok(()) }
        }

        fn running(&self, _vm: &str) -> bool {
            *self.running.lock().unwrap()
        }

        fn start_vm(&self, spec: &engine::VmSpec) -> Result<()> {
            self.note("start_vm");
            let mounts = spec.mounts.iter().map(|m| (m.host.clone(), m.guest.clone(), m.readonly)).collect();
            self.seen.lock().unwrap().spec = Some((spec.name.clone(), spec.image.clone(), spec.cpus, spec.memory.clone(), spec.socket.clone(), mounts, spec.docker));
            *self.running.lock().unwrap() = true;
            Ok(())
        }

        fn stop_vm(&self, _vm: &str) {
            self.note("stop_vm");
            *self.running.lock().unwrap() = false;
            self.seen.lock().unwrap().stopped = true;
            self.wake.notify_all();
        }

        fn start_door(&self, cfg: door::Config) -> Result<Box<dyn Any>> {
            self.note("start_door");
            if self.door_fails {
                bail!("the door can't start");
            }
            let mut seen = self.seen.lock().unwrap();
            seen.door_ca = cfg.ca.as_ref().map(|ca| ca.cert_pem());
            seen.net = Some((cfg.net.writes, cfg.net.allow_writes, cfg.log_key));
            seen.door = Some((cfg.allow, cfg.model, cfg.sites, cfg.log));
            Ok(Box::new(()))
        }

        fn install_ca(&self, _vm: &str, pem: &str) -> Result<()> {
            self.note("install_ca");
            self.seen.lock().unwrap().ca = Some(pem.to_string());
            Ok(())
        }

        fn model_uses_bearer(&self, model: &str) -> Result<bool> {
            self.note(format!("bearer: {model}"));
            Ok(true)
        }

        fn site_ready(&self, site: &str) -> Result<()> {
            self.note(format!("site: {site}"));
            Ok(())
        }

        fn key(&self, _name: &str) -> Result<String> {
            Ok(self.key.clone())
        }

        fn record_log_head(&self, _name: &str, head: &chain::Head) -> Result<()> {
            self.seen.lock().unwrap().log_head = Some(head.lines);
            Ok(())
        }

        fn exec(&self, _vm: &str, env: &[(String, String)], cmd: &[String], tty: bool) -> Result<ExitStatus> {
            self.note("exec");
            let mut seen = self.seen.lock().unwrap();
            seen.exec = Some((env.to_vec(), cmd.to_vec(), tty));
            let mounts = seen.spec.as_ref().map(|s| s.5.clone()).unwrap_or_default();
            let host = |guest: &str| mounts.iter().find(|m| m.1 == guest).map(|m| m.0.clone());
            if let Some(home) = host(GUEST_HOME) {
                for file in [".claude/settings.json", ".claude.json"] {
                    if let Ok(text) = fs::read_to_string(home.join(file)) {
                        seen.files.insert(file.to_string(), text);
                    }
                }
            }
            if let Some(work) = host(GUEST_WORK) {
                for entry in fs::read_dir(&work).unwrap().flatten() {
                    seen.files.insert(format!("work/{}", entry.file_name().to_string_lossy()), String::new());
                }
                if let Ok(text) = fs::read_to_string(work.join("proj/README")) {
                    seen.files.insert("work/proj/README".into(), text);
                }
                if let Some(hook) = &self.hook {
                    hook(&work);
                }
            }
            if self.block {
                while !seen.stopped {
                    seen = self.wake.wait(seen).unwrap();
                }
                return Ok(ExitStatus::from_raw(15));
            }
            Ok(ExitStatus::from_raw(0))
        }
    }

    struct Setup {
        dir: TempDir,
        layout: Layout,
        stop: AtomicBool,
    }

    fn setup() -> Setup {
        let dir = TempDir::new("cred-run").unwrap();
        let layout = Layout::under(&dir.0).unwrap();
        Setup { dir, layout, stop: AtomicBool::new(false) }
    }

    fn request<'a>(s: &'a Setup, policy: &'a BoxPolicy, persistent: bool) -> Request<'a> {
        Request { name: "r", id: "r".into(), policy, policy_sha: "sha-1".into(), persistent, unique: false, command: None, tty: false, stop: &s.stop }
    }

    fn policy(s: &Setup, extra: &str) -> BoxPolicy {
        let (proj, data) = (s.dir.0.join("proj"), s.dir.0.join("data"));
        fs::create_dir_all(proj.join(".git")).unwrap();
        fs::create_dir_all(&data).unwrap();
        fs::write(proj.join("README"), "original").unwrap();
        fs::write(proj.join(".git/HEAD"), "ref: refs/heads/main").unwrap();
        BoxPolicy::parse(&format!(
            r#"
            image = "{DIGEST}"
            model = "anthropic"
            sites = ["github"]
            standins = ["GH_TOKEN"]
            [net]
            allow = ["https://docs.rs"]
            writes = "ask"
            allow_writes = ["https://api.example.com/search"]
            [[mount]]
            path = "{}"
            [[mount]]
            path = "{}"
            mode = "ro"
            {extra}
            "#,
            proj.display(),
            data.display()
        ))
        .unwrap()
    }

    fn assert_put_away(s: &Setup) {
        assert!(!store::is_mounted(&s.layout.mount_point("r")), "the store is still attached");
        assert!(!s.layout.ephemeral_bundle("r").exists(), "the store was not shredded");
        assert!(!s.layout.socket("r").exists());
    }

    #[test]
    fn runs_a_box_in_order_and_puts_it_away() {
        let s = setup();
        let p = policy(&s, "");
        // A run that ended without cleaning up left a store no key can open again.
        let stale = s.layout.ephemeral_bundle("old-tmp-1");
        store::create(&s.layout, &stale, &store::new_key().unwrap()).unwrap();
        let fake = Fake::default();

        let code = run(&s.layout, &fake, &Request { command: Some(vec!["bash".into(), "-l".into()]), tty: true, ..request(&s, &p, false) }).unwrap();

        assert_eq!(code, 0);
        assert_eq!(
            fake.calls(),
            ["available", "bearer: anthropic", "site: anthropic", "site: github", "confirm: open box r and let it use github", "start_vm", "start_door", "install_ca", "exec", "stop_vm"]
        );
        assert_put_away(&s);
        assert!(!stale.exists(), "leftovers of crashed runs are cleared");

        let seen = fake.seen.lock().unwrap();
        let (name, image, cpus, memory, socket, mounts, docker) = seen.spec.clone().unwrap();
        assert_eq!((name.as_str(), image.as_str(), cpus, memory.as_str(), docker), ("cred-box-r", DIGEST, 4, "8G", false));
        assert_eq!(socket, s.layout.socket("r"));
        let guests: Vec<_> = mounts.iter().map(|m| (m.1.as_str(), m.2)).collect();
        assert_eq!(guests, [("/home/agent", false), ("/work", false), ("/downloads", false), ("/mnt/data", true)]);
        assert_eq!(mounts[3].0, fs::canonicalize(s.dir.0.join("data")).unwrap());
        let (allow, model, sites, log) = seen.door.clone().unwrap();
        assert_eq!((allow, model, sites), (vec!["https://docs.rs".to_string()], Some("anthropic".to_string()), vec!["github".to_string()]));
        assert!(log.ends_with("log/door.log"), "{}", log.display());

        let (env, cmd, tty) = seen.exec.clone().unwrap();
        assert!(env.contains(&("CLAUDE_CODE_OAUTH_TOKEN".into(), "cred-managed".into())), "the bearer stand-in: {env:?}");
        let pem = seen.ca.clone().expect("the CA is installed in the VM");
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----") && !pem.contains("PRIVATE"), "{pem}");
        assert_eq!(seen.door_ca.as_deref(), Some(pem.as_str()), "the door ends TLS with the CA the VM trusts");
        for var in ["NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "PIP_CERT", "GIT_SSL_CAINFO"] {
            assert!(env.iter().any(|(k, v)| k == var && v.starts_with("/")), "{var} in {env:?}");
        }
        assert!(env.contains(&("GH_TOKEN".into(), "cred-managed".into())), "the policy's stand-ins: {env:?}");
        let (writes, allow_writes, _) = seen.net.clone().unwrap();
        assert_eq!((writes, allow_writes), (policy::Mode::Ask, vec!["https://api.example.com/search".to_string()]));
        assert_eq!(&cmd[..2], ["sh", "-c"]);
        assert!(cmd[2].starts_with("cd /work && exec"), "{}", cmd[2]);
        assert_eq!(&cmd[3..], ["bash", "-l"]);
        assert!(tty);

        let settings: Value = serde_json::from_str(&seen.files[".claude/settings.json"]).unwrap();
        assert_eq!(settings["skipWebFetchPreflight"], json!(true));
        let claude: Value = serde_json::from_str(&seen.files[".claude.json"]).unwrap();
        assert_eq!((claude["mcpServers"]["cred"]["command"].clone(), claude["mcpServers"]["cred"]["args"].clone()), (json!("cred-shim"), json!(["mcp"])));
        assert!(seen.files.contains_key("work/proj"), "the clone: {:?}", seen.files.keys());
        assert_eq!(seen.files["work/proj/README"], "original");
        assert!(!seen.files.contains_key("work/data"), "ro folders are not copied");
    }

    #[test]
    fn a_kept_box_keeps_its_files_and_its_own_copy() {
        let s = setup();
        let p = policy(&s, "");
        let key = store::new_key().unwrap();
        store::create(&s.layout, &s.layout.bundle("r"), &key).unwrap();
        let log_key = super::super::log_key(&key);
        let hook: Hook = Box::new(move |work| {
            fs::write(work.join("proj/README"), "agent's edit").unwrap();
            // The line for the start is in the log, chained with the key the door gets.
            let log = store::door_log(work.parent().unwrap());
            assert_eq!(crate::chain::Chain::new(&log, log_key).verify().unwrap().chained, 1);
        });
        let first = Fake { key: key.clone(), hook: Some(hook), ..Fake::default() };
        run(&s.layout, &first, &request(&s, &p, true)).unwrap();
        assert_eq!(first.seen.lock().unwrap().net.as_ref().unwrap().2, log_key, "the door chains its log with a key derived from the box key");
        assert!(s.layout.bundle("r").exists() && !store::is_mounted(&s.layout.mount_point("r")));
        assert_eq!(first.seen.lock().unwrap().log_head, Some(2), "where the log stands (started, stopped) is kept outside the store");

        // The source changes; the agent's copy is not replaced.
        fs::write(s.dir.0.join("proj/README"), "changed on the Mac").unwrap();
        let second = Fake { key, ..Fake::default() };
        run(&s.layout, &second, &request(&s, &p, true)).unwrap();
        assert_eq!(second.seen.lock().unwrap().files["work/proj/README"], "agent's edit");
        assert_eq!(second.seen.lock().unwrap().log_head, Some(4));
        assert!(s.layout.bundle("r").exists());
    }

    #[test]
    fn joins_a_box_that_runs() {
        let s = setup();
        let p = policy(&s, "");
        s.layout.prepare().unwrap();
        let held = store::lock(&s.layout.lock("r")).unwrap().unwrap();
        fs::write(s.layout.opened_with("r"), "sha-1").unwrap();

        let fake = Fake { running: Mutex::new(true), ..Fake::default() };
        let code = run(&s.layout, &fake, &Request { command: Some(vec!["bash".into()]), ..request(&s, &p, false) }).unwrap();
        assert_eq!(code, 0);
        assert_eq!(fake.calls(), ["bearer: anthropic", "exec"], "no second store, VM or door");
        assert!(!store::is_mounted(&s.layout.mount_point("r")));

        // Approved again since the box opened: joining would run under rules the door doesn't know.
        let changed = Fake { running: Mutex::new(true), ..Fake::default() };
        let e = run(&s.layout, &changed, &Request { policy_sha: "sha-2".into(), ..request(&s, &p, false) }).unwrap_err().to_string();
        assert!(e.contains("cred box stop r"), "{e}");
        assert!(changed.calls().is_empty(), "nothing runs: {:?}", changed.calls());

        let starting = Fake::default();
        let e = run(&s.layout, &starting, &request(&s, &p, false)).unwrap_err().to_string();
        assert!(e.contains("another cred"), "{e}");
        assert!(starting.calls().is_empty());
        drop(held);
    }

    #[test]
    fn replaces_a_vm_nobody_runs() {
        let s = setup();
        let p = policy(&s, "");
        let fake = Fake { running: Mutex::new(true), ..Fake::default() };
        run(&s.layout, &fake, &request(&s, &p, false)).unwrap();
        assert_eq!(&fake.calls()[..2], ["stop_vm", "available"]);
        assert_put_away(&s);
    }

    #[test]
    fn asks_and_checks_before_anything_opens() {
        let s = setup();
        let p = policy(&s, "");
        let untouched = |fake: &Fake, last: &str| {
            assert_eq!(fake.calls().last().map(String::as_str), Some(last));
            assert!(!s.layout.root.join("temp").exists() || fs::read_dir(s.layout.root.join("temp")).unwrap().next().is_none(), "a store was made");
            assert_put_away(&s);
        };

        let denied = Fake { deny: true, ..Fake::default() };
        assert!(run(&s.layout, &denied, &request(&s, &p, false)).is_err());
        untouched(&denied, "confirm: open box r and let it use github");

        let missing = Fake { unavailable: true, ..Fake::default() };
        let e = run(&s.layout, &missing, &request(&s, &p, false)).unwrap_err().to_string();
        assert!(e.contains("container"), "{e}");
        assert_eq!(missing.calls(), ["available"]);

        let no_image = BoxPolicy::parse("").unwrap();
        let fake = Fake::default();
        assert!(run(&s.layout, &fake, &request(&s, &no_image, false)).unwrap_err().to_string().contains("names no image"));
        assert!(!fake.calls().iter().any(|c| c.starts_with("confirm")));

        let gone = policy(&s, "[[mount]]\npath = \"/nonexistent/folder\"");
        let fake = Fake::default();
        assert!(run(&s.layout, &fake, &request(&s, &gone, false)).unwrap_err().to_string().contains("doesn't exist"));
        assert!(!fake.calls().iter().any(|c| c.starts_with("confirm")));
    }

    #[test]
    fn puts_everything_away_when_the_door_fails() {
        let s = setup();
        let p = policy(&s, "");
        let fake = Fake { door_fails: true, ..Fake::default() };
        let e = run(&s.layout, &fake, &request(&s, &p, false)).unwrap_err().to_string();
        assert!(e.contains("door"), "{e}");
        assert_eq!(&fake.calls()[fake.calls().len() - 3..], ["start_vm", "start_door", "stop_vm"]);
        assert_put_away(&s);
        assert!(store::lock(&s.layout.lock("r")).unwrap().is_some(), "the lock is released");
    }

    #[test]
    fn a_signal_stops_the_box_and_puts_it_away() {
        let s = setup();
        let p = policy(&s, "");
        let fake = Fake { block: true, ..Fake::default() };
        let code = thread::scope(|scope| {
            scope.spawn(|| {
                thread::sleep(Duration::from_millis(1500));
                s.stop.store(true, Ordering::SeqCst);
            });
            run(&s.layout, &fake, &request(&s, &p, false)).unwrap()
        });
        assert_eq!(code, 143, "killed by SIGTERM");
        assert!(fake.calls().iter().filter(|c| *c == "stop_vm").count() >= 1);
        assert_put_away(&s);
    }

    #[test]
    fn a_temporary_box_has_its_own_name_and_lock() {
        let s = setup();
        let p = policy(&s, "");
        let fake = Fake::default();
        let id = "r-tmp-0a1b2c3d".to_string();
        run(&s.layout, &fake, &Request { id: id.clone(), unique: true, ..request(&s, &p, false) }).unwrap();
        assert_eq!(fake.seen.lock().unwrap().spec.as_ref().unwrap().0, "cred-box-r-tmp-0a1b2c3d");
        assert_eq!(fake.seen.lock().unwrap().log_head, None, "a box that isn't kept keeps nothing");
        assert!(!s.layout.ephemeral_bundle(&id).exists() && !s.layout.lock(&id).exists());
    }

    #[test]
    fn a_temporary_box_keeps_its_ca_in_memory_only() {
        let s = setup();
        let p = policy(&s, "");
        let hook: Hook = Box::new(|work| {
            let mnt = work.parent().unwrap();
            assert!(!mnt.join("door/ca.sealed").exists(), "nothing is written for a box that isn't kept");
        });
        let first = Fake { hook: Some(hook), ..Fake::default() };
        run(&s.layout, &first, &request(&s, &p, false)).unwrap();
        let second = Fake::default();
        run(&s.layout, &second, &request(&s, &p, false)).unwrap();
        let (a, b) = (first.seen.lock().unwrap().ca.clone().unwrap(), second.seen.lock().unwrap().ca.clone().unwrap());
        assert_ne!(a, b, "every temporary box has a CA of its own");
    }

    #[test]
    fn a_kept_box_gets_a_ca_once_sealed_in_its_store() {
        let s = setup();
        let p = policy(&s, "");
        let key = store::new_key().unwrap();
        store::create(&s.layout, &s.layout.bundle("r"), &key).unwrap();
        let sealed_at = |work: &Path| work.parent().unwrap().join("door/ca.sealed");

        // A box made before the door ended TLS has no CA; the first run makes one.
        let hook: Hook = Box::new(move |work| {
            let sealed = fs::read(sealed_at(work)).expect("the CA is saved in the store");
            assert!(!String::from_utf8_lossy(&sealed).contains("BEGIN"), "sealed, not plain");
            assert!(!work.parent().unwrap().join("work/door").exists());
        });
        let first = Fake { key: key.clone(), hook: Some(hook), ..Fake::default() };
        run(&s.layout, &first, &request(&s, &p, true)).unwrap();
        let second = Fake { key: key.clone(), ..Fake::default() };
        run(&s.layout, &second, &request(&s, &p, true)).unwrap();
        let (a, b) = (first.seen.lock().unwrap().ca.clone().unwrap(), second.seen.lock().unwrap().ca.clone().unwrap());
        assert_eq!(a, b, "later runs load the same CA");

        // No VM mounts the folder it is in.
        let mounted = first.seen.lock().unwrap().spec.clone().unwrap().5;
        assert!(mounted.iter().all(|m| !m.0.ends_with("door") && !m.0.ends_with("log")), "{mounted:?}");

        // A CA that doesn't open stops the run before any VM starts, rather than being replaced.
        let hook: Hook = Box::new(move |work| fs::write(sealed_at(work), b"garbage that isn't a sealed CA at all").unwrap());
        let damage = Fake { key: key.clone(), hook: Some(hook), ..Fake::default() };
        run(&s.layout, &damage, &request(&s, &p, true)).unwrap();
        let broken = Fake { key, ..Fake::default() };
        let e = format!("{:#}", run(&s.layout, &broken, &request(&s, &p, true)).unwrap_err());
        assert!(e.contains("CA"), "{e}");
        assert!(!broken.calls().iter().any(|c| c == "start_vm"));
        assert!(!store::is_mounted(&s.layout.mount_point("r")));
    }

    #[test]
    fn keeps_what_the_agent_wrote_in_its_settings() {
        let dir = TempDir::new("cred-home").unwrap();
        let home = dir.0.join("home");
        fs::create_dir_all(home.join(".claude")).unwrap();
        fs::write(home.join(".claude/settings.json"), r#"{"theme":"dark","skipWebFetchPreflight":false}"#).unwrap();
        fs::write(home.join(".claude.json"), r#"{"mcpServers":{"mine":{"command":"x"}},"cred":1}"#).unwrap();
        prepare_home(&home).unwrap();
        let settings: Value = serde_json::from_str(&fs::read_to_string(home.join(".claude/settings.json")).unwrap()).unwrap();
        assert_eq!((settings["theme"].clone(), settings["skipWebFetchPreflight"].clone()), (json!("dark"), json!(true)));
        let claude: Value = serde_json::from_str(&fs::read_to_string(home.join(".claude.json")).unwrap()).unwrap();
        assert_eq!((claude["mcpServers"]["mine"]["command"].clone(), claude["cred"].clone()), (json!("x"), json!(1)));
        assert_eq!(claude["mcpServers"]["cred"]["command"], json!("cred-shim"));

        fs::write(home.join(".claude.json"), "not json").unwrap();
        prepare_home(&home).unwrap();
        assert!(fs::read_to_string(home.join(".claude.json")).unwrap().contains("cred-shim"), "a broken file is replaced");
    }
}

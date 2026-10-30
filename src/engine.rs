//! The VM engine for boxes: Apple's `container` CLI, behind a small interface.
//!
//! A box's agent runs in a VM with no network at all. The only way out is a Unix socket that
//! `container` publishes on the Mac (`--publish-socket`), which cred's door dials into; inside,
//! `cred-shim serve` is the init process and turns that socket into local listeners (see
//! box/shim). Everything here is `Command` with arguments, never a shell string, and nothing
//! secret goes through it: the environment given to `exec` holds stand-ins only, because
//! command-line arguments are visible to every process on the Mac.
//!
//! This module uses only external crates, so tests/box_engine.rs can include it as it is.
#![allow(dead_code)] // used by the box commands

use std::fs::DirBuilder;
use std::io::{ErrorKind, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

/// The local image name; a box's policy pins it as `name@sha256:...`.
pub const AGENT_IMAGE: &str = "cred-agent";
/// The user the agent runs as (uid and gid 1000, home /home/agent).
pub const AGENT_USER: &str = "agent";
const AGENT_ID: &str = "1000";
const AGENT_HOME: &str = "/home/agent";
/// Where the shim in the VM listens for the door's connections.
const DOOR_SOCKET: &str = "/run/cred/door.sock";
/// What the box holds in place of the model key; the door's gateway swaps in the real one.
/// Same value as the door's `STANDIN`.
const STANDIN: &str = "cred-managed";
/// Where the box CA is installed in the VM, and the bundle `update-ca-certificates` builds from it
/// and the system's roots.
pub const CA_CERT: &str = "/usr/local/share/ca-certificates/cred-box.crt";
const CA_BUNDLE: &str = "/etc/ssl/certs/ca-certificates.crt";
/// The browser VM's image, and what it holds: where the runner is, the user's home (Chromium runs
/// as the image's user 1000), and where the Mac's downloads folder appears.
pub const BROWSER_IMAGE: &str = "cred-browser";
const BROWSER_HOME: &str = "/home/browser";
const RUNNER: &str = "/opt/runner/runner.mjs";
pub const BROWSER_DOWNLOADS: &str = "/downloads";
/// Where Chromium looks for the CAs it trusts (NSS), under the browser's home.
const NSS_DB: &str = "/home/browser/.pki/nssdb";
/// The longest Unix socket path macOS accepts (104 bytes, with the terminating NUL).
const SOCKET_PATH_MAX: usize = 103;

/// The environment inside the agent VM, for `exec`.
///
/// `container` rewrites /etc/hosts at every start, so the name `cred.internal` can't be defined
/// by the image: the model gateway is reached at its address, 127.0.0.2, where the shim listens. Both spellings are in NO_PROXY, as are the
/// loopback names, so a server the agent starts in the box isn't sent through the door.
/// `oauth` says how the model resource authenticates: a subscription token
/// (`Authorization`) or an API key (`x-api-key`).
pub fn agent_env(oauth: bool) -> Vec<(String, String)> {
    let proxy = "http://127.0.0.1:3128";
    let key = if oauth { "CLAUDE_CODE_OAUTH_TOKEN" } else { "ANTHROPIC_API_KEY" };
    [
        ("HTTPS_PROXY", proxy),
        ("https_proxy", proxy),
        ("HTTP_PROXY", proxy),
        ("http_proxy", proxy),
        ("NO_PROXY", NO_PROXY),
        ("no_proxy", NO_PROXY),
        // Node's built-in fetch ignores the proxy variables without this (it warns that it's
        // experimental once per process).
        ("NODE_USE_ENV_PROXY", "1"),
        ("ANTHROPIC_BASE_URL", "http://127.0.0.2/model"),
        (key, STANDIN),
        ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
        ("DISABLE_AUTOUPDATER", "1"),
        ("HOME", AGENT_HOME),
        // The door ends TLS with the box CA. Node ignores the system store; the rest are told
        // to use the bundle that includes the CA.
        ("NODE_EXTRA_CA_CERTS", CA_CERT),
        ("SSL_CERT_FILE", CA_BUNDLE),
        ("REQUESTS_CA_BUNDLE", CA_BUNDLE),
        ("CURL_CA_BUNDLE", CA_BUNDLE),
        ("PIP_CERT", CA_BUNDLE),
        ("GIT_SSL_CAINFO", CA_BUNDLE),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

const NO_PROXY: &str = "127.0.0.2,cred.internal,localhost,127.0.0.1";

/// A folder of the Mac mounted into the VM.
pub struct Mount {
    pub host: PathBuf,
    pub guest: String,
    pub readonly: bool,
}

pub struct VmSpec {
    /// The container's name, e.g. "cred-box-research".
    pub name: String,
    /// "cred-agent@sha256:..." as built by `build_agent_image`.
    pub image: String,
    pub cpus: u32,
    /// "8G"
    pub memory: String,
    /// Where the door's socket appears on the Mac. Must be short: macOS limits socket paths.
    pub socket: PathBuf,
    pub mounts: Vec<Mount>,
    /// Docker Engine inside the VM. Not supported yet: the agent image doesn't contain it.
    pub docker: bool,
}

fn container() -> Command {
    Command::new("container")
}

/// Run a command to completion and return its stdout; a failure carries what `container` said.
fn capture(cmd: &mut Command, what: &str) -> Result<String> {
    let out = cmd.stdin(Stdio::null()).output().with_context(|| format!("{what}: running container"))?;
    if !out.status.success() {
        bail!("{what}: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// `container` is installed and its system service is running.
pub fn available() -> Result<()> {
    let status = container().args(["system", "status"]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).status().map_err(|e| match e.kind() {
        ErrorKind::NotFound => anyhow!("Apple's `container` isn't installed: get it from https://github.com/apple/container/releases"),
        _ => anyhow!("running container: {e}"),
    })?;
    if !status.success() {
        bail!("container's system service isn't running: start it with `container system start`");
    }
    Ok(())
}

/// The arguments of `container run` for a VM: no network, memory-backed /tmp and /var/tmp (so
/// nothing the agent writes outside its folders lands in `container`'s own files), and
/// `cred-shim serve` as the init process. `--init` reaps the processes the agent leaves behind
/// and passes SIGTERM on, which the shim as PID 1 would ignore.
///
/// Not `--read-only`: `container` connects to a published socket from outside the VM's
/// container, where it sees the root filesystem but not the container's tmpfs mounts, so
/// /run/cred/door.sock has to be on a writable root. The image takes away what the agent could
/// write there instead (see box/agent.Containerfile).
fn run_args(spec: &VmSpec, image: &str) -> Result<Vec<String>> {
    let mut args: Vec<String> = ["run", "--progress", "none", "--detach", "--rm", "--init", "--network", "none", "--tmpfs", "/tmp", "--tmpfs", "/var/tmp"].map(String::from).into();
    args.extend(["--name".into(), spec.name.clone()]);
    args.extend(["--cpus".into(), spec.cpus.to_string(), "--memory".into(), spec.memory.clone()]);
    args.extend(["--publish-socket".into(), format!("{}:{DOOR_SOCKET}", spec.socket.display())]);
    for m in &spec.mounts {
        args.extend(["--mount".into(), mount_arg(m)?]);
    }
    args.extend(["--entrypoint".into(), "cred-shim".into(), image.into(), "serve".into()]);
    Ok(args)
}

fn mount_arg(m: &Mount) -> Result<String> {
    let host = m.host.to_string_lossy();
    // --mount takes comma-separated key=value pairs
    if host.contains(',') || m.guest.contains(',') {
        bail!("can't mount {host} at {}: commas in mount paths aren't supported", m.guest);
    }
    let readonly = if m.readonly { ",readonly" } else { "" };
    Ok(format!("type=bind,source={host},target={}{readonly}", m.guest))
}

/// Start the VM, detached. It is removed when it stops.
pub fn run(spec: &VmSpec) -> Result<()> {
    if spec.docker {
        bail!("Docker inside a box isn't supported yet: the agent image has no Docker Engine");
    }
    let socket = spec.socket.as_os_str().len();
    if socket > SOCKET_PATH_MAX {
        bail!("socket path {} is too long ({socket} bytes, macOS allows {SOCKET_PATH_MAX})", spec.socket.display());
    }
    for m in &spec.mounts {
        if !m.host.exists() {
            bail!("can't mount {}: it doesn't exist", m.host.display());
        }
    }
    if let Some(dir) = spec.socket.parent() {
        DirBuilder::new().recursive(true).mode(0o700).create(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let image = local_image(&spec.image)?;
    capture(container().args(run_args(spec, &image)?), &format!("starting {}", spec.name))?;
    Ok(())
}

/// Run a command in the VM as the agent, with the terminal if there is one. The environment is
/// on the command line, so it must hold no secrets (see `agent_env`).
pub fn exec(name: &str, env: &[(String, String)], cmd: &[String], tty: bool) -> Result<ExitStatus> {
    exec_command(name, env, cmd, tty).status().context("running container exec")
}

/// The `container exec` command behind `exec`, for callers that want to pipe its streams.
pub fn exec_command(name: &str, env: &[(String, String)], cmd: &[String], tty: bool) -> Command {
    let mut c = container();
    // --uid needs --gid, or the process stays in group root
    c.args(["exec", "--uid", AGENT_ID, "--gid", AGENT_ID, "-i"]);
    if tty {
        c.arg("-t");
    }
    for (key, value) in env {
        c.arg("-e").arg(format!("{key}={value}"));
    }
    c.arg(name).args(cmd);
    c
}

/// Make the box's CA (a public certificate, PEM) trusted in the VM: written where
/// `update-ca-certificates` looks and added to the system bundle, as root. The VM's system is
/// thrown away when it stops, so this is done at every start.
pub fn install_ca(name: &str, pem: &str) -> Result<()> {
    let script = format!("cat > {CA_CERT} && update-ca-certificates");
    let mut child = container()
        .args(["exec", "--uid", "0", "--gid", "0", "-i", name, "sh", "-c", &script])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("running container exec")?;
    child.stdin.take().expect("piped stdin").write_all(pem.as_bytes()).context("sending the CA to the VM")?;
    let out = child.wait_with_output().context("installing the CA")?;
    if !out.status.success() {
        bail!("installing the box CA in {name}: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

pub fn browser_vm_name(box_id: &str) -> String {
    format!("cred-browser-{box_id}")
}

/// The box's browser VM: one for all of the box's sites, with the same kind of door as the
/// agent's VM, but through a socket of its own so the door knows whose traffic it is.
pub struct BrowserSpec {
    pub name: String,
    /// "cred-browser@sha256:..." as built by `build_browser_image`.
    pub image: String,
    /// Where the browser door's socket appears on the Mac (short, like the agent's).
    pub socket: PathBuf,
    /// A folder of the Mac mounted read-write at `/downloads`, for the files pages download.
    /// It is made (private to the user) if it isn't there. `None`: no mount, and the runner is
    /// not given a place to save to.
    pub downloads: Option<PathBuf>,
}

/// Start the browser VM, detached; it is removed when it stops. The same isolation as the
/// agent's VM: no network, memory-backed /tmp, `cred-shim serve` as init.
pub fn run_browser(spec: &BrowserSpec) -> Result<()> {
    let mut mounts = Vec::new();
    if let Some(host) = &spec.downloads {
        DirBuilder::new().recursive(true).mode(0o700).create(host).with_context(|| format!("creating {}", host.display()))?;
        mounts.push(Mount { host: host.clone(), guest: BROWSER_DOWNLOADS.into(), readonly: false });
    }
    run(&VmSpec { name: spec.name.clone(), image: spec.image.clone(), cpus: 2, memory: "2G".into(), socket: spec.socket.clone(), mounts, docker: false })
}

/// Start a runner in the browser VM (`node /opt/runner/runner.mjs`, as the VM's user 1000),
/// speaking its JSON lines on the child's piped stdin and stdout. `env` is on the command
/// line, so it holds no secrets: the runner gets everything it needs over stdin.
///
/// `CRED_RUNNER_DEBUG_*` variables switch protections of the runner off, for tests; a release
/// build refuses them.
pub fn exec_runner(vm: &str, env: &[(String, String)]) -> Result<Child> {
    runner_command(vm, env)?.spawn().context("running container exec")
}

fn runner_command(vm: &str, env: &[(String, String)]) -> Result<Command> {
    #[cfg(not(debug_assertions))]
    if let Some((key, _)) = env.iter().find(|(key, _)| key.starts_with("CRED_RUNNER_DEBUG")) {
        bail!("{key} is only for tests");
    }
    let mut c = container();
    c.args(["exec", "--uid", AGENT_ID, "--gid", AGENT_ID, "-i"]);
    let base = [("HOME", BROWSER_HOME), ("PLAYWRIGHT_BROWSERS_PATH", "/ms-playwright")];
    for (key, value) in base.into_iter().chain(env.iter().map(|(k, v)| (k.as_str(), v.as_str()))) {
        c.arg("-e").arg(format!("{key}={value}"));
    }
    c.arg(vm).args(["node", RUNNER]);
    c.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
    Ok(c)
}

/// Make Chromium in the browser VM trust the box's CA (a public certificate, PEM). Chromium on
/// Linux trusts what is in its user's NSS database, so the CA goes there, with `certutil`, as
/// the user the runners run as. The VM's home is thrown away when it stops, so this is done at
/// every start, before the first runner.
pub fn install_browser_ca(name: &str, pem: &str) -> Result<()> {
    let script = format!(
        "set -e; mkdir -p {NSS_DB}; cat > /tmp/cred-box.crt; \
         [ -f {NSS_DB}/cert9.db ] || certutil -N -d sql:{NSS_DB} --empty-password; \
         certutil -A -d sql:{NSS_DB} -t 'C,,' -n cred-box -i /tmp/cred-box.crt; rm -f /tmp/cred-box.crt"
    );
    let mut child = container()
        .args(["exec", "--uid", AGENT_ID, "--gid", AGENT_ID, "-i", "-e", &format!("HOME={BROWSER_HOME}"), name, "sh", "-c", &script])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("running container exec")?;
    child.stdin.take().expect("piped stdin").write_all(pem.as_bytes()).context("sending the CA to the VM")?;
    let out = child.wait_with_output().context("installing the CA")?;
    if !out.status.success() {
        bail!("installing the box CA in {name}: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

fn exists(name: &str) -> bool {
    capture(container().args(["inspect", name]), "inspecting the VM").is_ok()
}

pub fn running(name: &str) -> bool {
    capture(container().args(["inspect", name]), "inspecting the VM")
        .ok()
        .and_then(|json| serde_json::from_str::<Value>(&json).ok())
        .is_some_and(|v| v[0]["status"]["state"] == "running")
}

/// Stop the VM, which removes it too. Fine if it is already gone.
pub fn stop(name: &str) -> Result<()> {
    if !exists(name) {
        return Ok(());
    }
    let stopped = capture(container().args(["stop", name]), &format!("stopping {name}"));
    // --rm removes the VM as it stops; give that a moment
    for _ in 0..50 {
        if !exists(name) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(100));
    }
    stopped?;
    bail!("{name} is still there after stopping it")
}

/// The digest of a local image, e.g. "sha256:ab12...".
fn inspect_digest(reference: &str) -> Result<String> {
    let json = capture(container().args(["image", "inspect", reference]), &format!("inspecting image {reference}"))?;
    let v: Value = serde_json::from_str(&json).context("reading container's image description")?;
    Ok(v[0]["configuration"]["descriptor"]["digest"].as_str().with_context(|| format!("container gave no digest for image {reference}"))?.to_string())
}

/// "cred-agent" or "cred-agent:latest" -> "cred-agent@sha256:...", which a policy can pin.
pub fn image_digest(reference: &str) -> Result<String> {
    Ok(format!("{}@{}", image_name(reference), inspect_digest(reference)?))
}

/// The reference without its tag or digest.
fn image_name(reference: &str) -> &str {
    let name = reference.split('@').next().unwrap_or(reference);
    match name.rsplit_once(':') {
        Some((base, tag)) if !tag.contains('/') => base,
        _ => name,
    }
}

/// `container` can't run a local image by digest, so it is run through a tag `name:<hex>`, made
/// here the first time from the build that `name` points at (install.sh builds that). A tag is
/// only used if it has the pinned digest, so a replaced image is never run.
fn local_image(image: &str) -> Result<String> {
    let Some((name, digest)) = image.split_once('@') else {
        return Ok(image.to_string());
    };
    let hex = digest.strip_prefix("sha256:").with_context(|| format!("unsupported image reference {image}"))?;
    let tag = format!("{name}:{hex}");
    if inspect_digest(&tag).is_ok_and(|found| found == digest) {
        return Ok(tag);
    }
    if inspect_digest(name).is_ok_and(|found| found == digest) {
        capture(container().args(["image", "tag", name, &tag]), "tagging the agent image")?;
        return Ok(tag);
    }
    bail!("image {image} isn't here, or was replaced: run install.sh to build the agent image")
}

/// Build box/agent.Containerfile (`repo_box_dir` is the repo's `box` folder, the build context)
/// and return the pinned reference of the result. The build's output goes to the terminal.
pub fn build_agent_image(repo_box_dir: &Path) -> Result<String> {
    let containerfile = repo_box_dir.join("agent.Containerfile");
    if !containerfile.is_file() {
        bail!("no agent.Containerfile in {}", repo_box_dir.display());
    }
    let status = container().arg("build").arg("-f").arg(&containerfile).args(["-t", AGENT_IMAGE]).arg(repo_box_dir).status().context("running container build")?;
    if !status.success() {
        bail!("building the agent image failed ({status})");
    }
    image_digest(AGENT_IMAGE)
}

/// Build box/browser.Containerfile (`repo_box_dir` is the repo's `box` folder; the build context
/// is the repo, which holds the runner) and return the pinned reference of the result.
pub fn build_browser_image(repo_box_dir: &Path) -> Result<String> {
    let containerfile = repo_box_dir.join("browser.Containerfile");
    if !containerfile.is_file() {
        bail!("no browser.Containerfile in {}", repo_box_dir.display());
    }
    let context = repo_box_dir.parent().context("the box folder has no parent")?;
    let status = container().arg("build").arg("-f").arg(&containerfile).args(["-t", BROWSER_IMAGE]).arg(context).status().context("running container build")?;
    if !status.success() {
        bail!("building the browser image failed ({status})");
    }
    image_digest(BROWSER_IMAGE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> VmSpec {
        VmSpec {
            name: "cred-box-research".into(),
            image: "cred-agent:abc".into(),
            cpus: 4,
            memory: "8G".into(),
            socket: "/tmp/cred-501/research.sock".into(),
            mounts: vec![
                Mount { host: "/Volumes/box/home".into(), guest: "/home/agent".into(), readonly: false },
                Mount { host: "/Users/me/src".into(), guest: "/work/src".into(), readonly: true },
            ],
            docker: false,
        }
    }

    #[test]
    fn env_uses_stand_ins_and_the_right_key() {
        let get = |env: &[(String, String)], k: &str| env.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
        let oauth = agent_env(true);
        assert_eq!(get(&oauth, "CLAUDE_CODE_OAUTH_TOKEN").as_deref(), Some("cred-managed"));
        assert_eq!(get(&oauth, "ANTHROPIC_API_KEY"), None);
        let key = agent_env(false);
        assert_eq!(get(&key, "ANTHROPIC_API_KEY").as_deref(), Some("cred-managed"));
        assert_eq!(get(&key, "CLAUDE_CODE_OAUTH_TOKEN"), None);
        assert_eq!(get(&key, "HTTPS_PROXY").as_deref(), Some("http://127.0.0.1:3128"));
        assert_eq!(get(&key, "HOME").as_deref(), Some("/home/agent"));
        // Node ignores the system store, so it gets the CA file; the others get the bundle.
        assert_eq!(get(&key, "NODE_EXTRA_CA_CERTS").as_deref(), Some(CA_CERT));
        for var in ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "PIP_CERT", "GIT_SSL_CAINFO"] {
            assert_eq!(get(&key, var).as_deref(), Some("/etc/ssl/certs/ca-certificates.crt"), "{var}");
        }
    }

    #[test]
    fn run_args_isolate_the_vm() {
        let args = run_args(&spec(), "cred-agent:abc").unwrap().join(" ");
        assert_eq!(
            args,
            "run --progress none --detach --rm --init --network none --tmpfs /tmp --tmpfs /var/tmp \
             --name cred-box-research --cpus 4 --memory 8G \
             --publish-socket /tmp/cred-501/research.sock:/run/cred/door.sock \
             --mount type=bind,source=/Volumes/box/home,target=/home/agent \
             --mount type=bind,source=/Users/me/src,target=/work/src,readonly \
             --entrypoint cred-shim cred-agent:abc serve"
        );
    }

    #[test]
    fn the_runner_starts_in_the_browser_vm_as_its_user() {
        assert_eq!(browser_vm_name("research"), "cred-browser-research");
        let env = vec![("CRED_RUNNER_DEBUG_NO_ROUTING".to_string(), "1".to_string())];
        let cmd = runner_command("cred-browser-research", &env).unwrap();
        let args: Vec<_> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(
            args,
            [
                "exec",
                "--uid",
                "1000",
                "--gid",
                "1000",
                "-i",
                "-e",
                "HOME=/home/browser",
                "-e",
                "PLAYWRIGHT_BROWSERS_PATH=/ms-playwright",
                "-e",
                "CRED_RUNNER_DEBUG_NO_ROUTING=1",
                "cred-browser-research",
                "node",
                "/opt/runner/runner.mjs"
            ]
        );
    }

    #[test]
    fn mount_paths_with_commas_are_refused() {
        let m = Mount { host: "/a,b".into(), guest: "/x".into(), readonly: false };
        assert!(mount_arg(&m).is_err());
    }

    #[test]
    fn exec_runs_as_the_agent_with_env_in_arguments() {
        let env = vec![("A".to_string(), "b c".to_string())];
        let cmd = exec_command("vm", &env, &["ls".into(), "-l".into()], true);
        let args: Vec<_> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert_eq!(args, ["exec", "--uid", "1000", "--gid", "1000", "-i", "-t", "-e", "A=b c", "vm", "ls", "-l"]);
    }

    #[test]
    fn image_names_lose_tag_and_digest() {
        assert_eq!(image_name("cred-agent"), "cred-agent");
        assert_eq!(image_name("cred-agent:latest"), "cred-agent");
        assert_eq!(image_name("cred-agent@sha256:ab"), "cred-agent");
        assert_eq!(image_name("localhost:5000/cred-agent"), "localhost:5000/cred-agent");
    }

    #[test]
    fn plain_references_run_as_they_are() {
        assert_eq!(local_image("cred-agent:abc").unwrap(), "cred-agent:abc");
    }

    #[test]
    fn docker_boxes_and_long_sockets_are_refused_before_anything_runs() {
        let mut s = spec();
        s.docker = true;
        assert!(run(&s).unwrap_err().to_string().contains("Docker"));
        let mut s = spec();
        s.socket = PathBuf::from(format!("/tmp/{}", "x".repeat(120)));
        assert!(run(&s).unwrap_err().to_string().contains("too long"));
    }
}

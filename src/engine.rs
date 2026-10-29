//! STUB: replaced at merge by the engine module (Apple `container`: images, run, exec, stop).
//! Signatures follow the phase 1 contract; bodies only let `boxes` compile and be tested.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use anyhow::{Result, bail};

pub const AGENT_IMAGE: &str = "cred-agent";
pub const AGENT_USER: &str = "agent";

pub fn agent_env(oauth: bool) -> Vec<(String, String)> {
    let auth = if oauth { "CLAUDE_CODE_OAUTH_TOKEN" } else { "ANTHROPIC_API_KEY" };
    [
        ("HTTPS_PROXY", "http://127.0.0.1:3128"),
        ("HTTP_PROXY", "http://127.0.0.1:3128"),
        ("NO_PROXY", "cred.internal,127.0.0.2"),
        ("ANTHROPIC_BASE_URL", "http://cred.internal/model"),
        (auth, "cred-managed"),
        ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
        ("DISABLE_AUTOUPDATER", "1"),
        ("HOME", "/home/agent"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

pub struct Mount {
    pub host: PathBuf,
    pub guest: String,
    pub readonly: bool,
}

pub struct VmSpec {
    pub name: String,
    pub image: String,
    pub cpus: u32,
    pub memory: String,
    pub socket: PathBuf,
    pub mounts: Vec<Mount>,
    pub docker: bool,
}

pub fn available() -> Result<()> {
    bail!("the engine isn't built in this branch yet")
}

pub fn run(_spec: &VmSpec) -> Result<()> {
    bail!("the engine isn't built in this branch yet")
}

pub fn exec(_name: &str, _env: &[(String, String)], _cmd: &[String], _tty: bool) -> Result<ExitStatus> {
    bail!("the engine isn't built in this branch yet")
}

pub fn running(_name: &str) -> bool {
    false
}

pub fn stop(_name: &str) -> Result<()> {
    Ok(())
}

pub fn image_digest(_reference: &str) -> Result<String> {
    bail!("the engine isn't built in this branch yet")
}

pub fn build_agent_image(_repo_box_dir: &Path) -> Result<String> {
    bail!("the engine isn't built in this branch yet")
}

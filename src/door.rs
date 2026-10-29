//! STUB: replaced at merge by the door module (proxy, model gateway, MCP endpoint, log).
//! Signatures follow the phase 1 contract; bodies only let `boxes` compile and be tested.
#![allow(dead_code)]

use std::path::PathBuf;

use anyhow::{Result, bail};

pub const STANDIN: &str = "cred-managed";

pub struct Config {
    pub name: String,
    pub socket: PathBuf,
    pub allow: Vec<String>,
    pub model: Option<String>,
    pub sites: Vec<String>,
    pub log: PathBuf,
}

pub struct Door {}

impl Door {
    pub fn start(_cfg: Config) -> Result<Door> {
        bail!("the door isn't built in this branch yet")
    }

    pub fn stop(self) {}
}

pub fn model_uses_bearer(_model: &str) -> Result<bool> {
    bail!("the door isn't built in this branch yet")
}

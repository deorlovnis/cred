//! The box's browser VM: where its sites' pages run. One VM holds all of the box's sites; each
//! open site is a runner process in it (`container exec`), so sites never share a Chromium
//! profile. The VM starts with the first runner and stops with the box.
//!
//! Its door is a socket of its own (see `door::Config::browser_socket`). A runner speaks to it as
//! its site, proving it with a token this module issues and the door checks (`door::Tokens`).
//! The VM trusts the box's CA like the agent's does, so the door can read what pages send.
#![allow(dead_code)] // used by the browser plumbing of box runs

use std::path::PathBuf;
use std::process::Child;
use std::sync::Mutex;

use anyhow::Result;

use crate::{door, engine};

pub struct BrowserVm {
    spec: engine::BrowserSpec,
    /// The box CA (PEM), to install in the VM when it starts.
    ca_pem: String,
    tokens: door::Tokens,
    /// Whether the VM is running; held while it starts, so two first runners start one VM.
    up: Mutex<bool>,
    /// For tests: variables for the next runners (see `engine::exec_runner`).
    #[cfg(debug_assertions)]
    runner_env: Mutex<Vec<(String, String)>>,
}

impl BrowserVm {
    /// A browser VM for the box `box_id`, not started yet. `image` is a pinned
    /// "cred-browser@sha256:..."; `downloads` the Mac folder for downloads, or `None` when the
    /// policy doesn't allow them; `tokens` the list the box's door checks.
    pub fn new(box_id: &str, image: &str, socket: PathBuf, downloads: Option<PathBuf>, ca_pem: String, tokens: door::Tokens) -> Self {
        let spec = engine::BrowserSpec { name: engine::browser_vm_name(box_id), image: image.to_string(), socket, downloads };
        Self {
            spec,
            ca_pem,
            tokens,
            up: Mutex::new(false),
            #[cfg(debug_assertions)]
            runner_env: Mutex::new(Vec::new()),
        }
    }

    /// Give the runners started from now on these variables (the `CRED_RUNNER_DEBUG_*` ones
    /// switch protections off; release builds refuse them).
    #[cfg(debug_assertions)]
    pub fn set_runner_env(&self, env: Vec<(String, String)>) {
        *self.runner_env.lock().unwrap_or_else(|e| e.into_inner()) = env;
    }

    /// Start a runner for `site` in the VM, which is started first if it isn't up. Returns the
    /// runner (JSON lines on its piped stdin and stdout) and the proxy password it must give
    /// Chromium, with the site's name as the user: `proxy: { server: 'http://127.0.0.1:3128',
    /// username: <site>, password: <token> }` in the runner's `open` config.
    pub fn runner(&self, site: &str) -> Result<(Child, String)> {
        self.start()?;
        let token = self.tokens.issue(site)?;
        #[cfg(debug_assertions)]
        let env = self.runner_env.lock().unwrap_or_else(|e| e.into_inner()).clone();
        #[cfg(not(debug_assertions))]
        let env = Vec::new();
        match engine::exec_runner(&self.spec.name, &env) {
            Ok(child) => Ok((child, token)),
            Err(e) => {
                self.tokens.revoke(&token);
                Err(e)
            }
        }
    }

    fn start(&self) -> Result<()> {
        let mut up = self.up.lock().unwrap_or_else(|e| e.into_inner());
        if !*up {
            engine::run_browser(&self.spec)?;
            // Marked at once: a VM that is there but half set up is stopped by `stop`.
            *up = true;
            engine::install_browser_ca(&self.spec.name, &self.ca_pem)?;
        }
        Ok(())
    }

    /// Stop the VM if it was started (which ends its runners too). Fine if it is gone already.
    pub fn stop(&self) {
        let mut up = self.up.lock().unwrap_or_else(|e| e.into_inner());
        if std::mem::take(&mut *up)
            && let Err(e) = engine::stop(&self.spec.name)
        {
            eprintln!("cred: stopping {}: {e:#}", self.spec.name);
        }
        let _ = std::fs::remove_file(&self.spec.socket);
    }
}

impl Drop for BrowserVm {
    fn drop(&mut self) {
        self.stop();
    }
}

//! The door: cred's side of the one connection a box has to the outside. A box's VMs have no
//! network; each has a socket cred published into it. cred dials into that socket and keeps a
//! few idle connections ready (the pool). When the guest takes one it first says what it
//! wants, one line `<kind>\n`, and then the connection carries that service:
//!
//! - `proxy`: an HTTP proxy that does CONNECT to port 443 of the hosts the box may reach, at
//!   public addresses cred resolved and checked itself (see `proxy`, `addr`). With a box CA the
//!   door ends the TLS inside the tunnel, so it can read the requests (see `tls`);
//! - `cred`: plain HTTP to cred itself, where `/model/...` is the model gateway that swaps in
//!   the real key (see `gateway`);
//! - `mcp`: cred's MCP server for the box, limited to its sites.
//!
//! The box's browser VM has a socket of its own, and only `proxy` connections through it are
//! served. They are not the agent's: each one says which site's page it carries (a runner's
//! identity, see `page`), and gets that site's `[browse]` rules instead of the box's `[net]`.
//!
//! Every decision is logged as a JSON line: time, kind, host or path, bytes, decision. Never
//! values or headers. Each line is chained to the one before with an HMAC (see `chain`), so an
//! edited or removed line shows; requests inside a connection the door has opened up are judged
//! and logged one by one (see `inspect`).

mod addr;
mod gateway;
mod http;
pub mod inspect;
mod page;
mod proxy;
mod tls;

use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::{Result, anyhow};
use jiff::Timestamp;
use serde::Serialize;

use crate::chain::Chain;
use crate::mcp::{self, Scope};
use crate::policy;
use addr::{Allow, Net};
pub use page::Tokens;
pub use tls::{BoxCa, PURPOSE as CA_PURPOSE};

/// What the box holds in place of the model key. Worthless anywhere but at the gateway.
pub const STANDIN: &str = "cred-managed";

/// Idle connections kept dialed in; a new one is dialed when one is taken.
const POOL: usize = 8;
/// Connections in use at once; no more are dialed beyond this.
const MAX_ACTIVE: usize = 256;
/// How long to wait between tries to dial while the box starts, and how often a stop is noticed.
const REDIAL: Duration = Duration::from_millis(200);
/// The longest `<kind>` line.
const MAX_KIND: u64 = 16;

pub struct Config {
    /// The box's name, for logs and errors.
    pub name: String,
    /// The published socket to dial.
    pub socket: PathBuf,
    /// `[net] allow`: `"*"` (any host) or patterns like `https://*.wikipedia.org`.
    pub allow: Vec<String>,
    /// The resource whose approved `[fetch]` policy (hosts[0], auth, auth_header) the model
    /// gateway uses.
    pub model: Option<String>,
    /// The resources served over `mcp`; their own approved policies apply.
    pub sites: Vec<String>,
    /// `[net] writes` and `allow_writes`: what the box's own requests may do (see `inspect`).
    pub net: inspect::Net,
    /// Where decisions are logged (JSON lines, each chained to the one before with an HMAC).
    pub log: PathBuf,
    /// The box's CA. With it the door ends TLS and reads the requests inside (see `tls`);
    /// without it, it tunnels bytes it can't read.
    pub ca: Option<Arc<BoxCa>>,
    /// The key of that chain, derived from the box key.
    pub log_key: [u8; 32],
    /// The published socket of the box's browser VM, if it has one. The door dials it like the
    /// agent's, but serves only `proxy` connections, as the site each one names.
    pub browser_socket: Option<PathBuf>,
    /// Which runner speaks for which site; the browser side fills it (see `Tokens`).
    pub browser_tokens: Tokens,
}

/// Which VM's socket a connection came in on. The only thing that tells them apart: nothing a
/// guest sends can make a connection of the agent's VM a browser's.
#[derive(Clone, Copy, PartialEq)]
enum Origin {
    Agent,
    Browser,
}

/// A running door. Dropping it stops it.
pub struct Door {
    shared: Arc<Shared>,
    dialers: Vec<JoinHandle<()>>,
}

impl Door {
    pub fn start(cfg: Config) -> Result<Door> {
        Self::start_with(cfg, Net::system())
    }

    fn start_with(cfg: Config, net: Net) -> Result<Door> {
        let shared = Arc::new(Shared::new(cfg, net)?);
        let mut sockets = vec![(shared.cfg.socket.clone(), Origin::Agent, "door-dialer")];
        sockets.extend(shared.cfg.browser_socket.clone().map(|socket| (socket, Origin::Browser, "door-dialer-browser")));
        let mut dialers = Vec::new();
        for (socket, origin, name) in sockets {
            let sh = shared.clone();
            dialers.push(thread::Builder::new().name(name.into()).spawn(move || dial_loop(&sh, &socket, origin))?);
        }
        Ok(Door { shared, dialers })
    }

    #[allow(dead_code)] // dropping a Door stops it too
    pub fn stop(self) {}
}

impl Drop for Door {
    fn drop(&mut self) {
        self.shared.stopped.store(true, Ordering::SeqCst);
        for stream in self.shared.conns.lock().unwrap_or_else(|e| e.into_inner()).values() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        for dialer in self.dialers.drain(..) {
            let _ = dialer.join();
        }
    }
}

/// Whether the model resource's calls carry `Authorization: Bearer ...` (a subscription token,
/// so the box's stand-in goes in `CLAUDE_CODE_OAUTH_TOKEN`) rather than another header such as
/// `x-api-key` (so it goes in `ANTHROPIC_API_KEY`).
pub fn model_uses_bearer(model: &str) -> Result<bool> {
    let approved = policy::load(model)?;
    let fetch = approved.policy.fetch.as_ref().ok_or_else(|| anyhow!("the policy for {model} has no [fetch] section"))?;
    Ok(fetch.auth_header.eq_ignore_ascii_case("authorization"))
}

struct Shared {
    cfg: Config,
    allow: Allow,
    net: Net,
    /// The gateway's client to the model host; it keeps connections between calls.
    agent: ureq::Agent,
    log: Log,
    stopped: AtomicBool,
    /// Connections the guest has taken.
    active: AtomicUsize,
    next_id: AtomicU64,
    /// Every open connection, so a stop can end them.
    conns: Mutex<HashMap<u64, UnixStream>>,
}

impl Shared {
    fn new(cfg: Config, net: Net) -> Result<Self> {
        Ok(Self {
            allow: Allow::parse(&cfg.allow)?,
            log: Log::open(&cfg.log, cfg.log_key)?,
            agent: gateway::agent(),
            net,
            cfg,
            stopped: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            next_id: AtomicU64::new(0),
            conns: Mutex::new(HashMap::new()),
        })
    }

    fn stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// Dial the socket, trying again until it answers (the box may still be starting) or the
    /// door stops.
    fn dial(&self, socket: &Path) -> Option<UnixStream> {
        while !self.stopped() {
            match UnixStream::connect(socket) {
                Ok(stream) => return Some(stream),
                Err(_) => thread::sleep(REDIAL),
            }
        }
        None
    }

    fn register(&self, stream: &UnixStream) -> Option<u64> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.conns.lock().unwrap_or_else(|e| e.into_inner()).insert(id, stream.try_clone().ok()?);
        // A stop may have gone through the list just before this was added.
        if self.stopped() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        Some(id)
    }
}

/// Keep `POOL` connections dialed in to `socket`, replacing each as the guest takes it.
fn dial_loop(sh: &Arc<Shared>, socket: &Path, origin: Origin) {
    let (taken, replace) = mpsc::channel::<()>();
    for _ in 0..POOL {
        let _ = taken.send(());
    }
    while !sh.stopped() {
        match replace.recv_timeout(REDIAL) {
            Ok(()) => {}
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
        while sh.active.load(Ordering::SeqCst) >= MAX_ACTIVE && !sh.stopped() {
            thread::sleep(REDIAL);
        }
        let Some(stream) = sh.dial(socket) else { break };
        let (sh, taken) = (sh.clone(), taken.clone());
        let _ = thread::Builder::new().name("door-conn".into()).spawn(move || connection(&sh, stream, taken, origin));
    }
}

/// One dialed connection: idle until the guest writes to it, then served until either side closes.
fn connection(sh: &Shared, stream: UnixStream, taken: Sender<()>, origin: Origin) {
    let id = sh.register(&stream);
    let mut reader = match stream.try_clone() {
        Ok(clone) => BufReader::new(clone),
        Err(_) => return,
    };
    // Block until the guest sends the first bytes (or the connection dies), without using them.
    let wanted = matches!(reader.fill_buf(), Ok(bytes) if !bytes.is_empty());
    if !wanted {
        // Don't redial in a tight loop if the other end keeps hanging up.
        thread::sleep(REDIAL);
    }
    let _ = taken.send(());
    if wanted {
        sh.active.fetch_add(1, Ordering::SeqCst);
        serve(sh, reader, stream.try_clone().ok(), origin);
        sh.active.fetch_sub(1, Ordering::SeqCst);
    }
    let _ = stream.shutdown(Shutdown::Both);
    if let Some(id) = id {
        sh.conns.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
    }
}

fn serve(sh: &Shared, mut reader: BufReader<UnixStream>, writer: Option<UnixStream>, origin: Origin) {
    let Some(writer) = writer else { return };
    let mut kind = String::new();
    if reader.by_ref().take(MAX_KIND).read_line(&mut kind).is_err() {
        return;
    }
    match (origin, kind.trim_end()) {
        (_, "proxy") => proxy::serve(sh, reader, writer, origin),
        // The browser VM has no business with cred itself.
        (Origin::Agent, "cred") => gateway::serve(sh, reader, writer),
        (Origin::Agent, "mcp") => serve_mcp(sh, reader, writer),
        (Origin::Browser, other) => {
            let other: String = other.chars().filter(|c| c.is_ascii_graphic()).take(MAX_KIND as usize).collect();
            sh.log.write(&Entry { host: Some(other), ..Entry::new("unknown", "blocked:browser-kind") });
        }
        (Origin::Agent, other) => {
            let other: String = other.chars().filter(|c| c.is_ascii_graphic()).take(MAX_KIND as usize).collect();
            sh.log.write(&Entry { host: Some(other), ..Entry::new("unknown", "blocked:unknown-kind") });
        }
    }
}

/// The MCP server for the box's sites, over the connection. The box run's Touch ID counts as
/// consent for them.
fn serve_mcp(sh: &Shared, reader: BufReader<UnixStream>, writer: UnixStream) {
    let (up, down) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    sh.log.write(&Entry::new("mcp", "opened"));
    let scope = Scope::boxed(&sh.cfg.name, &sh.cfg.sites);
    let result = mcp::serve_io(Counting::new(reader, up.clone()), Counting::new(writer, down.clone()), scope);
    let decision = match result {
        Ok(()) => "closed".to_string(),
        Err(e) => format!("failed: {e:#}"),
    };
    sh.log.write(&Entry { up: up.load(Ordering::Relaxed), down: down.load(Ordering::Relaxed), ..Entry::new("mcp", &decision) });
}

/// Counts the bytes that go through a reader or writer.
struct Counting<T> {
    inner: T,
    bytes: Arc<AtomicU64>,
}

impl<T> Counting<T> {
    fn new(inner: T, bytes: Arc<AtomicU64>) -> Self {
        Self { inner, bytes }
    }
}

impl<T: Read> Read for Counting<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

impl<T: BufRead> BufRead for Counting<T> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    fn consume(&mut self, amount: usize) {
        self.bytes.fetch_add(amount as u64, Ordering::Relaxed);
        self.inner.consume(amount);
    }
}

impl<T: Write> Write for Counting<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.bytes.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// One line of the door's log.
#[derive(Serialize)]
struct Entry {
    /// `proxy` (a connection), `request` (one request inside it), `model` (the gateway), `mcp`, or `unknown`.
    kind: &'static str,
    /// The site whose page made a browser VM's request.
    #[serde(skip_serializing_if = "Option::is_none")]
    site: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<String>,
    /// The address connected to.
    #[serde(skip_serializing_if = "Option::is_none")]
    addr: Option<String>,
    /// The request path without its query, for the gateway.
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    /// The URL of a request, masked.
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<u16>,
    /// Bytes from the guest, and to it.
    up: u64,
    down: u64,
    /// `allowed`, `asked:yes`, `asked:no`, `closed`, `blocked:<why>` or `failed:<why>`.
    decision: String,
}

impl Entry {
    fn new(kind: &'static str, decision: &str) -> Self {
        Self { kind, site: None, host: None, addr: None, path: None, method: None, url: None, status: None, up: 0, down: 0, decision: decision.to_string() }
    }
}

#[derive(Serialize)]
struct Line<'a> {
    time: String,
    #[serde(flatten)]
    entry: &'a Entry,
}

/// The door's log: every line chained to the one before (see `chain`), so an edit shows.
struct Log(Chain);

impl Log {
    fn open(path: &Path, key: [u8; 32]) -> Result<Self> {
        let chain = Chain::new(path, key);
        chain.create()?;
        Ok(Self(chain))
    }

    /// Append the entry. A log that can't be written doesn't stop the door.
    fn write(&self, entry: &Entry) {
        let time = Timestamp::from_millisecond(Timestamp::now().as_millisecond()).map(|t| t.to_string()).unwrap_or_default();
        let Ok(line) = serde_json::to_value(Line { time, entry }) else { return };
        let _ = self.0.append(line);
    }
}

#[cfg(test)]
mod intercept_tests;
#[cfg(test)]
mod page_tests;
#[cfg(test)]
mod page_vm_tests;
#[cfg(test)]
mod inspect_tests;
#[cfg(test)]
mod tests;

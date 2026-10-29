//! `inspect::serve` over plain sockets: the guest and the site are both ends of local socket
//! pairs, so no TLS is needed. The site is a scripted server that records what reaches it.
//!
//! Policies, approvals and values live in files (the debug-only fake Keychain), set up through
//! environment variables, so each scenario runs in a copy of this test binary started with its
//! own environment (as in `tests`), with Touch ID answering yes or no.

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde_json::{Value, json};

use super::addr::Net as Dial;
use super::http::{self, Body, Head};
use super::inspect::{Ctx, Net, serve};
use super::{Config, Shared};
use crate::chain::Chain;
use crate::policy::{self, Mode};
use crate::util::TempDir;
use crate::{approve, keychain};

const SECRET: &str = "tok-SECRET-0123456789-abcdef";
const LOG_KEY: [u8; 32] = [9; 32];
const WAIT: Duration = Duration::from_secs(10);
const MASK: &str = "********";

// --- the scenario's environment ---

const YES: &str = "door::inspect_tests::the_requests_of_a_box_are_judged_and_touch_id_says_yes";
const NO: &str = "door::inspect_tests::the_requests_of_a_box_are_judged_and_touch_id_says_no";

#[test]
fn the_requests_of_a_box_are_judged_and_touch_id_says_yes() {
    run_scenario(YES, "yes");
}

#[test]
fn the_requests_of_a_box_are_judged_and_touch_id_says_no() {
    run_scenario(NO, "no");
}

fn run_scenario(name: &str, answer: &str) {
    if let Some(dir) = std::env::var_os("CRED_INSPECT_DIR") {
        return scenario(Path::new(&dir), answer == "yes");
    }
    let dir = TempDir::new("cred-inspect").unwrap();
    for sub in ["keychain", "policy", "home"] {
        fs::create_dir(dir.0.join(sub)).unwrap();
    }
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env("CRED_INSPECT_DIR", &dir.0)
        .env("HOME", dir.0.join("home"))
        .env("CRED_INDEX", dir.0.join("index.json"))
        .env("CRED_POLICY_DIR", dir.0.join("policy"))
        .env("CRED_TEST_KEYCHAIN", dir.0.join("keychain"))
        .env("CRED_TEST_APPROVE", "yes")
        .env("CRED_AUDIT", dir.0.join("audit.log"))
        .env("CRED_AUDIT_KEY", "test-key");
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "scenario failed:\n{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
}

// --- a scripted site ---

/// What the site saw of a request; the body is decoded.
#[derive(Clone)]
struct Seen {
    line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    fn count(&self, name: &str) -> usize {
        self.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case(name)).count()
    }

    fn target(&self) -> &str {
        self.line.split(' ').nth(1).unwrap()
    }
}

/// Routes: `/plain`, `/echo` (the secret in a body with a length), `/split` (the secret cut
/// across two chunks), `/sse` (an event, then the secret cut across two chunks after `release`),
/// `/gzip`, `/close` (a body that ends with the connection), `POST /submit` (echoes the body).
fn respond(seen: &Seen, out: &mut UnixStream, released: &Mutex<Receiver<()>>) {
    let method = seen.line.split(' ').next().unwrap();
    let path = seen.target().split('?').next().unwrap();
    let whole = |out: &mut UnixStream, extra: &str, body: &str| {
        write!(out, "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n{extra}content-length: {}\r\n\r\n{body}", body.len()).unwrap();
    };
    let chunk = |out: &mut UnixStream, data: &str| {
        write!(out, "{:x}\r\n{data}\r\n", data.len()).unwrap();
        out.flush().unwrap();
        thread::sleep(Duration::from_millis(40));
    };
    match (method, path) {
        ("HEAD", _) => write!(out, "HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n").unwrap(),
        (_, "/plain") => whole(out, "", "plain page"),
        (_, "/echo") => whole(out, "etag: \"x\"\r\n", &format!("token is {SECRET} ok")),
        (_, "/split") => {
            write!(out, "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n").unwrap();
            chunk(out, "token is tok-SEC");
            chunk(out, "RET-0123456789-abcdef ok");
            write!(out, "0\r\n\r\n").unwrap();
        }
        (_, "/sse") => {
            write!(out, "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n").unwrap();
            chunk(out, "event: ping\ndata: 1\n\n");
            released.lock().unwrap().recv_timeout(WAIT).unwrap();
            chunk(out, "data: tok-SECR");
            chunk(out, "ET-0123456789-abcdef\n\n");
            write!(out, "0\r\n\r\n").unwrap();
        }
        (_, "/gzip") => out.write_all(b"HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ncontent-length: 4\r\n\r\n\x1f\x8b\x08\x00").unwrap(),
        (_, "/close") => {
            write!(out, "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\nclosing {SECRET}").unwrap();
            out.flush().unwrap();
            out.shutdown(Shutdown::Both).unwrap();
        }
        ("POST", "/submit") => whole(out, "", &format!("got {}", String::from_utf8_lossy(&seen.body))),
        _ => write!(out, "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n").unwrap(),
    }
    out.flush().unwrap();
}

/// One connection for a host: the guest's end, the site's record, and the thread running `serve`.
struct Rig {
    guest: Conn,
    seen: Arc<Mutex<Vec<Seen>>>,
    release: Sender<()>,
    serving: JoinHandle<(u64, u64)>,
}

impl Rig {
    fn new(shared: &Arc<Shared>, host: &str) -> Self {
        let (guest, door_guest) = UnixStream::pair().unwrap();
        let (door_upstream, site) = UnixStream::pair().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (release, released) = mpsc::channel();
        let (record, released) = (seen.clone(), Mutex::new(released));
        thread::spawn(move || {
            let mut reader = BufReader::new(site.try_clone().unwrap());
            let mut out = site;
            while let Ok(Some(head)) = http::read_head(&mut reader) {
                let framing = http::request_framing(&head).unwrap();
                let mut body = Vec::new();
                Body::new(&mut reader, framing).read_to_end(&mut body).unwrap();
                let seen = Seen { line: head.line.clone(), headers: head.headers.clone(), body };
                record.lock().unwrap().push(seen.clone());
                respond(&seen, &mut out, &released);
            }
        });
        let (shared, host) = (shared.clone(), host.to_string());
        let serving = thread::spawn(move || serve(door_guest, door_upstream, &Ctx { shared: &shared, host: &host }));
        guest.set_read_timeout(Some(WAIT)).unwrap();
        Self { guest: Conn { reader: BufReader::new(guest.try_clone().unwrap()), stream: guest, seen: Vec::new() }, seen, release, serving }
    }

    fn reached(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    /// End the guest's side and wait for the door to finish: the log is complete after this.
    fn finish(self) -> (u64, u64) {
        let _ = self.guest.stream.shutdown(Shutdown::Write);
        drop(self.guest);
        self.serving.join().unwrap()
    }
}

struct Conn {
    reader: BufReader<UnixStream>,
    stream: UnixStream,
    /// Everything the door sent back.
    seen: Vec<u8>,
}

struct Reply {
    status: u16,
    head: Head,
}

impl Conn {
    fn send(&mut self, text: &str) {
        self.stream.write_all(text.as_bytes()).unwrap();
    }

    fn head(&mut self) -> Reply {
        let head = http::read_head(&mut self.reader).unwrap().expect("the door closed the connection");
        self.seen.extend_from_slice(head.line.as_bytes());
        for (n, v) in &head.headers {
            self.seen.extend_from_slice(format!("{n}: {v}\n").as_bytes());
        }
        Reply { status: head.status().unwrap(), head }
    }

    /// One piece of a chunked body; empty for the last.
    fn chunk(&mut self) -> Vec<u8> {
        let mut size = String::new();
        self.reader.read_line(&mut size).unwrap();
        let size = usize::from_str_radix(size.trim(), 16).unwrap();
        let mut data = vec![0; size + 2];
        self.reader.read_exact(&mut data).unwrap();
        assert_eq!(&data[size..], b"\r\n");
        data.truncate(size);
        self.seen.extend_from_slice(&data);
        data
    }

    fn body(&mut self, reply: &Reply) -> String {
        let mut all = Vec::new();
        if reply.head.header("transfer-encoding") == Some("chunked") {
            loop {
                let chunk = self.chunk();
                if chunk.is_empty() {
                    break;
                }
                all.extend(chunk);
            }
        } else if let Some(len) = reply.head.header("content-length") {
            all = vec![0; len.parse().unwrap()];
            self.reader.read_exact(&mut all).unwrap();
            self.seen.extend_from_slice(&all);
        } else {
            self.reader.read_to_end(&mut all).unwrap();
            self.seen.extend_from_slice(&all);
        }
        String::from_utf8_lossy(&all).into_owned()
    }

    /// The door ends the connection within `WAIT`.
    fn closed(&mut self) -> bool {
        let mut byte = [0u8; 1];
        matches!(self.reader.read(&mut byte), Ok(0) | Err(_))
    }

    /// Send a request, return the status and the body.
    fn get(&mut self, host: &str, target: &str, headers: &[(&str, &str)]) -> (Reply, String) {
        self.send(&request("GET", target, host, headers, None));
        let reply = self.head();
        let body = self.body(&reply);
        (reply, body)
    }

    fn post(&mut self, host: &str, target: &str, headers: &[(&str, &str)], body: &str) -> (Reply, String) {
        self.send(&request("POST", target, host, headers, Some(body)));
        let reply = self.head();
        let body = self.body(&reply);
        (reply, body)
    }
}

fn request(method: &str, target: &str, host: &str, headers: &[(&str, &str)], body: Option<&str>) -> String {
    let headers: String = headers.iter().map(|(n, v)| format!("{n}: {v}\r\n")).collect();
    let length = body.map_or(String::new(), |b| format!("Content-Length: {}\r\n", b.len()));
    format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\n{headers}{length}\r\n{}", body.unwrap_or(""))
}

// --- the box ---

fn write_policy(res: &str, toml: &str) {
    fs::write(policy::path(res), toml).unwrap();
}

fn store(res: &str, field: &str, value: &str) {
    keychain::set(res, field, value).unwrap();
}

/// A door's shared state with these write rules, logging to `dir/<name>.log`.
fn shared(dir: &Path, name: &str, writes: Mode, allow_writes: &[&str]) -> Arc<Shared> {
    let config = Config {
        name: "testbox".into(),
        socket: dir.join("unused.sock"),
        allow: vec!["*".into()],
        model: None,
        sites: vec!["app".into(), "readonly".into(), "askme".into(), "pending".into()],
        net: Net { writes, allow_writes: allow_writes.iter().map(|p| p.to_string()).collect() },
        log: dir.join(format!("{name}.log")),
        log_key: LOG_KEY,
    };
    Arc::new(Shared::new(config, Dial::system()).unwrap())
}

fn log_lines(dir: &Path, name: &str) -> Vec<Value> {
    fs::read_to_string(dir.join(format!("{name}.log"))).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn scenario(dir: &Path, yes: bool) {
    // The box's sites: one that may write, one read-only, one that asks, one never approved.
    let hosts = [("app", "app.example.com", "writes = \"allow\"\n"), ("readonly", "ro.example.com", ""), ("askme", "ask.example.com", "writes = \"ask\"\n")];
    for (res, host, writes) in hosts {
        write_policy(res, &format!("[fetch]\nhosts = [\"https://{host}\"]\n{writes}auth = \"Bearer {{token}}\"\nheaders = {{ x-client = \"cred\" }}\n"));
        store(res, "token", SECRET);
    }
    write_policy("pending", "[fetch]\nhosts = [\"https://pending.example.com\"]\nwrites = \"allow\"\nauth = \"Bearer {token}\"\n");
    store("pending", "token", SECRET);
    fs::write(dir.join("index.json"), json!({ "app": site_index(), "readonly": site_index(), "askme": site_index(), "pending": site_index() }).to_string()).unwrap();
    policy::approve(&["app".into(), "readonly".into(), "askme".into()]).unwrap();
    approve::take_answers();
    // The policies are approved; from here Touch ID answers as this scenario says.
    // SAFETY: no other thread is running yet; the doors' threads start later.
    unsafe { std::env::set_var("CRED_TEST_APPROVE", if yes { "yes" } else { "no" }) };

    let deny = shared(dir, "deny", Mode::Deny, &["https://free.example.com/hook"]);
    other_hosts(&deny);
    site_hosts(&deny, yes);
    net_asks(&shared(dir, "ask", Mode::Ask, &[]), yes);
    net_allows(&shared(dir, "allow", Mode::Allow, &[]));
    the_log_chains(dir, yes);
}

fn site_index() -> Value {
    json!({ "fields": { "token": {} } })
}

/// Hosts no site covers: reads pass untouched; writes follow `[net]`.
fn other_hosts(sh: &Arc<Shared>) {
    let host = "web.example.com";
    let mut rig = Rig::new(sh, host);

    // The guest's own headers reach the site as they are, answers come back as they are.
    let (reply, body) = rig.guest.get(host, "/plain?token=abc123", &[("authorization", "Bearer guests-own"), ("accept-encoding", "gzip"), ("connection", "keep-alive")]);
    assert_eq!((reply.status, body.as_str()), (200, "plain page"));
    assert_eq!(reply.head.header("content-length"), Some("10"), "an answer that needs no change keeps its length");
    let first = rig.reached()[0].clone();
    assert_eq!(first.line, "GET /plain?token=abc123 HTTP/1.1");
    assert_eq!((first.header("authorization"), first.header("accept-encoding"), first.header("x-client")), (Some("Bearer guests-own"), Some("gzip"), None));
    assert_eq!(first.header("host"), Some(host));

    // A refused write is answered, and the same connection goes on to serve a read.
    let before = rig.reached().len();
    let (reply, body) = rig.guest.post(host, "/submit", &[], "payload");
    assert_eq!(reply.status, 403);
    assert!(body.contains("doesn't allow POST") && body.contains("allow_writes"), "{body}");
    assert_eq!(rig.reached().len(), before, "a refused write never reaches the site");
    let (reply, body) = rig.guest.get(host, "/plain", &[]);
    assert_eq!((reply.status, body.as_str()), (200, "plain page"));
    // The body of a refused write is read past, whatever its framing.
    rig.guest.send("POST /submit HTTP/1.1\r\nHost: web.example.com\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n");
    let reply = rig.guest.head();
    assert_eq!(reply.status, 403);
    rig.guest.body(&reply);
    assert_eq!(rig.guest.get(host, "/plain", &[]).0.status, 200);
    let methods = ["PUT", "PATCH", "DELETE"];
    for method in methods {
        rig.guest.send(&request(method, "/x", host, &[], Some("data")));
        let reply = rig.guest.head();
        assert_eq!(reply.status, 403, "{method}");
        rig.guest.body(&reply);
    }

    // Git: fetching and cloning are reads, pushing is not.
    let (reply, body) = rig.guest.post(host, "/o/r.git/git-upload-pack", &[("Content-Type", "application/x-git-upload-pack-request")], "0032want abc\n");
    assert_eq!(reply.status, 404, "the scripted site has no such route; it was reached");
    assert!(body.is_empty());
    assert_eq!(rig.reached().last().unwrap().target(), "/o/r.git/git-upload-pack");
    let (reply, _) = rig.guest.post(host, "/o/r.git/git-receive-pack", &[("Content-Type", "application/x-git-receive-pack-request")], "PACK");
    assert_eq!(reply.status, 403);
    assert_eq!(rig.guest.get(host, "/o/r.git/info/refs?service=git-receive-pack", &[]).0.status, 404, "advertising refs is a read");

    // An upgrade is a write; a request that isn't a path is refused.
    let (reply, _) = rig.guest.get(host, "/plain", &[("Connection", "Upgrade"), ("Upgrade", "websocket")]);
    assert_eq!(reply.status, 403);
    rig.guest.send("GET http://web.example.com/plain HTTP/1.1\r\nHost: web.example.com\r\n\r\n");
    let reply = rig.guest.head();
    assert_eq!(reply.status, 400);
    rig.guest.body(&reply);
    assert!(rig.guest.closed());
    let reached = rig.reached();
    rig.finish();

    // The Host header has to be the host the guest connected to, or the connection ends.
    let mut rig = Rig::new(sh, host);
    for header in ["evil.example.com", "web.example.com.evil.com", "app.example.com"] {
        let mut rig = Rig::new(sh, host);
        let (reply, body) = rig.guest.get(header, "/plain", &[]);
        assert_eq!(reply.status, 421, "{header}");
        assert!(body.contains("Host header must be web.example.com"), "{body}");
        assert!(rig.guest.closed());
        assert!(rig.reached().is_empty(), "a request for another host never reaches the site");
        rig.finish();
    }
    rig.guest.send("GET /plain HTTP/1.1\r\n\r\n");
    assert_eq!(rig.guest.head().status, 421, "no Host header at all");
    rig.finish();
    assert_eq!(reached.len(), 5);

    // Unmasked answers stream: the first event arrives before the site has sent the second.
    let mut rig = Rig::new(sh, host);
    rig.guest.send(&request("GET", "/sse", host, &[], None));
    let reply = rig.guest.head();
    assert_eq!(reply.head.header("transfer-encoding"), Some("chunked"));
    assert_eq!(rig.guest.chunk(), b"event: ping\ndata: 1\n\n");
    rig.release.send(()).unwrap();
    let mut rest = Vec::new();
    loop {
        let chunk = rig.guest.chunk();
        if chunk.is_empty() {
            break;
        }
        rest.extend(chunk);
    }
    assert_eq!(String::from_utf8(rest).unwrap(), format!("data: {SECRET}\n\n"), "other hosts' answers are not masked");
    // Compression is the guest's business there.
    let (reply, _) = rig.guest.get(host, "/gzip", &[]);
    assert_eq!((reply.status, reply.head.header("content-encoding")), (200, Some("gzip")));
    rig.finish();

    // [net] allow_writes: a prefix on the host and path boundaries, nothing near it.
    let free = "free.example.com";
    let mut rig = Rig::new(sh, free);
    assert_eq!(rig.guest.post(free, "/hook", &[], "a").0.status, 404, "reached");
    assert_eq!(rig.guest.post(free, "/hook/deeper?x=1", &[], "a").0.status, 404, "reached");
    for refused in ["/hooks", "/hook/../admin", "/hook/%2e%2e/admin", "/hook%2Fx", "/other"] {
        assert_eq!(rig.guest.post(free, refused, &[], "a").0.status, 403, "{refused}");
    }
    assert_eq!(rig.reached().len(), 2);
    rig.finish();
    let mut rig = Rig::new(sh, "free.example.com.evil.com");
    assert_eq!(rig.guest.post("free.example.com.evil.com", "/hook", &[], "a").0.status, 403, "another host is not the prefix's");
    rig.finish();
}

/// Hosts of the box's sites: the site's policy rules, its credentials replace the guest's, and
/// answers are masked as they stream.
fn site_hosts(sh: &Arc<Shared>, yes: bool) {
    let host = "app.example.com";
    let mut rig = Rig::new(sh, host);

    // The credential is the site's whatever the guest sent, once, and the answer is masked.
    let (reply, body) = rig.guest.get(host, "/echo?api_key=hunter2", &[("Authorization", "Bearer guests-own"), ("authorization", "Basic Zm9v"), ("X-Client", "mine"), ("Accept-Encoding", "gzip, br")]);
    assert_eq!(reply.status, 200);
    assert_eq!(body, format!("token is {MASK} ok"));
    assert_eq!(reply.head.header("content-length"), None, "masking changes the length");
    assert_eq!(reply.head.header("transfer-encoding"), Some("chunked"));
    assert_eq!(reply.head.header("etag"), Some("\"x\""), "other headers pass");
    let seen = rig.reached()[0].clone();
    assert_eq!(seen.count("authorization"), 1);
    assert_eq!((seen.header("authorization"), seen.header("x-client"), seen.header("accept-encoding")), (Some(format!("Bearer {SECRET}").as_str()), Some("cred"), Some("identity")));
    assert_eq!(seen.count("x-client"), 1);

    // A value cut across two chunks is still found.
    let (_, body) = rig.guest.get(host, "/split", &[]);
    assert_eq!(body, format!("token is {MASK} ok"));
    // Events arrive one by one, before the site is done; the secret cut across chunks is masked.
    rig.guest.send(&request("GET", "/sse", host, &[], None));
    rig.guest.head();
    assert_eq!(rig.guest.chunk(), b"event: ping\ndata: 1\n\n", "the first event isn't held back");
    rig.release.send(()).unwrap();
    let mut rest = Vec::new();
    loop {
        let chunk = rig.guest.chunk();
        if chunk.is_empty() {
            break;
        }
        rest.extend(chunk);
    }
    assert_eq!(String::from_utf8(rest).unwrap(), format!("data: {MASK}\n\n"));

    // Writes follow the site's policy; a chunked body with Expect arrives whole, and the
    // answer's body is read once the request is done.
    rig.guest.send("POST /submit HTTP/1.1\r\nHost: app.example.com\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\nAuthorization: Bearer guests-own\r\n\r\n");
    assert_eq!(rig.guest.head().status, 100);
    rig.guest.send("6\r\nhello \r\n5\r\nworld\r\n0\r\n\r\n");
    let reply = rig.guest.head();
    assert_eq!((reply.status, rig.guest.body(&reply).as_str()), (200, "got hello world"));
    let seen = rig.reached().last().unwrap().clone();
    assert_eq!(seen.body, b"hello world");
    assert_eq!((seen.header("transfer-encoding"), seen.header("expect"), seen.header("authorization")), (Some("chunked"), None, Some(format!("Bearer {SECRET}").as_str())));
    // A body with a length, and a HEAD, go through the same connection.
    let (reply, body) = rig.guest.post(host, "/submit", &[], "x".repeat(40_000).as_str());
    assert_eq!((reply.status, body.len()), (200, 4 + 40_000));
    assert_eq!(rig.reached().last().unwrap().header("content-length"), Some("40000"));
    rig.guest.send(&request("HEAD", "/plain", host, &[], None));
    let reply = rig.guest.head();
    assert_eq!((reply.status, reply.head.header("content-length")), (200, Some("10")));
    assert_eq!(rig.guest.get(host, "/plain", &[]).1, "plain page");

    // A compressed answer can't be masked, so it isn't passed on.
    let (reply, body) = rig.guest.get(host, "/gzip", &[]);
    assert_eq!(reply.status, 502);
    assert!(body.contains("can't mask"), "{body}");
    assert!(rig.guest.closed());
    rig.finish();

    // An answer that ends with the connection is masked and ends the guest's connection too.
    let mut rig = Rig::new(sh, host);
    rig.guest.send(&request("GET", "/close", host, &[], None));
    let reply = rig.guest.head();
    assert_eq!(reply.head.header("connection"), Some("close"));
    assert_eq!(rig.guest.body(&reply), format!("closing {MASK}"));
    let (up, down) = rig.finish();
    assert_eq!((up, down), (0, format!("closing {SECRET}").len() as u64));

    // A guest that speaks HTTP/1.0 can't take chunks: the masked answer ends with the connection.
    let mut rig = Rig::new(sh, host);
    rig.guest.send("GET /echo HTTP/1.0\r\nHost: app.example.com\r\n\r\n");
    let reply = rig.guest.head();
    assert_eq!((reply.head.header("transfer-encoding"), reply.head.header("connection")), (None, Some("close")));
    assert_eq!(rig.guest.body(&reply), format!("token is {MASK} ok"));
    rig.finish();

    // Nothing the door sent back anywhere holds the secret.
    let mut rig = Rig::new(sh, host);
    rig.guest.get(host, "/echo", &[]);
    rig.guest.get(host, "/split", &[]);
    assert!(!String::from_utf8_lossy(&rig.guest.seen).contains(SECRET));
    rig.finish();

    // A read-only site refuses writes in its own words; reads carry its credential.
    let ro = "ro.example.com";
    let mut rig = Rig::new(sh, ro);
    let (reply, body) = rig.guest.post(ro, "/submit", &[], "x");
    assert_eq!(reply.status, 403);
    assert!(body.contains("the policy for readonly doesn't allow POST") && !body.contains("allow_writes"), "{body}");
    assert!(rig.reached().is_empty());
    rig.guest.get(ro, "/plain", &[]);
    assert_eq!(rig.reached()[0].header("authorization"), Some(format!("Bearer {SECRET}").as_str()));
    rig.finish();

    // A site whose policy asks: Touch ID's answer decides.
    let ask = "ask.example.com";
    let mut rig = Rig::new(sh, ask);
    let (reply, body) = rig.guest.post(ask, "/submit?id=1", &[], "data");
    if yes {
        assert_eq!((reply.status, body.as_str()), (200, "got data"));
        assert_eq!(rig.reached().len(), 1);
    } else {
        assert_eq!(reply.status, 403);
        assert!(body.contains("wasn't approved"), "{body}");
        assert!(rig.reached().is_empty());
        assert_eq!(rig.guest.get(ask, "/plain", &[]).0.status, 200, "the connection goes on");
    }
    rig.finish();
    let answers = approve::take_answers();
    assert_eq!(answers, [yes], "one prompt for the one write, none for reads");

    // A site whose policy isn't approved gets no credentials, and its writes follow [net].
    let pending = "pending.example.com";
    let mut rig = Rig::new(sh, pending);
    rig.guest.get(pending, "/plain", &[("Authorization", "Bearer guests-own")]);
    let seen = rig.reached()[0].clone();
    assert_eq!((seen.header("authorization"), seen.header("x-client")), (Some("Bearer guests-own"), None));
    assert_eq!(rig.guest.post(pending, "/submit", &[], "x").0.status, 403);
    let (_, body) = rig.guest.get(pending, "/echo", &[]);
    assert!(body.contains(SECRET), "nothing is masked for it: the agent's own values are its own");
    rig.finish();
    assert!(approve::take_answers().is_empty());

    // A site approved a moment ago and revoked since covers nothing (policies are read per request).
    policy::revoke("readonly");
    let mut rig = Rig::new(sh, ro);
    rig.guest.get(ro, "/plain", &[]);
    assert_eq!(rig.reached()[0].header("authorization"), None);
    rig.finish();
}

/// `[net] writes = "ask"` on a host no site covers.
fn net_asks(sh: &Arc<Shared>, yes: bool) {
    approve::take_answers();
    let host = "web.example.com";
    let mut rig = Rig::new(sh, host);
    let (reply, body) = rig.guest.post(host, "/submit?token=sekrit&q=1", &[], "data");
    assert_eq!(reply.status, if yes { 200 } else { 403 }, "{body}");
    assert_eq!(rig.reached().len(), usize::from(yes));
    assert_eq!(rig.guest.get(host, "/plain", &[]).0.status, 200);
    rig.finish();
    assert_eq!(approve::take_answers(), [yes]);
}

/// `[net] writes = "allow"`: everything passes, and the log says so.
fn net_allows(sh: &Arc<Shared>) {
    let host = "web.example.com";
    let mut rig = Rig::new(sh, host);
    assert_eq!(rig.guest.post(host, "/submit", &[], "data").1, "got data");
    rig.guest.send(&request("DELETE", "/x", host, &[], None));
    assert_eq!(rig.guest.head().status, 404);
    // A WebSocket can't be carried, even where writes are allowed.
    let (reply, body) = rig.guest.get(host, "/socket", &[("Connection", "Upgrade"), ("Upgrade", "websocket")]);
    assert_eq!(reply.status, 501, "{body}");
    let (up, down) = rig.finish();
    assert_eq!((up, down), (4, 8));
    assert!(approve::take_answers().is_empty());
}

/// One line per request, chained, with the URL masked; an edit or a deletion shows.
fn the_log_chains_check(dir: &Path, name: &str, lines: usize) {
    let chain = Chain::new(&dir.join(format!("{name}.log")), LOG_KEY);
    let found = chain.verify().unwrap();
    assert_eq!(found.unchained, 0);
    assert_eq!(found.chained, lines);
}

fn the_log_chains(dir: &Path, yes: bool) {
    the_log_chains_check(dir, "deny", fs::read_to_string(dir.join("deny.log")).unwrap().lines().count());
    let text = fs::read_to_string(dir.join("deny.log")).unwrap();
    assert!(!text.contains(SECRET) && !text.contains("guests-own") && !text.to_lowercase().contains("authorization"), "{text}");
    let lines = log_lines(dir, "deny");
    let find = |method: &str, decision: &str, host: &str| {
        lines.iter().find(|l| l["method"] == method && l["decision"] == decision && l["host"] == host).unwrap_or_else(|| panic!("no {method} {decision} {host} in {text}"))
    };
    let read = find("GET", "allowed", "web.example.com");
    assert_eq!(read["kind"], "request");
    assert_eq!(read["status"], 200);
    assert_eq!(read["url"], format!("https://web.example.com/plain?token={MASK}"), "the query's token is masked");
    assert!(read["time"].is_string());
    let refused = find("POST", "blocked:writes", "web.example.com");
    assert_eq!((refused["status"].clone(), refused["url"].clone()), (json!(403), json!("https://web.example.com/submit")));
    assert_eq!(find("GET", "blocked:host-mismatch", "web.example.com")["status"], 421);
    assert_eq!(find("POST", "blocked:writes", "pending.example.com")["status"], 403, "an unapproved site's writes follow [net]");
    assert_eq!(find("POST", "blocked:writes", "ro.example.com")["status"], 403);
    assert_eq!(find("GET", "blocked:encoded", "app.example.com")["status"], 502);
    assert_eq!(find("GET", "allowed", "app.example.com")["url"], format!("https://app.example.com/echo?api_key={MASK}"), "a key in a query is masked");
    assert!(lines.iter().any(|l| l["host"] == "app.example.com" && l["method"] == "POST" && l["up"] == 11 && l["down"] == 15), "bytes up and down are the request's own");
    assert_eq!(find("POST", if yes { "asked:yes" } else { "asked:no" }, "ask.example.com")["method"], "POST");
    assert!(lines.iter().any(|l| l["host"] == "free.example.com" && l["decision"] == "allowed" && l["method"] == "POST"));
    assert_eq!(find("GET", "blocked:writes", "web.example.com")["url"], "https://web.example.com/plain", "an upgrade is refused as a write");
    the_log_chains_check(dir, "ask", 2);
    the_log_chains_check(dir, "allow", 3);

    // Changing a line shows, wherever it is; so does taking one out of the middle.
    let path = dir.join("deny.log");
    let original = fs::read_to_string(&path).unwrap();
    let chain = Chain::new(&path, LOG_KEY);
    let mut edited: Vec<String> = original.lines().map(str::to_string).collect();
    let target = edited.iter().position(|l| l.contains("blocked:writes")).unwrap();
    edited[target] = edited[target].replace("blocked:writes", "allowed");
    fs::write(&path, edited.join("\n") + "\n").unwrap();
    let e = chain.verify().unwrap_err().to_string();
    assert!(e.contains(&format!("line {}", target + 1)), "{e}");

    let mut missing: Vec<&str> = original.lines().collect();
    let middle = missing.len() / 2;
    missing.remove(middle);
    fs::write(&path, missing.join("\n") + "\n").unwrap();
    let e = chain.verify().unwrap_err().to_string();
    assert!(e.contains(&format!("line {}", middle + 1)), "{e}");
    fs::write(&path, &original).unwrap();
    chain.verify().unwrap();
    assert!(Chain::new(&path, [1; 32]).verify().is_err(), "only the box's key verifies it");
}

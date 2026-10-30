//! The door against a fake guest: a Unix socket standing in for the one the shim publishes,
//! which hands the door's pool connections a kind line and then speaks the protocol.
//!
//! Policies, approvals and keys live in files (the debug-only fake Keychain), set up through
//! environment variables, so the scenario runs in a copy of this test binary started with its
//! own environment rather than changing the one the other tests share.

use std::cell::RefCell;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::addr::Net;
use super::http::{self, Head};
use super::{Config, Door};
use crate::util::TempDir;
use crate::{approve, keychain, policy};

const REAL_KEY: &str = "sk-ant-REAL-0123456789abcdef";
const PUBLIC_IP: &str = "93.184.216.34";
const WAIT: Duration = Duration::from_secs(10);
const LOG_KEY: [u8; 32] = [7; 32];

// --- the scenario's environment ---

const SCENARIO: &str = "door::tests::a_fake_guest_uses_all_three_kinds_of_connection";

#[test]
fn a_fake_guest_uses_all_three_kinds_of_connection() {
    if std::env::var_os("CRED_DOOR_CHILD").is_none() {
        return rerun_with_private_environment();
    }
    scenario(Path::new(&std::env::var("CRED_DOOR_DIR").unwrap()));
}

fn rerun_with_private_environment() {
    let dir = TempDir::new("cred-door").unwrap();
    for sub in ["keychain", "policy", "home"] {
        fs::create_dir(dir.0.join(sub)).unwrap();
    }
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", SCENARIO, "--nocapture", "--test-threads=1"])
        .env("CRED_DOOR_CHILD", "1")
        .env("CRED_DOOR_DIR", &dir.0)
        .env("HOME", dir.0.join("home"))
        .env("CRED_INDEX", dir.0.join("index.json"))
        .env("CRED_POLICY_DIR", dir.0.join("policy"))
        .env("CRED_TEST_KEYCHAIN", dir.0.join("keychain"))
        .env("CRED_TEST_APPROVE", "yes")
        .env("CRED_AUDIT", dir.0.join("audit.log"))
        .env("CRED_AUDIT_KEY", "test-key");
    for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"] {
        cmd.env_remove(var);
    }
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "scenario failed:\n{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
}

// --- a fake model host and site ---

/// What the fake host saw of a request.
struct Seen {
    line: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

struct Upstream {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Seen>>>,
    /// The stream route waits for this before its second event.
    release: Sender<()>,
}

/// An HTTP server on localhost. `POST /v1/messages?stream` answers with two server-sent events,
/// the second only after `release`; `POST /v1/messages` with a JSON body; `GET /notes` with text.
fn fake_upstream() -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (release, released) = mpsc::channel();
    let released = Arc::new(Mutex::new(released));
    let record = seen.clone();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (record, released) = (record.clone(), released.clone());
            thread::spawn(move || upstream_connection(stream, record, released));
        }
    });
    Upstream { addr, seen, release }
}

fn upstream_connection(stream: TcpStream, record: Arc<Mutex<Vec<Seen>>>, released: Arc<Mutex<Receiver<()>>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut out = stream;
    while let Ok(Some(head)) = http::read_head(&mut reader) {
        let body = http::read_body(&mut reader, &head, 1 << 20).unwrap();
        let target = head.parts().unwrap().1.to_string();
        record.lock().unwrap().push(Seen { line: head.line.clone(), headers: head.headers.clone(), body });
        if target.starts_with("/v1/messages?stream") {
            write!(out, "HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\nrequest-id: req_1\r\n\r\n").unwrap();
            for (i, event) in ["event: ping\ndata: 1\n\n", "event: done\ndata: 2\n\n"].iter().enumerate() {
                if i == 1 {
                    released.lock().unwrap().recv_timeout(WAIT).unwrap();
                }
                write!(out, "{:x}\r\n{event}\r\n", event.len()).unwrap();
                out.flush().unwrap();
            }
            write!(out, "0\r\n\r\n").unwrap();
        } else if target.starts_with("/v1/messages") {
            let body = json!({ "type": "message", "content": "hi" }).to_string();
            write!(out, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}", body.len()).unwrap();
        } else if target == "/notes" {
            write!(out, "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 10\r\n\r\nnote data!").unwrap();
        } else {
            write!(out, "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n").unwrap();
        }
        out.flush().unwrap();
    }
}

// --- a fake guest ---

/// The listener the guest's shim would hold. `accept` is what the shim does with a request: take
/// one of the connections the door dialed in.
struct Guest {
    listener: UnixListener,
    /// Connections accepted and not yet used.
    idle: RefCell<Vec<UnixStream>>,
}

impl Guest {
    fn new(path: &Path) -> Self {
        let listener = UnixListener::bind(path).unwrap();
        listener.set_nonblocking(true).unwrap();
        Self { listener, idle: RefCell::new(Vec::new()) }
    }

    fn try_accept(&self, wait: Duration) -> Option<UnixStream> {
        let end = Instant::now() + wait;
        while Instant::now() < end {
            if let Ok((stream, _)) = self.listener.accept() {
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(WAIT)).unwrap();
                return Some(stream);
            }
            thread::sleep(Duration::from_millis(10));
        }
        None
    }

    fn accept(&self) -> UnixStream {
        self.try_accept(WAIT).expect("the door dialed no connection")
    }

    /// Take a connection and say what it is for.
    fn connection(&self, kind: &str) -> Conn {
        let idle = self.idle.borrow_mut().pop();
        let mut stream = idle.unwrap_or_else(|| self.accept());
        stream.write_all(format!("{kind}\n").as_bytes()).unwrap();
        Conn { reader: BufReader::new(stream.try_clone().unwrap()), stream, seen: Vec::new() }
    }
}

struct Conn {
    reader: BufReader<UnixStream>,
    stream: UnixStream,
    /// Everything the door sent back, for checks that something never appears in it.
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
        let status = head.line.split(' ').nth(1).unwrap().parse().unwrap();
        Reply { status, head }
    }

    /// One chunk of a chunked body; empty for the last.
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

    fn body(&mut self, reply: &Reply) -> Vec<u8> {
        if reply.head.header("transfer-encoding") == Some("chunked") {
            let mut all = Vec::new();
            loop {
                let chunk = self.chunk();
                if chunk.is_empty() {
                    return all;
                }
                all.extend(chunk);
            }
        }
        let len: usize = reply.head.header("content-length").map_or(0, |l| l.parse().unwrap());
        let mut body = vec![0; len];
        self.reader.read_exact(&mut body).unwrap();
        self.seen.extend_from_slice(&body);
        body
    }

    /// The connection ends within `WAIT`.
    fn closed(&mut self) -> bool {
        let mut byte = [0u8; 1];
        matches!(self.reader.read(&mut byte), Ok(0) | Err(_))
    }
}

fn post(path: &str, headers: &[(&str, &str)], body: &str) -> String {
    let headers: String = headers.iter().map(|(n, v)| format!("{n}: {v}\r\n")).collect();
    format!("POST {path} HTTP/1.1\r\nHost: cred.internal\r\n{headers}Content-Length: {}\r\n\r\n{body}", body.len())
}

// --- the scenario ---

fn write_policy(res: &str, toml: &str) {
    fs::write(policy::path(res), toml).unwrap();
}

fn scenario(dir: &Path) {
    let upstream = fake_upstream();
    let base = format!("http://{}", upstream.addr);
    write_policy(
        "anthropic",
        &format!("[fetch]\nhosts = [\"{base}\"]\nwrites = \"allow\"\nauth = \"{{key}}\"\nauth_header = \"x-api-key\"\nheaders = {{ anthropic-version = \"2023-06-01\" }}\n"),
    );
    write_policy("readonly", &format!("[fetch]\nhosts = [\"{base}\"]\nauth = \"Bearer {{key}}\"\n"));
    write_policy("notes", &format!("[fetch]\nhosts = [\"{base}\"]\n"));
    write_policy("other", &format!("[fetch]\nhosts = [\"{base}\"]\n"));
    keychain::set("anthropic", "key", REAL_KEY).unwrap();
    keychain::set("readonly", "key", REAL_KEY).unwrap();
    policy::approve(&["anthropic".into(), "readonly".into(), "notes".into(), "other".into()]).unwrap();
    approve::take_answers();

    assert!(!super::model_uses_bearer("anthropic").unwrap());
    assert!(super::model_uses_bearer("no-such-resource").is_err());
    write_policy("subscription", &format!("[fetch]\nhosts = [\"{base}\"]\nwrites = \"allow\"\nauth = \"Bearer {{token}}\"\n"));
    policy::approve(&["subscription".into()]).unwrap();
    assert!(super::model_uses_bearer("subscription").unwrap());
    approve::take_answers();

    // Names resolve to a public address, except one that points at this machine; whatever
    // is dialed lands on a local server that echoes.
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_addr = target.local_addr().unwrap();
    let dialed = Arc::new(Mutex::new(Vec::<SocketAddr>::new()));
    let log_dials = dialed.clone();
    let net = Net::new(
        Box::new(|host| {
            Ok(match host {
                "rebind.example.com" => vec!["127.0.0.1".parse().unwrap(), "10.0.0.1".parse().unwrap()],
                _ => vec!["10.9.9.9".parse().unwrap(), PUBLIC_IP.parse().unwrap()],
            })
        }),
        Box::new(move |addr| {
            log_dials.lock().unwrap().push(addr);
            TcpStream::connect(target_addr)
        }),
    );
    thread::spawn(move || {
        for mut stream in target.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 64];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 || stream.write_all(&buf[..n].to_ascii_uppercase()).is_err() {
                        break;
                    }
                }
            });
        }
    });

    let socket = dir.join("door.sock");
    let guest = Guest::new(&socket);
    let log_path = dir.join("box-log").join("door.log");
    let door = Door::start_with(
        Config {
            name: "testbox".into(),
            socket: socket.clone(),
            allow: vec!["https://allowed.example.com".into(), "https://*.wiki.example.org".into(), "https://rebind.example.com".into()],
            model: Some("anthropic".into()),
            sites: vec!["notes".into()],
            net: Default::default(),
            log: log_path.clone(),
            ca: None,
            log_key: LOG_KEY,
            browser_socket: None,
            browser_tokens: Default::default(),
            browser: None,
        },
        net,
    )
    .unwrap();

    // The pool: eight idle connections, and a new one as soon as one is taken.
    let pool: Vec<UnixStream> = (0..8).map(|_| guest.accept()).collect();
    assert!(guest.try_accept(Duration::from_millis(600)).is_none(), "the pool should stop at eight");
    guest.idle.borrow_mut().extend(pool);
    let mut conn = guest.connection("proxy");
    let replacement = guest.try_accept(WAIT).expect("a taken connection should be replaced");
    guest.idle.borrow_mut().push(replacement);

    proxy(&mut conn, &guest, &dialed);
    gateway(&guest, &upstream);
    mcp(&guest, &upstream, dir);
    model_refusals(dir);

    // The log: one JSON line per decision, with no values and no headers.
    drop(conn);
    thread::sleep(Duration::from_millis(300));
    let log = fs::read_to_string(&log_path).unwrap();
    assert!(!log.contains(REAL_KEY) && !log.contains("cred-managed") && !log.to_lowercase().contains("authorization"), "{log}");
    let lines: Vec<Value> = log.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    let find = |kind: &str, decision: &str| lines.iter().find(|l| l["kind"] == kind && l["decision"] == decision).unwrap_or_else(|| panic!("no {kind} {decision} in {log}"));
    assert!(find("proxy", "allowed")["time"].is_string());
    assert_eq!(find("proxy", "allowed")["host"], "allowed.example.com");
    assert_eq!(find("proxy", "allowed")["addr"], PUBLIC_IP);
    let closed = find("proxy", "closed");
    assert!(closed["up"].as_u64().unwrap() >= 5 && closed["down"].as_u64().unwrap() >= 5, "{closed}");
    assert_eq!(find("proxy", "blocked:policy")["host"], "other.example.com");
    assert_eq!(find("proxy", "blocked:port")["host"], "allowed.example.com");
    assert_eq!(find("proxy", "blocked:not-connect")["method"], "GET");
    assert_eq!(find("proxy", "blocked:not-public")["host"], "rebind.example.com");
    assert_eq!(find("model", "allowed")["path"], "/model/v1/messages");
    assert_eq!(find("model", "blocked:no-standin")["status"], 401);
    assert_eq!(find("mcp", "opened")["kind"], "mcp");
    assert!(find("mcp", "closed")["down"].as_u64().unwrap() > 0);

    // Stopping ends every connection, idle ones included.
    let mut idle = guest.idle.take();
    while let Some(stream) = guest.try_accept(Duration::from_millis(300)) {
        idle.push(stream);
    }
    assert_eq!(idle.len(), 8, "the pool should be full again");
    door.stop();
    for stream in &mut idle {
        // macOS refuses setsockopt on a socket whose peer has already hung up.
        let _ = stream.set_read_timeout(Some(WAIT));
        let mut byte = [0u8; 1];
        assert!(matches!(stream.read(&mut byte), Ok(0) | Err(_)), "an idle connection stayed open after stop");
    }
}

fn proxy(conn: &mut Conn, guest: &Guest, dialed: &Arc<Mutex<Vec<SocketAddr>>>) {
    conn.send("CONNECT allowed.example.com:443 HTTP/1.1\r\nHost: allowed.example.com:443\r\n\r\n");
    let reply = conn.head();
    assert_eq!(reply.status, 200, "{}", reply.head.line);
    // The door connected to the vetted public address, not the private one the name also had.
    assert_eq!(*dialed.lock().unwrap(), vec![SocketAddr::new(PUBLIC_IP.parse::<IpAddr>().unwrap(), 443)]);
    conn.send("hello");
    let mut echoed = [0u8; 5];
    conn.reader.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"HELLO");
    conn.send("again");
    conn.reader.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"AGAIN");
    conn.stream.shutdown(Shutdown::Write).unwrap();
    assert!(conn.closed(), "the tunnel should end when the guest closes its side");

    let refuse = |request: &str, status: u16| {
        let mut c = guest.connection("proxy");
        c.send(request);
        let reply = c.head();
        assert_eq!(reply.status, status, "{request:?} got {}", reply.head.line);
        assert!(c.closed());
        reply
    };
    refuse("CONNECT other.example.com:443 HTTP/1.1\r\n\r\n", 403);
    refuse("CONNECT allowed.example.com:8443 HTTP/1.1\r\n\r\n", 403);
    refuse("CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n", 403);
    refuse("CONNECT allowed.example.com HTTP/1.1\r\n\r\n", 400);
    refuse("CONNECT rebind.example.com:443 HTTP/1.1\r\n\r\n", 403);
    assert_eq!(refuse("GET http://allowed.example.com/?token=secret HTTP/1.1\r\n\r\n", 405).head.header("allow"), Some("CONNECT"));
    refuse("not http at all\r\n\r\n", 400);
    // A pattern entry covers subdomains.
    let mut wiki = guest.connection("proxy");
    wiki.send("CONNECT en.wiki.example.org:443 HTTP/1.1\r\n\r\n");
    assert_eq!(wiki.head().status, 200);
    // Nothing but the vetted address was ever dialed, and the refused names dialed nothing.
    let dials = dialed.lock().unwrap();
    assert_eq!(dials.len(), 2, "{dials:?}");
    assert!(dials.iter().all(|d| d.ip() == PUBLIC_IP.parse::<IpAddr>().unwrap() && d.port() == 443));
}

fn gateway(guest: &Guest, upstream: &Upstream) {
    let mut conn = guest.connection("cred");
    let calls = upstream.seen.lock().unwrap().len();

    // A streamed answer arrives event by event, before the upstream has finished it.
    let stream_request = post(
        "/model/v1/messages?stream",
        &[
            ("x-api-key", "cred-managed"),
            ("anthropic-version", "1999-01-01"),
            ("accept-encoding", "gzip"),
            ("connection", "keep-alive"),
            ("content-type", "application/json"),
            ("user-agent", "claude-cli/1"),
        ],
        r#"{"stream":true}"#,
    );
    conn.send(&stream_request);
    let reply = conn.head();
    assert_eq!(reply.status, 200);
    assert_eq!(reply.head.header("transfer-encoding"), Some("chunked"));
    assert_eq!(reply.head.header("content-type"), Some("text/event-stream"));
    assert_eq!(reply.head.header("request-id"), Some("req_1"));
    assert_eq!(conn.chunk(), b"event: ping\ndata: 1\n\n");
    upstream.release.send(()).unwrap();
    assert_eq!(conn.chunk(), b"event: done\ndata: 2\n\n");
    assert!(conn.chunk().is_empty());

    {
        let seen = upstream.seen.lock().unwrap();
        let call = &seen[calls];
        assert_eq!(call.line, "POST /v1/messages?stream HTTP/1.1");
        assert_eq!(call.header("x-api-key"), Some(REAL_KEY));
        assert_eq!(call.header("anthropic-version"), Some("2023-06-01"), "the policy's fixed header wins");
        assert_eq!(call.header("user-agent"), Some("claude-cli/1"));
        assert_eq!(call.header("accept-encoding"), Some("identity"));
        assert_eq!(call.body, br#"{"stream":true}"#);
        assert!(call.headers.iter().all(|(_, v)| !v.contains("cred-managed")));
    }

    // The same connection serves more requests, and a plain answer is passed on whole.
    conn.send(&post("/model/v1/messages", &[("authorization", "Bearer cred-managed")], "{}"));
    let reply = conn.head();
    assert_eq!(reply.status, 200);
    assert_eq!(conn.body(&reply), json!({ "type": "message", "content": "hi" }).to_string().into_bytes());
    assert!(upstream.seen.lock().unwrap()[calls + 1].header("authorization").is_none());

    // Refusals are Anthropic-shaped errors, and don't reach the upstream.
    let calls = upstream.seen.lock().unwrap().len();
    for (request, status, kind) in [
        (post("/model/v1/messages", &[("x-api-key", "sk-ant-the-agents-own-guess")], "{}"), 401, "authentication_error"),
        (post("/model/v1/messages", &[], "{}"), 401, "authentication_error"),
        (post("/elsewhere", &[("x-api-key", "cred-managed")], "{}"), 404, "not_found_error"),
        ("GET /model HTTP/1.1\r\nx-api-key: cred-managed\r\n\r\n".to_string(), 404, "not_found_error"),
    ] {
        conn.send(&request);
        let reply = conn.head();
        assert_eq!(reply.status, status, "{request}");
        let body: Value = serde_json::from_slice(&conn.body(&reply)).unwrap();
        assert_eq!(body["error"]["type"], kind);
        assert!(body["error"]["message"].is_string());
    }
    assert_eq!(upstream.seen.lock().unwrap().len(), calls);

    // A chunked request body, as some HTTP clients send.
    conn.send("POST /model/v1/messages HTTP/1.1\r\nx-api-key: cred-managed\r\ntransfer-encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n");
    let reply = conn.head();
    assert_eq!(reply.status, 200);
    conn.body(&reply);
    assert_eq!(upstream.seen.lock().unwrap().last().unwrap().body, b"abcde");

    // Connection: close ends the connection after the answer.
    conn.send(&post("/model/v1/messages", &[("x-api-key", "cred-managed"), ("connection", "close")], "{}"));
    let reply = conn.head();
    assert_eq!(reply.head.header("connection"), Some("close"));
    conn.body(&reply);
    assert!(conn.closed());

    let everything = String::from_utf8_lossy(&conn.seen);
    assert!(!everything.contains(REAL_KEY), "the real key reached the guest");
}

/// A model call through a door whose model resource doesn't allow writes, and through one with no model.
fn model_refusals(dir: &Path) {
    for (model, status, expect) in [(Some("readonly"), 403, "writes = \"allow\""), (None, 404, "no model")] {
        let socket = dir.join("second.sock");
        let _ = fs::remove_file(&socket);
        let guest = Guest::new(&socket);
        let config = Config {
            name: "second".into(),
            socket,
            allow: vec![],
            model: model.map(String::from),
            sites: vec![],
            net: Default::default(),
            log: dir.join("second.log"),
            log_key: LOG_KEY,
            ca: None,
            browser_socket: None,
            browser_tokens: Default::default(),
            browser: None,
        };
        let door = Door::start_with(config, Net::system()).unwrap();
        let mut conn = guest.connection("cred");
        conn.send(&post("/model/v1/messages", &[("x-api-key", "cred-managed")], "{}"));
        let reply = conn.head();
        assert_eq!(reply.status, status);
        let body: Value = serde_json::from_slice(&conn.body(&reply)).unwrap();
        let message = body["error"]["message"].as_str().unwrap();
        assert!(message.contains(expect), "{message}");
        assert!(!String::from_utf8_lossy(&conn.seen).contains(REAL_KEY));
        door.stop();
    }
}

fn mcp(guest: &Guest, upstream: &Upstream, dir: &Path) {
    let mut conn = guest.connection("mcp");
    let mut call = |id: u64, method: &str, params: Value| -> Value {
        conn.send(&format!("{}\n", json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params })));
        let mut line = String::new();
        conn.reader.read_line(&mut line).unwrap();
        let reply: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(reply["id"], id);
        reply["result"].clone()
    };
    let init = call(1, "initialize", json!({ "protocolVersion": "2025-06-18" }));
    assert_eq!(init["serverInfo"]["name"], "cred");
    let tools = call(2, "tools/list", json!({}));
    let names: Vec<&str> = tools["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"fetch") && names.contains(&"sites"), "{names:?}");

    // Only the box's sites are offered, and using one needs no prompt: the run already asked.
    approve::take_answers();
    let sites = call(3, "tools/call", json!({ "name": "sites", "arguments": {} }));
    let text = sites["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("notes:") && !text.contains("other:") && !text.contains("anthropic:"), "{text}");
    let calls = upstream.seen.lock().unwrap().len();
    let fetched = call(4, "tools/call", json!({ "name": "fetch", "arguments": { "site": "notes", "method": "GET", "url": format!("http://{}/notes", upstream.addr) } }));
    assert_eq!(fetched["isError"], false, "{fetched}");
    assert!(fetched["content"][0]["text"].as_str().unwrap().contains("note data!"));
    assert_eq!(upstream.seen.lock().unwrap().len(), calls + 1);
    let outside = call(5, "tools/call", json!({ "name": "fetch", "arguments": { "site": "other", "method": "GET", "url": format!("http://{}/notes", upstream.addr) } }));
    assert_eq!(outside["isError"], true);
    assert!(outside["content"][0]["text"].as_str().unwrap().contains("unknown site"), "{outside}");
    assert_eq!(upstream.seen.lock().unwrap().len(), calls + 1);
    assert!(approve::take_answers().is_empty(), "a box's sites need no prompt of their own");

    // Audit entries are written, tagged with the box.
    let audit = fs::read_to_string(dir.join("audit.log")).unwrap();
    let entries: Vec<Value> = audit.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert!(entries.len() >= 3 && entries.iter().all(|e| e["box"] == "testbox"), "{audit}");
    assert!(entries.iter().any(|e| e["tool"] == "fetch" && e["site"] == "notes" && e["decision"] == "allowed"));
    conn.stream.shutdown(Shutdown::Both).unwrap();
}

/// Run a real door against a socket published by a VM, for checking by hand:
/// `CRED_DOOR_LIVE=/tmp/cred-501/x.sock CRED_DOOR_ALLOW=https://example.com,... cargo test live_door -- --ignored`
/// then use the box (e.g. curl through the proxy) for CRED_DOOR_SECONDS (default 60).
#[test]
#[ignore = "needs a VM publishing a door socket: CRED_DOOR_LIVE=<socket>"]
fn live_door() {
    let Some(socket) = std::env::var_os("CRED_DOOR_LIVE") else { return };
    let allow = std::env::var("CRED_DOOR_ALLOW").unwrap_or_default().split(',').filter(|s| !s.is_empty()).map(String::from).collect();
    let seconds = std::env::var("CRED_DOOR_SECONDS").ok().and_then(|s| s.parse().ok()).unwrap_or(60);
    let log = std::env::temp_dir().join(format!("cred-door-live-{}.log", std::process::id()));
    let door = Door::start(Config {
        name: "live".into(),
        socket: socket.into(),
        allow,
        model: None,
        sites: vec![],
        net: Default::default(),
        log: log.clone(),
        log_key: LOG_KEY,
        ca: None,
        browser_socket: None,
        browser_tokens: Default::default(),
        browser: None,
    })
    .unwrap();
    eprintln!("door log: {}", log.display());
    thread::sleep(Duration::from_secs(seconds));
    door.stop();
}

#[test]
fn bad_allow_patterns_stop_the_door_from_starting() {
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = TempDir::new(&format!("cred-door-bad{}", N.fetch_add(1, Ordering::Relaxed))).unwrap();
    let cfg = Config {
        name: "x".into(),
        socket: dir.0.join("s"),
        allow: vec!["example.com".into()],
        model: None,
        sites: vec![],
        net: Default::default(),
        log: dir.0.join("log"),
        ca: None,
        log_key: LOG_KEY,
        browser_socket: None,
        browser_tokens: Default::default(),
        browser: None,
    };
    let err = Door::start(cfg).err().expect("should fail");
    assert!(format!("{err:#}").contains("example.com"), "{err:#}");
}

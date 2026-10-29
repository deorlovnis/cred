//! The door ending TLS, against a fake guest and a fake site that both speak real TLS.
//!
//! The guest trusts only the box CA (as the tools in the VM do), and the site has a certificate
//! from a test CA of its own that the door is told to trust instead of the web's roots (a
//! test-only setting: `Net::trusting` does not exist in other builds). Nothing here needs
//! the network, the Keychain or a VM.

use std::io::{BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, ServerConnection, StreamOwned};
use serde_json::Value;

use super::addr::Net;
use super::http;
use super::tls::{BoxCa, client_config_trusting, trust_only};
use super::{Config, Door};
use crate::util::TempDir;

const WAIT: Duration = Duration::from_secs(10);

/// What the fake site saw: request line, and body.
type Seen = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

/// An HTTPS site on localhost with a certificate for `name` from `signer`. `GET /hello` answers
/// `hello`, `GET /big` a megabyte of `b`, `POST /echo` its body.
fn site(signer: &BoxCa, name: &str) -> (SocketAddr, Seen) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let config = signer.server_config(name).unwrap();
    let seen = Seen::default();
    let record = seen.clone();
    thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let (config, record) = (config.clone(), record.clone());
            thread::spawn(move || {
                let tls = StreamOwned::new(ServerConnection::new(config).unwrap(), tcp);
                let mut reader = BufReader::new(tls);
                while let Ok(Some(head)) = http::read_head(&mut reader) {
                    let Ok(body) = http::read_body(&mut reader, &head, 1 << 20) else { return };
                    record.lock().unwrap().push((head.line.clone(), body.clone()));
                    let answer = match head.parts().map(|(m, t, _)| (m, t)) {
                        Some(("GET", "/hello")) => b"hello".to_vec(),
                        Some(("GET", "/big")) => vec![b'b'; 1 << 20],
                        Some(("POST", "/echo")) => body,
                        _ => b"?".to_vec(),
                    };
                    let out = reader.get_mut();
                    if write!(out, "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", answer.len()).is_err() || out.write_all(&answer).is_err() || out.flush().is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, seen)
}

/// The guest's side of the stream after CONNECT: what is left in the reader, and the socket.
struct Duplex {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Read for Duplex {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

impl Write for Duplex {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

type Guest = StreamOwned<ClientConnection, Duplex>;

/// The listener the guest's shim would hold; the door dials the connections it hands out.
struct Shim(UnixListener);

impl Shim {
    /// Take a connection, ask for the proxy and CONNECT to `target`. The status of the answer,
    /// its reason phrase, and the connection.
    fn connect(&self, target: &str) -> (u16, String, Duplex) {
        let end = Instant::now() + WAIT;
        let stream = loop {
            match self.0.accept() {
                Ok((stream, _)) => break stream,
                Err(_) if Instant::now() < end => thread::sleep(Duration::from_millis(10)),
                Err(e) => panic!("the door dialed no connection: {e}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut writer = stream;
        write!(writer, "proxy\nCONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").unwrap();
        let head = http::read_head(&mut reader).unwrap().expect("an answer");
        let status = head.line.split(' ').nth(1).unwrap().parse().unwrap();
        let reason = head.line.splitn(3, ' ').nth(2).unwrap_or("").to_string();
        (status, reason, Duplex { reader, writer })
    }
}

/// A TLS client like the tools in the VM: only `trusting` is a root, `alpn` is offered.
fn client(trusting: &BoxCa, alpn: &[&[u8]], host: &str, io: Duplex) -> Guest {
    let mut config = (*client_config_trusting(trust_only(&trusting.cert_pem()))).clone();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let name = ServerName::try_from(host.to_string()).unwrap();
    StreamOwned::new(ClientConnection::new(Arc::new(config), name).unwrap(), io)
}

/// One request and its whole answer, on a connection that stays open.
fn request(tls: &mut Guest, line: &str, body: &str) -> (String, Vec<u8>) {
    write!(tls, "{line}\r\nHost: site\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    tls.flush().unwrap();
    let mut reader = BufReader::new(&mut *tls);
    let head = http::read_head(&mut reader).unwrap().expect("an answer");
    let len: usize = head.header("content-length").unwrap().parse().unwrap();
    let mut answer = vec![0; len];
    reader.read_exact(&mut answer).unwrap();
    (head.line, answer)
}

fn log_lines(path: &std::path::Path) -> Vec<Value> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    text.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn wait_for<T>(mut found: impl FnMut() -> Option<T>) -> T {
    let end = Instant::now() + WAIT;
    loop {
        if let Some(value) = found() {
            return value;
        }
        assert!(Instant::now() < end, "timed out");
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn the_door_ends_tls_for_a_guest_that_trusts_only_the_box_ca() {
    let dir = TempDir::new("cred-tls-door").unwrap();
    let box_ca = Arc::new(BoxCa::generate("testbox").unwrap());
    let sites = BoxCa::generate("sites").unwrap();
    let rogue = BoxCa::generate("rogue").unwrap();

    // Three sites. The door reaches them through addresses it believes are public.
    let (good, good_seen) = site(&sites, "good.example.com");
    let (wrong_name, _) = site(&sites, "other.example.com");
    let (untrusted, _) = site(&rogue, "rogue.example.com");
    let public = |last: u8| IpAddr::from([93, 184, 216, last]);
    let routes = [(public(34), good), (public(35), wrong_name), (public(36), untrusted)];
    let net = Net::new(
        Box::new(move |host| Ok(vec![match host {
            "good.example.com" => public(34),
            "wrongname.example.com" => public(35),
            _ => public(36),
        }])),
        Box::new(move |addr| TcpStream::connect(routes.iter().find(|(ip, _)| *ip == addr.ip()).unwrap().1)),
    )
    .trusting(trust_only(&sites.cert_pem()));

    let socket = dir.0.join("door.sock");
    let shim = Shim(UnixListener::bind(&socket).unwrap());
    shim.0.set_nonblocking(true).unwrap();
    let log = dir.0.join("log").join("door.log");
    let door = Door::start_with(
        Config { name: "testbox".into(), socket, allow: vec!["*".into()], model: None, sites: vec![], log: log.clone(), ca: Some(box_ca.clone()) },
        net,
    )
    .unwrap();

    // The guest trusts the box CA and nothing else. It reads and writes through the door, on
    // one connection, and a megabyte comes back whole.
    let (status, _, io) = shim.connect("good.example.com:443");
    assert_eq!(status, 200);
    let mut tls = client(&box_ca, &[b"h2", b"http/1.1"], "good.example.com", io);
    assert_eq!(request(&mut tls, "GET /hello HTTP/1.1", ""), ("HTTP/1.1 200 OK".to_string(), b"hello".to_vec()));
    assert_eq!(tls.conn.alpn_protocol(), Some(&b"http/1.1"[..]));
    assert_eq!(request(&mut tls, "POST /echo HTTP/1.1", "ping").1, b"ping");
    let big = request(&mut tls, "GET /big HTTP/1.1", "").1;
    assert!(big.len() == 1 << 20 && big.iter().all(|&b| b == b'b'));
    {
        let seen = good_seen.lock().unwrap();
        let lines: Vec<&str> = seen.iter().map(|(l, _)| l.as_str()).collect();
        assert_eq!(lines, ["GET /hello HTTP/1.1", "POST /echo HTTP/1.1", "GET /big HTTP/1.1"]);
        assert_eq!(seen[1].1, b"ping");
    }
    // Closing ends the whole path and the door says how much went through.
    drop(tls);
    let closed = wait_for(|| log_lines(&log).into_iter().find(|l| l["kind"] == "proxy" && l["decision"] == "closed"));
    assert_eq!(closed["host"], "good.example.com");
    assert!(closed["up"].as_u64().unwrap() > 100 && closed["down"].as_u64().unwrap() > 1 << 20, "{closed}");

    // A site whose certificate is for another name, or from a CA nobody trusts, gets the
    // guest a 502 and no tunnel: the door's own check is as strict as any client's.
    for (target, why) in [("wrongname.example.com:443", "not valid for name"), ("rogue.example.com:443", "UnknownIssuer")] {
        let (status, reason, mut io) = shim.connect(target);
        assert_eq!(status, 502, "{target}");
        assert!(reason.starts_with("Bad Gateway: can't verify") && reason.contains(why), "{reason}");
        let mut rest = Vec::new();
        assert!(io.read_to_end(&mut rest).map(|_| rest.is_empty()).unwrap_or(true), "no tunnel after a refusal");
    }

    // A guest that doesn't trust the box CA never gets through the handshake, and the site
    // is asked for nothing.
    let requests = good_seen.lock().unwrap().len();
    let (status, _, io) = shim.connect("good.example.com:443");
    assert_eq!(status, 200);
    let mut tls = client(&rogue, &[b"http/1.1"], "good.example.com", io);
    let e = write!(tls, "GET /hello HTTP/1.1\r\n\r\n").and_then(|()| tls.flush()).and_then(|()| tls.read(&mut [0u8; 1]).map(drop)).unwrap_err();
    assert!(e.to_string().contains("UnknownIssuer"), "{e}");
    drop(tls);
    assert_eq!(good_seen.lock().unwrap().len(), requests);

    // The log has each of these, without anything from inside the requests.
    let lines = wait_for(|| Some(log_lines(&log)).filter(|l| l.iter().filter(|e| e["decision"].as_str().is_some_and(|d| d.starts_with("failed:tls"))).count() == 3));
    let failures: Vec<String> = lines.iter().filter_map(|l| l["decision"].as_str()).filter(|d| d.starts_with("failed:tls")).map(String::from).collect();
    assert!(failures.iter().any(|d| d.contains("not valid for name")), "{failures:?}");
    assert!(failures.iter().any(|d| d.contains("UnknownIssuer")), "{failures:?}");
    assert!(lines.iter().any(|l| l["host"] == "good.example.com" && l["decision"] == "allowed"));
    let text = std::fs::read_to_string(&log).unwrap();
    assert!(!text.contains("/hello") && !text.contains("ping"), "{text}");
    door.stop();
}

// --- a real VM ---

/// Run a script in the VM as the agent: (succeeded, stdout and stderr).
fn sh(vm: &str, env: &[(String, String)], script: &str) -> (bool, String) {
    let cmd = ["sh".to_string(), "-c".to_string(), script.to_string()];
    let out = crate::engine::exec_command(vm, env, &cmd, false).stdin(std::process::Stdio::null()).output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text.trim().to_string())
}

/// The VM stops when the test ends, however it ends.
struct Vm(String);

impl Drop for Vm {
    fn drop(&mut self) {
        let _ = crate::engine::stop(&self.0);
    }
}

/// The tools in a real agent VM trust the box CA, with the real door ending TLS between them
/// and the real internet (so it needs the network, and Apple's `container` with the
/// `cred-agent` image built: `container build -f box/agent.Containerfile -t cred-agent box`).
/// The door doesn't weaken verification: a site with a bad certificate is a 502.
///
///     mise run e2e-box        # includes this
#[test]
#[ignore = "needs Apple's `container`, the cred-agent image and the internet; run with `mise run e2e-box`"]
fn real_vm_tools_trust_the_door_and_only_the_door() {
    use crate::engine;
    if std::env::var_os("CRED_E2E_BOX").is_none() {
        eprintln!("CRED_E2E_BOX isn't set: skipping");
        return;
    }
    engine::available().unwrap();
    let name = format!("p2t-{}", std::process::id());
    let dir = std::path::PathBuf::from(format!("/tmp/{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let spec = engine::VmSpec {
        name: name.clone(),
        image: engine::image_digest(engine::AGENT_IMAGE).unwrap(),
        cpus: 2,
        memory: "2G".into(),
        socket: dir.join("door.sock"),
        mounts: vec![],
        docker: false,
    };
    let ca = Arc::new(BoxCa::generate("e2e").unwrap());
    let log = dir.join("log").join("door.log");
    let config = Config { name: name.clone(), socket: spec.socket.clone(), allow: vec!["*".into()], model: None, sites: vec![], log: log.clone(), ca: Some(ca.clone()) };
    let door = Door::start(config).unwrap();
    let vm = Vm(name.clone());
    engine::run(&spec).unwrap();
    engine::install_ca(&name, &ca.cert_pem()).unwrap();

    // Node 22 has to be told to use HTTPS_PROXY for fetch (Claude Code does it itself).
    let mut env = engine::agent_env(true);
    env.push(("NODE_USE_ENV_PROXY".into(), "1".into()));
    let ok = |what: &str, script: &str| {
        let (ok, out) = sh(&name, &env, script);
        println!("--- {what}\n{out}");
        assert!(ok, "{what} failed: {out}");
        out
    };
    let fails = |what: &str, script: &str| {
        let (ok, out) = sh(&name, &env, script);
        println!("--- {what} (must fail)\n{out}");
        assert!(!ok, "{what} should have failed: {out}");
        out
    };

    // The certificate the tools see is the door's, issued by this box's CA.
    let seen = ok("who issues", "curl -sv -m 60 -o /dev/null https://example.com 2>&1 | grep -i 'issuer'");
    assert!(seen.contains("cred box e2e"), "{seen}");
    ok("curl", "curl -sS -m 60 -o /dev/null -w '%{http_code}\\n' https://example.com | grep -q 200");
    ok("git clone", "rm -rf /tmp/hw && timeout 180 git clone --depth 1 https://github.com/octocat/Hello-World /tmp/hw && test -f /tmp/hw/README");
    ok("node fetch", "node -e \"fetch('https://example.com').then(r => { console.log(r.status); process.exit(r.status === 200 ? 0 : 1) })\"");
    ok("python urllib", "python3 -c \"import urllib.request as u; print(u.urlopen('https://example.com', timeout=60).status)\"");
    ok("pip download", "rm -rf /tmp/x && timeout 180 pip download --no-deps six -d /tmp/x && ls /tmp/x | grep -q six");

    // Sites with bad certificates fail, as they would without the door: the door says 502.
    for host in ["expired.badssl.com", "wrong.host.badssl.com", "self-signed.badssl.com", "untrusted-root.badssl.com"] {
        let out = fails(host, &format!("curl -sS -m 60 -o /dev/null https://{host}"));
        assert!(out.contains("502"), "{host}: {out}");
    }
    fails("node on a bad cert", "node -e \"fetch('https://expired.badssl.com').then(() => process.exit(0), e => { console.log(String(e.cause || e)); process.exit(1) })\"");
    fails("python on a bad cert", "python3 -c \"import urllib.request as u; u.urlopen('https://expired.badssl.com', timeout=60)\"");

    let lines = log_lines(&log);
    let allowed: Vec<&str> = lines.iter().filter(|l| l["decision"] == "allowed").filter_map(|l| l["host"].as_str()).collect();
    for host in ["example.com", "github.com", "pypi.org"] {
        assert!(allowed.contains(&host), "{host} in {allowed:?}");
    }
    assert!(lines.iter().any(|l| l["host"] == "expired.badssl.com" && l["decision"].as_str().is_some_and(|d| d.starts_with("failed:tls"))));

    drop(vm);
    drop(door);
    let _ = std::fs::remove_dir_all(&dir);
}

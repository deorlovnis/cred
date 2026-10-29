//! A real browser VM behind the real door: Chromium in the `cred-browser` image, driven by the
//! runner, with every byte it sends going through the door's browser socket.
//!
//! Needs Apple's `container`, the internet (https://example.com) and a few minutes the first time
//! (it builds the image). Run with `mise run e2e-box`. The scenario runs in a copy of this test
//! binary with a private environment (policies and a fake Keychain), like the door's other
//! scenarios; the VMs it creates are named `cred-browser-p3v-<pid>`.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rustls::{ServerConnection, StreamOwned};
use serde_json::{Value, json};

use super::addr::Net;
use super::http;
use super::intercept_tests::{log_lines, wait_for};
use super::tls::{BoxCa, trust_only};
use super::{Config, Door, Tokens};
use crate::boxes::browser_vm::BrowserVm;
use crate::util::{TempDir, sha256_hex};
use crate::{approve, engine, policy};

const FILES_HOST: &str = "files.example.net";
const FILES_IP: [u8; 4] = [93, 184, 216, 77];
const PROXY: &str = "http://127.0.0.1:3128";
const REPLY_WAIT: Duration = Duration::from_secs(120);

const SCENARIO: &str = "door::page_vm_tests::real_vm_pages_browse_only_through_the_door";

/// A real browser VM, with the door in front of it: what the pages of two sites can and can't do.
///
///     mise run e2e-box        # includes this
#[test]
#[ignore = "needs Apple's `container` and the internet; run with `mise run e2e-box`"]
fn real_vm_pages_browse_only_through_the_door() {
    if std::env::var_os("CRED_E2E_BOX").is_none() {
        eprintln!("CRED_E2E_BOX isn't set: skipping");
        return;
    }
    if std::env::var_os("CRED_PAGE_VM_DIR").is_some() {
        return scenario();
    }
    let dir = TempDir::new("cred-page-vm").unwrap();
    for sub in ["keychain", "policy", "home"] {
        fs::create_dir(dir.0.join(sub)).unwrap();
    }
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", SCENARIO, "--nocapture", "--test-threads=1"])
        .env("CRED_PAGE_VM_DIR", &dir.0)
        .env("HOME", dir.0.join("home"))
        .env("CRED_INDEX", dir.0.join("index.json"))
        .env("CRED_POLICY_DIR", dir.0.join("policy"))
        .env("CRED_TEST_KEYCHAIN", dir.0.join("keychain"))
        .env("CRED_TEST_APPROVE", "yes")
        .env("CRED_AUDIT", dir.0.join("audit.log"))
        .env("CRED_AUDIT_KEY", "test-key")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .status()
        .unwrap();
    assert!(status.success(), "the scenario failed");
}

// --- a site with a downloadable file and a rotating cookie ---

/// An HTTPS site on localhost, certificate for `FILES_HOST` from `signer`. `/` is a page that
/// shows the cookie it was sent and sets a new one each visit, with a link to `/file`, which is
/// an attachment named `../evil name.txt` (Chromium makes that `_evil name.txt`).
fn files_site(signer: &BoxCa) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let config = signer.server_config(FILES_HOST).unwrap();
    let visits = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let (config, visits) = (config.clone(), visits.clone());
            thread::spawn(move || {
                let mut reader = BufReader::new(StreamOwned::new(ServerConnection::new(config).unwrap(), tcp));
                while let Ok(Some(head)) = http::read_head(&mut reader) {
                    let target = head.parts().map(|(_, t, _)| t.to_string()).unwrap_or_default();
                    let (status, headers, body) = match target.as_str() {
                        "/" => {
                            let n = visits.fetch_add(1, Ordering::SeqCst) + 1;
                            let cookie = head.header("cookie").unwrap_or("none");
                            let page = format!("<html><head><title>Files</title></head><body><h1>Files</h1><p>cookie: {cookie}</p><a href=\"/file\">Get the file</a></body></html>");
                            ("200 OK", format!("content-type: text/html\r\nset-cookie: sid=visit{n}; Path=/; Secure; HttpOnly\r\n"), page)
                        }
                        "/file" => ("200 OK", "content-type: application/octet-stream\r\ncontent-disposition: attachment; filename=\"../evil name.txt\"\r\n".to_string(), "downloaded content\n".to_string()),
                        _ => ("404 Not Found", "content-type: text/plain\r\n".to_string(), "no".to_string()),
                    };
                    let out = reader.get_mut();
                    if write!(out, "HTTP/1.1 {status}\r\n{headers}content-length: {}\r\n\r\n{body}", body.len()).is_err() || out.flush().is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

// --- a runner, spoken to over its pipes ---

struct Runner {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    next_id: u64,
}

impl Runner {
    fn start(vm: &BrowserVm, site: &str) -> (Runner, String) {
        let (mut child, token) = vm.runner(site).unwrap();
        let stdin = child.stdin.take().unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let (tx, lines) = mpsc::channel();
        thread::spawn(move || {
            let mut line = String::new();
            while stdout.read_line(&mut line).unwrap_or(0) > 0 {
                if tx.send(std::mem::take(&mut line)).is_err() {
                    break;
                }
            }
        });
        (Runner { child, stdin, lines, next_id: 0 }, token)
    }

    /// One command and its answer: the text, or the runner's error. Writes the page asks about
    /// are refused.
    fn call(&mut self, mut command: Value) -> Result<String, String> {
        self.next_id += 1;
        command["id"] = json!(self.next_id);
        writeln!(self.stdin, "{command}").unwrap();
        self.stdin.flush().unwrap();
        loop {
            let line = self.lines.recv_timeout(REPLY_WAIT).expect("the runner answered");
            let Ok(msg) = serde_json::from_str::<Value>(&line) else { continue };
            if let Some(ask) = msg.get("ask") {
                writeln!(self.stdin, "{}", json!({ "answer": ask, "allow": false })).unwrap();
                continue;
            }
            if msg["id"] != json!(self.next_id) {
                continue;
            }
            return match msg["ok"].as_bool() {
                Some(true) => Ok(msg["text"].as_str().unwrap_or("").to_string()),
                _ => Err(msg["error"].as_str().unwrap_or("failed").to_string()),
            };
        }
    }

    /// Open the site: `config` with the proxy identity this runner was given.
    fn open(&mut self, site: &str, token: &str, mut config: Value) -> Result<String, String> {
        config["proxy"] = json!({ "server": PROXY, "username": site, "password": token });
        self.call(json!({ "cmd": "open", "config": config }))
    }

    /// Close the page and take the session back.
    fn close(mut self) -> Value {
        let text = self.call(json!({ "cmd": "close" })).unwrap();
        let _ = self.child.wait();
        serde_json::from_str::<Value>(&text).unwrap()["storageState"].clone()
    }
}

impl Drop for Runner {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn browse_config(origins: &[&str], start: &str) -> Value {
    json!({ "origins": origins, "requests": [], "writes": "deny", "allow_writes": [], "start": start, "cookies": [], "storage": [], "screenshots": false })
}

/// The element ref of the first line of a snapshot that has `needle`.
fn ref_of(snapshot: &str, needle: &str) -> String {
    let line = snapshot.lines().find(|l| l.contains(needle)).unwrap_or_else(|| panic!("no {needle} in\n{snapshot}"));
    line.split("[ref=").nth(1).and_then(|r| r.split(']').next()).unwrap_or_else(|| panic!("no ref in {line}")).to_string()
}

// --- the scenario ---

fn scenario() {
    engine::available().unwrap();
    let built = Instant::now();
    let image = engine::build_browser_image(&Path::new(env!("CARGO_MANIFEST_DIR")).join("box")).unwrap();
    println!("image {image} ready after {:?}", built.elapsed());

    // Two sites of the box. `example` is the real example.com; `files` a local one with a
    // download and a rotating cookie, reached through the door's test hooks.
    fs::write(policy::path("example"), "[browse]\norigins = [\"https://example.com\"]\nstart = \"https://example.com\"\n").unwrap();
    fs::write(policy::path("files"), format!("[browse]\norigins = [\"https://{FILES_HOST}\"]\nstart = \"https://{FILES_HOST}/\"\n")).unwrap();
    policy::approve(&["example".into(), "files".into()]).unwrap();
    approve::take_answers();

    let box_ca = Arc::new(BoxCa::generate("e2e").unwrap());
    let signer = BoxCa::generate("sites").unwrap();
    let files = files_site(&signer);
    let mut roots = trust_only(&signer.cert_pem());
    roots.roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // Names resolve as usual, except the local site; dials land there too.
    let files_ip = IpAddr::from(FILES_IP);
    let net = Net::new(
        Box::new(move |host| {
            use std::net::ToSocketAddrs;
            if host == FILES_HOST {
                return Ok(vec![files_ip]);
            }
            Ok((host, 443).to_socket_addrs()?.map(|a| a.ip()).collect())
        }),
        Box::new(move |addr| {
            if addr.ip() == files_ip {
                return TcpStream::connect(files);
            }
            let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(8))?;
            stream.set_nodelay(true)?;
            Ok(stream)
        }),
    );
    let net = net.trusting(roots);

    let id = format!("p3v-{}", std::process::id());
    let short = PathBuf::from(format!("/tmp/{id}"));
    let _ = fs::remove_dir_all(&short);
    fs::create_dir(&short).unwrap();
    let _cleanup = Cleanup(short.clone());
    let downloads = short.join("downloads");
    let tokens = Tokens::default();
    let log = short.join("log").join("door.log");
    let door = Door::start_with(
        Config {
            name: id.clone(),
            socket: short.join("agent.sock"),
            allow: vec![],
            model: None,
            sites: vec!["example".into(), "files".into()],
            net: Default::default(),
            log: log.clone(),
            ca: Some(box_ca.clone()),
            log_key: [4; 32],
            browser_socket: Some(short.join("browser.sock")),
            browser_tokens: tokens.clone(),
            browser: None,
        },
        net,
    )
    .unwrap();
    let vm = BrowserVm::new(&id, &image, short.join("browser.sock"), Some(downloads.clone()), box_ca.cert_pem(), tokens);

    // The VM starts with the first runner and trusts the box CA: a real page over TLS the door ended.
    let started = Instant::now();
    let (mut example, token) = Runner::start(&vm, "example");
    println!("browser VM up and runner started after {:?}", started.elapsed());
    let opened = Instant::now();
    let snapshot = example.open("example", &token, browse_config(&["https://example.com"], "https://example.com")).unwrap();
    println!("example.com opened after {:?}\n{snapshot}", opened.elapsed());
    assert!(snapshot.contains("Example Domain"), "{snapshot}");
    assert!(example.call(json!({ "cmd": "snapshot" })).unwrap().contains("Example Domain"));
    let lines = log_lines(&log);
    assert!(lines.iter().any(|l| l["site"] == "example" && l["host"] == "example.com" && l["decision"] == "allowed"), "{lines:?}");
    assert!(lines.iter().any(|l| l["site"] == "example" && l["kind"] == "request" && l["url"] == "https://example.com/" && l["status"] == 200), "TLS was ended at the door and the page read: {lines:?}");

    // The trust is real: a Chromium that doesn't have the CA in its NSS database (another HOME)
    // refuses the door's certificate, and the door sees the handshake fail.
    vm.set_runner_env(vec![("HOME".into(), "/tmp".into())]);
    let (mut untrusting, token) = Runner::start(&vm, "example");
    let error = untrusting.open("example", &token, browse_config(&["https://example.com"], "https://example.com")).unwrap_err();
    println!("Chromium without the CA: {error}");
    assert!(error.contains("ERR_CERT"), "{error}");
    wait_for(|| log_lines(&log).into_iter().find(|l| l["site"] == "example" && l["decision"].as_str().is_some_and(|d| d.starts_with("failed:tls"))));
    drop(untrusting);
    vm.set_runner_env(vec![]);

    // The runner's own routing refuses a page outside the site's origins ...
    let error = example.call(json!({ "cmd": "goto", "url": "https://example.org/" })).unwrap_err();
    assert!(error.contains("isn't one of the pages this site allows"), "{error}");
    assert!(!log_lines(&log).iter().any(|l| l["host"] == "example.org"), "the runner never asked the door");
    let session = example.close();
    assert!(session["cookies"].is_array() && session["origins"].is_array(), "storageState comes back: {session}");

    // ... and with that routing turned off the door still does.
    vm.set_runner_env(vec![("CRED_RUNNER_DEBUG_NO_ROUTING".into(), "1".into())]);
    let (mut bare, token) = Runner::start(&vm, "example");
    bare.open("example", &token, browse_config(&["https://example.com"], "https://example.com")).unwrap();
    let error = bare.call(json!({ "cmd": "goto", "url": "https://example.org/" })).unwrap_err();
    println!("goto outside the origins, runner routing off: {error}");
    assert!(error.contains("ERR_") || error.contains("net::"), "the browser failed to load it: {error}");
    let blocked = wait_for(|| log_lines(&log).into_iter().find(|l| l["host"] == "example.org"));
    assert!(blocked["site"] == "example" && blocked["decision"] == "blocked:policy", "{blocked}");
    drop(bare);
    // Without a proxy there is nothing to enforce the rules, so the switch is refused.
    let (mut raw, _) = Runner::start(&vm, "example");
    let error = raw.call(json!({ "cmd": "open", "config": browse_config(&["https://example.com"], "https://example.com") })).unwrap_err();
    assert!(error.contains("only be switched off behind a proxy"), "{error}");
    drop(raw);
    vm.set_runner_env(vec![]);

    // Downloads: saved to the Mac folder when the runner was given one, refused otherwise.
    let (mut saving, token) = Runner::start(&vm, "files");
    let mut config = browse_config(&[&format!("https://{FILES_HOST}")], &format!("https://{FILES_HOST}/"));
    config["downloads"] = json!("/downloads/files");
    let page = saving.open("files", &token, config).unwrap();
    assert!(page.contains("cookie: none"), "{page}");
    let link = ref_of(&page, "Get the file");
    let after = saving.call(json!({ "cmd": "click", "ref": link })).unwrap();
    let saved = downloads.join("files").join("_evil name.txt");
    let content = fs::read_to_string(&saved).unwrap_or_else(|e| panic!("{e}: {after}\n{:?}", fs::read_dir(&downloads).map(|d| d.flatten().map(|e| e.path()).collect::<Vec<_>>())));
    assert_eq!(content, "downloaded content\n", "{after}");
    let sha = sha256_hex(b"downloaded content\n");
    assert!(after.contains(&format!("saved download _evil name.txt (19 bytes, sha256 {sha})")), "{after}");
    assert_eq!(fs::read_dir(downloads.join("files")).unwrap().count(), 1, "the name from the page stayed inside the folder");
    assert!(!downloads.join("_evil name.txt").exists() && !downloads.join("evil name.txt").exists());

    // The session comes back on close, and goes back in: the cookie the site rotated.
    let page = saving.call(json!({ "cmd": "goto", "url": format!("https://{FILES_HOST}/") })).unwrap();
    assert!(page.contains("cookie: sid=visit1"), "the browser keeps its cookie: {page}");
    let state = saving.close();
    let cookie = state["cookies"].as_array().unwrap().iter().find(|c| c["name"] == "sid").unwrap_or_else(|| panic!("no sid in {state}"));
    assert_eq!(cookie["value"], "visit2");
    let (mut again, token) = Runner::start(&vm, "files");
    let mut config = browse_config(&[&format!("https://{FILES_HOST}")], &format!("https://{FILES_HOST}/"));
    config["storageState"] = state;
    let page = again.open("files", &token, config).unwrap();
    assert!(page.contains("cookie: sid=visit2"), "the session goes back in: {page}");
    drop(again);

    // No downloads configured: the runner refuses them, and nothing lands on the Mac.
    let (mut refusing, token) = Runner::start(&vm, "files");
    let page = refusing.open("files", &token, browse_config(&[&format!("https://{FILES_HOST}")], &format!("https://{FILES_HOST}/"))).unwrap();
    let link = ref_of(&page, "Get the file");
    let after = refusing.call(json!({ "cmd": "click", "ref": link })).unwrap();
    assert!(after.contains("blocked download _evil name.txt"), "{after}");
    assert_eq!(fs::read_dir(downloads.join("files")).unwrap().count(), 1, "still only the first download");
    drop(refusing);

    // One site's runner can't speak as the other site.
    let (mut thief, token) = Runner::start(&vm, "files");
    let error = thief.open("example", &token, browse_config(&["https://example.com"], "https://example.com")).unwrap_err();
    println!("runner of one site posing as another: {error}");
    assert!(error.contains("ERR_") || error.contains("net::"), "{error}");
    drop(thief);

    let stopping = Instant::now();
    drop(vm);
    println!("browser VM stopped after {:?}", stopping.elapsed());
    drop(door);
}

/// The scenario's folder goes, however it ends.
struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// --- a session the site rotates, through cred's browser tools ---

const SESSION_SCENARIO: &str = "door::page_vm_tests::real_vm_session_the_site_rotates_survives_close_and_restart";

/// The sealed session of a site and the browser tools over a real browser VM and door: a site
/// that sets a new cookie on every visit is signed in with the latest value each time, after
/// `browse_close`, after the connection ending, and after the box restarts.
#[test]
#[ignore = "needs Apple's `container` and the internet; run with `mise run e2e-box`"]
fn real_vm_session_the_site_rotates_survives_close_and_restart() {
    if std::env::var_os("CRED_E2E_BOX").is_none() {
        eprintln!("CRED_E2E_BOX isn't set: skipping");
        return;
    }
    if std::env::var_os("CRED_PAGE_VM_DIR").is_some() {
        return session_scenario();
    }
    let dir = TempDir::new("cred-page-vm").unwrap();
    for sub in ["keychain", "policy", "home"] {
        fs::create_dir(dir.0.join(sub)).unwrap();
    }
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", SESSION_SCENARIO, "--nocapture", "--test-threads=1"])
        .env("CRED_PAGE_VM_DIR", &dir.0)
        .env("HOME", dir.0.join("home"))
        .env("CRED_INDEX", dir.0.join("index.json"))
        .env("CRED_POLICY_DIR", dir.0.join("policy"))
        .env("CRED_TEST_KEYCHAIN", dir.0.join("keychain"))
        .env("CRED_TEST_APPROVE", "yes")
        .env("CRED_AUDIT", dir.0.join("audit.log"))
        .env("CRED_AUDIT_KEY", "test-key")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .status()
        .unwrap();
    assert!(status.success(), "the scenario failed");
}

/// An HTTPS site on localhost (certificate for `FILES_HOST` from `signer`) whose page sets
/// `sid=visitN` on every visit, and records the Cookie header each visit came with.
fn rotating_site(signer: &BoxCa) -> (SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let config = signer.server_config(FILES_HOST).unwrap();
    let cookies: Arc<std::sync::Mutex<Vec<String>>> = Arc::default();
    let seen = cookies.clone();
    thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let (config, seen) = (config.clone(), seen.clone());
            thread::spawn(move || {
                let mut reader = BufReader::new(StreamOwned::new(ServerConnection::new(config).unwrap(), tcp));
                while let Ok(Some(head)) = http::read_head(&mut reader) {
                    let target = head.parts().map(|(_, t, _)| t.to_string()).unwrap_or_default();
                    let (headers, body) = if target == "/" {
                        let mut seen = seen.lock().unwrap();
                        seen.push(head.header("cookie").unwrap_or("none").to_string());
                        (format!("content-type: text/html\r\nset-cookie: sid=visit{}; Path=/; Secure; HttpOnly\r\n", seen.len()), "<html><head><title>Rotating</title></head><body><h1>Rotating</h1></body></html>")
                    } else {
                        ("content-type: text/plain\r\n".to_string(), "no")
                    };
                    let out = reader.get_mut();
                    if write!(out, "HTTP/1.1 200 OK\r\n{headers}content-length: {}\r\n\r\n{body}", body.len()).is_err() || out.flush().is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, cookies)
}

/// One MCP connection to the box: these requests, then the connection ends (the agent is gone).
fn connection(browser: Arc<dyn crate::browse::BoxBrowser>, calls: &[(&str, Value)]) -> Vec<Value> {
    let input: String = calls
        .iter()
        .enumerate()
        .map(|(i, (name, args))| format!("{}\n", json!({ "jsonrpc": "2.0", "id": i + 1, "method": "tools/call", "params": { "name": name, "arguments": args } })))
        .collect();
    let mut out = Vec::new();
    crate::mcp::serve_io(std::io::Cursor::new(input.into_bytes()), &mut out, crate::mcp::Scope::boxed("p3v", &["files".to_string()], Some(browser))).unwrap();
    String::from_utf8(out).unwrap().lines().map(|l| serde_json::from_str::<Value>(l).unwrap()["result"].clone()).collect()
}

fn session_scenario() {
    engine::available().unwrap();
    let image = engine::build_browser_image(&Path::new(env!("CARGO_MANIFEST_DIR")).join("box")).unwrap();
    fs::write(policy::path("files"), format!("[browse]\norigins = [\"https://{FILES_HOST}\"]\nstart = \"https://{FILES_HOST}/\"\n")).unwrap();
    fs::write(std::env::var("CRED_INDEX").unwrap(), json!({ "files": { "fields": {} } }).to_string()).unwrap();
    policy::approve(&["files".into()]).unwrap();
    approve::take_answers();

    let box_ca = Arc::new(BoxCa::generate("e2e").unwrap());
    let signer = BoxCa::generate("sites").unwrap();
    let (site, cookies) = rotating_site(&signer);
    let mut roots = trust_only(&signer.cert_pem());
    roots.roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let files_ip = IpAddr::from(FILES_IP);
    let net = Net::new(
        Box::new(move |host| {
            use std::net::ToSocketAddrs;
            if host == FILES_HOST {
                return Ok(vec![files_ip]);
            }
            Ok((host, 443).to_socket_addrs()?.map(|a| a.ip()).collect())
        }),
        Box::new(move |addr| {
            if addr.ip() == files_ip {
                return TcpStream::connect(site);
            }
            let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(8))?;
            stream.set_nodelay(true)?;
            Ok(stream)
        }),
    )
    .trusting(roots);

    let id = format!("p3v-{}", std::process::id());
    let short = PathBuf::from(format!("/tmp/{id}"));
    let _ = fs::remove_dir_all(&short);
    fs::create_dir_all(short.join("store/browser")).unwrap();
    let _cleanup = Cleanup(short.clone());
    let tokens = Tokens::default();
    let vm = Arc::new(BrowserVm::new(&id, &image, short.join("browser.sock"), None, box_ca.cert_pem(), tokens.clone()));
    // The box: its store folder (sessions are sealed in it), and a browser that starts runners in the VM.
    let browser = |keep: bool| -> Arc<dyn crate::browse::BoxBrowser> {
        let vm = vm.clone();
        let sessions = crate::boxes::sessions::Sessions::new(&short.join("store"), "the box key", keep);
        Arc::new(crate::boxes::sessions::InBox::new(sessions, Box::new(move |site| vm.runner(site)), false))
    };
    let door = Door::start_with(
        Config {
            name: id.clone(),
            socket: short.join("agent.sock"),
            allow: vec![],
            model: None,
            sites: vec!["files".into()],
            net: Default::default(),
            log: short.join("log/door.log"),
            ca: Some(box_ca.clone()),
            log_key: [4; 32],
            browser_socket: Some(short.join("browser.sock")),
            browser_tokens: tokens,
            browser: Some(browser(true)),
        },
        net,
    )
    .unwrap();

    let ok = |results: &[Value]| {
        for r in results {
            assert_eq!(r["isError"], json!(false), "{r}");
        }
    };
    let open = || ("browse_open", json!({ "site": "files" }));
    let close = || ("browse_close", json!({}));

    // First visit: nothing sealed, nothing sent. browse_close seals what the site set.
    let first = connection(browser(true), &[open(), close()]);
    ok(&first);
    assert!(first[0]["content"][0]["text"].as_str().unwrap().contains("Rotating"), "{first:?}");
    assert_eq!(*cookies.lock().unwrap(), ["none"]);
    assert_eq!(fs::read_dir(short.join("store/browser")).unwrap().count(), 1, "the session is sealed in the store");

    // The box restarts (new connection, new objects over the same store): the latest value goes in.
    let second = connection(browser(true), &[open(), close()]);
    ok(&second);
    assert!(!format!("{second:?}").contains("visit"), "the session is masked for the agent: {second:?}");
    assert_eq!(cookies.lock().unwrap()[1], "sid=visit1");

    // The agent goes away with its browser open: the end of the connection closes and seals it.
    ok(&connection(browser(true), &[open()]));
    assert_eq!(cookies.lock().unwrap()[2], "sid=visit2");
    ok(&connection(browser(true), &[open(), close()]));
    assert_eq!(cookies.lock().unwrap()[3], "sid=visit3", "every visit brought the value the visit before it set");

    // keep_sessions = false never reads one: the site sees a new browser.
    ok(&connection(browser(false), &[open(), close()]));
    assert_eq!(cookies.lock().unwrap()[4], "none");

    drop(door);
    vm.stop();
}

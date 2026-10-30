//! The door and the pages of the box's browser VM: a fake browser VM (the listener its shim would
//! hold) on the browser socket, a fake agent VM on the agent socket, and fake sites that speak
//! real TLS. Pages must name a site of the box and prove it with their runner's token; they
//! reach the hosts of that site's `[browse]` rules and send writes as those rules say, and the
//! agent's socket can never carry a page's identity.
//!
//! Policies and approvals live in files (the debug-only fake Keychain), set up through
//! environment variables, so each scenario runs in a copy of this test binary started with its
//! own environment (as in `tests`), with Touch ID answering yes or no.

use std::fs;
use std::io::{BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rustls::{ServerConnection, StreamOwned};
use serde_json::{Value, json};

use super::addr::Net;
use super::http;
use super::intercept_tests::{Guest, Shim, client, log_lines, wait_for};
use super::tls::{BoxCa, trust_only};
use super::{Config, Door, Tokens};
use crate::util::TempDir;
use crate::{approve, keychain, policy};

const SECRET: &str = "tok-SECRET-0123456789-abcdef";
const LOG_KEY: [u8; 32] = [5; 32];

const YES: &str = "door::page_tests::pages_speak_for_their_site_and_nobody_else_touch_id_says_yes";
const NO: &str = "door::page_tests::pages_speak_for_their_site_and_nobody_else_touch_id_says_no";

#[test]
fn pages_speak_for_their_site_and_nobody_else_touch_id_says_yes() {
    run_scenario(YES, "yes");
}

#[test]
fn pages_speak_for_their_site_and_nobody_else_touch_id_says_no() {
    run_scenario(NO, "no");
}

fn run_scenario(name: &str, answer: &str) {
    if let Some(dir) = std::env::var_os("CRED_PAGE_DIR") {
        return scenario(Path::new(&dir), answer == "yes");
    }
    let dir = TempDir::new("cred-page").unwrap();
    for sub in ["keychain", "policy", "home"] {
        fs::create_dir(dir.0.join(sub)).unwrap();
    }
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env("CRED_PAGE_DIR", &dir.0)
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

// --- fake sites ---

/// What the fake sites saw: host, request line, headers.
type Reached = Arc<Mutex<Vec<(String, String, Vec<(String, String)>)>>>;

/// An HTTPS site on localhost with a certificate for `host` from `signer`. `GET` answers `hello`;
/// any other method echoes its body.
fn site(signer: &BoxCa, host: &str, reached: &Reached) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let config = signer.server_config(host).unwrap();
    let (host, reached) = (host.to_string(), reached.clone());
    thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let (config, host, reached) = (config.clone(), host.clone(), reached.clone());
            thread::spawn(move || {
                let mut reader = BufReader::new(StreamOwned::new(ServerConnection::new(config).unwrap(), tcp));
                while let Ok(Some(head)) = http::read_head(&mut reader) {
                    let Ok(body) = http::read_body(&mut reader, &head, 1 << 20) else { return };
                    reached.lock().unwrap().push((host.clone(), head.line.clone(), head.headers.clone()));
                    let answer = if head.line.starts_with("GET ") { b"hello".to_vec() } else { body };
                    let out = reader.get_mut();
                    if write!(out, "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", answer.len()).is_err() || out.write_all(&answer).is_err() || out.flush().is_err() {
                        return;
                    }
                }
            });
        }
    });
    addr
}

/// One request through a tunnel, and its whole answer: status and body.
fn call(tls: &mut Guest, host: &str, method: &str, path: &str, body: &str) -> (u16, String) {
    write!(tls, "{method} {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    tls.flush().unwrap();
    let mut reader = BufReader::new(&mut *tls);
    let head = http::read_head(&mut reader).unwrap().expect("an answer");
    let status = head.line.split(' ').nth(1).unwrap().parse().unwrap();
    let mut answer = Vec::new();
    http::Body::new(&mut reader, http::response_framing(&head, method, status).unwrap()).read_to_end(&mut answer).unwrap();
    (status, String::from_utf8(answer).unwrap())
}

/// `Proxy-Authorization` as Chromium sends it for the proxy credentials Playwright was given.
fn identity(site: &str, token: &str) -> String {
    format!("Proxy-Authorization: Basic {}\r\n", STANDARD.encode(format!("{site}:{token}")))
}

fn write_policy(res: &str, toml: &str) {
    fs::write(policy::path(res), toml).unwrap();
}

// --- the scenario ---

fn scenario(dir: &Path, yes: bool) {
    write_policy(
        "app",
        "[fetch]\nhosts = [\"https://app.example.com\"]\nauth = \"Bearer {token}\"\n\n[browse]\norigins = [\"https://app.example.com\"]\nrequests = [\"https://cdn.example.com\"]\nallow_writes = [\"https://app.example.com/telemetry\"]\n",
    );
    write_policy("loose", "[browse]\norigins = [\"https://loose.example.com\"]\nwrites = \"allow\"\n");
    write_policy("askme", "[browse]\norigins = [\"https://ask.example.com\"]\nwrites = \"ask\"\n");
    write_policy("fetchonly", "[fetch]\nhosts = [\"https://fetch.example.com\"]\n");
    write_policy("outsider", "[browse]\norigins = [\"https://outsider.example.com\"]\n");
    keychain::set("app", "token", SECRET).unwrap();
    let field = json!({ "fields": { "token": {} } });
    fs::write(dir.join("index.json"), json!({ "app": field }).to_string()).unwrap();
    policy::approve(&["app".into(), "loose".into(), "askme".into(), "fetchonly".into(), "outsider".into()]).unwrap();
    approve::take_answers();
    // The policies are approved; from here Touch ID answers as this scenario says.
    // SAFETY: no other thread is running yet; the door's threads start later.
    unsafe { std::env::set_var("CRED_TEST_APPROVE", if yes { "yes" } else { "no" }) };

    let box_ca = Arc::new(BoxCa::generate("pagebox").unwrap());
    let signer = BoxCa::generate("sites").unwrap();
    let reached = Reached::default();
    let hosts = ["app.example.com", "cdn.example.com", "loose.example.com", "ask.example.com", "other.example.com", "fetch.example.com"];
    let routes: Vec<(IpAddr, SocketAddr)> = hosts.iter().enumerate().map(|(i, h)| (IpAddr::from([93, 184, 216, 10 + i as u8]), site(&signer, h, &reached))).collect();
    let (resolve_routes, dial_routes) = (routes.clone(), routes);
    let net = Net::new(
        Box::new(move |host| {
            let i = hosts.iter().position(|h| *h == host).ok_or_else(|| std::io::Error::other("no such host"))?;
            Ok(vec![resolve_routes[i].0])
        }),
        Box::new(move |addr| TcpStream::connect(dial_routes.iter().find(|(ip, _)| *ip == addr.ip()).unwrap().1)),
    )
    .trusting(trust_only(&signer.cert_pem()));

    let (agent_socket, browser_socket) = (dir.join("agent.sock"), dir.join("browser.sock"));
    let (agent, browser) = (Shim(UnixListener::bind(&agent_socket).unwrap()), Shim(UnixListener::bind(&browser_socket).unwrap()));
    agent.0.set_nonblocking(true).unwrap();
    browser.0.set_nonblocking(true).unwrap();
    let tokens = Tokens::default();
    let log = dir.join("log").join("door.log");
    let door = Door::start_with(
        Config {
            name: "pagebox".into(),
            socket: agent_socket,
            allow: vec!["https://app.example.com".into()],
            model: None,
            sites: vec!["app".into(), "loose".into(), "askme".into(), "fetchonly".into()],
            net: Default::default(),
            log: log.clone(),
            ca: Some(box_ca.clone()),
            log_key: LOG_KEY,
            browser_socket: Some(browser_socket),
            browser_tokens: tokens.clone(),
            browser: None,
        },
        net,
    )
    .unwrap();
    let issue = |site: &str| tokens.issue(site).unwrap();
    let (app, loose, askme, fetchonly, outsider) = (issue("app"), issue("loose"), issue("askme"), issue("fetchonly"), issue("outsider"));
    let seen = |host: &str| -> Vec<String> { reached.lock().unwrap().iter().filter(|(h, ..)| h == host).map(|(_, line, _)| line.clone()).collect() };

    // A connection with no identity is asked for one (as Chromium is) and may answer on the same
    // connection; asking twice and getting nothing ends it.
    let mut io = browser.take();
    writeln!(io.writer, "proxy").unwrap();
    let (status, reason) = Shim::send_connect(&mut io, "app.example.com:443", "");
    assert_eq!((status, reason.as_str()), (407, "Proxy Authentication Required"));
    let (status, _) = Shim::send_connect(&mut io, "app.example.com:443", &identity("app", &app));
    assert_eq!(status, 200, "the same connection takes the credentials");
    let mut tls = client(&box_ca, &[b"http/1.1"], "app.example.com", io);

    // Pages reach what the site's browse policy says: its origins, and the hosts it requests from.
    assert_eq!(call(&mut tls, "app.example.com", "GET", "/hello", ""), (200, "hello".into()));
    // No credentials are added to a page's requests: the session is in the browser.
    let (_, _, headers) = reached.lock().unwrap().iter().find(|(h, ..)| h == "app.example.com").unwrap().clone();
    assert!(!headers.iter().any(|(n, v)| n.eq_ignore_ascii_case("authorization") || v.contains(SECRET)), "{headers:?}");
    // Writes follow the browse policy: denied unless under allow_writes.
    let (status, body) = call(&mut tls, "app.example.com", "POST", "/submit", "data");
    assert!(status == 403 && body.contains("[browse] policy for app doesn't allow POST"), "{status} {body}");
    assert_eq!(call(&mut tls, "app.example.com", "POST", "/telemetry/ping", "ok"), (200, "ok".into()));
    assert_eq!(call(&mut tls, "app.example.com", "PUT", "/telemetry", "ok"), (200, "ok".into()));
    assert_eq!(call(&mut tls, "app.example.com", "POST", "/telemetryx", "no").0, 403, "a prefix ends at a path segment");
    assert_eq!(seen("app.example.com"), ["GET /hello HTTP/1.1", "POST /telemetry/ping HTTP/1.1", "PUT /telemetry HTTP/1.1"]);

    // A host the policy lists under `requests` is reachable, with the same write rules.
    let (status, _, io) = browser.connect_with("cdn.example.com:443", &identity("app", &app));
    assert_eq!(status, 200);
    let mut cdn = client(&box_ca, &[b"http/1.1"], "cdn.example.com", io);
    assert_eq!(call(&mut cdn, "cdn.example.com", "GET", "/lib.js", ""), (200, "hello".into()));
    assert_eq!(call(&mut cdn, "cdn.example.com", "POST", "/beacon", "x").0, 403);
    drop(cdn);

    // Hosts outside origins and requests, other ports, and sites that don't allow browsing are
    // refused at CONNECT, whatever the identity.
    for (site_token, who, target, why) in [
        (&app, "app", "other.example.com:443", "browse policy allows"),
        (&app, "app", "loose.example.com:443", "browse policy allows"),
        (&app, "app", "app.example.com:8443", "Only port 443"),
        (&app, "app", "10.0.0.1:443", "browse policy allows"),
        (&fetchonly, "fetchonly", "fetch.example.com:443", "doesn't allow browsing"),
        (&loose, "loose", "app.example.com:443", "browse policy allows"),
    ] {
        let (status, reason, mut io) = browser.connect_with(target, &identity(who, site_token));
        assert!(status == 403 && reason.contains(why), "{who} {target}: {status} {reason}");
        let mut rest = Vec::new();
        assert!(io.read_to_end(&mut rest).map(|_| rest.is_empty()).unwrap_or(true), "no tunnel after a refusal");
    }
    assert!(seen("other.example.com").is_empty() && seen("fetch.example.com").is_empty(), "nothing reached them");

    // Identities that aren't a runner of this box's sites: another runner's token, a made-up
    // site or token, a site the box doesn't have, a token that was revoked, and other schemes.
    let gone = issue("loose");
    tokens.revoke(&gone);
    let bogus = [
        identity("loose", &app),
        identity("app", &loose),
        identity("ghost", &app),
        identity("app", "guess"),
        identity("outsider", &outsider),
        identity("loose", &gone),
        "Proxy-Authorization: Bearer abc\r\n".to_string(),
        "Proxy-Authorization: Basic !!!\r\n".to_string(),
    ];
    for auth in &bogus {
        let (status, reason, _) = browser.connect_with("app.example.com:443", auth);
        assert!(status == 403 && reason.contains("Not an identity"), "{auth:?}: {status} {reason}");
    }
    let mut io = browser.take();
    writeln!(io.writer, "proxy").unwrap();
    assert_eq!(Shim::send_connect(&mut io, "app.example.com:443", "").0, 407);
    assert_eq!(Shim::send_connect(&mut io, "app.example.com:443", "").0, 407, "asked twice");
    let mut rest = Vec::new();
    assert!(io.read_to_end(&mut rest).map(|_| rest.is_empty()).unwrap_or(true));

    // Write rules are each site's own: allowed outright, or asked per write.
    let (status, _, io) = browser.connect_with("loose.example.com:443", &identity("loose", &loose));
    assert_eq!(status, 200);
    let mut tls_loose = client(&box_ca, &[b"http/1.1"], "loose.example.com", io);
    assert_eq!(call(&mut tls_loose, "loose.example.com", "POST", "/x", "free"), (200, "free".into()));
    let (status, _, io) = browser.connect_with("ask.example.com:443", &identity("askme", &askme));
    assert_eq!(status, 200);
    let mut tls_ask = client(&box_ca, &[b"http/1.1"], "ask.example.com", io);
    let (status, body) = call(&mut tls_ask, "ask.example.com", "POST", "/x", "please");
    if yes {
        assert_eq!((status, body.as_str()), (200, "please"));
    } else {
        assert!(status == 403 && body.contains("wasn't approved"), "{status} {body}");
        assert!(seen("ask.example.com").is_empty());
    }
    assert_eq!(call(&mut tls_ask, "ask.example.com", "GET", "/", "").0, 200, "reads aren't asked about");

    // The agent's socket never carries a page's identity: it is judged as the agent, by the
    // box's [net], however it presents itself.
    let (status, reason, _) = agent.connect_with("cdn.example.com:443", &identity("app", &app));
    assert!(status == 403 && reason.contains("Not allowed by the box policy"), "{status} {reason}");
    let (status, _, io) = agent.connect_with("app.example.com:443", &identity("loose", &app));
    assert_eq!(status, 200, "an identity header means nothing there");
    let mut as_agent = client(&box_ca, &[b"http/1.1"], "app.example.com", io);
    assert_eq!(call(&mut as_agent, "app.example.com", "GET", "/hello", "").0, 200);
    let (status, body) = call(&mut as_agent, "app.example.com", "POST", "/telemetry/ping", "x");
    assert!(status == 403 && body.contains("the policy for app doesn't allow"), "the agent gets the fetch rules, not the browse rules: {status} {body}");
    let with_credentials = reached.lock().unwrap().iter().rfind(|(h, line, _)| h == "app.example.com" && line == "GET /hello HTTP/1.1").unwrap().2.clone();
    assert!(
        with_credentials.iter().any(|(n, v)| n.eq_ignore_ascii_case("authorization") && v == &format!("Bearer {SECRET}")),
        "the agent gets the site's credentials: {with_credentials:?}"
    );
    drop(as_agent);

    // The browser's VM has no business with cred itself or MCP.
    for kind in ["cred", "mcp"] {
        let mut io = browser.take();
        write!(io.writer, "{kind}\nGET /model/v1/messages HTTP/1.1\r\nHost: cred.internal\r\n\r\n").unwrap();
        let mut rest = Vec::new();
        assert!(io.read_to_end(&mut rest).map(|_| rest.is_empty()).unwrap_or(true), "{kind} got an answer");
    }

    // Rules are read as the policy stands: once it changes, an open tunnel is refused its next
    // request and no new one opens.
    let mut text = fs::read_to_string(policy::path("app")).unwrap();
    text.push_str("\n# edited\n");
    write_policy("app", &text);
    let (status, body) = call(&mut tls, "app.example.com", "GET", "/hello", "");
    assert!(status == 403 && body.contains("changed since it was approved"), "{status} {body}");
    let (status, reason, _) = browser.connect_with("app.example.com:443", &identity("app", &app));
    assert!(status == 403 && reason.contains("changed since it was approved"), "{status} {reason}");

    // What the log says: the site of each page's decisions, and nothing secret.
    drop((tls, tls_loose, tls_ask));
    let lines = wait_for(|| Some(log_lines(&log)).filter(|l| l.iter().any(|e| e["site"] == "app" && e["decision"] == "closed")));
    let has = |site: &str, host: &str, decision: &str| lines.iter().any(|l: &Value| l["site"] == site && l["host"] == host && l["decision"] == decision);
    assert!(has("app", "other.example.com", "blocked:policy") && has("app", "app.example.com", "allowed") && has("app", "cdn.example.com", "allowed"));
    assert!(has("fetchonly", "fetch.example.com", "blocked:policy"));
    assert!(lines.iter().any(|l| l["site"] == "app" && l["kind"] == "request" && l["method"] == "POST" && l["decision"] == "blocked:writes"));
    assert!(lines.iter().any(|l| l["site"] == "app" && l["kind"] == "request" && l["url"] == "https://app.example.com/telemetry/ping" && l["decision"] == "allowed"));
    assert!(lines.iter().any(|l| l["decision"] == "blocked:identity") && lines.iter().any(|l| l["decision"] == "blocked:no-identity"));
    assert!(lines.iter().any(|l| l["kind"] == "unknown" && l["decision"] == "blocked:browser-kind"));
    // Requests of the agent are logged without a site; its CONNECT was refused by the box policy.
    assert!(lines.iter().any(|l| l["site"].is_null() && l["host"] == "cdn.example.com" && l["decision"] == "blocked:policy"));
    let text = fs::read_to_string(&log).unwrap();
    for secret in [SECRET, &app, &loose, STANDARD.encode(format!("app:{app}")).as_str()] {
        assert!(!text.contains(secret), "the log holds {secret}");
    }
    door.stop();
}

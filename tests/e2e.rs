//! End-to-end tests: the built `cred` binary, driven the way a person and an agent drive it.
//!
//! The debug binary keeps Keychain items in a temp folder (CRED_TEST_KEYCHAIN) and answers
//! Touch ID prompts from CRED_TEST_APPROVE, so these tests need no human and never touch the
//! real Keychain. Run them with `mise run e2e`. Two groups need more, and are opt-in:
//!
//!   CRED_E2E_BROWSER=1       the sandboxed browser (needs `npm ci` in runner/ and Chromium)
//!   CRED_E2E_INTERACTIVE=1   a real Touch ID approval in the real Keychain (a human taps)
//!
//! Run those with `mise run e2e-opt-in`; they are #[ignore]d otherwise.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::{env, fs, thread};

use serde_json::{Value, json};

const CRED: &str = env!("CARGO_BIN_EXE_cred");
const TOKEN: &str = "s3cret-token-value";

/// A private home for one test: index, policies and fake Keychain, removed when dropped.
struct Env {
    dir: PathBuf,
}

impl Env {
    fn new() -> Self {
        // Only debug builds honor the test variables; a release build would use the real Keychain.
        if !cfg!(debug_assertions) {
            panic!("run the e2e tests with a debug build (no --release)");
        }
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        let dir = env::temp_dir().join(format!("cred-e2e-{}-{}", std::process::id(), COUNT.fetch_add(1, Ordering::Relaxed)));
        let _ = fs::remove_dir_all(&dir);
        for sub in ["keychain", "policy", "home"] {
            fs::create_dir_all(dir.join(sub)).unwrap();
        }
        Self { dir }
    }

    /// `cred ARGS` with every path pointing into this test's folder; Touch ID answers yes.
    fn command(&self) -> Command {
        let mut cmd = Command::new(CRED);
        cmd.env("HOME", self.dir.join("home"))
            .env("CRED_INDEX", self.dir.join("index.json"))
            .env("CRED_POLICY_DIR", self.dir.join("policy"))
            .env("CRED_TEST_KEYCHAIN", self.dir.join("keychain"))
            .env("CRED_TEST_APPROVE", "yes")
            .env_remove("CRED_REFRESHING")
            .current_dir(&self.dir)
            .stdin(Stdio::null());
        cmd
    }

    fn cred(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }

    /// Store a field as `cred set` would (which needs a terminal for the hidden prompt).
    fn store(&self, res: &str, field: &str, value: &str) {
        fs::write(self.dir.join("keychain").join(format!("{res}.{field}")), value).unwrap();
        let index = self.dir.join("index.json");
        let mut map: Value = fs::read_to_string(&index).map_or(json!({}), |s| serde_json::from_str(&s).unwrap());
        map[res]["description"] = json!(format!("the {res} test site"));
        map[res]["fields"][field] = json!({});
        fs::write(index, map.to_string()).unwrap();
    }

    fn write_policy(&self, res: &str, toml: &str) {
        fs::write(self.dir.join("policy").join(format!("{res}.toml")), toml).unwrap();
    }

    /// Write a policy and approve it through `cred policy approve`.
    fn policy(&self, res: &str, toml: &str) {
        self.write_policy(res, toml);
        let out = self.cred(&["policy", "approve", res]);
        assert!(out.status.success(), "approve failed: {}", text(&out.stderr));
    }

    fn mcp(&self) -> Mcp {
        Mcp::start(self.command().arg("mcp"))
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn stdout(out: &Output) -> String {
    text(&out.stdout)
}

/// What a failed command said, for assertion messages.
fn stderr(out: &Output) -> String {
    text(&out.stderr)
}

// --- an MCP client, as an agent's would talk to `cred mcp` ---

struct Mcp {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Mcp {
    fn start(cmd: &mut Command) -> Self {
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let (stdin, stdout) = (child.stdin.take().unwrap(), BufReader::new(child.stdout.take().unwrap()));
        Self { child, stdin: Some(stdin), stdout, next_id: 0 }
    }

    fn send(&mut self, message: &Value) {
        writeln!(self.stdin.as_mut().unwrap(), "{message}").unwrap();
    }

    /// A request and its result (or the error object).
    fn rpc(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let request = json!({ "jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params });
        self.send(&request);
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        let reply: Value = serde_json::from_str(&line).unwrap_or_else(|_| panic!("not JSON: {line:?}"));
        assert_eq!(reply["id"], json!(self.next_id));
        reply.get("result").cloned().unwrap_or_else(|| reply["error"].clone())
    }

    fn handshake(&mut self) -> Value {
        let init = self.rpc("initialize", json!({ "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "e2e", "version": "0" } }));
        self.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        init
    }

    fn tool_names(&mut self) -> Vec<String> {
        let list = self.rpc("tools/list", json!({}));
        list["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap().to_string()).collect()
    }

    /// Call a tool; returns (is_error, text).
    fn call(&mut self, name: &str, args: Value) -> (bool, String) {
        let result = self.rpc("tools/call", json!({ "name": name, "arguments": args }));
        (result["isError"].as_bool().unwrap(), result["content"][0]["text"].as_str().unwrap().to_string())
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        // Closing stdin lets cred exit on its own and close any browser it started.
        drop(self.stdin.take());
        let _ = self.child.wait();
    }
}

// --- a local web site ---

/// Serves on 127.0.0.1 and keeps every request it gets (head only, header names lowercased).
struct Site {
    port: u16,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Site {
    /// `/echo` says which Authorization it got, `/redirect` redirects to `/echo`, `/page` is
    /// an HTML page showing its Cookie header, anything else is "ok".
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&requests);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let seen = Arc::clone(&seen);
                thread::spawn(move || answer(stream, port, &seen));
            }
        });
        Self { port, requests }
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    fn origin(&self) -> String {
        self.url("")
    }

    /// The requests seen so far, as "METHOD /path" followed by the lowercased headers.
    fn seen(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

fn answer(mut stream: TcpStream, port: u16, seen: &Mutex<Vec<String>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut head = String::new();
    let mut length = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        if line == "\r\n" {
            break;
        }
        if let Some(n) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = n.trim().parse().unwrap_or(0);
        }
        match line.split_once(':') {
            Some((name, value)) if !head.is_empty() => head += &format!("{}:{value}", name.to_ascii_lowercase()),
            _ => head += &line,
        }
    }
    let mut body = vec![0; length];
    let _ = reader.read_exact(&mut body);
    seen.lock().unwrap().push(head.clone());

    let header = |name: &str| head.lines().find_map(|l| l.strip_prefix(&format!("{name}: "))).unwrap_or("none").to_string();
    let (status, extra, content_type, body) = match head.split_whitespace().nth(1).unwrap_or("/") {
        "/echo" => ("200 OK", String::new(), "text/plain", format!("authorization: {}", header("authorization"))),
        "/redirect" => ("302 Found", format!("Location: http://127.0.0.1:{port}/echo\r\n"), "text/plain", String::new()),
        "/page" => ("200 OK", String::new(), "text/html", format!("<html><body><h1>Hello e2e</h1><p>cookie: {}</p></body></html>", header("cookie"))),
        _ => ("200 OK", String::new(), "text/plain", "ok".into()),
    };
    let _ = write!(stream, "HTTP/1.1 {status}\r\n{extra}Content-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
}

fn fetch_policy(site: &Site) -> String {
    format!(
        r#"
        [fetch]
        hosts = ["{}"]
        auth = "Bearer {{token}}"

        [[tool]]
        name = "echo"
        about = "Echo the authorization"
        request = "GET {}/{{what}}"
        "#,
        site.origin(),
        site.origin()
    )
}

// --- cred run ---

#[test]
fn run_exports_fields_and_masks_them_in_output() {
    let env = Env::new();
    env.store("app", "token", TOKEN);
    env.policy("app", "[run]\nmode = \"allow\"\nexport = { token = \"APP_TOKEN\" }\n");
    let out = env.cred(&["run", "-s", "app", "--", "sh", "-c", "echo \"out=$APP_TOKEN\"; echo \"err=$APP_TOKEN\" >&2; exit 3"]);
    assert_eq!(out.status.code(), Some(3), "the command's exit code is passed on");
    assert_eq!(stdout(&out), "out=********\n");
    assert_eq!(stderr(&out), "err=********\n");
}

#[test]
fn run_loads_resources_from_a_credfile() {
    let env = Env::new();
    env.store("app", "token", TOKEN);
    env.policy("app", "[run]\nmode = \"allow\"\nexport = { token = \"APP_TOKEN\" }\n");
    fs::write(env.dir.join(".cred"), "# resources for this repo\napp\n").unwrap();
    let out = env.cred(&["run", "--", "sh", "-c", "echo $APP_TOKEN"]);
    assert_eq!(stdout(&out), "********\n", "{}", stderr(&out));
}

#[test]
fn run_refuses_policies_that_are_not_approved_or_not_permissive() {
    let env = Env::new();
    env.store("app", "token", TOKEN);
    let run = |env: &Env| env.cred(&["run", "-s", "app", "--", "true"]);

    env.write_policy("app", "[run]\nmode = \"allow\"\nexport = { token = \"APP_TOKEN\" }\n");
    let out = run(&env);
    assert!(!out.status.success() && stderr(&out).contains("isn't approved"), "{}", stderr(&out));

    env.cred(&["policy", "approve", "app"]);
    assert!(run(&env).status.success());

    env.write_policy("app", "[run]\nmode = \"allow\"\nexport = { token = \"OTHER_VAR\" }\n");
    let out = run(&env);
    assert!(!out.status.success() && stderr(&out).contains("changed since it was approved"), "{}", stderr(&out));

    env.policy("app", "[run]\nmode = \"deny\"\nexport = { token = \"APP_TOKEN\" }\n");
    let out = run(&env);
    assert!(!out.status.success() && stderr(&out).contains("doesn't allow cred run"), "{}", stderr(&out));
}

#[test]
fn run_in_ask_mode_follows_the_touch_id_answer() {
    let env = Env::new();
    env.store("app", "token", TOKEN);
    env.policy("app", "[run]\nmode = \"ask\"\nexport = { token = \"APP_TOKEN\" }\n");
    let args = ["run", "-s", "app", "--", "sh", "-c", "echo $APP_TOKEN"];
    assert!(env.cred(&args).status.success());
    let out = env.command().args(args).env("CRED_TEST_APPROVE", "no").output().unwrap();
    assert!(!out.status.success() && stdout(&out).is_empty(), "nothing runs when Touch ID is refused");
}

// --- info, ls and policy edit ---

#[test]
fn info_and_ls_show_the_approved_rules() {
    let env = Env::new();
    env.store("app", "token", TOKEN);
    let toml = "[run]\nmode = \"ask\"\nexport = { token = \"APP_TOKEN\" }\n[fetch]\nhosts = [\"https://api.example.com\"]\nwrites = \"ask\"\nauth = \"Bearer {token}\"\n\
                [[tool]]\nname = \"item\"\nabout = \"One item\"\nrequest = \"GET https://api.example.com/items/{id}\"\n\
                [browse]\norigins = [\"https://app.example.com\"]\nscreenshots = true\n";
    env.write_policy("app", toml);

    let info = stdout(&env.cred(&["info", "app"]));
    assert!(info.contains("not approved") && info.contains("nothing in it applies until approved"), "{info}");
    assert!(!info.contains("api.example.com"), "unapproved rules aren't shown:\n{info}");
    assert!(stdout(&env.cred(&["ls"])).contains("not approved"));

    env.cred(&["policy", "approve", "app"]);
    let info = stdout(&env.cred(&["info", "app"]));
    for expected in [
        "approved",
        "hosts https://api.example.com; writes ask; auth in Authorization",
        "item: GET https://api.example.com/items/{id}",
        "pages on https://app.example.com; writes deny; screenshots",
        "exported as APP_TOKEN",
    ] {
        assert!(info.contains(expected), "missing {expected:?}:\n{info}");
    }
    assert!(!info.contains(TOKEN));
    let ls = stdout(&env.cred(&["ls"]));
    assert!(ls.contains("run:ask fetch:ask browse"), "{ls}");

    env.write_policy("app", &format!("{toml}\n# edited\n"));
    let info = stdout(&env.cred(&["info", "app"]));
    assert!(info.contains("changed since approval") && !info.contains("api.example.com"), "{info}");
    assert!(stdout(&env.cred(&["ls"])).contains("changed since approval"));
}

#[test]
fn policy_edit_shows_a_diff_against_the_approved_version() {
    let env = Env::new();
    env.policy("app", "[run]\nmode = \"ask\"\n");
    let edited = env.dir.join("edited.toml");
    fs::write(&edited, "[run]\nmode = \"allow\"\n").unwrap();

    // The "editor" replaces the file with the edited copy.
    let edit = |env: &Env| env.command().args(["policy", "edit", "app"]).env("EDITOR", format!("cp {}", edited.display())).output().unwrap();
    let out = edit(&env);
    let shown = stdout(&out);
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(shown.contains("-mode = \"ask\"\n+mode = \"allow\"\n"), "{shown}");
    assert!(!shown.contains('\x1b'), "no colors when stdout isn't a terminal");
    assert!(shown.contains("takes effect once approved"), "{shown}");
    assert!(stdout(&env.cred(&["policy", "show", "app"])).contains("changed since approval"));

    env.cred(&["policy", "approve", "app"]);
    assert!(stdout(&edit(&env)).contains("no change from the approved policy"));
}

// --- cred mcp ---

#[test]
fn mcp_handshake_and_tool_list() {
    let env = Env::new();
    let site = Site::start();
    env.store("app", "token", TOKEN);
    env.policy("app", &fetch_policy(&site));
    env.store("draft", "token", TOKEN);
    env.write_policy("draft", &fetch_policy(&site));

    let mut mcp = env.mcp();
    let init = mcp.handshake();
    assert_eq!(init["serverInfo"]["name"], "cred");
    assert_eq!(init["protocolVersion"], "2025-06-18");
    assert!(init["instructions"].as_str().unwrap().contains("without ever revealing"));
    assert_eq!(mcp.rpc("ping", json!({})), json!({}));
    assert_eq!(mcp.rpc("nope", json!({}))["code"], -32601);

    let names = mcp.tool_names();
    assert_eq!(names, ["sites", "fetch", "app_echo"], "unapproved policies and absent browse sections add nothing");
    let (is_error, sites) = mcp.call("sites", json!({}));
    assert!(!is_error && sites.contains("app: the app test site") && !sites.contains("draft"), "{sites}");
}

#[test]
fn mcp_fetch_adds_credentials_and_masks_the_response() {
    let env = Env::new();
    let site = Site::start();
    env.store("app", "token", TOKEN);
    env.policy("app", &fetch_policy(&site));

    let mut mcp = env.mcp();
    mcp.handshake();
    let (is_error, reply) = mcp.call("fetch", json!({ "site": "app", "method": "GET", "url": site.url("/echo") }));
    assert!(!is_error, "{reply}");
    assert!(reply.contains("HTTP 200") && reply.contains("authorization: Bearer ********"), "{reply}");
    assert!(!reply.contains(TOKEN));
    assert!(site.seen().iter().any(|r| r.contains(&format!("authorization: Bearer {TOKEN}"))), "{:?}", site.seen());

    let (is_error, reply) = mcp.call("app_echo", json!({ "what": "echo" }));
    assert!(!is_error && reply.contains("authorization: Bearer ********"), "{reply}");
}

#[test]
fn mcp_fetch_enforces_the_policy() {
    let env = Env::new();
    let site = Site::start();
    env.store("app", "token", TOKEN);
    env.policy("app", &fetch_policy(&site));
    let mut mcp = env.mcp();
    mcp.handshake();
    let before = site.seen().len();

    let (is_error, reply) = mcp.call("fetch", json!({ "site": "app", "method": "GET", "url": "http://127.0.0.2:1/x" }));
    assert!(is_error && reply.contains("isn't one of this site's hosts"), "{reply}");
    let (is_error, reply) = mcp.call("fetch", json!({ "site": "app", "method": "POST", "url": site.url("/echo"), "body": "{}" }));
    assert!(is_error && reply.contains("doesn't allow POST"), "{reply}");
    let (is_error, reply) = mcp.call("fetch", json!({ "site": "other", "method": "GET", "url": site.url("/echo") }));
    assert!(is_error && reply.contains("unknown site"), "{reply}");
    assert_eq!(site.seen().len(), before, "refused requests never reach the site");

    // A redirect is reported, not followed: the credentials would go wherever it points.
    let (is_error, reply) = mcp.call("fetch", json!({ "site": "app", "method": "GET", "url": site.url("/redirect") }));
    assert!(!is_error && reply.contains("HTTP 302") && reply.contains("location:"), "{reply}");
    assert_eq!(site.seen().len(), before + 1);

    // The policy is checked again on every call.
    env.write_policy("app", &format!("{}\n# edited\n", fetch_policy(&site)));
    let (is_error, reply) = mcp.call("fetch", json!({ "site": "app", "method": "GET", "url": site.url("/echo") }));
    assert!(is_error && reply.contains("changed since it was approved"), "{reply}");
}

#[test]
fn mcp_asks_for_consent_and_for_writes() {
    let env = Env::new();
    let site = Site::start();
    env.store("app", "token", TOKEN);
    env.policy("app", &fetch_policy(&site));
    let get = json!({ "site": "app", "method": "GET", "url": site.url("/echo") });

    // The default policy asks for Touch ID when an agent first uses the site; refused here.
    let mut mcp = Mcp::start(env.command().arg("mcp").env("CRED_TEST_APPROVE", "no"));
    mcp.handshake();
    let (is_error, reply) = mcp.call("fetch", get.clone());
    assert!(is_error && reply.contains("not approved"), "{reply}");

    // Without consent, writes still follow their own rule: ask means Touch ID.
    let policy = format!("[agent]\nconsent = \"none\"\n[fetch]\nhosts = [\"{}\"]\nwrites = \"ask\"\n", site.origin());
    env.policy("app", &policy);
    let post = json!({ "site": "app", "method": "POST", "url": site.url("/echo"), "body": "{}" });
    let mut refused = Mcp::start(env.command().arg("mcp").env("CRED_TEST_APPROVE", "no"));
    refused.handshake();
    assert!(!refused.call("fetch", get).0, "reads need no consent here");
    let (is_error, reply) = refused.call("fetch", post.clone());
    assert!(is_error && reply.contains("not approved"), "{reply}");
    let mut allowed = env.mcp();
    allowed.handshake();
    let (is_error, reply) = allowed.call("fetch", post);
    assert!(!is_error && reply.contains("HTTP 200"), "{reply}");
}

// --- opt-in: the browser and the real Touch ID ---

fn opt_in(name: &str) -> bool {
    let on = env::var_os(name).is_some();
    if !on {
        eprintln!("skipped: set {name}=1 to run this test");
    }
    on
}

#[test]
#[ignore = "needs Node, the runner's dependencies and Chromium: CRED_E2E_BROWSER=1"]
fn browser_opens_a_page_signed_in_and_masks_it() {
    if !opt_in("CRED_E2E_BROWSER") {
        return;
    }
    let env = Env::new();
    let site = Site::start();
    env.store("app", "token", TOKEN);
    env.policy(
        "app",
        &format!(
            "[agent]\nconsent = \"none\"\n[browse]\norigins = [\"{0}\"]\nstart = \"{0}/page\"\ncookies = [{{ name = \"session\", field = \"token\", domain = \"127.0.0.1\" }}]\n",
            site.origin()
        ),
    );
    let runner = env::var("CRED_RUNNER_DIR").unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("runner").display().to_string());
    // The test's HOME is empty, so Playwright must be told where the real one keeps Chromium.
    let browsers = env::var("PLAYWRIGHT_BROWSERS_PATH")
        .unwrap_or_else(|_| format!("{}/Library/Caches/ms-playwright", env::var("HOME").unwrap()));
    let mut mcp = Mcp::start(env.command().arg("mcp").env("CRED_RUNNER_DIR", runner).env("PLAYWRIGHT_BROWSERS_PATH", browsers));
    mcp.handshake();
    assert!(mcp.tool_names().contains(&"browse_open".to_string()));

    let (is_error, page) = mcp.call("browse_open", json!({ "site": "app" }));
    assert!(!is_error, "{page}");
    assert!(page.contains("Hello e2e"), "{page}");
    assert!(page.contains("cookie: session=********"), "the page got the session, masked for the agent:\n{page}");
    assert!(!page.contains(TOKEN));
    assert!(site.seen().iter().any(|r| r.contains(&format!("session={TOKEN}"))), "{:?}", site.seen());

    let (is_error, reply) = mcp.call("browse_goto", json!({ "url": "https://elsewhere.example.com/" }));
    assert!(is_error || reply.to_lowercase().contains("blocked"), "{reply}");
    assert_eq!(mcp.call("browse_close", json!({})), (false, "browser closed".to_string()));
}

#[test]
#[ignore = "asks a human for Touch ID and uses the real Keychain: CRED_E2E_INTERACTIVE=1"]
fn touch_id_approval_pins_the_policy_in_the_real_keychain() {
    if !opt_in("CRED_E2E_INTERACTIVE") {
        return;
    }
    let env = Env::new();
    // A throwaway resource name; its only Keychain item is the approval, removed at the end.
    let res = format!("e2e-touchid-{}", std::process::id());
    fs::write(env.dir.join("index.json"), json!({ res.clone(): { "fields": { "token": {} } } }).to_string()).unwrap();
    env.write_policy(&res, "[run]\nmode = \"deny\"\n");
    let real = || {
        let mut cmd = env.command();
        cmd.env("HOME", env::var("HOME").unwrap()).env_remove("CRED_TEST_KEYCHAIN").env_remove("CRED_TEST_APPROVE");
        cmd
    };

    eprintln!("Touch ID prompt: approve the policy for {res}");
    let out = real().args(["policy", "approve", &res]).output().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let shown = stdout(&real().args(["policy", "show", &res]).output().unwrap());
    let removed = real().args(["rm", &res]).output().unwrap();
    assert!(shown.contains("(approved)"), "{shown}");
    assert!(removed.status.success(), "{}", stderr(&removed));
}

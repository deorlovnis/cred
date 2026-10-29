//! The smart door: what happens to the requests inside a box's TLS connection, once the door
//! has ended TLS (the guest's side) and opened its own to the site (the upstream side). Each
//! request is read, judged, and streamed on, then its answer is streamed back:
//!
//! - **Reads and writes.** GET, HEAD and OPTIONS are reads, and so is a POST to
//!   `.../git-upload-pack` with git's content type (that is how `git fetch` and `git clone`
//!   ask for objects). Everything else is a write, and so is anything that asks for an
//!   `Upgrade` (WebSocket). Reads pass. A write follows the site's `[fetch] writes` on the
//!   hosts of one of the box's sites, and `[net] writes` and `allow_writes` everywhere else;
//!   `ask` is a Touch ID per write. A refused request gets a 403 with the reason, and the
//!   connection stays usable.
//! - **Credentials for any tool.** On the hosts of one of the box's sites (read fresh from its
//!   approved policy, like the model gateway does), the site's auth header and fixed headers
//!   replace whatever the guest sent, whatever tool sent it.
//! - **Masking.** On those same hosts the answer is masked with the site's stored values as it
//!   streams (see `mask::Stream`). A masked body changes length, so it is sent chunked
//!   (`Content-Length` is dropped), and the upstream is asked for no compression. A site that
//!   compresses anyway can't be masked, so its answer is refused. The agent's own pages on
//!   other hosts are not masked: there is nothing to mask them against.
//! - **The Host header** must be the host the guest connected to, or a guest could tunnel to
//!   one allowed host and ask for another.
//! - **Pages.** A request from a page in the box's browser VM (see `page`) is judged by its
//!   site's `[browse]` rules, not the box's: `writes` and `allow_writes` instead of `[net]`.
//!   No credentials are added to it, and its answer is not masked here (cred masks what the
//!   runner reports): the session is in the browser already.
//! - **The log:** one chained line per request, with the method and the masked URL, never
//!   headers or bodies.
//!
//! The functions here work on any pair of streams, so tests run them over plain sockets.

use std::io::{self, BufReader, Read, Write};

use anyhow::{Result, anyhow, bail};
use url::Url;

use super::addr::split_target;
use super::gateway::HOP_BY_HOP;
use super::http::{self, Body, Framing, Head};
use super::{Entry, Shared, page};
use crate::audit::mask_url;
use crate::index::Index;
use crate::mask::{Masker, Stream};
use crate::policy::{self, Fetch, Mode};
use crate::{approve, keychain};

/// A refused request's body is read and dropped, if it is no longer than this; a longer one ends
/// the connection instead.
const MAX_DISCARD: u64 = 64 * 1024 * 1024;

/// `[net]`: what the box's own requests may do on hosts no site covers.
#[derive(Default, Clone)]
pub struct Net {
    /// Requests other than reads: `deny`, `ask` (Touch ID each) or `allow`.
    pub writes: Mode,
    /// URL prefixes (`https://host/path`) that may receive writes whatever `writes` says. A
    /// prefix ends at a `/` of the path: `https://a.com/api` covers `/api` and `/api/x`, not `/apix`.
    pub allow_writes: Vec<String>,
}

/// Whose connection it is.
pub(super) enum Caller {
    /// The agent's VM: the box's `[net]`, and the credentials of the sites it has.
    Agent,
    /// A page of this site, in the browser VM.
    Page(String),
}

impl Caller {
    pub fn site(&self) -> Option<&str> {
        match self {
            Caller::Agent => None,
            Caller::Page(site) => Some(site),
        }
    }
}

/// What `serve` needs to know about the connection.
pub(super) struct Ctx<'a> {
    /// The door: its box, its sites, its log.
    pub shared: &'a Shared,
    /// The host the guest asked to be connected to (as `addr::split_target` gives it).
    pub host: &'a str,
    pub caller: &'a Caller,
}

/// A request body this small is kept while it is sent, so the request can be sent again if the
/// site turns out to have closed the connection.
pub(super) const RETRY_BODY: usize = 1024 * 1024;

/// Serve requests from the guest (TLS already ended) until it closes. `connect` makes the
/// connection to the site (verified TLS to the vetted address); it is called when the first
/// request that is let through needs it, and again if the site has closed the connection by the
/// time a later request uses it (see `call_site`). Returns the request body bytes sent up and the
/// response body bytes received (before masking), over every request.
pub(super) fn serve<G: Read + Write, U: Read + Write>(guest: G, mut connect: impl FnMut() -> Result<U>, ctx: &Ctx) -> (u64, u64) {
    let mut guest = BufReader::new(guest);
    let mut upstream: Option<BufReader<U>> = None;
    let mut counts = Counts::default();
    while !ctx.shared.stopped() {
        if !matches!(exchange(&mut guest, &mut upstream, &mut connect, ctx, &mut counts), Ok(true)) {
            break;
        }
    }
    (counts.up, counts.down)
}

#[derive(Default)]
struct Counts {
    up: u64,
    down: u64,
}

// --- what a request is ---

#[derive(Debug, PartialEq, Clone, Copy)]
enum Kind {
    Read,
    Write,
    /// Asks to switch protocols (WebSocket): a write that can't be passed on (see `exchange`).
    Upgrade,
}

fn classify(head: &Head, method: &str, target: &str) -> Kind {
    let upgrades = head.header("upgrade").is_some() || connection_tokens(head).iter().any(|t| t == "upgrade");
    if upgrades {
        return Kind::Upgrade;
    }
    match method {
        "GET" | "HEAD" | "OPTIONS" => Kind::Read,
        "POST" if git_fetch(head, target) => Kind::Read,
        _ => Kind::Write,
    }
}

/// A `git fetch` or `git clone` over HTTP: git POSTs the objects it wants to `.../git-upload-pack`.
fn git_fetch(head: &Head, target: &str) -> bool {
    let path = target.split('?').next().unwrap_or("");
    let media = head.header("content-type").and_then(|t| t.split(';').next()).unwrap_or("").trim();
    path.ends_with("/git-upload-pack") && media.eq_ignore_ascii_case("application/x-git-upload-pack-request")
}

/// The lower-case tokens of the `Connection` headers.
fn connection_tokens(head: &Head) -> Vec<String> {
    head.headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| v.split(',').map(|t| t.trim().to_ascii_lowercase()))
        .filter(|t| !t.is_empty())
        .collect()
}

/// Whether the Host header names the host the guest connected to (default port only).
fn host_matches(header: Option<&str>, host: &str) -> bool {
    let Some(value) = header else { return false };
    let named = split_target(value).filter(|(_, port)| *port == 443).or_else(|| split_target(&format!("{value}:443")));
    named.is_some_and(|(name, _)| name == host)
}

/// A target the guest may send inside TLS: a path, or `*` for `OPTIONS *`.
fn valid_target(target: &str) -> bool {
    (target.starts_with('/') || target == "*") && target.bytes().all(|b| b > b' ' && b != 0x7f)
}

fn full_url(host: &str, target: &str) -> String {
    let authority = if host.contains(':') { format!("[{host}]") } else { host.to_string() };
    format!("https://{authority}{}", if target == "*" { "" } else { target })
}

// --- allow_writes ---

/// A `[net] allow_writes` entry, checked: `https://host[/path]`, default port, no user, query or
/// fragment, and no wildcards.
pub fn parse_prefix(entry: &str) -> Result<Url> {
    let url = Url::parse(entry).map_err(|e| anyhow!("{e}"))?;
    if url.scheme() != "https" || url.host_str().is_none_or(|h| h.is_empty() || h.contains('*')) {
        bail!("must be an https URL like https://api.example.com/search");
    }
    if !url.username().is_empty() || url.password().is_some() || url.port().is_some() || url.query().is_some() || url.fragment().is_some() {
        bail!("must be just https://host/path (default port, no user, query or fragment)");
    }
    Ok(url)
}

/// Whether a request is under one of the prefixes: same host, and a path that is the prefix's or
/// continues it after a `/`. Dot segments are resolved first (`/api/../admin` is `/admin`); a
/// path with an encoded slash or a backslash matches nothing, since servers differ on those.
fn under_prefix(prefixes: &[String], host: &str, target: &str) -> bool {
    let raw_path = target.split(['?', '#']).next().unwrap_or("");
    let lower = raw_path.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") || raw_path.contains('\\') || target == "*" {
        return false;
    }
    let Ok(request) = Url::parse(&full_url(host, target)) else { return false };
    prefixes.iter().filter_map(|p| parse_prefix(p).ok()).any(|prefix| {
        let base = prefix.path().trim_end_matches('/');
        prefix.host_str() == request.host_str() && (request.path() == base || request.path().starts_with(&format!("{base}/")))
    })
}

// --- the box's sites ---

/// What a site of the box does to the requests on its hosts.
struct Site {
    name: String,
    writes: Mode,
    /// Headers the request ends up with, whatever the guest sent: the policy's fixed ones, then
    /// the auth header.
    headers: Vec<(String, String)>,
    /// What the answers are masked with.
    masker: Masker,
}

impl Site {
    fn sets(&self, name: &str) -> bool {
        self.headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
    }
}

/// The site of the box that has this host, from its approved policy as it is now: a policy
/// that was changed or revoked since the box started covers nothing. `Err` if the site covers
/// the host but its credentials can't be had.
fn site_for(sh: &Shared, host: &str) -> Result<Option<Site>> {
    for name in &sh.cfg.sites {
        let Ok(approved) = policy::load(name) else { continue };
        match &approved.policy.fetch {
            Some(fetch) if fetch.covers_host(host) => return site_of(name, fetch).map(Some),
            _ => {}
        }
    }
    Ok(None)
}

fn site_of(name: &str, fetch: &Fetch) -> Result<Site> {
    // Fields that expire are renewed first, as cred's own fetch does.
    crate::refresh::refresh_due(&[name.to_string()], false, false);
    let mut secrets = Index::load().map(|index| index.values(name)).unwrap_or_default();
    let mut headers: Vec<(String, String)> = fetch.headers.iter().map(|(n, v)| (n.clone(), v.clone())).collect();
    if let Some(template) = &fetch.auth {
        let auth = policy::fill(template, |field| keychain::get(name, field).ok_or_else(|| anyhow!("{name}/{field} isn't stored (cred set {name} {field})")))?;
        // The assembled header may hold the secret in a form no field has ("Basic <base64>").
        secrets.extend(auth.split_whitespace().map(str::to_string));
        secrets.push(auth.clone());
        headers.retain(|(n, _)| !n.eq_ignore_ascii_case(&fetch.auth_header));
        headers.push((fetch.auth_header.clone(), auth));
    }
    if let Some((n, _)) = headers.iter().find(|(n, v)| n.bytes().any(|b| b <= b' ' || b == b':') || v.bytes().any(|b| b < b' ' && b != b'\t' || b == 0x7f)) {
        bail!("the policy for {name} has a header ({n}) that can't be sent");
    }
    Ok(Site { name: name.to_string(), writes: fetch.writes, headers, masker: Masker::new(secrets) })
}

// --- one request ---

/// Why a request got no further.
struct Refusal {
    status: u16,
    decision: &'static str,
    message: String,
}

fn refusal(status: u16, decision: &'static str, message: impl Into<String>) -> Refusal {
    Refusal { status, decision, message: message.into() }
}

/// Whose rules decide about writes.
enum Rules<'a> {
    /// The box's `[net]`, for the agent's requests to hosts no site covers.
    Net,
    /// A site's `[fetch]`, for the agent's requests to the site's hosts.
    Fetch(&'a Site),
    /// A site's `[browse]`, for its pages.
    Page(&'a page::Rules),
}

/// What the request does at this host: `allowed`, or `asked:yes` after Touch ID, or why not.
fn decide(sh: &Shared, kind: Kind, rules: &Rules, method: &str, host: &str, target: &str, url: &str) -> Result<&'static str, Refusal> {
    if kind == Kind::Read {
        return Ok("allowed");
    }
    // A site rules its own hosts; the box's exceptions are for the rest.
    let (mode, who, hint) = match rules {
        Rules::Fetch(site) => (site.writes, format!("the policy for {}", site.name), ""),
        Rules::Page(page) => {
            let mode = if under_prefix(&page.allow_writes, host, target) { Mode::Allow } else { page.writes };
            (mode, format!("the [browse] policy for {}", page.site), "")
        }
        Rules::Net => {
            let mode = if under_prefix(&sh.cfg.net.allow_writes, host, target) { Mode::Allow } else { sh.cfg.net.writes };
            (mode, format!("the policy of box {}", sh.cfg.name), " ([net] writes, allow_writes)")
        }
    };
    match (mode, kind) {
        (Mode::Deny, _) => Err(refusal(403, "blocked:writes", format!("{who} doesn't allow {method} requests here{hint}"))),
        (_, Kind::Upgrade) => Err(refusal(501, "blocked:upgrade", "the door can't carry an upgraded connection (WebSocket) yet")),
        (Mode::Ask, _) => match approve::confirm(&format!("let box {} send {method} {url}", sh.cfg.name)) {
            Ok(()) => Ok("asked:yes"),
            Err(_) => Err(refusal(403, "asked:no", format!("{method} {url} wasn't approved"))),
        },
        (Mode::Allow, _) => Ok("allowed"),
    }
}

/// One request and its answer. `Ok(true)` if the connection can serve another.
fn exchange<G: Read + Write, U: Read + Write>(
    guest: &mut BufReader<G>,
    upstream: &mut Option<BufReader<U>>,
    connect: &mut impl FnMut() -> Result<U>,
    ctx: &Ctx,
    counts: &mut Counts,
) -> io::Result<bool> {
    let sh = ctx.shared;
    let plain = Masker::new([]);
    // The log line has this request's bytes, not the connection's so far.
    let before = (counts.up, counts.down);
    let entry = |method: &str, url: &str, status: Option<u16>, decision: &str, counts: &Counts| Entry {
        site: ctx.caller.site().map(String::from),
        host: Some(ctx.host.to_string()),
        method: Some(method.to_string()),
        url: Some(url.to_string()),
        status,
        up: counts.up - before.0,
        down: counts.down - before.1,
        ..Entry::new("request", decision)
    };

    let head = match http::read_head(guest) {
        Ok(Some(head)) => head,
        Ok(None) => return Ok(false),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => return end_with(sh, guest, entry("", "", Some(400), "blocked:bad-request", counts), "bad request"),
        Err(e) => return Err(e),
    };
    let (method, target, version) = match head.parts() {
        Some((m, t, v)) if matches!(v, "HTTP/1.1" | "HTTP/1.0") && valid_target(t) => (m, t, v),
        _ => return end_with(sh, guest, entry("", "", Some(400), "blocked:bad-request", counts), "bad request"),
    };
    let method_shown: String = method.chars().filter(|c| c.is_ascii_graphic()).take(16).collect();
    let framing = match http::request_framing(&head) {
        Ok(framing) => framing,
        Err(_) => return end_with(sh, guest, entry(&method_shown, "", Some(400), "blocked:bad-request", counts), "bad request"),
    };
    if !host_matches(head.header("host"), ctx.host) {
        let url = mask_url(&full_url(ctx.host, target), &plain);
        let message = format!("the Host header must be {}, the host this connection is for", ctx.host);
        return end_with(sh, guest, entry(&method_shown, &url, Some(421), "blocked:host-mismatch", counts), &message);
    }

    // A page has the site's browser rules and no credentials added; the agent has the credentials
    // of the site that covers the host, or the box's rules.
    let page_rules = match ctx.caller {
        Caller::Page(name) => match page::rules(name) {
            Ok(rules) => Some(rules),
            Err(e) => {
                let url = mask_url(&full_url(ctx.host, target), &plain);
                sh.log.write(&entry(&method_shown, &url, Some(403), "blocked:policy", counts));
                return end_with_message(guest, 403, &format!("{e:#}"));
            }
        },
        Caller::Agent => None,
    };
    let site = match page_rules.as_ref().map_or_else(|| site_for(sh, ctx.host), |_| Ok(None)) {
        Ok(site) => site,
        Err(e) => {
            let url = mask_url(&full_url(ctx.host, target), &plain);
            let message = format!("{e:#}");
            sh.log.write(&entry(&method_shown, &url, Some(502), "failed:key", counts));
            return end_with_message(guest, 502, &message);
        }
    };
    let url = mask_url(&full_url(ctx.host, target), site.as_ref().map_or(&plain, |s| &s.masker));
    let keep = head.keep_alive();

    let kind = classify(&head, method, target);
    let rules = match (&page_rules, &site) {
        (Some(page), _) => Rules::Page(page),
        (None, Some(site)) => Rules::Fetch(site),
        (None, None) => Rules::Net,
    };
    let decision = match decide(sh, kind, &rules, &method_shown, ctx.host, target, &url) {
        Ok(decision) => decision,
        Err(r) => {
            sh.log.write(&entry(&method_shown, &url, Some(r.status), r.decision, counts));
            return refuse(guest, &head, framing, &r, keep);
        }
    };

    // The request, on its way: what the site sets replaces what the guest sent.
    if head.header("expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue")) {
        guest.get_mut().write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
        guest.get_mut().flush()?;
    }
    let answer = match call_site(guest, upstream, connect, &head, method, target, framing, site.as_ref(), &mut counts.up) {
        Ok(answer) => answer,
        Err(Failure::Guest(e)) => return Err(e),
        Err(Failure::Site { decision, message }) => {
            sh.log.write(&entry(&method_shown, &url, Some(502), decision, counts));
            return end_with_message(guest, 502, message);
        }
    };
    let upstream = upstream.as_mut().expect("call_site left a connection");
    let status = answer.status().unwrap_or(502);
    let Ok(answer_framing) = http::response_framing(&answer, method, status) else {
        sh.log.write(&entry(&method_shown, &url, Some(502), "failed:upstream", counts));
        return end_with_message(guest, 502, "the site's answer can't be read");
    };
    let masker = site.as_ref().map(|s| &s.masker);
    let encoded = answer.header("content-encoding").is_some_and(|e| !e.trim().eq_ignore_ascii_case("identity"));
    if masker.is_some() && encoded && answer_framing != Framing::None {
        sh.log.write(&entry(&method_shown, &url, Some(502), "blocked:encoded", counts));
        return end_with_message(guest, 502, "the site compressed its answer, so cred can't mask it");
    }

    let shape = shape_of(answer_framing, masker.is_some(), version == "HTTP/1.1");
    let keep = keep && shape != Shape::Close && !connection_tokens(&answer).iter().any(|t| t == "close");
    let relayed = relay_answer(guest, upstream, &answer, status, answer_framing, shape, keep, masker, &mut counts.down);
    match relayed {
        Ok(()) => {
            sh.log.write(&entry(&method_shown, &url, Some(status), decision, counts));
            Ok(keep)
        }
        Err(e) => {
            sh.log.write(&entry(&method_shown, &url, Some(status), &format!("failed:stream: {}", e.kind()), counts));
            Err(e)
        }
    }
}

/// Log a request the door turned away before it read further, and end the connection.
fn end_with(sh: &Shared, guest: &mut BufReader<impl Read + Write>, entry: Entry, message: &str) -> io::Result<bool> {
    let status = entry.status.unwrap_or(400);
    sh.log.write(&entry);
    end_with_message(guest, status, message)
}

fn end_with_message(guest: &mut BufReader<impl Read + Write>, status: u16, message: &str) -> io::Result<bool> {
    http::respond(guest.get_mut(), status, "text/plain", format!("cred: {message}\n").as_bytes(), false).map(|()| false)
}

/// Answer a refused request. The connection goes on if the request's body can be read past.
fn refuse<G: Read + Write>(guest: &mut BufReader<G>, head: &Head, framing: Framing, r: &Refusal, keep: bool) -> io::Result<bool> {
    // A client that waits for 100 Continue won't send the body of a refused request.
    let waits = head.header("expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue"));
    let keep = keep && !waits;
    http::respond(guest.get_mut(), r.status, "text/plain", format!("cred: {}\n", r.message).as_bytes(), keep)?;
    if !keep {
        return Ok(false);
    }
    Ok(Body::new(guest, framing).discard(MAX_DISCARD).unwrap_or(false))
}

/// The headers the site gets: the guest's, without its connection-level headers, framing and
/// `Expect` (rebuilt here), and without whatever the box's site sets itself.
fn request_headers(head: &Head, framing: Framing, method: &str, site: Option<&Site>) -> Vec<(String, String)> {
    let named = connection_tokens(head);
    let mut out: Vec<(String, String)> = head
        .headers
        .iter()
        .filter(|(name, _)| {
            let name = name.to_ascii_lowercase();
            let dropped = HOP_BY_HOP.contains(&name.as_str())
                || named.contains(&name)
                || matches!(name.as_str(), "content-length" | "expect")
                || (site.is_some() && name == "accept-encoding")
                || site.is_some_and(|s| s.sets(&name));
            !dropped
        })
        .cloned()
        .collect();
    match framing {
        Framing::Length(n) => out.push(("content-length".into(), n.to_string())),
        Framing::Chunked => out.push(("transfer-encoding".into(), "chunked".into())),
        Framing::None if matches!(method, "POST" | "PUT" | "PATCH") => out.push(("content-length".into(), "0".into())),
        Framing::None | Framing::UntilClose => {}
    }
    if let Some(site) = site {
        out.extend(site.headers.iter().cloned());
        // Masking needs to see the bytes.
        out.push(("accept-encoding".into(), "identity".into()));
    }
    out
}

/// Why a request got no answer from the site.
enum Failure {
    /// The guest's side broke: nothing more can be said to it.
    Guest(io::Error),
    Site { decision: &'static str, message: &'static str },
}

fn site_failure(decision: &'static str, message: &'static str) -> Failure {
    Failure::Site { decision, message }
}

/// What the site sent first, if anything.
enum Answer {
    Head(Head),
    /// The connection ended before a single byte of an answer: the site had closed it.
    Gone,
    /// Something arrived, but no answer that can be used.
    Broken,
}

fn read_answer<U: Read + Write>(upstream: &mut BufReader<U>) -> Answer {
    let mut interim = false;
    loop {
        match http::read_head(upstream) {
            Ok(Some(h)) if h.status().is_some_and(|s| (100..200).contains(&s)) && h.status() != Some(101) => interim = true,
            Ok(Some(h)) if h.status().is_some() && h.status() != Some(101) => return Answer::Head(h),
            Ok(None) if !interim => return Answer::Gone,
            Err(e) if !interim && matches!(e.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe | io::ErrorKind::NotConnected) => return Answer::Gone,
            _ => return Answer::Broken,
        }
    }
}

/// The request body as far as it was kept for a second try.
#[derive(Default)]
struct Kept {
    data: Vec<u8>,
    /// More than `RETRY_BODY`: it can't be sent again.
    overflow: bool,
}

impl Kept {
    fn push(&mut self, piece: &[u8]) {
        if self.overflow {
            return;
        }
        if self.data.len() + piece.len() > RETRY_BODY {
            self.overflow = true;
            self.data = Vec::new();
        } else {
            self.data.extend_from_slice(piece);
        }
    }
}

/// Send the request to the site and read the start of its answer. The connection is made here
/// if there is none. If it was in use before and turns out to have been closed by the site, with
/// no byte of an answer, the request is sent once more on a new connection, as long as the whole
/// body was kept. Nothing is sent again once any of an answer has arrived.
#[allow(clippy::too_many_arguments)]
fn call_site<G: Read + Write, U: Read + Write>(
    guest: &mut BufReader<G>,
    upstream: &mut Option<BufReader<U>>,
    connect: &mut impl FnMut() -> Result<U>,
    head: &Head,
    method: &str,
    target: &str,
    framing: Framing,
    site: Option<&Site>,
    sent: &mut u64,
) -> Result<Head, Failure> {
    let mut dial = |upstream: &mut Option<BufReader<U>>| match connect() {
        Ok(stream) => {
            *upstream = Some(BufReader::new(stream));
            Ok(())
        }
        Err(_) => Err(site_failure("failed:connect", "cred couldn't connect to the site")),
    };
    let reused = upstream.is_some();
    if !reused {
        dial(upstream)?;
    }
    let (line, headers) = (format!("{method} {target} HTTP/1.1"), request_headers(head, framing, method, site));
    let mut kept = Kept::default();
    let conn = upstream.as_mut().expect("connected");
    let delivered = stream_request(guest, conn.get_mut(), &line, &headers, framing, sent, &mut kept).map_err(Failure::Guest)?;
    match read_answer(conn) {
        Answer::Head(answer) => return Ok(answer),
        Answer::Gone if reused && !kept.overflow => {}
        Answer::Gone | Answer::Broken => {
            let message = if delivered { "the site gave no usable answer" } else { "cred couldn't send the request to the site" };
            return Err(site_failure("failed:upstream", message));
        }
    }
    // The site had closed the connection while it sat idle: a new one, and the same request.
    dial(upstream)?;
    let conn = upstream.as_mut().expect("connected");
    let again = http::write_head(conn.get_mut(), &line, &headers).and_then(|()| write_body(conn.get_mut(), framing, &kept.data));
    match again {
        Ok(()) => match read_answer(conn) {
            Answer::Head(answer) => Ok(answer),
            _ => Err(site_failure("failed:upstream", "the site gave no usable answer")),
        },
        Err(_) => Err(site_failure("failed:upstream", "cred couldn't send the request to the site")),
    }
}

/// The body of a request, all at once (for sending it again).
fn write_body(out: &mut impl Write, framing: Framing, data: &[u8]) -> io::Result<()> {
    if framing == Framing::Chunked {
        http::write_chunk(out, data)?;
        out.write_all(b"0\r\n\r\n")?;
    } else {
        out.write_all(data)?;
    }
    out.flush()
}

/// Send the request, its body streamed as it arrives from the guest, and keep the body if it is
/// small. `Ok(false)` if the site's side broke: the body is then read to its end if it can be
/// kept, so the request can be sent again. `Err` if the guest's side broke.
fn stream_request<G: Read + Write>(
    guest: &mut BufReader<G>,
    out: &mut impl Write,
    line: &str,
    headers: &[(String, String)],
    framing: Framing,
    sent: &mut u64,
    kept: &mut Kept,
) -> io::Result<bool> {
    let mut ok = http::write_head(out, line, headers).and_then(|()| out.flush()).is_ok();
    let mut body = Body::new(guest, framing);
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = match body.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            break;
        }
        *sent += n as u64;
        kept.push(&buf[..n]);
        if ok {
            let piece = if framing == Framing::Chunked { http::write_chunk(out, &buf[..n]) } else { out.write_all(&buf[..n]) };
            ok = piece.and_then(|()| out.flush()).is_ok();
        }
        if !ok && kept.overflow {
            // Nothing can be done with the rest of the body.
            return Ok(false);
        }
    }
    if ok && framing == Framing::Chunked {
        ok = out.write_all(b"0\r\n\r\n").is_ok();
    }
    Ok(ok && out.flush().is_ok())
}

/// How an answer's body goes to the guest.
#[derive(Debug, PartialEq, Clone, Copy)]
enum Shape {
    /// As it came: no body, or the upstream's own `Content-Length`.
    Plain,
    /// Chunked, whatever the upstream used (a masked body has no length known in advance).
    Chunked,
    /// Until the connection closes, for what has no length and a guest that can't take chunks.
    Close,
}

fn shape_of(framing: Framing, masked: bool, chunks_ok: bool) -> Shape {
    match framing {
        Framing::None => Shape::Plain,
        Framing::Length(_) if !masked => Shape::Plain,
        Framing::UntilClose => Shape::Close,
        _ if chunks_ok => Shape::Chunked,
        _ => Shape::Close,
    }
}

#[allow(clippy::too_many_arguments)]
fn relay_answer<G: Read + Write, U: Read + Write>(
    guest: &mut BufReader<G>,
    upstream: &mut BufReader<U>,
    answer: &Head,
    status: u16,
    framing: Framing,
    shape: Shape,
    keep: bool,
    masker: Option<&Masker>,
    received: &mut u64,
) -> io::Result<()> {
    let reason = answer.line.splitn(3, ' ').nth(2).filter(|r| !r.is_empty()).map_or(http::reason(status), |r| r);
    let named = connection_tokens(answer);
    let mut headers: Vec<(String, String)> = answer
        .headers
        .iter()
        .filter(|(name, _)| {
            let name = name.to_ascii_lowercase();
            // Where there is no body, a length only says what a GET would get: it stays.
            let length = name == "content-length" && framing != Framing::None;
            let dropped = HOP_BY_HOP.contains(&name.as_str()) || named.contains(&name) || length || (masker.is_some() && name == "content-md5");
            !dropped
        })
        .cloned()
        .collect();
    if let (Shape::Plain, Framing::Length(n)) = (shape, framing) {
        headers.push(("content-length".into(), n.to_string()));
    }
    if shape == Shape::Chunked {
        headers.push(("transfer-encoding".into(), "chunked".into()));
    }
    headers.push(("connection".into(), if keep { "keep-alive" } else { "close" }.into()));
    let out = guest.get_mut();
    http::write_head(out, &format!("HTTP/1.1 {status} {reason}"), &headers)?;
    out.flush()?;

    let mut body = Body::new(upstream, framing);
    let mut stream = masker.map(Stream::new);
    let mut buf = [0u8; 16 * 1024];
    let mut emit = |piece: &[u8]| -> io::Result<()> {
        if piece.is_empty() {
            return Ok(());
        }
        if shape == Shape::Chunked {
            http::write_chunk(out, piece)?;
        } else {
            out.write_all(piece)?;
        }
        // Each piece goes on at once: events must not wait for the next.
        out.flush()
    };
    loop {
        let n = match body.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            break;
        }
        *received += n as u64;
        match &mut stream {
            Some(stream) => emit(&stream.push(&buf[..n]))?,
            None => emit(&buf[..n])?,
        }
    }
    if let Some(stream) = &mut stream {
        emit(&stream.finish())?;
    }
    if shape == Shape::Chunked {
        out.write_all(b"0\r\n\r\n")?;
        out.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(line: &str, headers: &[(&str, &str)]) -> Head {
        Head { line: line.into(), headers: headers.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect() }
    }

    fn kind(method: &str, target: &str, headers: &[(&str, &str)]) -> Kind {
        classify(&head(&format!("{method} {target} HTTP/1.1"), headers), method, target)
    }

    #[test]
    fn reads_are_get_head_options_and_git_fetches() {
        for method in ["GET", "HEAD", "OPTIONS"] {
            assert_eq!(kind(method, "/x?y=1", &[]), Kind::Read, "{method}");
        }
        let git = [("Content-Type", "application/x-git-upload-pack-request")];
        assert_eq!(kind("POST", "/owner/repo.git/git-upload-pack", &git), Kind::Read);
        assert_eq!(kind("POST", "/git-upload-pack?x=1", &[("content-type", "Application/X-Git-Upload-Pack-Request; charset=x")]), Kind::Read);
        // Pushing, other POSTs, and a look-alike are writes.
        assert_eq!(kind("POST", "/owner/repo.git/git-receive-pack", &[("content-type", "application/x-git-receive-pack-request")]), Kind::Write);
        assert_eq!(kind("POST", "/owner/repo.git/git-receive-pack", &git), Kind::Write);
        assert_eq!(kind("POST", "/owner/repo.git/git-upload-pack", &[("content-type", "application/json")]), Kind::Write);
        assert_eq!(kind("POST", "/owner/repo.git/git-upload-pack", &[]), Kind::Write);
        assert_eq!(kind("POST", "/git-upload-pack/more", &git), Kind::Write);
        assert_eq!(kind("POST", "/x?path=/git-upload-pack", &git), Kind::Write);
        assert_eq!(kind("GET", "/info/refs?service=git-receive-pack", &[]), Kind::Read, "advertising refs only reads");
        for method in ["POST", "PUT", "PATCH", "DELETE", "CONNECT", "TRACE", "PROPFIND", "get", "Get", "G ET"] {
            assert_eq!(kind(method, "/x", &[]), Kind::Write, "{method}");
        }
    }

    #[test]
    fn an_upgrade_is_never_a_read() {
        assert_eq!(kind("GET", "/socket", &[("Upgrade", "websocket"), ("Connection", "Upgrade")]), Kind::Upgrade);
        assert_eq!(kind("GET", "/socket", &[("Connection", "keep-alive, Upgrade")]), Kind::Upgrade);
        assert_eq!(kind("GET", "/socket", &[("Upgrade", "h2c")]), Kind::Upgrade);
        assert_eq!(kind("POST", "/git-upload-pack", &[("Upgrade", "x"), ("content-type", "application/x-git-upload-pack-request")]), Kind::Upgrade);
        assert_eq!(kind("GET", "/", &[("Connection", "keep-alive")]), Kind::Read);
    }

    #[test]
    fn the_host_header_must_be_the_connected_host() {
        let ok = |header: &str| host_matches(Some(header), "api.example.com");
        assert!(ok("api.example.com") && ok("API.example.com") && ok("api.example.com:443") && ok("api.example.com."));
        assert!(!ok("other.example.com") && !ok("api.example.com:8443") && !ok("api.example.com.evil.com") && !ok("") && !ok("evil.com, api.example.com"));
        assert!(!host_matches(None, "api.example.com"));
        assert!(host_matches(Some("[::1]"), "::1") && host_matches(Some("[::1]:443"), "::1") && !host_matches(Some("[::2]"), "::1"));
    }

    #[test]
    fn targets_are_paths() {
        for ok in ["/", "/a/b?c=d", "*"] {
            assert!(valid_target(ok), "{ok}");
        }
        for bad in ["", "http://evil.com/", "evil.com:443", "a", "/a\tb", "/a\x7f"] {
            assert!(!valid_target(bad), "{bad:?}");
        }
    }

    fn prefixes(list: &[&str]) -> Vec<String> {
        list.iter().map(|p| p.to_string()).collect()
    }

    #[test]
    fn prefixes_match_on_host_and_path_boundaries() {
        let p = prefixes(&["https://api.example.com/search", "https://other.example.com", "https://docs.example.com/a/"]);
        let under = |host: &str, target: &str| under_prefix(&p, host, target);
        assert!(under("api.example.com", "/search") && under("api.example.com", "/search/") && under("api.example.com", "/search/x/y"));
        assert!(under("api.example.com", "/search?q=1") && under("api.example.com", "/search/x?q=/other"));
        assert!(under("other.example.com", "/") && under("other.example.com", "/anything/at/all?x=1"));
        assert!(under("docs.example.com", "/a") && under("docs.example.com", "/a/b"));
        // Not a prefix of the path as a whole segment, or another host that merely starts alike.
        assert!(!under("api.example.com", "/searching") && !under("api.example.com", "/") && !under("api.example.com", "/other"));
        assert!(!under("api.example.com.evil.com", "/search") && !under("evilapi.example.com", "/search") && !under("example.com", "/search"));
        assert!(!under("docs.example.com", "/ab"));
        // The way out through the path.
        assert!(!under("api.example.com", "/search/../admin") && !under("api.example.com", "/search/%2e%2e/admin"));
        assert!(under("api.example.com", "/other/../search/x"), "resolved like the server will");
        assert!(!under("api.example.com", "/search%2Fx") && !under("api.example.com", "/search%2fx") && !under("api.example.com", "/search\\x"));
        assert!(!under("api.example.com", "*") && !under("api.example.com", "//search"));
        assert!(!under_prefix(&[], "api.example.com", "/search"));
    }

    #[test]
    fn prefixes_are_https_urls_without_extras() {
        for ok in ["https://api.example.com", "https://api.example.com/", "https://api.example.com/a/b", "https://API.example.com/a"] {
            assert!(parse_prefix(ok).is_ok(), "{ok}");
        }
        for bad in ["http://api.example.com/a", "api.example.com/a", "https://*.example.com/a", "https://api.example.com:8443/a", "https://u:p@api.example.com/", "https://api.example.com/a?x=1", "https://api.example.com/a#f", "*", ""] {
            assert!(parse_prefix(bad).is_err(), "{bad}");
        }
        // An explicit default port is the same host.
        assert!(parse_prefix("https://api.example.com:443/a").is_ok());
    }

    #[test]
    fn the_request_the_site_gets_has_its_credentials_and_none_of_the_guests() {
        let h = head(
            "POST /v1/x HTTP/1.1",
            &[
                ("Host", "api.example.com"),
                ("Authorization", "Bearer guest-guess"),
                ("authorization", "Basic another"),
                ("X-Api-Key", "guest-key"),
                ("Content-Length", "99"),
                ("Connection", "keep-alive, X-Hop"),
                ("X-Hop", "1"),
                ("Expect", "100-continue"),
                ("Accept-Encoding", "gzip, br"),
                ("User-Agent", "tool/1"),
            ],
        );
        let site = Site {
            name: "app".into(),
            writes: Mode::Allow,
            headers: vec![("X-Client".into(), "id".into()), ("Authorization".into(), "Bearer real".into())],
            masker: Masker::new([]),
        };
        let out = request_headers(&h, Framing::Length(3), "POST", Some(&site));
        let names: Vec<String> = out.iter().map(|(n, _)| n.to_ascii_lowercase()).collect();
        assert_eq!(names, ["host", "x-api-key", "user-agent", "content-length", "x-client", "authorization", "accept-encoding"]);
        assert_eq!(out.iter().filter(|(n, _)| n.eq_ignore_ascii_case("authorization")).count(), 1);
        assert!(out.contains(&("Authorization".into(), "Bearer real".into())) && out.contains(&("accept-encoding".into(), "identity".into())));
        assert!(out.contains(&("content-length".into(), "3".into())), "the framing is rebuilt");
        assert!(!out.iter().any(|(_, v)| v.contains("guest-guess") || v.contains("another")), "{out:?}");
        assert!(out.contains(&("X-Api-Key".into(), "guest-key".into())), "only the header the site sets is replaced");

        // Without a site nothing is added or taken, but the framing and hop-by-hop headers.
        let out = request_headers(&h, Framing::Chunked, "POST", None);
        let names: Vec<String> = out.iter().map(|(n, _)| n.to_ascii_lowercase()).collect();
        assert_eq!(names, ["host", "authorization", "authorization", "x-api-key", "accept-encoding", "user-agent", "transfer-encoding"]);
        let out = request_headers(&head("POST /x HTTP/1.1", &[]), Framing::None, "POST", None);
        assert_eq!(out, [("content-length".to_string(), "0".to_string())]);
        assert!(request_headers(&head("GET /x HTTP/1.1", &[]), Framing::None, "GET", None).is_empty());
    }

    #[test]
    fn answers_are_shaped_by_their_length_masking_and_the_guest() {
        use Framing::*;
        assert_eq!(shape_of(None, true, true), Shape::Plain);
        assert_eq!(shape_of(Length(5), false, true), Shape::Plain);
        assert_eq!(shape_of(Length(5), true, true), Shape::Chunked, "masking changes the length");
        assert_eq!(shape_of(Length(5), true, false), Shape::Close);
        assert_eq!(shape_of(Chunked, false, true), Shape::Chunked);
        assert_eq!(shape_of(Chunked, false, false), Shape::Close);
        assert_eq!(shape_of(UntilClose, false, true), Shape::Close);
        assert_eq!(shape_of(UntilClose, true, true), Shape::Close);
    }
}

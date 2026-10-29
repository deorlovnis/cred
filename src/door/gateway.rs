//! The `cred` kind: plain HTTP/1.1 to cred itself, with keep-alive because Claude Code reuses
//! its connections. Its one route is `/model/...`, the model gateway. The box holds a stand-in
//! key; the gateway checks for it, drops the box's own auth headers, adds the real one from the
//! model resource's approved policy and fields, sends the call over TLS to the policy's first
//! host and streams the answer back as it arrives, server-sent events included.
//!
//! The answers are the agent's own conversation, so they aren't masked, but the real key never
//! appears in anything the gateway writes itself.

use std::collections::BTreeMap;
use std::io::{self, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use serde_json::json;
use ureq::http::{self, Response};

use super::http::{self as wire, Head};
use super::{Entry, STANDIN, Shared};
use crate::keychain;
use crate::mask::Masker;
use crate::policy::{self, METHODS, Mode};

/// Request bodies (a long conversation with images) are read whole, up to this size.
const MAX_BODY: usize = 128 * 1024 * 1024;
/// A connection that sends no request for this long is closed.
const IDLE: Duration = Duration::from_secs(300);
/// The model host has this long to connect, and each wait for its answer or its next bytes
/// can last this long (a model may think a while before the first byte of a plain reply).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(600);
/// Longest path kept in the log.
const MAX_PATH: usize = 200;

/// Headers that belong to one connection, not to the request.
pub(super) const HOP_BY_HOP: [&str; 9] =
    ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"];
/// Other headers that aren't passed on: the box's own address and framing (rebuilt for the
/// upstream call), its credentials, and content encodings (the upstream is asked for none).
const DROPPED: [&str; 6] = ["host", "content-length", "expect", "x-api-key", "authorization", "accept-encoding"];

/// The client to the model host. It keeps connections between calls and never follows redirects.
pub fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .max_redirects(0)
        .max_redirects_will_error(false)
        .http_status_as_error(false)
        .timeout_connect(Some(CONNECT_TIMEOUT))
        .timeout_per_read(Some(READ_TIMEOUT))
        .build()
        .into()
}

pub fn serve(sh: &Shared, mut reader: BufReader<UnixStream>, mut writer: UnixStream) {
    let _ = writer.set_read_timeout(Some(IDLE));
    while let Ok(true) = exchange(sh, &mut reader, &mut writer) {}
}

/// Why a request was turned away, as the guest and the log hear it.
struct Denied {
    status: u16,
    decision: &'static str,
    message: String,
}

fn denied(status: u16, decision: &'static str, message: impl Into<String>) -> Denied {
    Denied { status, decision, message: message.into() }
}

/// What to send upstream.
struct Plan {
    url: String,
    headers: Vec<(String, String)>,
    /// The key's parts, which must not appear in anything cred says.
    secrets: Vec<String>,
}

/// One request and its response. `Ok(true)` if the connection can serve another.
fn exchange(sh: &Shared, reader: &mut BufReader<UnixStream>, writer: &mut UnixStream) -> io::Result<bool> {
    let head = match wire::read_head(reader) {
        Ok(Some(head)) => head,
        Ok(None) => return Ok(false),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => return close_with(writer, 400, "bad request"),
        Err(e) => return Err(e),
    };
    let Some((method, target, _)) = head.parts() else { return close_with(writer, 400, "bad request") };
    let keep = head.keep_alive();
    if head.header("expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue")) {
        writer.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
    }
    let body = match wire::read_body(reader, &head, MAX_BODY) {
        Ok(body) => body,
        Err(e) if e.kind() == io::ErrorKind::FileTooLarge => return close_with(writer, 413, "request body too large"),
        Err(e) if e.kind() == io::ErrorKind::InvalidData => return close_with(writer, 400, "bad request"),
        Err(e) => return Err(e),
    };

    let path: String = target.split('?').next().unwrap_or("").chars().filter(|c| c.is_ascii_graphic()).take(MAX_PATH).collect();
    let up = body.len() as u64;
    let entry = |decision: &str| Entry { method: Some(method.to_string()), path: Some(path.clone()), up, ..Entry::new("model", decision) };
    let response = match plan(sh, &head, method, target).and_then(|plan| send(sh, &plan, method, body)) {
        Ok(response) => response,
        Err(d) => {
            sh.log.write(&Entry { status: Some(d.status), ..entry(d.decision) });
            fail(writer, d.status, &d.message, keep)?;
            return Ok(keep);
        }
    };
    let status = response.status().as_u16();
    let (down, result) = relay(writer, response, method, keep);
    let decision = if result.is_ok() { "allowed" } else { "failed:stream" };
    sh.log.write(&Entry { status: Some(status), down, ..entry(decision) });
    result.map(|()| keep)
}

/// Decide what the request becomes upstream, or why it is refused. The model resource's policy
/// is loaded for each call, so a change or a revocation takes effect at once.
fn plan(sh: &Shared, head: &Head, method: &str, target: &str) -> Result<Plan, Denied> {
    let Some(rest) = target.strip_prefix("/model/") else {
        return Err(denied(404, "blocked:route", "cred has only /model/... here"));
    };
    if target.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(denied(400, "blocked:bad-request", "bad request target"));
    }
    let Some(model) = &sh.cfg.model else {
        return Err(denied(404, "blocked:no-model", format!("box {} has no model configured", sh.cfg.name)));
    };
    if !has_standin(head) {
        return Err(denied(401, "blocked:no-standin", format!("send {STANDIN} as the key; cred adds the real one")));
    }
    let approved = policy::load(model).map_err(|e| denied(403, "blocked:policy", format!("{e:#}")))?;
    crate::refresh::refresh_due(std::slice::from_ref(model), false, false);
    let fetch = approved
        .policy
        .fetch
        .as_ref()
        .ok_or_else(|| denied(403, "blocked:policy", format!("the policy for {model} has no [fetch] section")))?;
    let method = method.to_ascii_uppercase();
    if !METHODS.contains(&method.as_str()) {
        return Err(denied(405, "blocked:method", format!("method must be one of {}", METHODS.join(", "))));
    }
    // Model calls are POSTs. A resource that asks each time can't serve a conversation.
    if !matches!(method.as_str(), "GET" | "HEAD") && fetch.writes != Mode::Allow {
        let message = format!("the policy for {model} must set writes = \"allow\" in [fetch]: model calls are POST requests");
        return Err(denied(403, "blocked:writes", message));
    }
    let host = fetch.hosts.first().ok_or_else(|| denied(403, "blocked:policy", format!("the policy for {model} lists no hosts")))?;

    let mut secrets = Vec::new();
    let auth = match &fetch.auth {
        Some(template) => {
            let value = policy::fill(template, |field| {
                let value = keychain::get(model, field).ok_or_else(|| anyhow::anyhow!("{model}/{field} isn't stored (cred set {model} {field})"))?;
                secrets.push(value.clone());
                Ok(value)
            });
            Some(value.map_err(|e| denied(502, "failed:key", format!("{e:#}")))?)
        }
        None => None,
    };
    Ok(Plan {
        url: format!("{}/{rest}", host.trim_end_matches('/')),
        headers: rewrite_headers(&head.headers, &fetch.auth_header, &fetch.headers, auth.as_deref()),
        secrets,
    })
}

/// Whether the box sent the stand-in as its key: `x-api-key: cred-managed`, or
/// `Authorization: Bearer cred-managed` for a subscription token.
fn has_standin(head: &Head) -> bool {
    let bearer = |v: &str| match v.split_once(' ') {
        Some((scheme, token)) if scheme.eq_ignore_ascii_case("bearer") => token.trim().to_string(),
        _ => v.trim().to_string(),
    };
    head.header("x-api-key").is_some_and(|v| v.trim() == STANDIN) || head.header("authorization").is_some_and(|v| bearer(v) == STANDIN)
}

/// The headers for the upstream call: the box's, minus hop-by-hop headers, any header the
/// `Connection` header names, its own address and framing, and every credential; then the
/// policy's fixed headers (replacing any of the same name), the real auth header, and a request
/// for uncompressed answers (the gateway doesn't recompress what it streams).
fn rewrite_headers(incoming: &[(String, String)], auth_header: &str, fixed: &BTreeMap<String, String>, auth: Option<&str>) -> Vec<(String, String)> {
    let named: Vec<String> = incoming
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| v.split(',').map(|t| t.trim().to_ascii_lowercase()))
        .collect();
    let mut out: Vec<(String, String)> = incoming
        .iter()
        .filter(|(name, _)| {
            let name = name.to_ascii_lowercase();
            !HOP_BY_HOP.contains(&name.as_str())
                && !DROPPED.contains(&name.as_str())
                && !named.contains(&name)
                && !name.eq_ignore_ascii_case(auth_header)
                && !fixed.keys().any(|k| k.eq_ignore_ascii_case(&name))
        })
        .cloned()
        .collect();
    out.extend(fixed.iter().map(|(n, v)| (n.clone(), v.clone())));
    if let Some(value) = auth {
        out.push((auth_header.to_string(), value.to_string()));
    }
    out.push(("accept-encoding".into(), "identity".into()));
    out
}

/// Make the upstream call. The answer is still unread when this returns.
fn send(sh: &Shared, plan: &Plan, method: &str, body: Vec<u8>) -> Result<Response<ureq::Body>, Denied> {
    let mut request = http::Request::builder().method(method.to_ascii_uppercase().as_str()).uri(plan.url.as_str());
    for (name, value) in &plan.headers {
        request = request.header(name.as_str(), value.as_str());
    }
    let bad = |_| denied(400, "blocked:bad-request", "the request can't be forwarded");
    let result = if body.is_empty() { sh.agent.run(request.body(()).map_err(bad)?) } else { sh.agent.run(request.body(body).map_err(bad)?) };
    result.map_err(|e| {
        let masker = Masker::new(plan.secrets.clone());
        denied(502, "failed:upstream", masker.mask(&format!("cred couldn't get an answer from the model host: {e}")))
    })
}

/// Write the upstream answer to the guest as it arrives, chunked, flushing each piece so
/// events reach the client at once. A failure partway leaves the chunked body unterminated, so
/// the client sees the break. Returns the body bytes written, and how it went.
fn relay(writer: &mut UnixStream, response: Response<ureq::Body>, method: &str, keep: bool) -> (u64, io::Result<()>) {
    let (parts, body) = response.into_parts();
    let status = parts.status.as_u16();
    let bodiless = method.eq_ignore_ascii_case("HEAD") || matches!(status, 204 | 304);
    let mut head = format!("HTTP/1.1 {status} {}\r\n", wire::reason(status)).into_bytes();
    for (name, value) in &parts.headers {
        let name = name.as_str();
        if !HOP_BY_HOP.contains(&name) && !matches!(name, "content-length" | "content-encoding") {
            head.extend_from_slice(format!("{name}: ").as_bytes());
            head.extend_from_slice(value.as_bytes());
            head.extend_from_slice(b"\r\n");
        }
    }
    if !bodiless {
        head.extend_from_slice(b"transfer-encoding: chunked\r\n");
    }
    head.extend_from_slice(if keep { b"connection: keep-alive\r\n\r\n" } else { b"connection: close\r\n\r\n" });
    if let Err(e) = writer.write_all(&head).and_then(|()| writer.flush()) {
        return (0, Err(e));
    }
    if bodiless {
        return (0, Ok(()));
    }
    let (mut body, mut buf, mut total) = (body.into_reader(), [0u8; 16 * 1024], 0u64);
    loop {
        let n = match body.read(&mut buf) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return (total, Err(e)),
        };
        let mut chunk = format!("{n:x}\r\n").into_bytes();
        chunk.extend_from_slice(&buf[..n]);
        chunk.extend_from_slice(b"\r\n");
        if let Err(e) = writer.write_all(&chunk).and_then(|()| writer.flush()) {
            return (total, Err(e));
        }
        if n == 0 {
            // The "0\r\n\r\n" above is the last chunk with no trailers.
            return (total, Ok(()));
        }
        total += n as u64;
    }
}

/// Answer a request that can't be read on, and end the connection.
fn close_with(writer: &mut UnixStream, status: u16, message: &str) -> io::Result<bool> {
    fail(writer, status, message, false).map(|()| false)
}

/// Answer with an error in the shape the Anthropic API uses, so clients show the message.
fn fail(writer: &mut UnixStream, status: u16, message: &str, keep: bool) -> io::Result<()> {
    let kind = match status {
        400 | 405 => "invalid_request_error",
        401 => "authentication_error",
        403 => "permission_error",
        404 => "not_found_error",
        413 => "request_too_large",
        _ => "api_error",
    };
    let body = json!({ "type": "error", "error": { "type": kind, "message": message } });
    wire::respond(writer, status, "application/json", body.to_string().as_bytes(), keep)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()
    }

    fn names(headers: &[(String, String)]) -> Vec<String> {
        headers.iter().map(|(n, _)| n.to_ascii_lowercase()).collect()
    }

    fn head(headers: &[(&str, &str)]) -> Head {
        Head { line: "POST /model/v1/messages HTTP/1.1".into(), headers: pairs(headers) }
    }

    #[test]
    fn the_standin_is_accepted_as_an_api_key_or_a_bearer_token() {
        assert!(has_standin(&head(&[("x-api-key", "cred-managed")])));
        assert!(has_standin(&head(&[("X-Api-Key", " cred-managed ")])));
        assert!(has_standin(&head(&[("Authorization", "Bearer cred-managed")])));
        assert!(has_standin(&head(&[("authorization", "bearer cred-managed")])));
        assert!(has_standin(&head(&[("authorization", "cred-managed")])));
    }

    #[test]
    fn anything_else_as_a_key_is_refused() {
        assert!(!has_standin(&head(&[])));
        assert!(!has_standin(&head(&[("x-api-key", "sk-ant-real")])));
        assert!(!has_standin(&head(&[("authorization", "Bearer sk-ant-oat-real")])));
        assert!(!has_standin(&head(&[("x-api-key", "not-cred-managed")])));
        assert!(!has_standin(&head(&[("authorization", "Basic cred-managed")])));
        assert!(!has_standin(&head(&[("x-other", "cred-managed")])));
    }

    #[test]
    fn rewriting_drops_the_boxs_credentials_and_adds_the_real_one() {
        let incoming = pairs(&[
            ("Host", "cred.internal"),
            ("X-Api-Key", "cred-managed"),
            ("Authorization", "Bearer cred-managed"),
            ("anthropic-version", "2023-06-01"),
            ("Content-Type", "application/json"),
            ("Content-Length", "42"),
            ("Accept-Encoding", "gzip, br"),
            ("User-Agent", "claude-cli"),
        ]);
        let out = rewrite_headers(&incoming, "x-api-key", &BTreeMap::new(), Some("sk-real"));
        assert_eq!(
            out,
            pairs(&[
                ("anthropic-version", "2023-06-01"),
                ("Content-Type", "application/json"),
                ("User-Agent", "claude-cli"),
                ("x-api-key", "sk-real"),
                ("accept-encoding", "identity"),
            ])
        );
        assert!(!out.iter().any(|(_, v)| v.contains("cred-managed")));
    }

    #[test]
    fn rewriting_uses_the_policys_auth_header() {
        let incoming = pairs(&[("authorization", "Bearer cred-managed"), ("anthropic-beta", "oauth-2025-04-20")]);
        let out = rewrite_headers(&incoming, "Authorization", &BTreeMap::new(), Some("Bearer real-token"));
        assert_eq!(out[0], ("anthropic-beta".to_string(), "oauth-2025-04-20".to_string()));
        assert_eq!(out[1], ("Authorization".to_string(), "Bearer real-token".to_string()));
        assert_eq!(out.iter().filter(|(n, _)| n.eq_ignore_ascii_case("authorization")).count(), 1);
    }

    #[test]
    fn rewriting_drops_hop_by_hop_headers_and_those_the_connection_header_names() {
        let incoming = pairs(&[
            ("Connection", "keep-alive, X-Secret-Hop"),
            ("Keep-Alive", "timeout=5"),
            ("Transfer-Encoding", "chunked"),
            ("TE", "trailers"),
            ("Upgrade", "websocket"),
            ("Proxy-Authorization", "Basic abc"),
            ("Expect", "100-continue"),
            ("x-secret-hop", "1"),
            ("x-keep", "1"),
        ]);
        let out = rewrite_headers(&incoming, "x-api-key", &BTreeMap::new(), None);
        assert_eq!(names(&out), ["x-keep", "accept-encoding"]);
    }

    #[test]
    fn rewriting_lets_the_policys_fixed_headers_win_and_adds_no_auth_without_one() {
        let incoming = pairs(&[("anthropic-version", "1999-01-01"), ("X-Client", "mine")]);
        let fixed = BTreeMap::from([("Anthropic-Version".to_string(), "2023-06-01".to_string())]);
        let out = rewrite_headers(&incoming, "x-api-key", &fixed, None);
        assert_eq!(out, pairs(&[("X-Client", "mine"), ("Anthropic-Version", "2023-06-01"), ("accept-encoding", "identity")]));
    }
}

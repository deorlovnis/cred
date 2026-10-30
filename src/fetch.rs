//! HTTP requests cred makes on an agent's behalf. cred adds the resource's credentials itself,
//! only for hosts its approved policy lists, and never follows redirects, which could carry
//! the credentials elsewhere.

use std::io::Read;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use ureq::http;

use crate::policy::{self, Approved, METHODS, Mode};
use crate::{approve, keychain};

/// Response bodies are cut off after this many bytes.
const BODY_LIMIT: usize = 256 * 1024;

pub struct Request<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub body: Option<&'a str>,
    pub content_type: Option<&'a str>,
}

/// Make the request and describe the response as text. The caller masks it.
pub fn perform(res: &str, approved: &Approved, req: &Request) -> Result<String> {
    let fetch = approved.policy.fetch.as_ref().ok_or_else(|| anyhow!("the policy for {res} allows no requests (no [fetch] section)"))?;
    let method = req.method.to_ascii_uppercase();
    if !METHODS.contains(&method.as_str()) {
        bail!("method must be one of {}", METHODS.join(", "));
    }
    let url = fetch.check_url(req.url)?;
    if !matches!(method.as_str(), "GET" | "HEAD") {
        match fetch.writes {
            Mode::Deny => bail!("the policy for {res} doesn't allow {method} requests"),
            Mode::Ask => approve::confirm(&format!("send {method} {url} for {res}"))?,
            Mode::Allow => {}
        }
    }

    let mut request = http::Request::builder().method(method.as_str()).uri(url.as_str());
    if let Some(template) = &fetch.auth {
        let value = policy::fill(template, |field| keychain::get(res, field).ok_or_else(|| anyhow!("{res}/{field} isn't stored (cred set {res} {field})")))?;
        request = request.header(fetch.auth_header.as_str(), value);
    }
    for (name, value) in &fetch.headers {
        request = request.header(name.as_str(), value.as_str());
    }
    if let Some(content_type) = req.content_type {
        request = request.header("content-type", content_type);
    }
    let agent: ureq::Agent =
        ureq::Agent::config_builder().max_redirects(0).max_redirects_will_error(false).http_status_as_error(false).timeout_global(Some(Duration::from_secs(30))).build().into();
    let response = match req.body {
        Some(body) => agent.run(request.body(body.as_bytes().to_vec())?),
        None => agent.run(request.body(())?),
    }
    .map_err(|e| anyhow!("{method} {url}: {e}"))?;
    describe(response)
}

fn describe(mut response: http::Response<ureq::Body>) -> Result<String> {
    let mut out = format!("HTTP {}\n", response.status().as_u16());
    for name in ["content-type", "location"] {
        if let Some(value) = response.headers().get(name).and_then(|v| v.to_str().ok()) {
            out += &format!("{name}: {value}\n");
        }
    }
    let mut body = Vec::new();
    response.body_mut().as_reader().take(BODY_LIMIT as u64 + 1).read_to_end(&mut body)?;
    let cut = body.len() > BODY_LIMIT;
    body.truncate(BODY_LIMIT);
    out.push('\n');
    match std::str::from_utf8(&body) {
        Ok("") => out += "(empty body)",
        Ok(text) => out += text,
        // A cut can split a character; keep the valid part.
        Err(e) if cut && e.valid_up_to() > 0 => out += std::str::from_utf8(&body[..e.valid_up_to()])?,
        Err(_) => out += &format!("({} bytes of binary data)", body.len()),
    }
    if cut {
        out += &format!("\n(cut off after {} KB)", BODY_LIMIT / 1024);
    }
    Ok(out)
}

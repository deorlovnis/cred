//! Pages in the box's browser VM, at the door. Every page there belongs to one site and is
//! driven by one runner, which launches Chromium with a proxy identity: the site's name as the
//! user and a token cred gave that runner alone as the password. So a connection from the
//! browser VM is accepted only when it says (in `Proxy-Authorization`) which site it is for, and
//! proves it with the token; one runner can't speak as another site, and whatever runs in the
//! agent's VM can't speak as any, since its connections arrive on another socket.
//!
//! A page gets that site's approved `[browse]` rules, read fresh as the policy is now: only the
//! hosts of `origins` and `requests` can be reached, and writes follow `writes` and
//! `allow_writes` (see `inspect`). What the box's own policy says about the agent's traffic
//! does not apply to pages, and the site's credentials are not added to their requests: their
//! session is in the browser already.

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use super::addr::Allow;
use super::http::Head;
use crate::policy::{self, Mode};

/// The tokens of the runners that are running: token -> the site it speaks for. Clones share
/// one list; the browser side issues a token to each runner it starts, and the door checks them.
#[derive(Clone, Default)]
pub struct Tokens(Arc<Mutex<HashMap<String, String>>>);

impl Tokens {
    /// A new secret token for a runner of `site`: 256 random bits as hex.
    pub fn issue(&self, site: &str) -> Result<String> {
        let mut bytes = [0u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        let token: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        self.list().insert(token.clone(), site.to_string());
        Ok(token)
    }

    /// The runner is gone; its token speaks for nothing from now on.
    pub fn revoke(&self, token: &str) {
        self.list().remove(token);
    }

    fn site(&self, token: &str) -> Option<String> {
        self.list().get(token).cloned()
    }

    fn list(&self) -> std::sync::MutexGuard<'_, HashMap<String, String>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// How the head of a CONNECT from the browser VM stands with the door.
pub(super) enum Identity {
    /// The head carries no credentials at all: Chromium first asks without, and sends them once
    /// it is told (407) that the proxy wants them.
    Missing,
    /// A site of the box, and the token that runner was given.
    Site(String),
    /// Credentials that name no runner of this box, or a site other than the runner's.
    Refused,
}

/// Who a CONNECT claims to be, checked against the tokens issued and the box's sites.
pub(super) fn identify(head: &Head, tokens: &Tokens, sites: &[String]) -> Identity {
    let Some(value) = head.header("proxy-authorization") else { return Identity::Missing };
    let Some(encoded) = value.split_once(' ').filter(|(scheme, _)| scheme.eq_ignore_ascii_case("basic")).map(|(_, rest)| rest.trim()) else {
        return Identity::Refused;
    };
    let Some((user, token)) =
        STANDARD.decode(encoded).ok().and_then(|raw| String::from_utf8(raw).ok()).and_then(|text| text.split_once(':').map(|(u, t)| (u.to_string(), t.to_string())))
    else {
        return Identity::Refused;
    };
    match tokens.site(&token) {
        Some(site) if site == user && sites.contains(&site) => Identity::Site(site),
        _ => Identity::Refused,
    }
}

/// What a site's pages may do, from its approved policy as it is now.
pub(super) struct Rules {
    pub site: String,
    /// The hosts of `origins` and `requests`.
    pub hosts: Allow,
    /// Requests other than reads, and the URL prefixes that may be sent without asking.
    pub writes: Mode,
    pub allow_writes: Vec<String>,
}

/// The site's `[browse]` rules. `Err` if the policy is gone, changed since it was approved, or
/// doesn't allow browsing: then the site's pages reach nothing.
pub(super) fn rules(site: &str) -> Result<Rules> {
    let approved = policy::load(site)?;
    let browse = approved.policy.browse.as_ref().ok_or_else(|| anyhow!("the policy for {site} doesn't allow browsing"))?;
    let hosts: Vec<String> = browse.origins().into_iter().chain(browse.requests()).collect();
    Ok(Rules { site: site.to_string(), hosts: Allow::parse(&hosts)?, writes: browse.writes, allow_writes: browse.allow_writes.clone() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(auth: Option<&str>) -> Head {
        let headers = auth.map(|a| ("Proxy-Authorization".to_string(), a.to_string())).into_iter().collect();
        Head { line: "CONNECT example.com:443 HTTP/1.1".into(), headers }
    }

    fn basic(user: &str, token: &str) -> String {
        format!("Basic {}", STANDARD.encode(format!("{user}:{token}")))
    }

    #[test]
    fn a_connection_speaks_for_the_site_its_runners_token_was_issued_for() {
        let tokens = Tokens::default();
        let sites = vec!["app".to_string(), "wiki".to_string()];
        let app = tokens.issue("app").unwrap();
        let wiki = tokens.issue("wiki").unwrap();
        assert_ne!(app, wiki);
        assert_eq!(app.len(), 64);

        assert!(matches!(identify(&head(Some(&basic("app", &app))), &tokens, &sites), Identity::Site(s) if s == "app"));
        assert!(matches!(identify(&head(Some(&format!("basic {}", STANDARD.encode(format!("wiki:{wiki}"))))), &tokens, &sites), Identity::Site(s) if s == "wiki"));
        assert!(matches!(identify(&head(None), &tokens, &sites), Identity::Missing));
        // Another runner's token, a made-up one, a site that isn't the token's, no token.
        for auth in [basic("app", &wiki), basic("wiki", &app), basic("app", "guess"), basic("app", ""), basic("", &app), basic("other", &app)] {
            assert!(matches!(identify(&head(Some(&auth)), &tokens, &sites), Identity::Refused), "{auth}");
        }
        // Not Basic, or not decodable.
        for auth in ["Bearer abc", "Basic", "Basic !!!", &format!("Basic {}", STANDARD.encode("nocolon"))] {
            assert!(matches!(identify(&head(Some(auth)), &tokens, &sites), Identity::Refused), "{auth}");
        }
        // A token for a site that isn't (any longer) one of the box's.
        let gone = tokens.issue("gone").unwrap();
        assert!(matches!(identify(&head(Some(&basic("gone", &gone))), &tokens, &sites), Identity::Refused));
        // A revoked token speaks for nothing.
        tokens.revoke(&app);
        assert!(matches!(identify(&head(Some(&basic("app", &app))), &tokens, &sites), Identity::Refused));
    }

    #[test]
    fn clones_share_the_tokens() {
        let tokens = Tokens::default();
        let token = tokens.clone().issue("app").unwrap();
        assert_eq!(tokens.site(&token).as_deref(), Some("app"));
    }
}

//! `cred box login`: the person signs in to a box's sites by hand, in a visible browser on the
//! Mac with an empty profile (SSO and two-factor work as they always do), and cred seals the
//! session each one ends with into the box (see `sessions`). The session is never printed.
//!
//! One site after another: a window opens on the site's start page, and closing it (or pressing
//! Enter in the terminal) takes the session as it is. Ctrl-C skips just that site, and so does
//! closing the window before signing in: a browser with nothing in it seals nothing.

use std::io::BufRead;
use std::process::Child;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::thread;

use anyhow::{Result, bail};

use super::sessions::Sessions;
use super::{BoxPolicy, load, run, with_store};
use crate::browse::{self, Stop};
use crate::policy::{self, Policy};

/// What a sign-in needs from outside: a runner to start, how the person ends it, and where words go.
pub struct Window<'a> {
    pub spawn: &'a dyn Fn() -> Result<Child>,
    /// A real window (false: none, for tests).
    pub headed: bool,
    pub stop: &'a mut dyn FnMut() -> Option<Stop>,
    pub say: &'a mut dyn FnMut(&str),
}

/// Go through the sites one by one; returns those whose session was sealed.
pub fn sign_in_sites(sessions: &Sessions, sites: &[(String, Policy)], window: &mut Window) -> Result<Vec<String>> {
    let (mut sealed, mut failed) = (Vec::new(), 0);
    for (n, (site, policy)) in sites.iter().enumerate() {
        (window.say)(&format!(
            "signing in to {site} ({} of {}): close the window when done (Enter in this terminal also finishes, Ctrl-C skips this site)",
            n + 1,
            sites.len()
        ));
        let outcome = (|| {
            let start = browse::login_start(site, policy)?;
            browse::sign_in(site, policy, &start, (window.spawn)()?, window.headed, &mut *window.stop)
        })();
        match outcome {
            Ok(Some(state)) if !browse::state_is_empty(&state) => match sessions.put(site, &state.to_string()) {
                Ok(()) => {
                    (window.say)(&format!("sealed the session for {site} in the box"));
                    sealed.push(site.clone());
                }
                Err(e) => {
                    (window.say)(&format!("{site}: couldn't seal the session: {e:#}"));
                    failed += 1;
                }
            },
            Ok(_) => (window.say)(&format!("{site}: nothing signed in, so nothing sealed")),
            Err(e) => {
                (window.say)(&format!("{site}: {e:#}"));
                failed += 1;
            }
        }
    }
    if failed > 0 {
        bail!("{failed} of {} sites didn't get a session", sites.len());
    }
    Ok(sealed)
}

/// The box's sites that can be signed in to: the ones with a `[browse]` section in their policy.
/// `only` picks one; otherwise those not in `have` (a sealed session already), or all with `all`.
fn pick(name: &str, box_policy: &BoxPolicy, only: Option<&str>, all: bool, have: &[String]) -> Result<Vec<(String, Policy)>> {
    if let Some(site) = only {
        if !box_policy.sites.iter().any(|s| s == site) {
            bail!("{site} isn't one of box {name}'s sites ({})", box_policy.sites.join(", "));
        }
        let approved = policy::load(site)?;
        if approved.policy.browse.is_none() {
            bail!("the policy for {site} doesn't allow browsing (no [browse] section)");
        }
        return Ok(vec![(site.to_string(), approved.policy)]);
    }
    let mut sites = Vec::new();
    for site in &box_policy.sites {
        match policy::load(site) {
            Ok(a) if a.policy.browse.is_some() && (all || !have.contains(site)) => sites.push((site.clone(), a.policy)),
            Ok(_) => {}
            Err(e) => eprintln!("cred: skipping {site}: {e:#}"),
        }
    }
    Ok(sites)
}

/// `cred box login NAME [SITE] [--all]`: Touch ID, then the box's store (the box must be stopped).
pub fn login(name: &str, only: Option<&str>, all: bool) -> Result<()> {
    let (box_policy, _) = load(name)?;
    if !box_policy.browser.keep_sessions {
        bail!("box {name} has keep_sessions = false in its [browser] policy, so it keeps no sessions");
    }
    // A site that was named is checked before Touch ID.
    let named = only.map(|_| pick(name, &box_policy, only, all, &[])).transpose()?;
    let reason = match only {
        Some(site) => format!("sign in to {site} for box {name} and keep its session in the box"),
        None => format!("sign in to the sites of box {name} and keep their sessions in the box"),
    };
    with_store(name, &reason, false, |mnt| {
        let sessions = Sessions::new(mnt, &super::box_key(name)?, true);
        let sites = match named {
            Some(sites) => sites,
            None => pick(name, &box_policy, None, all, &sessions.sites())?,
        };
        if sites.is_empty() {
            let why = if all {
                "has no sites that allow browsing"
            } else {
                "has no site that allows browsing and still needs a session (--all signs in again to every one)"
            };
            println!("box {name} {why}");
            return Ok(());
        }
        let result = in_terminal(&sessions, &sites);
        // Whatever got sealed counts, even if a later site failed.
        if let Err(e) = super::keep_session_names(name, &sessions.sites()) {
            eprintln!("cred: keeping which sites of box {name} have a session: {e:#}");
        }
        let sealed = result?;
        println!("{} of {} sites signed in; their sessions are sealed in box {name}", sealed.len(), sites.len());
        Ok(())
    })
}

/// A window on the Mac. Debug builds can name a stand-in program (without a window), so tests
/// need no screen.
fn headed() -> bool {
    !(cfg!(debug_assertions) && std::env::var_os("CRED_TEST_LOGIN_RUNNER").is_some())
}

fn spawn() -> Result<Child> {
    #[cfg(debug_assertions)]
    if let Some(script) = std::env::var_os("CRED_TEST_LOGIN_RUNNER") {
        return std::process::Command::new("node")
            .arg(script)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| anyhow::anyhow!("starting the stand-in runner: {e}"));
    }
    browse::mac_runner()
}

/// Run the sign-ins with the terminal: Enter finishes the open window, Ctrl-C skips its site.
fn in_terminal(sessions: &Sessions, sites: &[(String, Policy)]) -> Result<Vec<String>> {
    run::catch_signals();
    let (tx, enters) = mpsc::channel();
    thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            if line.is_err() || tx.send(()).is_err() {
                return;
            }
        }
    });
    let interrupted = run::signalled();
    interrupted.store(false, Ordering::SeqCst);
    let mut stop = || {
        if interrupted.swap(false, Ordering::SeqCst) {
            return Some(Stop::Skip);
        }
        enters.try_recv().ok().map(|()| Stop::Done)
    };
    // What was typed before a window opened isn't an answer to it.
    let launch = || {
        while enters.try_recv().is_ok() {}
        interrupted.store(false, Ordering::SeqCst);
        spawn()
    };
    sign_in_sites(sessions, sites, &mut Window { spawn: &launch, headed: headed(), stop: &mut stop, say: &mut |line| println!("{line}") })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::process::{Command, Stdio};

    use serde_json::Value;

    use super::*;
    use crate::util::TempDir;

    fn site(page: &str) -> Policy {
        Policy::parse(&format!("[browse]\norigins = [\"http://127.0.0.1:9\"]\nstart = \"http://127.0.0.1:9/{page}\"\n")).unwrap()
    }

    fn fake() -> Result<Child> {
        let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fake-runner.mjs");
        Ok(Command::new("node").arg(script).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn()?)
    }

    fn has_node() -> bool {
        let found = Command::new("node").arg("--version").output().is_ok();
        if !found {
            eprintln!("skipped: needs node");
        }
        found
    }

    /// Sign in to `sites` with a stand-in window; `stops` says what the person does at each poll
    /// (nothing, once the list is used up).
    fn go(dir: &TempDir, sites: &[(&str, &str)], mut stops: Vec<Option<Stop>>) -> (Result<Vec<String>>, Vec<String>, Sessions) {
        fs::create_dir_all(dir.0.join("browser")).unwrap();
        let sessions = Sessions::new(&dir.0, "box key", true);
        let sites: Vec<(String, Policy)> = sites.iter().map(|(name, page)| (name.to_string(), site(page))).collect();
        let mut said = Vec::new();
        stops.reverse();
        let result = sign_in_sites(
            &sessions,
            &sites,
            &mut Window { spawn: &fake, headed: false, stop: &mut || stops.pop().flatten(), say: &mut |line| said.push(line.to_string()) },
        );
        (result, said, sessions)
    }

    #[test]
    fn goes_through_the_sites_and_seals_each_session_as_it_closes() {
        if !has_node() {
            return;
        }
        let dir = TempDir::new("cred-login").unwrap();
        // app closes itself; docs waits until Enter; blank is closed without signing in.
        let (result, said, sessions) = go(&dir, &[("app", "autoclose?site=app"), ("docs", "wait?site=docs"), ("blank", "nothing")], vec![None, Some(Stop::Done)]);
        assert_eq!(result.unwrap(), ["app", "docs"]);
        assert_eq!(sessions.sites(), ["app", "docs"]);
        let said = said.join("\n");
        assert!(said.contains("signing in to app (1 of 3): close the window when done"), "{said}");
        assert!(said.contains("signing in to blank (3 of 3)") && said.contains("blank: nothing signed in"), "{said}");
        assert!(!said.contains("by-hand") && !said.contains("local-"), "the session is never printed: {said}");

        // What was sealed is what the person signed in with.
        let state: Value = serde_json::from_str(&sessions.get("docs").unwrap().unwrap()).unwrap();
        assert_eq!(state["cookies"][0]["value"], "signed-in-to-docs-by-hand");
        assert_eq!(state["origins"][0]["localStorage"][0]["value"], "local-docs-token-value");
    }

    #[test]
    fn ctrl_c_skips_only_the_site_it_was_pressed_for() {
        if !has_node() {
            return;
        }
        let dir = TempDir::new("cred-login").unwrap();
        let (result, said, sessions) = go(&dir, &[("one", "wait?site=one"), ("two", "autoclose?site=two")], vec![Some(Stop::Skip)]);
        assert_eq!(result.unwrap(), ["two"]);
        assert_eq!(sessions.sites(), ["two"], "the skipped site got nothing");
        assert!(said.iter().any(|l| l.contains("one: nothing signed in")), "{said:?}");
    }

    #[test]
    fn a_site_that_cannot_start_does_not_stop_the_others() {
        if !has_node() {
            return;
        }
        let dir = TempDir::new("cred-login").unwrap();
        let (result, said, sessions) = go(&dir, &[("bad", "fail"), ("good", "autoclose?site=good")], vec![]);
        assert!(result.unwrap_err().to_string().contains("1 of 2 sites didn't get a session"));
        assert_eq!(sessions.sites(), ["good"]);
        assert!(said.iter().any(|l| l.contains("bad: cannot start the window")), "{said:?}");
    }

    /// The real runner in login mode (without a window): a page that sets a cookie and Local Storage,
    /// then Enter. Opt-in, like the other tests that need Chromium.
    #[test]
    #[ignore = "needs Node, the runner's dependencies and Chromium: CRED_E2E_BROWSER=1"]
    fn the_real_runner_gives_back_what_the_page_set() {
        if std::env::var_os("CRED_E2E_BROWSER").is_none() {
            return eprintln!("skipped: set CRED_E2E_BROWSER=1 to run this test");
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                use std::io::{Read, Write};
                let _ = stream.read(&mut [0u8; 4096]);
                let body = "<html><body><script>localStorage.setItem('jwt','LOCAL-VALUE-0123')</script>hi</body></html>";
                let _ = write!(stream, "HTTP/1.1 200 OK\r\nSet-Cookie: sid=HAND-MADE-0123; Path=/\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            }
        });
        let policy = Policy::parse(&format!("[browse]\norigins = [\"http://127.0.0.1:{port}\"]\nstart = \"http://127.0.0.1:{port}/\"\n")).unwrap();
        let runner = Path::new(env!("CARGO_MANIFEST_DIR")).join("runner/runner.mjs");
        let child = Command::new("node").arg(runner).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let begun = std::time::Instant::now();
        let state = browse::sign_in("app", &policy, &format!("http://127.0.0.1:{port}/"), child, false, || (begun.elapsed().as_secs() >= 3).then_some(Stop::Done)).unwrap().unwrap();
        assert_eq!(state["cookies"][0]["value"], "HAND-MADE-0123");
        assert_eq!(state["origins"][0]["localStorage"][0]["value"], "LOCAL-VALUE-0123");
    }

    #[test]
    fn signs_in_on_the_start_page_or_the_one_exact_origin() {
        let start = |toml: &str| browse::login_start("app", &Policy::parse(toml).unwrap());
        assert_eq!(start("[browse]\norigins = [\"https://a.example.com\"]\nstart = \"https://a.example.com/login\"").unwrap(), "https://a.example.com/login");
        assert_eq!(start("[browse]\norigins = [\"https://a.example.com\"]").unwrap(), "https://a.example.com");
        assert!(start("[browse]\norigins = [\"https://*.example.com\"]").unwrap_err().to_string().contains("set start"));
        assert!(start("[fetch]\nhosts = [\"https://a.example.com\"]\nauth = \"Bearer {token}\"").is_err());
    }
}

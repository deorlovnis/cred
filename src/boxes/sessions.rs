//! Sealed browser sessions: what a site's browser ends with (cookies and Local Storage) is kept in
//! the store's `browser/` folder, one file per site, so the next browser on that site starts
//! signed in, even after the site rotated its cookies.
//!
//! Each file is `seal(derive(box_key, "browser:<site>"), "browser:<site>", storageState)`: a file
//! doesn't open as another site's, and nothing but cred can read it. No VM mounts the folder;
//! the state reaches a runner over its stdin and comes back over its stdout.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Child;

use anyhow::{Context, Result, anyhow};

use super::store;
use crate::browse::BoxBrowser;
use crate::{parse_resource, seal};

const EXTENSION: &str = "sealed";

/// A box's sealed sessions. Created for an open store.
pub struct Sessions {
    dir: PathBuf,
    box_key: String,
    keep: bool,
}

fn purpose(site: &str) -> String {
    format!("browser:{site}")
}

impl Sessions {
    /// The sessions in the open store at `mnt`. With `keep` false (`[browser] keep_sessions =
    /// false`) nothing is ever read or written.
    pub fn new(mnt: &Path, box_key: &str, keep: bool) -> Self {
        Self { dir: store::browser_dir(mnt), box_key: box_key.to_string(), keep }
    }

    fn file(&self, site: &str) -> Result<PathBuf> {
        // The site name is a file name: only what a resource may be called gets in.
        parse_resource(site).map_err(|e| anyhow!("site '{site}': {e}"))?;
        Ok(self.dir.join(format!("{site}.{EXTENSION}")))
    }

    /// The site's session, if there is one. A file that doesn't open (changed, or sealed for
    /// another site) is an error.
    pub fn get(&self, site: &str) -> Result<Option<String>> {
        if !self.keep {
            return Ok(None);
        }
        let file = self.file(site)?;
        let sealed = match fs::read(&file) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", file.display())),
        };
        let key = seal::derive(self.box_key.as_bytes(), &purpose(site));
        let state = seal::open(&key, &purpose(site), &sealed).with_context(|| format!("the session of {site}"))?;
        Ok(Some(String::from_utf8(state).context("the session isn't text")?))
    }

    /// Replace the site's session. The folder must exist (it does while the store is open); a
    /// store that was closed meanwhile fails the write rather than leaving files outside it.
    pub fn put(&self, site: &str, state: &str) -> Result<()> {
        if !self.keep {
            return Ok(());
        }
        let file = self.file(site)?;
        let key = seal::derive(self.box_key.as_bytes(), &purpose(site));
        let tmp = file.with_extension("new");
        let mut out = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp).with_context(|| format!("writing {}", tmp.display()))?;
        out.write_all(&seal::seal(&key, &purpose(site), state.as_bytes()))?;
        out.sync_all()?;
        fs::rename(&tmp, &file).with_context(|| format!("saving {}", file.display()))
    }

    /// The sites that have a session sealed (names only).
    pub fn sites(&self) -> Vec<String> {
        let mut sites: Vec<String> = fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|e| e.file_name().to_str()?.strip_suffix(&format!(".{EXTENSION}")).map(str::to_string))
            .collect();
        sites.sort();
        sites
    }
}

/// How a box starts a runner for a site in its browser VM: the child, and the token the door
/// will accept from it.
pub type Launch = Box<dyn Fn(&str) -> Result<(Child, String)> + Send + Sync>;

/// The browser of a running box: runners come from `launch`, sessions from the store.
pub struct InBox {
    sessions: Sessions,
    launch: Launch,
}

impl InBox {
    pub fn new(sessions: Sessions, launch: Launch) -> Self {
        Self { sessions, launch }
    }
}

impl BoxBrowser for InBox {
    fn runner(&self, site: &str) -> Result<(Child, String)> {
        (self.launch)(site)
    }

    fn sealed(&self, site: &str) -> Result<Option<String>> {
        self.sessions.get(site)
    }

    fn seal(&self, site: &str, state: &str) -> Result<()> {
        self.sessions.put(site, state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::TempDir;

    fn sessions(dir: &TempDir, key: &str, keep: bool) -> Sessions {
        fs::create_dir_all(dir.0.join("browser")).unwrap();
        Sessions::new(&dir.0, key, keep)
    }

    #[test]
    fn a_session_is_sealed_per_site_and_comes_back() {
        let dir = TempDir::new("cred-sessions").unwrap();
        let s = sessions(&dir, "box key", true);
        assert_eq!(s.get("app").unwrap(), None);

        let state = r#"{"cookies":[{"name":"sid","value":"PLAIN-COOKIE-0123456789"}],"origins":[]}"#;
        s.put("app", state).unwrap();
        s.put("other", "{}").unwrap();
        assert_eq!(s.get("app").unwrap().as_deref(), Some(state));
        assert_eq!(s.sites(), ["app", "other"]);
        let on_disk = fs::read(dir.0.join("browser/app.sealed")).unwrap();
        assert!(!String::from_utf8_lossy(&on_disk).contains("PLAIN-COOKIE"), "sealed, not plain");
        assert_eq!(fs::metadata(dir.0.join("browser/app.sealed")).unwrap().permissions().mode() & 0o777, 0o600);

        // Another box key can't open it.
        assert!(sessions(&dir, "another key", true).get("app").is_err());
        // Putting again replaces it, and leaves no temporary file.
        s.put("app", "{\"cookies\":[]}").unwrap();
        assert_eq!(s.get("app").unwrap().as_deref(), Some("{\"cookies\":[]}"));
        assert_eq!(fs::read_dir(dir.0.join("browser")).unwrap().count(), 2);
    }

    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_session_sealed_for_one_site_does_not_open_as_another() {
        let dir = TempDir::new("cred-sessions").unwrap();
        let s = sessions(&dir, "box key", true);
        s.put("app", "{\"cookies\":[]}").unwrap();
        // A file moved to another site's name is refused: the site is bound into it.
        fs::copy(dir.0.join("browser/app.sealed"), dir.0.join("browser/other.sealed")).unwrap();
        let e = format!("{:#}", s.get("other").unwrap_err());
        assert!(e.contains("other") && e.contains("changed"), "{e}");
        assert!(s.get("app").is_ok());
    }

    #[test]
    fn a_changed_or_cut_file_fails_cleanly() {
        let dir = TempDir::new("cred-sessions").unwrap();
        let s = sessions(&dir, "box key", true);
        s.put("app", "{\"cookies\":[]}").unwrap();
        let file = dir.0.join("browser/app.sealed");
        let good = fs::read(&file).unwrap();
        for bad in [vec![], good[..10].to_vec(), good[..good.len() - 1].to_vec(), b"not sealed at all, just text of some length".to_vec(), [good.clone(), vec![0]].concat()] {
            fs::write(&file, &bad).unwrap();
            assert!(s.get("app").is_err(), "{} bytes", bad.len());
        }
        let mut flipped = good.clone();
        flipped[30] ^= 1;
        fs::write(&file, flipped).unwrap();
        assert!(s.get("app").is_err());
    }

    #[test]
    fn nothing_is_kept_when_the_box_does_not_keep_sessions() {
        let dir = TempDir::new("cred-sessions").unwrap();
        let s = sessions(&dir, "box key", false);
        s.put("app", "{\"cookies\":[]}").unwrap();
        assert!(s.sites().is_empty() && fs::read_dir(dir.0.join("browser")).unwrap().next().is_none());
        // Not even one that is there (from before the setting changed) is used.
        sessions(&dir, "box key", true).put("app", "{}").unwrap();
        assert_eq!(s.get("app").unwrap(), None);
    }

    #[test]
    fn only_resource_names_become_file_names() {
        let dir = TempDir::new("cred-sessions").unwrap();
        let s = sessions(&dir, "box key", true);
        for site in ["../x", "a/b", "", "A", "a.b", ".."] {
            assert!(s.put(site, "{}").is_err() && s.get(site).is_err(), "{site}");
        }
    }

    #[test]
    fn nothing_is_written_outside_a_closed_store() {
        let dir = TempDir::new("cred-sessions").unwrap();
        // No browser/ folder: the store is gone. The write fails and creates nothing.
        let s = Sessions::new(&dir.0, "box key", true);
        assert!(s.put("app", "{}").is_err());
        assert!(!dir.0.join("browser").exists());
    }
}

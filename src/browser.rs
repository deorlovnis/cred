//! Read one Local Storage key a browser keeps for a site, so a login only the browser can do
//! (e.g. Google sign-in) can feed cred. Firefox only, for now.
//!
//! Firefox keeps each site's Local Storage in
//! <profile>/storage/default/<scheme>+++<host>[+port][^userContextId=N]/ls/data.sqlite.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::{env, fs, process};

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, OpenFlags};

/// A browser source, written `firefox:https://example.com#storage_key`.
pub struct Source {
    origin: String,
    key: String,
}

impl Source {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let usage = "expected BROWSER:ORIGIN#KEY, e.g. firefox:https://example.com#session";
        let (browser, rest) = spec.split_once(':').ok_or(usage)?;
        let (origin, key) = rest.rsplit_once('#').ok_or(usage)?;
        if browser != "firefox" {
            return Err(format!("unsupported browser '{browser}' (supported: firefox)"));
        }
        if !(origin.starts_with("https://") || origin.starts_with("http://")) || key.is_empty() {
            return Err(usage.into());
        }
        Ok(Self { origin: origin.trim_end_matches('/').to_string(), key: key.to_string() })
    }

    pub fn read(&self) -> Result<String> {
        let storage = firefox_profile()?.join("storage/default");
        // https://host:8080 -> https+++host+8080; container tabs add ^userContextId=N.
        let base = self.origin.replacen("://", "+++", 1).replace(':', "+");
        let mut dbs: Vec<PathBuf> = fs::read_dir(&storage)
            .with_context(|| format!("reading {}", storage.display()))?
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name == base || name.starts_with(&format!("{base}^"))
            })
            .map(|e| e.path().join("ls/data.sqlite"))
            .filter(|p| p.is_file())
            .collect();
        dbs.sort_by_key(|p| p.parent().map(|d| d.to_string_lossy().len()));
        if dbs.is_empty() {
            bail!("Firefox has no Local Storage for {} — sign in there first", self.origin);
        }
        let mut keys = Vec::new();
        for db in &dbs {
            match read_key(db, &self.key)? {
                Lookup::Found(v) => return Ok(v),
                Lookup::Missing(mut k) => keys.append(&mut k),
            }
        }
        keys.sort();
        keys.dedup();
        bail!(
            "Firefox Local Storage for {} has no key '{}' (keys there: {})",
            self.origin,
            self.key,
            if keys.is_empty() { "none".into() } else { keys.join(", ") }
        )
    }
}

/// The profile Firefox opens by default, from profiles.ini; CRED_FIREFOX_PROFILE overrides it.
fn firefox_profile() -> Result<PathBuf> {
    if let Some(p) = env::var_os("CRED_FIREFOX_PROFILE") {
        return Ok(p.into());
    }
    let root = PathBuf::from(env::var_os("HOME").unwrap_or_default())
        .join("Library/Application Support/Firefox");
    let ini = fs::read_to_string(root.join("profiles.ini")).context("reading Firefox profiles.ini")?;
    let rel = default_profile(&ini).context("no profile in Firefox profiles.ini")?;
    // Paths in profiles.ini are relative to it unless absolute.
    Ok(if Path::new(&rel).is_absolute() { rel.into() } else { root.join(rel) })
}

fn default_profile(ini: &str) -> Option<String> {
    let (mut section, mut install_default, mut marked_default, mut first) =
        (String::new(), None, None, None);
    let mut path: Option<String> = None;
    for line in ini.lines().map(str::trim) {
        if line.starts_with('[') {
            section = line.to_string();
            path = None;
        } else if let Some(v) = line.strip_prefix("Default=") {
            // [Install…] names the profile Firefox actually opens; Default=1 marks the legacy default.
            if section.starts_with("[Install") {
                install_default = Some(v.to_string());
            } else if v == "1" {
                marked_default = path.clone();
            }
        } else if let Some(v) = line.strip_prefix("Path=") {
            path = Some(v.to_string());
            first = first.or(path.clone());
        }
    }
    install_default.or(marked_default).or(first)
}

enum Lookup {
    Found(String),
    Missing(Vec<String>),
}

/// Look KEY up in a copy of the database: Firefox keeps it open, and recent writes may still
/// sit in the -wal file. The copy is private and removed afterwards.
fn read_key(db: &Path, key: &str) -> Result<Lookup> {
    let tmp = TempDir::new()?;
    for suffix in ["", "-wal"] {
        let src = PathBuf::from(format!("{}{suffix}", db.display()));
        if src.is_file() {
            fs::copy(&src, tmp.0.join(format!("data.sqlite{suffix}")))
                .with_context(|| format!("copying {}", src.display()))?;
        }
    }
    let conn = Connection::open_with_flags(tmp.0.join("data.sqlite"), OpenFlags::SQLITE_OPEN_READ_WRITE)
        .context("opening Firefox Local Storage copy")?;
    let mut stmt = conn
        .prepare("SELECT key, conversion_type, compression_type, value FROM data")
        .context("reading Firefox Local Storage (unknown schema)")?;
    let mut rows = stmt.query([])?;
    let mut keys = Vec::new();
    while let Some(row) = rows.next()? {
        let k: String = row.get(0)?;
        if k == key {
            let value = decode(row.get(1)?, row.get(2)?, row.get_ref(3)?.as_bytes()?)?;
            return Ok(Lookup::Found(value));
        }
        keys.push(k);
    }
    Ok(Lookup::Missing(keys))
}

/// Firefox stores values as UTF-8 (conversion 1) or UTF-16LE (0), optionally snappy-compressed (compression 1).
fn decode(conversion: i64, compression: i64, bytes: &[u8]) -> Result<String> {
    let raw = if compression == 1 {
        snap::raw::Decoder::new().decompress_vec(bytes).context("decompressing Firefox value")?
    } else {
        bytes.to_vec()
    };
    if conversion == 1 {
        return String::from_utf8(raw).context("Firefox value is not UTF-8");
    }
    if raw.len() % 2 != 0 {
        bail!("Firefox value is not UTF-16");
    }
    let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16(&units).context("Firefox value is not UTF-16")
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Result<Self> {
        let dir = env::temp_dir().join(format!("cred-firefox-{}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        Ok(Self(dir))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_snappy_utf8() {
        let packed = snap::raw::Encoder::new().compress_vec(b"eyJ.payload.sig").unwrap();
        assert_eq!(decode(1, 1, &packed).unwrap(), "eyJ.payload.sig");
    }

    #[test]
    fn decodes_utf16() {
        let bytes: Vec<u8> = "abc".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(decode(0, 0, &bytes).unwrap(), "abc");
    }

    #[test]
    fn picks_install_default_profile() {
        let ini = "[Profile1]\nPath=Profiles/old.default\nDefault=1\n\n[Profile0]\nPath=Profiles/abc.default-release\n\n\
                   [Install4F96D1932A9F858E]\nDefault=Profiles/abc.default-release\nLocked=1\n";
        assert_eq!(default_profile(ini).as_deref(), Some("Profiles/abc.default-release"));
        let legacy = "[Profile0]\nPath=Profiles/a\n\n[Profile1]\nPath=Profiles/b\nDefault=1\n";
        assert_eq!(default_profile(legacy).as_deref(), Some("Profiles/b"));
    }

    #[test]
    fn parses_spec() {
        let s = Source::parse("firefox:https://app.example.com/#session_token").unwrap();
        assert_eq!((s.origin.as_str(), s.key.as_str()), ("https://app.example.com", "session_token"));
        assert!(Source::parse("chrome:https://x.com#k").is_err());
        assert!(Source::parse("firefox:x.com#k").is_err());
    }
}

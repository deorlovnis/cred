//! Read one value a browser keeps for a site, so a login only the browser can do (e.g. Google
//! sign-in) can feed cred: a Local Storage key or a cookie from Firefox, or a cookie from Chrome.
//!
//! Firefox keeps each site's Local Storage in
//! <profile>/storage/default/<scheme>+++<host>[+port][^userContextId=N]/ls/data.sqlite and its
//! cookies in <profile>/cookies.sqlite. Chrome keeps cookies in <profile>/Network/Cookies,
//! encrypted with a key derived from the "Chrome Safe Storage" Keychain password.

use std::cmp::Reverse;
use std::path::{Path, PathBuf};
use std::{env, fs};

use aes::Aes128;
use anyhow::{Context, Result, anyhow, bail};
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
use rusqlite::{Connection, OpenFlags};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use url::Url;

use crate::keychain;
use crate::util::{TempDir, home};

#[derive(Clone, Copy)]
enum Kind {
    FirefoxStorage,
    FirefoxCookie,
    ChromeCookie,
}

/// A browser source, written `firefox:https://example.com#storage_key`, or with
/// `firefox-cookie` or `chrome-cookie` to read the cookie of that name.
pub struct Source {
    kind: Kind,
    origin: String,
    key: String,
}

impl Source {
    pub fn parse(spec: &str) -> Result<Self, String> {
        let usage = "expected BROWSER:ORIGIN#KEY, e.g. firefox:https://example.com#session";
        let (browser, rest) = spec.split_once(':').ok_or(usage)?;
        let (origin, key) = rest.rsplit_once('#').ok_or(usage)?;
        let kind = match browser {
            "firefox" => Kind::FirefoxStorage,
            "firefox-cookie" => Kind::FirefoxCookie,
            "chrome-cookie" => Kind::ChromeCookie,
            _ => return Err(format!("unsupported browser '{browser}' (supported: firefox, firefox-cookie, chrome-cookie)")),
        };
        if !(origin.starts_with("https://") || origin.starts_with("http://")) || key.is_empty() {
            return Err(usage.into());
        }
        Ok(Self { kind, origin: origin.trim_end_matches('/').to_string(), key: key.to_string() })
    }

    pub fn read(&self) -> Result<String> {
        let (browser, cookies) = match self.kind {
            Kind::FirefoxStorage => return self.read_local_storage(),
            Kind::FirefoxCookie => ("Firefox", firefox_cookies(&firefox_profile()?.join("cookies.sqlite"), &self.key)?),
            Kind::ChromeCookie => {
                // macOS asks the user before cred may read this item.
                let password = keychain::get_app_password("Chrome Safe Storage", "Chrome").context("reading the Chrome Safe Storage password from the Keychain")?;
                ("Chrome", chrome_cookies(&chrome_cookie_db()?, &self.key, &chrome_key(&password))?)
            }
        };
        let host = Url::parse(&self.origin)?.host_str().unwrap_or_default().to_string();
        pick(cookies, &host).with_context(|| format!("{browser} has no cookie '{}' for {host} — sign in there first", self.key))
    }

    fn read_local_storage(&self) -> Result<String> {
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
        bail!("Firefox Local Storage for {} has no key '{}' (keys there: {})", self.origin, self.key, if keys.is_empty() { "none".into() } else { keys.join(", ") })
    }
}

/// The profile Firefox opens by default, from profiles.ini; CRED_FIREFOX_PROFILE overrides it.
fn firefox_profile() -> Result<PathBuf> {
    if let Some(p) = env::var_os("CRED_FIREFOX_PROFILE") {
        return Ok(p.into());
    }
    let root = PathBuf::from(env::var_os("HOME").unwrap_or_default()).join("Library/Application Support/Firefox");
    let ini = fs::read_to_string(root.join("profiles.ini")).context("reading Firefox profiles.ini")?;
    let rel = default_profile(&ini).context("no profile in Firefox profiles.ini")?;
    // Paths in profiles.ini are relative to it unless absolute.
    Ok(if Path::new(&rel).is_absolute() { rel.into() } else { root.join(rel) })
}

fn default_profile(ini: &str) -> Option<String> {
    let (mut section, mut install_default, mut marked_default, mut first) = (String::new(), None, None, None);
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

/// Open a copy of a browser's database: the browser keeps it open, and recent writes may still
/// sit in the -wal file. The copy is private and removed when the returned directory is dropped.
fn open_copy(db: &Path) -> Result<(Connection, TempDir)> {
    let tmp = TempDir::new("cred-browser")?;
    let name = db.file_name().context("not a database file")?.to_string_lossy().into_owned();
    for suffix in ["", "-wal"] {
        let src = PathBuf::from(format!("{}{suffix}", db.display()));
        if src.is_file() {
            fs::copy(&src, tmp.0.join(format!("{name}{suffix}"))).with_context(|| format!("copying {}", src.display()))?;
        }
    }
    let conn = Connection::open_with_flags(tmp.0.join(&name), OpenFlags::SQLITE_OPEN_READ_WRITE).with_context(|| format!("opening a copy of {}", db.display()))?;
    Ok((conn, tmp))
}

/// Look KEY up in Firefox's Local Storage database.
fn read_key(db: &Path, key: &str) -> Result<Lookup> {
    let (conn, _tmp) = open_copy(db)?;
    let mut stmt = conn.prepare("SELECT key, conversion_type, compression_type, value FROM data").context("reading Firefox Local Storage (unknown schema)")?;
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
    let raw = if compression == 1 { snap::raw::Decoder::new().decompress_vec(bytes).context("decompressing Firefox value")? } else { bytes.to_vec() };
    if conversion == 1 {
        return String::from_utf8(raw).context("Firefox value is not UTF-8");
    }
    if raw.len() % 2 != 0 {
        bail!("Firefox value is not UTF-16");
    }
    let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    String::from_utf16(&units).context("Firefox value is not UTF-16")
}

/// A cookie as far as choosing one goes. `expires` is unix seconds, 0 for a session cookie.
struct Cookie {
    host: String,
    path: String,
    value: String,
    expires: i64,
    /// Set in a container tab rather than the default one (Firefox).
    container: bool,
}

/// The value of the cookie that applies to `host`: not expired, from the default container,
/// then the most specific path.
fn pick(mut cookies: Vec<Cookie>, host: &str) -> Option<String> {
    let now = jiff::Timestamp::now().as_second();
    cookies.retain(|c| cookie_covers(&c.host, host) && (c.expires == 0 || c.expires > now));
    cookies.sort_by_key(|c| (c.container, Reverse(c.path.len())));
    cookies.into_iter().next().map(|c| c.value)
}

/// A cookie set for ".example.com" goes to example.com and its subdomains; one for
/// "app.example.com" (no dot) only to that host.
fn cookie_covers(cookie_host: &str, host: &str) -> bool {
    match cookie_host.strip_prefix('.') {
        Some(domain) => host == domain || host.ends_with(&format!(".{domain}")),
        None => host == cookie_host,
    }
}

fn firefox_cookies(db: &Path, name: &str) -> Result<Vec<Cookie>> {
    let (conn, _tmp) = open_copy(db)?;
    let mut stmt = conn.prepare("SELECT host, path, value, expiry, originAttributes FROM moz_cookies WHERE name = ?1").context("reading Firefox cookies (unknown schema)")?;
    let rows = stmt.query_map([name], |row| {
        // Seconds, though some Firefox versions have stored milliseconds.
        let expiry: i64 = row.get(3)?;
        Ok(Cookie {
            host: row.get(0)?,
            path: row.get(1)?,
            value: row.get(2)?,
            expires: if expiry > 100_000_000_000 { expiry / 1000 } else { expiry },
            container: !row.get::<_, String>(4)?.is_empty(),
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Chrome's cookie database; CRED_CHROME_PROFILE overrides the default profile folder.
fn chrome_cookie_db() -> Result<PathBuf> {
    let profile = env::var_os("CRED_CHROME_PROFILE").map_or_else(|| home().join("Library/Application Support/Google/Chrome/Default"), PathBuf::from);
    ["Network/Cookies", "Cookies"].iter().map(|p| profile.join(p)).find(|p| p.is_file()).ok_or_else(|| anyhow!("Chrome has no Cookies database in {}", profile.display()))
}

/// Chrome on macOS encrypts cookies with AES-128-CBC; the key comes from the Safe Storage
/// password by PBKDF2-SHA1, salt "saltysalt", 1003 rounds.
fn chrome_key(password: &[u8]) -> [u8; 16] {
    let mut key = [0u8; 16];
    pbkdf2::pbkdf2_hmac::<Sha1>(password, b"saltysalt", 1003, &mut key);
    key
}

fn chrome_cookies(db: &Path, name: &str, key: &[u8; 16]) -> Result<Vec<Cookie>> {
    let (conn, _tmp) = open_copy(db)?;
    let mut stmt = conn.prepare("SELECT host_key, path, value, encrypted_value, expires_utc FROM cookies WHERE name = ?1").context("reading Chrome cookies (unknown schema)")?;
    let mut rows = stmt.query([name])?;
    let mut cookies = Vec::new();
    while let Some(row) = rows.next()? {
        let host: String = row.get(0)?;
        let (plain, encrypted): (String, Vec<u8>) = (row.get(2)?, row.get(3)?);
        let expires_utc: i64 = row.get(4)?;
        cookies.push(Cookie {
            value: if encrypted.is_empty() { plain } else { chrome_decrypt(key, &host, &encrypted)? },
            path: row.get(1)?,
            // Microseconds since 1601-01-01; 0 is a session cookie.
            expires: if expires_utc == 0 { 0 } else { expires_utc / 1_000_000 - 11_644_473_600 },
            container: false,
            host,
        });
    }
    Ok(cookies)
}

fn chrome_decrypt(key: &[u8; 16], host: &str, encrypted: &[u8]) -> Result<String> {
    let blob = encrypted.strip_prefix(b"v10").context("unknown Chrome cookie encryption")?;
    let plain = cbc::Decryptor::<Aes128>::new(key.into(), (&[b' '; 16]).into())
        .decrypt_padded_vec::<Pkcs7>(blob)
        .map_err(|_| anyhow!("decrypting a Chrome cookie failed (wrong Safe Storage password?)"))?;
    // Newer Chrome puts sha256(host) in front of the value.
    let value = plain.strip_prefix(&Sha256::digest(host.as_bytes())[..]).unwrap_or(&plain);
    String::from_utf8(value.to_vec()).context("Chrome cookie is not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbc::cipher::BlockModeEncrypt;

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
        assert!(Source::parse("chrome-cookie:https://x.com#k").is_ok());
        assert!(Source::parse("firefox:x.com#k").is_err());
    }

    fn cookie(host: &str, path: &str, value: &str, expires: i64) -> Cookie {
        Cookie { host: host.into(), path: path.into(), value: value.into(), expires, container: false }
    }

    #[test]
    fn picks_the_cookie_that_applies() {
        let future = jiff::Timestamp::now().as_second() + 3600;
        let mut container = cookie(".example.com", "/", "container", future);
        container.container = true;
        let cookies = vec![
            cookie(".other.com", "/", "other site", 0),
            cookie("app.example.com", "/", "expired", 1),
            container,
            cookie(".example.com", "/", "domain", future),
            cookie("app.example.com", "/app", "specific", 0),
            cookie("www.example.com", "/", "other host", 0),
        ];
        assert_eq!(pick(cookies, "app.example.com").as_deref(), Some("specific"));
        assert_eq!(pick(vec![cookie(".example.com", "/", "v", 0)], "example.com").as_deref(), Some("v"));
        assert_eq!(pick(vec![cookie("app.example.com", "/", "v", 0)], "example.com"), None);
        assert_eq!(pick(vec![cookie(".example.com", "/", "v", 0)], "notexample.com"), None);
    }

    /// A database in a private folder, built with `setup`.
    fn fixture(name: &str, setup: impl FnOnce(&Connection)) -> (PathBuf, TempDir) {
        let dir = TempDir::new("cred-test").unwrap();
        let db = dir.0.join(name);
        setup(&Connection::open(&db).unwrap());
        (db, dir)
    }

    #[test]
    fn reads_firefox_cookies() {
        let (db, _dir) = fixture("cookies.sqlite", |c| {
            c.execute_batch(
                "CREATE TABLE moz_cookies (name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, originAttributes TEXT);
                 INSERT INTO moz_cookies VALUES ('session', 'default', '.example.com', '/', 4102444800, '');
                 INSERT INTO moz_cookies VALUES ('session', 'in a container', '.example.com', '/', 4102444800000, '^userContextId=2');
                 INSERT INTO moz_cookies VALUES ('other', 'x', '.example.com', '/', 4102444800, '');",
            )
            .unwrap();
        });
        let cookies = firefox_cookies(&db, "session").unwrap();
        assert_eq!(cookies.len(), 2);
        assert_eq!(cookies[1].expires, 4102444800); // milliseconds are converted
        assert_eq!(pick(cookies, "app.example.com").as_deref(), Some("default"));
    }

    // Made with openssl, independently of the code under test:
    // openssl kdf -keylen 16 -kdfopt digest:SHA1 -kdfopt pass:peanuts -kdfopt salt:saltysalt -kdfopt iter:1003 PBKDF2
    // printf 'cookie-value-123' | openssl enc -aes-128-cbc -K <key> -iv 20202020202020202020202020202020
    const PEANUTS_KEY: [u8; 16] = [0xd9, 0xa0, 0x9d, 0x49, 0x9b, 0x4e, 0x1b, 0x74, 0x61, 0xf2, 0x8e, 0x67, 0x97, 0x2c, 0x6d, 0xbd];
    const PEANUTS_COOKIE: [u8; 32] = [
        0xfa, 0xcc, 0x06, 0x07, 0x80, 0x78, 0xee, 0xb9, 0xe7, 0xbf, 0x83, 0x51, 0xe8, 0x7a, 0x87, 0x5d, 0xb4, 0xd1, 0x28, 0x73, 0xea, 0x58, 0x8d, 0xa0, 0xb5, 0xe0, 0x7a, 0xfa,
        0x24, 0x54, 0x69, 0x38,
    ];

    #[test]
    fn derives_chrome_key_and_decrypts() {
        assert_eq!(chrome_key(b"peanuts"), PEANUTS_KEY);
        let blob = [b"v10".as_slice(), &PEANUTS_COOKIE].concat();
        assert_eq!(chrome_decrypt(&PEANUTS_KEY, ".example.com", &blob).unwrap(), "cookie-value-123");
        assert!(chrome_decrypt(&[0; 16], ".example.com", &blob).is_err());
        assert!(chrome_decrypt(&PEANUTS_KEY, ".example.com", &PEANUTS_COOKIE).is_err());
    }

    #[test]
    fn reads_chrome_cookies() {
        let key = chrome_key(b"safe storage password");
        let encrypt = |host: &str, value: &str, hashed: bool| {
            let mut plain = if hashed { Sha256::digest(host.as_bytes()).to_vec() } else { Vec::new() };
            plain.extend(value.as_bytes());
            let ct = cbc::Encryptor::<Aes128>::new((&key).into(), (&[b' '; 16]).into()).encrypt_padded_vec::<Pkcs7>(&plain);
            [b"v10".as_slice(), &ct].concat()
        };
        let (db, _dir) = fixture("Cookies", |c| {
            c.execute_batch("CREATE TABLE cookies (host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT, expires_utc INTEGER);").unwrap();
            // Chrome time is microseconds since 1601; 11_644_473_600 seconds after that is 1970.
            let (far, past) = ((11_644_473_600i64 + 4_000_000_000) * 1_000_000, (11_644_473_600i64 + 1) * 1_000_000);
            let insert = "INSERT INTO cookies VALUES (?1, ?2, ?3, ?4, '/', ?5)";
            c.execute(insert, rusqlite::params![".example.com", "session", "", encrypt(".example.com", "with-host-hash", true), far]).unwrap();
            c.execute(insert, rusqlite::params![".old.com", "session", "", encrypt(".old.com", "no-hash", false), 0]).unwrap();
            c.execute(insert, rusqlite::params![".plain.com", "session", "unencrypted", Vec::<u8>::new(), 0]).unwrap();
            c.execute(insert, rusqlite::params![".gone.com", "session", "", encrypt(".gone.com", "expired", true), past]).unwrap();
        });
        let cookies = chrome_cookies(&db, "session", &key).unwrap();
        assert_eq!(cookies.len(), 4);
        assert_eq!(pick(chrome_cookies(&db, "session", &key).unwrap(), "app.example.com").as_deref(), Some("with-host-hash"));
        assert_eq!(pick(chrome_cookies(&db, "session", &key).unwrap(), "old.com").as_deref(), Some("no-hash"));
        assert_eq!(pick(chrome_cookies(&db, "session", &key).unwrap(), "plain.com").as_deref(), Some("unencrypted"));
        assert_eq!(pick(cookies, "gone.com"), None);
        assert!(chrome_cookies(&db, "session", &[1; 16]).is_err());
    }
}

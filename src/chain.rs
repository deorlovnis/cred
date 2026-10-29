//! A log of JSON lines chained with an HMAC, for the logs that live outside a box's reach (the
//! door's, in the box's store). Each line gets a `mac` field: HMAC-SHA256, with a key only cred
//! holds, over the previous line's mac and this line's other fields. Editing a line, or taking
//! one out of the middle, breaks the chain from there on, which `verify` reports. Cutting off the
//! end can't be seen from the log alone; the `Head` that cred keeps elsewhere when a box stops
//! covers that up to the last stop. (The same scheme as `audit`.)

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Map, Value};

use crate::audit::hmac_sha256;

/// The last line is looked for in this many bytes at the end of the file.
const TAIL: u64 = 16384;
const MAC: &str = "mac";

pub struct Chain {
    path: PathBuf,
    key: [u8; 32],
}

/// What a check found.
#[derive(Debug, PartialEq)]
pub struct Verified {
    /// Lines whose chain holds.
    pub chained: usize,
    /// Lines from before the log was chained: they can't be checked.
    pub unchained: usize,
    /// The mac of each chained line, first to last.
    pub macs: Vec<String>,
}

/// Where a log's chain stood when cred last put it away: how many chained lines, and the mac of
/// the last. Kept outside the log (in the Keychain), it is what shows a log whose chain was
/// stripped, or whose end was cut off before that point.
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Head {
    pub lines: usize,
    pub mac: String,
}

impl Verified {
    pub fn head(&self) -> Option<Head> {
        self.macs.last().map(|mac| Head { lines: self.macs.len(), mac: mac.clone() })
    }

    /// Whether this log still holds `head`: at least as many chained lines, the same mac there.
    pub fn check(&self, head: &Head) -> Result<()> {
        match self.macs.get(head.lines.wrapping_sub(1)) {
            Some(mac) if *mac == head.mac => Ok(()),
            Some(_) => bail!("line {} isn't the one cred recorded when the box last stopped: the log was replaced or rewritten", self.unchained + head.lines),
            None => bail!(
                "the log has {} chained lines, but had {} when the box last stopped: lines were cut off or their chain was stripped",
                self.macs.len(),
                head.lines
            ),
        }
    }
}

impl Chain {
    pub fn new(path: &Path, key: [u8; 32]) -> Self {
        Self { path: path.to_path_buf(), key }
    }

    /// Make sure the log can be written: its folder and the file (private to the user).
    pub fn create(&self) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        OpenOptions::new().append(true).create(true).mode(0o600).open(&self.path).with_context(|| format!("opening {}", self.path.display()))?;
        Ok(())
    }

    /// Add a line (a JSON object) to the end, chained to the one before. Whoever else appends
    /// to the same file waits for the lock, so two writers can't chain to the same line.
    pub fn append(&self, line: Value) -> Result<()> {
        let Value::Object(mut fields) = line else { bail!("a log line is a JSON object") };
        fields.remove(MAC);
        let mut file = OpenOptions::new().read(true).append(true).create(true).mode(0o600).open(&self.path).with_context(|| format!("opening {}", self.path.display()))?;
        file.lock()?;
        let prev = last_mac(&mut file)?;
        let mac = self.mac(&prev, &fields)?;
        fields.insert(MAC.into(), Value::String(mac));
        file.write_all(format!("{}\n", Value::Object(fields)).as_bytes())?;
        Ok(())
    }

    fn mac(&self, prev: &str, fields: &Map<String, Value>) -> Result<String> {
        // `Map` keeps its keys in one order, so what is written and what is read back agree.
        let body = serde_json::to_string(fields)?;
        Ok(hmac_sha256(&self.key, &[prev.as_bytes(), b"\n", body.as_bytes()]))
    }

    /// Check every line against the chain. A line without a mac is fine only before the first
    /// one that has it (a log from before chaining); anything else that fails names its line.
    pub fn verify(&self) -> Result<Verified> {
        let text = match fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", self.path.display())),
        };
        let (mut prev, mut found) = (String::new(), Verified { chained: 0, unchained: 0, macs: Vec::new() });
        for (no, line) in text.lines().enumerate().map(|(i, l)| (i + 1, l)).filter(|(_, l)| !l.trim().is_empty()) {
            let broken = || anyhow!("the chain breaks at line {no}: that line, or one before it, was changed or removed");
            let Ok(Value::Object(mut fields)) = serde_json::from_str::<Value>(line) else { return Err(broken()) };
            match fields.remove(MAC) {
                None if found.chained == 0 => found.unchained += 1,
                Some(Value::String(mac)) if self.mac(&prev, &fields)? == mac => {
                    found.macs.push(mac.clone());
                    prev = mac;
                    found.chained += 1;
                }
                _ => return Err(broken()),
            }
        }
        Ok(found)
    }
}

/// The mac of the last line, or "" if there is none (or it has none).
fn last_mac(file: &mut File) -> Result<String> {
    let len = file.metadata()?.len();
    file.seek(SeekFrom::Start(len.saturating_sub(TAIL)))?;
    let mut tail = Vec::new();
    file.read_to_end(&mut tail)?;
    let text = String::from_utf8_lossy(&tail);
    let last = text.lines().rev().find(|l| !l.trim().is_empty());
    Ok(last
        .and_then(|l| serde_json::from_str::<Value>(l).ok())
        .and_then(|v| v.get(MAC).and_then(Value::as_str).map(str::to_string))
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::TempDir;
    use serde_json::json;

    fn chain(dir: &TempDir) -> Chain {
        Chain::new(&dir.0.join("log").join("door.log"), [7; 32])
    }

    fn write(chain: &Chain, n: usize) {
        chain.create().unwrap();
        for i in 0..n {
            chain.append(json!({ "kind": "request", "n": i, "url": format!("https://a.example.com/{i}") })).unwrap();
        }
    }

    fn lines(chain: &Chain) -> Vec<String> {
        fs::read_to_string(&chain.path).unwrap().lines().map(str::to_string).collect()
    }

    fn put(chain: &Chain, lines: &[String]) {
        fs::write(&chain.path, lines.join("\n") + "\n").unwrap();
    }

    fn counts(chain: &Chain) -> (usize, usize) {
        let found = chain.verify().unwrap();
        (found.chained, found.unchained)
    }

    #[test]
    fn the_head_kept_elsewhere_shows_a_stripped_cut_or_replaced_log() {
        let dir = TempDir::new("cred-chain").unwrap();
        let c = chain(&dir);
        write(&c, 5);
        let head = c.verify().unwrap().head().unwrap();
        assert_eq!(head.lines, 5);
        let original = lines(&c);

        // More lines since: the head still holds.
        write(&c, 2);
        c.verify().unwrap().check(&head).unwrap();

        // Every mac taken out: on its own the log reads as one from before chaining.
        let stripped: Vec<String> = original
            .iter()
            .map(|l| {
                let mut v: Value = serde_json::from_str(l).unwrap();
                v.as_object_mut().unwrap().remove(MAC);
                v.to_string()
            })
            .collect();
        put(&c, &stripped);
        assert_eq!(counts(&c), (0, 5), "the log alone can't tell");
        let e = c.verify().unwrap().check(&head).unwrap_err().to_string();
        assert!(e.contains("stripped"), "{e}");

        // The end cut off.
        put(&c, &original[..3]);
        assert!(c.verify().unwrap().check(&head).is_err());

        // A whole new log with other lines, chained with the same key.
        fs::remove_file(&c.path).unwrap();
        c.create().unwrap();
        for i in 0..6 {
            c.append(json!({ "kind": "request", "n": i, "url": "https://other.example.com/" })).unwrap();
        }
        let e = c.verify().unwrap().check(&head).unwrap_err().to_string();
        assert!(e.contains("replaced"), "{e}");
    }

    #[test]
    fn a_chain_of_lines_verifies() {
        let dir = TempDir::new("cred-chain").unwrap();
        let c = chain(&dir);
        assert_eq!(counts(&c), (0, 0), "a log that doesn't exist is empty");
        write(&c, 5);
        assert_eq!(counts(&c), (5, 0));
        assert!(lines(&c).iter().all(|l| l.contains("\"mac\":\"")));
        // A second writer carries on from the last line.
        Chain::new(&c.path, [7; 32]).append(json!({ "kind": "box", "decision": "stopped" })).unwrap();
        assert_eq!(c.verify().unwrap().chained, 6);
        assert!(Chain::new(&c.path, [8; 32]).verify().is_err(), "another key can't verify it");
    }

    #[test]
    fn an_edited_line_is_found() {
        let dir = TempDir::new("cred-chain").unwrap();
        let c = chain(&dir);
        write(&c, 5);
        let mut l = lines(&c);
        l[2] = l[2].replace("/2", "/9");
        put(&c, &l);
        let e = c.verify().unwrap_err().to_string();
        assert!(e.contains("line 3"), "{e}");
    }

    #[test]
    fn a_deleted_line_in_the_middle_is_found() {
        let dir = TempDir::new("cred-chain").unwrap();
        let c = chain(&dir);
        write(&c, 5);
        let mut l = lines(&c);
        l.remove(2);
        put(&c, &l);
        let e = c.verify().unwrap_err().to_string();
        assert!(e.contains("line 3"), "{e}");
        // So is the first line taken out.
        let mut l = lines(&c);
        l.remove(0);
        l.insert(2, "{}".into());
        put(&c, &l);
        assert!(c.verify().is_err());
    }

    #[test]
    fn a_stripped_mac_and_garbage_are_found_but_an_old_unchained_start_is_allowed() {
        let dir = TempDir::new("cred-chain").unwrap();
        let c = chain(&dir);
        write(&c, 3);
        let mut l = lines(&c);
        let stripped = l[1].split(",\"mac\"").next().unwrap().to_string() + "}";
        let original = l[1].clone();
        l[1] = stripped;
        put(&c, &l);
        assert!(c.verify().unwrap_err().to_string().contains("line 2"));
        l[1] = "not json".into();
        put(&c, &l);
        assert!(c.verify().is_err());
        l[1] = original;

        // A log from before chaining: its lines stay unchecked, the new ones chain on.
        let old = [r#"{"kind":"proxy","decision":"allowed"}"#.to_string(), r#"{"kind":"proxy","decision":"closed"}"#.to_string()];
        fs::remove_file(&c.path).unwrap();
        put(&c, &old);
        c.append(json!({ "kind": "request" })).unwrap();
        c.append(json!({ "kind": "request" })).unwrap();
        assert_eq!(counts(&c), (2, 2));
        // But a line without a mac after a chained one is an edit.
        let mut l = lines(&c);
        l.push(old[0].clone());
        put(&c, &l);
        assert!(c.verify().unwrap_err().to_string().contains("line 5"));
    }

    #[test]
    fn only_objects_are_lines_and_a_mac_in_one_is_replaced() {
        let dir = TempDir::new("cred-chain").unwrap();
        let c = chain(&dir);
        c.create().unwrap();
        assert!(c.append(json!("text")).is_err());
        c.append(json!({ "kind": "x", "mac": "forged" })).unwrap();
        assert_eq!(c.verify().unwrap().chained, 1);
    }
}

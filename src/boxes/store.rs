//! A box's store: an AES-256 encrypted APFS sparse bundle, mounted only while the box runs.
//!
//! The key (256 random bits, hex) reaches `hdiutil` on stdin, NUL-terminated, and is never put in
//! an argument list or a file. The bundle sits in a 0700 folder; the volume is attached with
//! `-nobrowse` (no Finder, Spotlight or fseventsd) at a mount point whose parent is 0700, since
//! a volume's root is 0755. Closing detaches it, with `-force` only as a fallback.
//!
//! A store never shrinks when files are deleted: `hdiutil compact` fails on APFS images, and
//! `diskutil image attach` (which gives space back) mounts `noowners`, so files would show the
//! wrong owner. TODO: `cred box compact` (copy into a new store) if this matters in practice.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, anyhow, bail};
use jiff::Timestamp;
use serde_json::json;

use crate::chain::Chain;
use crate::util::home;

/// The most a store can hold; the bundle grows as needed and starts small.
const SIZE: &str = "100g";
/// Folders of a store. `log` and `door` (the box CA, sealed) are cred's; no VM mounts them.
pub const FOLDERS: [&str; 5] = ["home", "work", "downloads", "log", "door"];
const DOOR_LOG: &str = "log/door.log";
const CA_FILE: &str = "door/ca.sealed";

/// Where a box's files live on the Mac. `real()` is the user's; tests build their own.
pub struct Layout {
    /// Stores, mount points and locks: ~/Library/Application Support/cred/box
    pub root: PathBuf,
    /// The sockets the VMs publish, in a short path (104-byte limit): /tmp/cred-<uid>
    pub sockets: PathBuf,
    uid: u32,
}

impl Layout {
    pub fn real() -> Result<Self> {
        let home = home();
        if !home.is_absolute() {
            bail!("HOME isn't set");
        }
        let uid = uid()?;
        Ok(Self { root: home.join("Library/Application Support/cred/box"), sockets: PathBuf::from(format!("/tmp/cred-{uid}")), uid })
    }

    #[cfg(test)]
    pub fn under(dir: &Path) -> Result<Self> {
        // No `id` here: a child process forked while another test holds a lock would keep it.
        Ok(Self { root: dir.join("box"), sockets: dir.join("sock"), uid: fs::metadata(dir)?.uid() })
    }

    pub fn bundle(&self, name: &str) -> PathBuf {
        self.root.join(format!("{name}.sparsebundle"))
    }

    /// The store of a box that is shredded when it stops, or of `--temp`; its key is never kept.
    pub fn ephemeral_bundle(&self, id: &str) -> PathBuf {
        self.root.join("temp").join(format!("{id}.sparsebundle"))
    }

    pub fn open_dir(&self) -> PathBuf {
        self.root.join("open")
    }

    pub fn mount_point(&self, id: &str) -> PathBuf {
        self.open_dir().join(id)
    }

    pub fn lock(&self, id: &str) -> PathBuf {
        self.open_dir().join(format!("{id}.lock"))
    }

    /// The hash of the approved policy an open box runs with, written by the cred that opened it.
    pub fn opened_with(&self, id: &str) -> PathBuf {
        self.open_dir().join(format!("{id}.policy"))
    }

    pub fn socket(&self, id: &str) -> PathBuf {
        self.sockets.join(format!("{id}.sock"))
    }

    /// The socket of the box's browser VM, next to the agent's.
    #[allow(dead_code)] // for the browser VM of box runs
    pub fn browser_socket(&self, id: &str) -> PathBuf {
        self.sockets.join(format!("{id}-browser.sock"))
    }

    /// Where the box's browser VM saves downloads, one folder per site: outside every store, and
    /// mounted into the browser VM only (~/Library/Application Support/cred/downloads/<box>).
    #[allow(dead_code)] // for the browser VM of box runs
    pub fn downloads(&self, name: &str) -> PathBuf {
        self.root.parent().unwrap_or(&self.root).join("downloads").join(name)
    }

    /// Create the folders a run needs, private to the user.
    pub fn prepare(&self) -> Result<()> {
        for dir in [&self.root, &self.open_dir(), &self.root.join("temp"), &self.sockets] {
            private_dir(dir, self.uid)?;
        }
        Ok(())
    }
}

fn uid() -> Result<u32> {
    let out = Command::new("id").arg("-u").output().context("running id")?;
    String::from_utf8_lossy(&out.stdout).trim().parse().map_err(|_| anyhow!("can't tell the user id"))
}

/// A folder only this user can enter. One that exists must already be ours, not a link, and private.
fn private_dir(dir: &Path, uid: u32) -> Result<()> {
    if let Some(parent) = dir.parent().filter(|p| !p.exists()) {
        fs::create_dir_all(parent)?;
    }
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("creating {}", dir.display())),
    }
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.uid() != uid {
        bail!("{} isn't a folder of yours", dir.display());
    }
    if meta.mode() & 0o077 != 0 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// 256 random bits as 64 hex characters.
pub fn new_key() -> Result<String> {
    let mut bytes = [0u8; 32];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Run `hdiutil`, with the key (if any) on stdin. Returns what it printed.
fn hdiutil(args: &[&std::ffi::OsStr], key: Option<&str>) -> Result<String> {
    let mut child = Command::new("hdiutil")
        .args(args)
        .stdin(if key.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running hdiutil")?;
    if let Some(key) = key {
        let mut stdin = child.stdin.take().expect("piped stdin");
        stdin.write_all(key.as_bytes())?;
        stdin.write_all(&[0])?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let why = String::from_utf8_lossy(&out.stderr);
        bail!("hdiutil {}: {}", args.first().map_or(String::new(), |a| a.to_string_lossy().into_owned()), why.trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Create an empty encrypted store.
pub fn create(layout: &Layout, bundle: &Path, key: &str) -> Result<()> {
    layout.prepare()?;
    if bundle.exists() {
        bail!("{} already exists", bundle.display());
    }
    let result = hdiutil(
        &[
            "create".as_ref(),
            "-encryption".as_ref(),
            "AES-256".as_ref(),
            "-stdinpass".as_ref(),
            "-type".as_ref(),
            "SPARSEBUNDLE".as_ref(),
            "-fs".as_ref(),
            "APFS".as_ref(),
            "-size".as_ref(),
            SIZE.as_ref(),
            "-volname".as_ref(),
            "box".as_ref(),
            "-quiet".as_ref(),
            bundle.as_os_str(),
        ],
        Some(key),
    );
    match result {
        Ok(_) => fs::set_permissions(bundle, fs::Permissions::from_mode(0o700)).context("securing the store"),
        Err(e) => {
            let _ = fs::remove_dir_all(bundle);
            Err(e)
        }
    }
}

/// Delete a store. Its key goes first (the caller's job); this only removes the ciphertext.
pub fn shred(bundle: &Path) -> Result<()> {
    match fs::remove_dir_all(bundle) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("deleting {}", bundle.display())),
    }
}

/// Whether a volume is mounted at this path: it is on another device than its parent folder.
pub fn is_mounted(mnt: &Path) -> bool {
    let (Ok(m), Some(Ok(p))) = (fs::metadata(mnt), mnt.parent().map(fs::metadata)) else { return false };
    m.dev() != p.dev()
}

/// Detach the volume at a mount point (`-force` only if it stays busy) and remove the folder.
pub fn detach(mnt: &Path) -> Result<()> {
    if is_mounted(mnt) {
        let polite = (0..5).any(|i| {
            if i > 0 {
                thread::sleep(Duration::from_millis(400));
            }
            hdiutil(&["detach".as_ref(), mnt.as_os_str()], None).is_ok() || !is_mounted(mnt)
        });
        if !polite {
            hdiutil(&["detach".as_ref(), "-force".as_ref(), mnt.as_os_str()], None)
                .with_context(|| format!("detaching {}", mnt.display()))?;
        }
    }
    let _ = fs::remove_dir(mnt);
    Ok(())
}

/// An attached store. Dropping it detaches the volume, and deletes the store if it is to be shredded.
pub struct Open {
    mnt: PathBuf,
    bundle: PathBuf,
    shred: bool,
}

impl Open {
    pub fn path(&self) -> &Path {
        &self.mnt
    }

    /// Delete the store when this is closed (after detaching it).
    pub fn shred_on_close(&mut self) {
        self.shred = true;
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        match detach(&self.mnt) {
            Ok(()) if self.shred => {
                let _ = shred(&self.bundle);
            }
            Ok(()) => {}
            Err(e) => eprintln!("cred: {e:#} (detach it with: hdiutil detach -force '{}')", self.mnt.display()),
        }
    }
}

/// Attach a store at `mnt`, whose parent must be a private folder. A volume still mounted there is
/// left over from a crash (the caller holds the box's lock, so nobody else uses it) and is
/// detached first. Writable attaches make sure the folders exist.
pub fn open(bundle: &Path, mnt: &Path, key: &str, readonly: bool) -> Result<Open> {
    if !bundle.exists() {
        bail!("{} doesn't exist", bundle.display());
    }
    detach(mnt)?;
    fs::DirBuilder::new().mode(0o700).create(mnt).with_context(|| format!("creating {}", mnt.display()))?;
    let mut args: Vec<&std::ffi::OsStr> = vec![
        "attach".as_ref(),
        "-stdinpass".as_ref(),
        "-nobrowse".as_ref(),
        "-noautoopen".as_ref(),
        "-owners".as_ref(),
        "on".as_ref(),
        "-mountpoint".as_ref(),
        mnt.as_os_str(),
    ];
    if readonly {
        args.push("-readonly".as_ref());
    }
    args.push(bundle.as_os_str());
    if let Err(e) = hdiutil(&args, Some(key)) {
        let _ = fs::remove_dir(mnt);
        return Err(e.context("opening the store (is the key right?)"));
    }
    let store = Open { mnt: mnt.to_path_buf(), bundle: bundle.to_path_buf(), shred: false };
    if !readonly {
        for folder in FOLDERS {
            fs::create_dir_all(mnt.join(folder))?;
        }
        for private in ["log", "door"] {
            fs::set_permissions(mnt.join(private), fs::Permissions::from_mode(0o700))?;
        }
        let marker = mnt.join(".metadata_never_index");
        if !marker.exists() {
            File::create(marker)?;
        }
    }
    Ok(store)
}

/// An exclusive lock on a file, held until dropped: one cred process per open box.
pub struct Lock(#[allow(dead_code)] File);

/// Take the lock; `None` if another process holds it. A busy lock is tried again for a moment:
/// a child that one of our threads has forked but not yet exec'd still shares the lock of a
/// file we just let go of.
pub fn lock(path: &Path) -> Result<Option<Lock>> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    for attempt in 0..20 {
        match file.try_lock() {
            Ok(()) => return Ok(Some(Lock(file))),
            Err(TryLockError::WouldBlock) if attempt < 19 => thread::sleep(Duration::from_millis(10)),
            Err(TryLockError::WouldBlock) => {}
            Err(TryLockError::Error(e)) => return Err(e).with_context(|| format!("locking {}", path.display())),
        }
    }
    Ok(None)
}

/// Whether some process holds the lock right now (a missing lock file is nobody's).
pub fn is_held(path: &Path) -> bool {
    path.exists() && matches!(lock(path), Ok(None))
}

/// Space the store takes on disk, and when it last changed.
pub fn usage(bundle: &Path) -> (u64, Option<SystemTime>) {
    let mut bytes = 0;
    let mut newest = None;
    let mut stack = vec![bundle.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                bytes += meta.blocks() * 512;
                let modified = meta.modified().ok();
                newest = newest.max(modified);
            }
        }
    }
    (bytes, newest)
}

/// Append a line to the store's log, in the door's shape: time, kind, path, bytes, decision. The
/// door's lines chain with the same key, so this one is part of the chain too.
pub fn log_event(mnt: &Path, log_key: &[u8; 32], kind: &str, path: &str, bytes: u64, decision: &str) -> Result<()> {
    let line = json!({ "time": Timestamp::now().to_string(), "kind": kind, "path": path, "bytes": bytes, "decision": decision });
    let chain = Chain::new(&door_log(mnt), *log_key);
    chain.create()?;
    chain.append(line)
}

pub fn door_log(mnt: &Path) -> PathBuf {
    mnt.join(DOOR_LOG)
}

/// Where the box CA is sealed.
pub fn ca_file(mnt: &Path) -> PathBuf {
    mnt.join(CA_FILE)
}

/// What a copy brought over.
pub struct Copied {
    /// Regular files, relative to the destination (just the file's name when one file was copied).
    pub files: Vec<PathBuf>,
    /// Links and special files, which are never followed or copied.
    pub skipped: usize,
}

/// Copy a file or a folder to `dst`, which must not exist. Links, sockets and devices are
/// skipped, never followed, so a link in a box can't make cred read a file outside it. Modes are
/// reduced to rw-r--r-- or rwxr-xr-x.
pub fn copy_tree(src: &Path, dst: &Path) -> Result<Copied> {
    let meta = fs::symlink_metadata(src).with_context(|| format!("reading {}", src.display()))?;
    let mut copied = Copied { files: Vec::new(), skipped: 0 };
    if meta.file_type().is_symlink() {
        bail!("{} is a link; links aren't followed", src.display());
    } else if meta.is_dir() {
        copy_dir(src, dst, Path::new(""), &mut copied)?;
    } else if meta.is_file() {
        copy_file(src, dst, &meta)?;
        copied.files.push(PathBuf::from(dst.file_name().unwrap_or_default()));
    } else {
        bail!("{} isn't a file or folder", src.display());
    }
    Ok(copied)
}

fn copy_dir(src: &Path, dst: &Path, rel: &Path, copied: &mut Copied) -> Result<()> {
    fs::DirBuilder::new().mode(0o755).create(dst).with_context(|| format!("creating {}", dst.display()))?;
    let mut entries: Vec<_> = fs::read_dir(src).with_context(|| format!("reading {}", src.display()))?.collect::<io::Result<_>>()?;
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let (from, to, rel) = (entry.path(), dst.join(entry.file_name()), rel.join(entry.file_name()));
        let meta = fs::symlink_metadata(&from)?;
        if meta.is_dir() {
            copy_dir(&from, &to, &rel, copied)?;
        } else if meta.is_file() {
            copy_file(&from, &to, &meta)?;
            copied.files.push(rel);
        } else {
            copied.skipped += 1;
        }
    }
    Ok(())
}

fn copy_file(src: &Path, dst: &Path, meta: &fs::Metadata) -> Result<()> {
    let mode = if meta.mode() & 0o111 != 0 { 0o755 } else { 0o644 };
    let mut from = File::open(src).with_context(|| format!("reading {}", src.display()))?;
    let mut to = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(dst)
        .with_context(|| format!("creating {}", dst.display()))?;
    io::copy(&mut from, &mut to).with_context(|| format!("copying {}", src.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;
    use crate::util::TempDir;

    #[test]
    fn makes_random_hex_keys() {
        let (a, b) = (new_key().unwrap(), new_key().unwrap());
        assert!(a.len() == 64 && a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn copies_trees_without_following_links() {
        let dir = TempDir::new("cred-copy").unwrap();
        let src = dir.0.join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("a.txt"), "a").unwrap();
        fs::write(src.join("sub/run.sh"), "#!/bin/sh").unwrap();
        fs::set_permissions(src.join("sub/run.sh"), fs::Permissions::from_mode(0o4750)).unwrap();
        fs::write(dir.0.join("secret"), "s3cret").unwrap();
        symlink(dir.0.join("secret"), src.join("link")).unwrap();

        let copied = copy_tree(&src, &dir.0.join("dst")).unwrap();
        assert_eq!(copied.files, [PathBuf::from("a.txt"), PathBuf::from("sub/run.sh")]);
        assert_eq!(copied.skipped, 1);
        assert!(!dir.0.join("dst/link").exists());
        let mode = |p: &str| fs::metadata(dir.0.join(p)).unwrap().mode() & 0o7777;
        assert_eq!((mode("dst/a.txt"), mode("dst/sub/run.sh")), (0o644, 0o755));

        assert!(copy_tree(&src, &dir.0.join("dst")).is_err(), "never merges into an existing folder");
        assert!(copy_tree(&src.join("link"), &dir.0.join("x")).is_err(), "a link as the source");
        let one = copy_tree(&src.join("a.txt"), &dir.0.join("one.txt")).unwrap();
        assert_eq!(one.files, [PathBuf::from("one.txt")]);
        assert!(copy_tree(&src.join("a.txt"), &dir.0.join("one.txt")).is_err(), "never overwrites");
    }

    #[test]
    fn locks_exclude_each_other() {
        let dir = TempDir::new("cred-lock").unwrap();
        let path = dir.0.join("x.lock");
        let first = lock(&path).unwrap().expect("free");
        assert!(lock(&path).unwrap().is_none(), "held");
        drop(first);
        assert!(lock(&path).unwrap().is_some(), "released");
    }

    #[test]
    fn keeps_folders_private() {
        let dir = TempDir::new("cred-private").unwrap();
        let layout = Layout::under(&dir.0).unwrap();
        layout.prepare().unwrap();
        for d in [&layout.root, &layout.open_dir(), &layout.sockets] {
            assert_eq!(fs::metadata(d).unwrap().mode() & 0o777, 0o700, "{}", d.display());
        }
        fs::set_permissions(&layout.sockets, fs::Permissions::from_mode(0o755)).unwrap();
        layout.prepare().unwrap();
        assert_eq!(fs::metadata(&layout.sockets).unwrap().mode() & 0o777, 0o700, "loosened folders are tightened");
        fs::remove_dir(layout.root.join("temp")).unwrap();
        symlink(&dir.0, layout.root.join("temp")).unwrap();
        assert!(layout.prepare().is_err(), "a link where a private folder belongs");
    }

    /// The real thing: hdiutil, in a temp folder, with a random key.
    #[test]
    fn stores_are_encrypted_and_open_only_with_the_key() {
        let dir = TempDir::new("cred-store").unwrap();
        let layout = Layout::under(&dir.0).unwrap();
        let (key, other) = (new_key().unwrap(), new_key().unwrap());
        let bundle = layout.bundle("t");
        let mnt = layout.mount_point("t");
        create(&layout, &bundle, &key).unwrap();
        assert!(create(&layout, &bundle, &key).is_err(), "never replaces a store");
        assert_eq!(fs::metadata(&bundle).unwrap().mode() & 0o777, 0o700);

        let store = open(&bundle, &mnt, &key, false).unwrap();
        assert!(is_mounted(&mnt));
        for folder in FOLDERS {
            assert!(mnt.join(folder).is_dir(), "{folder}");
        }
        assert!(mnt.join(".metadata_never_index").exists());
        let marker = "MARKER-0123456789-abcdefghijklmnopqrstuvwxyz";
        fs::write(mnt.join("work/note.txt"), marker.repeat(100)).unwrap();
        assert_eq!(fs::metadata(mnt.join("work/note.txt")).unwrap().uid(), fs::metadata(&dir.0).unwrap().uid(), "owners are kept");
        log_event(store.path(), &[7; 32], "export", "work/note.txt", 4300, "allowed").unwrap();
        assert!(fs::read_to_string(door_log(&mnt)).unwrap().contains("\"kind\":\"export\""));
        drop(store);
        assert!(!is_mounted(&mnt) && !mnt.exists());

        // At rest, the bundle holds no plaintext.
        let (bytes, newest) = usage(&bundle);
        assert!(bytes > 0 && newest.is_some());
        let mut stack = vec![bundle.clone()];
        while let Some(d) = stack.pop() {
            for e in fs::read_dir(d).unwrap().flatten() {
                if e.path().is_dir() {
                    stack.push(e.path());
                } else {
                    let content = fs::read(e.path()).unwrap();
                    assert!(!content.windows(marker.len()).any(|w| w == marker.as_bytes()), "{}", e.path().display());
                }
            }
        }

        assert!(open(&bundle, &mnt, &other, false).is_err(), "a wrong key");
        assert!(!mnt.exists(), "a failed open leaves no mount folder");

        // Read-only attaches refuse writes; a crash's leftover mount is detached by the next open.
        let ro = open(&bundle, &mnt, &key, true).unwrap();
        assert_eq!(fs::read_to_string(mnt.join("work/note.txt")).unwrap().len(), marker.len() * 100);
        assert!(fs::write(mnt.join("work/new.txt"), "x").is_err());
        std::mem::forget(ro);
        assert!(is_mounted(&mnt));
        let mut again = open(&bundle, &mnt, &key, false).unwrap();
        assert!(mnt.join("work/note.txt").exists());
        again.shred_on_close();
        drop(again);
        assert!(!is_mounted(&mnt) && !bundle.exists(), "dropping a shredded store detaches and deletes it");
    }
}

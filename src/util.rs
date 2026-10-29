//! Small helpers shared by several commands.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{env, fs, process};

use anyhow::Result;
use sha2::{Digest, Sha256};

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

pub fn home() -> PathBuf {
    PathBuf::from(env::var_os("HOME").unwrap_or_default())
}

pub fn config_dir() -> PathBuf {
    home().join(".config/cred")
}

/// Expand a leading "~/" to the home directory.
pub fn expand_home(path: &str) -> PathBuf {
    match path.strip_prefix("~/") {
        Some(rest) => home().join(rest),
        None => PathBuf::from(path),
    }
}

/// A private temporary directory (mode 700), removed when dropped.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new(prefix: &str) -> Result<Self> {
        static COUNT: AtomicUsize = AtomicUsize::new(0);
        let n = COUNT.fetch_add(1, Ordering::Relaxed);
        let dir = env::temp_dir().join(format!("{prefix}-{}-{n}", process::id()));
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

/// Put stdin, stdout and stderr back in blocking mode. A program that shared the terminal
/// (`container`'s progress display, say) can leave it non-blocking, and then a long print fails
/// with EAGAIN, which panics before any prompt is shown.
pub fn blocking_stdio() {
    for fd in 0..3 {
        set_blocking(fd);
    }
}

fn set_blocking(fd: i32) {
    // The values of <fcntl.h> on macOS.
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;
    const O_NONBLOCK: i32 = 0x0004;
    unsafe {
        let flags = fcntl(fd, F_GETFL);
        if flags >= 0 && flags & O_NONBLOCK != 0 {
            fcntl(fd, F_SETFL, flags & !O_NONBLOCK);
        }
    }
}

unsafe extern "C" {
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
}

#[cfg(test)]
mod tests {
    use std::io::{ErrorKind, Read};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    #[test]
    fn a_non_blocking_descriptor_blocks_again() {
        let (mut a, _b) = UnixStream::pair().unwrap();
        a.set_nonblocking(true).unwrap();
        assert_eq!(a.read(&mut [0; 1]).unwrap_err().kind(), ErrorKind::WouldBlock);
        super::set_blocking(a.as_raw_fd());
        // Blocking again: a read waits, so only the timeout ends it.
        a.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        assert_eq!(a.read(&mut [0; 1]).unwrap_err().kind(), ErrorKind::WouldBlock);
        let started = std::time::Instant::now();
        let _ = a.read(&mut [0; 1]);
        assert!(started.elapsed() >= Duration::from_millis(40));
    }
}

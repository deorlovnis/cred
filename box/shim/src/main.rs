//! cred-shim: the guest side of a box's door.
//!
//! A box has no network. cred, on the Mac, dials connections into the Unix socket this daemon
//! listens on (`serve`, the VM's init process); programs in the box talk to local listeners
//! instead, and each of their connections is paired with one of those idle connections from the
//! Mac. The first line sent to the Mac says which listener the program came to:
//!
//! - `proxy`: TCP 127.0.0.1:3128, the HTTP proxy
//! - `cred`:  TCP 127.0.0.2:80, `cred.internal`
//! - `mcp`:   /run/cred/local.sock, which `cred-shim mcp` (cred's MCP server over stdio) dials
//!
//! After that line the bytes go both ways until both sides are done (half-close aware).

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
use std::{env, fs, process, thread};

const RUN_DIR: &str = "/run/cred";
const DOOR_SOCK: &str = "/run/cred/door.sock";
const LOCAL_SOCK: &str = "/run/cred/local.sock";
const PROXY_ADDR: (&str, u16) = ("127.0.0.1", 3128);
const CRED_ADDR: (&str, u16) = ("127.0.0.2", 80);

fn main() {
    let result = match env::args().nth(1).as_deref() {
        Some("serve") => serve(),
        Some("mcp") => UnixStream::connect(LOCAL_SOCK)
            .map_err(|e| io::Error::new(e.kind(), format!("connecting to {LOCAL_SOCK}: {e}")))
            .and_then(|sock| relay(sock, io::stdin(), io::stdout())),
        _ => {
            eprintln!("usage: cred-shim serve | mcp");
            process::exit(2);
        }
    };
    if let Err(e) = result {
        eprintln!("cred-shim: {e}");
        process::exit(1);
    }
}

/// A byte stream that can be duplicated and half-closed, TCP or Unix.
trait Conn: Read + Write + Send + Sized + 'static {
    fn dup(&self) -> io::Result<Self>;
    fn shut(&self, how: Shutdown) -> io::Result<()>;
}

impl Conn for TcpStream {
    fn dup(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn shut(&self, how: Shutdown) -> io::Result<()> {
        self.shutdown(how)
    }
}

impl Conn for UnixStream {
    fn dup(&self) -> io::Result<Self> {
        self.try_clone()
    }
    fn shut(&self, how: Shutdown) -> io::Result<()> {
        self.shutdown(how)
    }
}

/// The idle connections the Mac has dialed in, waiting for a client.
#[derive(Default)]
struct Pool {
    idle: Mutex<VecDeque<UnixStream>>,
    arrived: Condvar,
}

impl Pool {
    fn put(&self, host: UnixStream) {
        self.idle.lock().unwrap_or_else(|e| e.into_inner()).push_back(host);
        self.arrived.notify_one();
    }

    /// The oldest idle connection that is still open, waiting for one if there is none.
    fn take(&self) -> UnixStream {
        let mut idle = self.idle.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            match idle.pop_front() {
                Some(host) if still_open(&host) => return host,
                Some(_) => {}
                None => idle = self.arrived.wait(idle).unwrap_or_else(|e| e.into_inner()),
            }
        }
    }
}

/// An idle connection has nothing to read; end-of-file, or data nobody asked for, means the Mac
/// side is gone or confused (and the connection is dropped, so a byte consumed here is no loss).
fn still_open(mut host: &UnixStream) -> bool {
    let mut byte = [0u8];
    if host.set_nonblocking(true).is_err() {
        return false;
    }
    let idle = matches!(host.read(&mut byte), Err(e) if e.kind() == io::ErrorKind::WouldBlock);
    idle && host.set_nonblocking(false).is_ok()
}

/// Copy `from` to `to` until `from` ends. A clean end is passed on as a half-close, so the other
/// direction can still finish; an error tears both down so the other direction stops too.
fn pump<R: Conn, W: Conn>(mut from: R, mut to: W) {
    let how = if io::copy(&mut from, &mut to).is_ok() { Shutdown::Write } else { Shutdown::Both };
    let _ = to.shut(how);
    if how == Shutdown::Both {
        let _ = from.shut(Shutdown::Both);
    }
}

/// Copy both ways between two streams until each direction has ended.
fn bridge<A: Conn, B: Conn>(a: A, b: B) -> io::Result<()> {
    let (a2, b2) = (a.dup()?, b.dup()?);
    let forward = thread::spawn(move || pump(a, b2));
    pump(b, a2);
    let _ = forward.join();
    Ok(())
}

/// Pair one client with an idle connection from the Mac, tell the Mac which listener the client
/// came to, and carry the bytes.
fn serve_client<C: Conn>(client: C, kind: &str, pool: &Pool) -> io::Result<()> {
    let host = loop {
        let mut host = pool.take();
        if host.write_all(format!("{kind}\n").as_bytes()).is_ok() {
            break host;
        }
    };
    bridge(client, host)
}

/// A thread per client, so one slow or broken client never holds up the rest.
fn accept_loop<C: Conn>(incoming: impl Iterator<Item = io::Result<C>>, kind: &'static str, pool: Arc<Pool>) {
    for client in incoming {
        match client {
            Ok(client) => {
                let pool = pool.clone();
                thread::spawn(move || {
                    let _ = serve_client(client, kind, &pool);
                });
            }
            // e.g. out of file descriptors: wait for some to free up
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
}

/// Everything the Mac dials in goes into the pool.
fn collect_hosts(listener: UnixListener, pool: Arc<Pool>) {
    for host in listener.incoming() {
        match host {
            Ok(host) => pool.put(host),
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
}

fn bind_unix(path: &str, mode: u32) -> io::Result<UnixListener> {
    let _ = fs::remove_file(path);
    let listener = UnixListener::bind(path).map_err(|e| io::Error::new(e.kind(), format!("listening on {path}: {e}")))?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(listener)
}

fn bind_tcp(addr: (&str, u16)) -> io::Result<TcpListener> {
    TcpListener::bind(addr).map_err(|e| io::Error::new(e.kind(), format!("listening on {}:{}: {e}", addr.0, addr.1)))
}

/// The init process of the VM: the listeners, and the pool the Mac fills. Returns only on a
/// startup error; client trouble never ends it.
fn serve() -> io::Result<()> {
    fs::create_dir_all(RUN_DIR)?;
    fs::set_permissions(RUN_DIR, fs::Permissions::from_mode(0o755))?;
    let pool = Arc::new(Pool::default());
    // Only root may connect to the door socket: a program in the box must not pose as the Mac.
    let door = bind_unix(DOOR_SOCK, 0o600)?;
    let local = bind_unix(LOCAL_SOCK, 0o666)?;
    let proxy = bind_tcp(PROXY_ADDR)?;
    let cred = bind_tcp(CRED_ADDR)?;

    let p = pool.clone();
    thread::spawn(move || collect_hosts(door, p));
    let p = pool.clone();
    thread::spawn(move || accept_loop(local.incoming(), "mcp", p));
    let p = pool.clone();
    thread::spawn(move || accept_loop(proxy.incoming(), "proxy", p));
    accept_loop(cred.incoming(), "cred", pool);
    Ok(())
}

/// `cred-shim mcp`: carry `input` and `output` (an MCP client's stdio) over `sock`, which the
/// daemon pairs with cred's MCP server. Ends when the server hangs up.
fn relay(sock: UnixStream, mut input: impl Read + Send + 'static, mut output: impl Write) -> io::Result<()> {
    let mut up = sock.try_clone()?;
    thread::spawn(move || {
        let _ = io::copy(&mut input, &mut up);
        // stdin ended: tell the server, which answers what is left and hangs up
        let _ = up.shutdown(Shutdown::Write);
    });
    let mut down = sock;
    let mut buf = [0u8; 16 * 1024];
    loop {
        match down.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                output.write_all(&buf[..n])?;
                output.flush()?;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    /// A connected pair standing in for (cred's end, the pool's end) of a dialed-in connection.
    fn dialed() -> (UnixStream, UnixStream) {
        UnixStream::pair().unwrap()
    }

    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        (client, listener.accept().unwrap().0)
    }

    #[test]
    fn pairs_a_client_with_a_host_and_names_the_kind() {
        let pool = Pool::default();
        let (mac, shim_end) = dialed();
        pool.put(shim_end);
        let (mut program, client) = tcp_pair();
        let handle = thread::spawn(move || serve_client(client, "proxy", &pool));

        let mut mac = BufReader::new(mac);
        let mut line = String::new();
        mac.read_line(&mut line).unwrap();
        assert_eq!(line, "proxy\n");

        program.write_all(b"CONNECT example.com:443\n").unwrap();
        line.clear();
        mac.read_line(&mut line).unwrap();
        assert_eq!(line, "CONNECT example.com:443\n");

        mac.get_mut().write_all(b"200\n").unwrap();
        let mut reply = [0u8; 4];
        program.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"200\n");

        drop(program);
        mac.get_mut().shutdown(Shutdown::Both).unwrap();
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn half_close_still_lets_the_reply_through() {
        let pool = Pool::default();
        let (mac, shim_end) = dialed();
        pool.put(shim_end);
        let (mut program, client) = tcp_pair();
        thread::spawn(move || serve_client(client, "cred", &pool));

        program.write_all(b"request").unwrap();
        program.shutdown(Shutdown::Write).unwrap();

        // the Mac reads the kind line and the request up to end-of-file, then answers
        let mut mac = mac;
        let mut got = String::new();
        mac.read_to_string(&mut got).unwrap();
        assert_eq!(got, "cred\nrequest");
        mac.write_all(b"response").unwrap();
        mac.shutdown(Shutdown::Write).unwrap();

        let mut reply = String::new();
        program.read_to_string(&mut reply).unwrap();
        assert_eq!(reply, "response");
    }

    #[test]
    fn skips_hosts_that_have_gone() {
        let pool = Pool::default();
        let (gone, gone_shim) = dialed();
        drop(gone);
        pool.put(gone_shim);
        let (mut mac, live_shim) = dialed();
        pool.put(live_shim);

        let (_program, client) = tcp_pair();
        thread::spawn(move || serve_client(client, "mcp", &pool));

        let mut line = [0u8; 4];
        mac.read_exact(&mut line).unwrap();
        assert_eq!(&line, b"mcp\n");
    }

    #[test]
    fn waits_for_a_host_to_arrive() {
        let pool = Arc::new(Pool::default());
        let (mut program, client) = tcp_pair();
        let p = pool.clone();
        thread::spawn(move || serve_client(client, "proxy", &p));
        thread::sleep(Duration::from_millis(100));

        let (mut mac, shim_end) = dialed();
        pool.put(shim_end);
        program.write_all(b"x").unwrap();
        let mut got = [0u8; 7];
        mac.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"proxy\nx");
    }

    #[test]
    fn a_client_that_vanishes_does_not_stop_the_listener() {
        let pool = Arc::new(Pool::default());
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let p = pool.clone();
        thread::spawn(move || accept_loop(listener.incoming(), "proxy", p));

        let mut macs = Vec::new();
        for _ in 0..2 {
            let (mac, shim_end) = dialed();
            pool.put(shim_end);
            macs.push(mac);
            // connect, send a little, and go
            let mut c = TcpStream::connect(addr).unwrap();
            c.write_all(b"junk").unwrap();
            drop(c);
        }
        for mac in &mut macs {
            let mut got = String::new();
            BufReader::new(mac).read_line(&mut got).unwrap();
            assert_eq!(got, "proxy\n");
        }
    }

    #[test]
    fn relay_carries_stdio_both_ways_and_ends_with_the_server() {
        let (server, sock) = dialed();
        let (mut stdin_w, stdin_r) = dialed();
        let (stdout_w, mut stdout_r) = dialed();
        let handle = thread::spawn(move || relay(sock, stdin_r, stdout_w));

        stdin_w.write_all(b"{\"id\":1}\n").unwrap();
        let mut server = BufReader::new(server);
        let mut line = String::new();
        server.read_line(&mut line).unwrap();
        assert_eq!(line, "{\"id\":1}\n");

        server.get_mut().write_all(b"{\"result\":1}\n").unwrap();
        let mut reply = [0u8; 13];
        stdout_r.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"{\"result\":1}\n");

        // stdin ends: the server sees end-of-file, and hanging up ends the relay
        stdin_w.shutdown(Shutdown::Write).unwrap();
        let mut rest = String::new();
        server.read_line(&mut rest).unwrap();
        assert_eq!(rest, "");
        drop(server);
        handle.join().unwrap().unwrap();
    }
}

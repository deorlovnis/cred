//! The `proxy` kind: an HTTP proxy that understands CONNECT to port 443 and nothing else. The
//! box's tools send host names; cred decides by name whether the box may reach it, resolves it
//! itself and connects to a public address (see `addr`).
//!
//! With a box CA (the normal case) the door then ends TLS. It makes its own verified TLS
//! connection to the site first, so a site whose certificate doesn't verify gets a 502 and the
//! guest never has a tunnel. Then it tells the guest the tunnel is open, answers the guest's TLS
//! with a certificate from the box CA, and hands both sides, decrypted, to `inspect`. Without a
//! CA it copies bytes both ways and sees no requests.

use std::io::{self, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, TcpStream};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

use super::addr::{HTTPS_PORT, split_target};
use super::http::{self, Head};
use super::inspect::{self, Ctx};
use super::tls;
use super::{Entry, Shared};

/// The guest has this long to send its CONNECT line once it has taken a connection.
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);

pub fn serve(sh: &Shared, mut reader: BufReader<UnixStream>, mut writer: UnixStream) {
    let _ = writer.set_read_timeout(Some(HEAD_TIMEOUT));
    let head = match http::read_head(&mut reader) {
        Ok(Some(head)) => head,
        Ok(None) => return,
        Err(_) => return refuse(sh, &mut writer, Entry::new("proxy", "blocked:bad-request"), 400, "Bad request"),
    };
    let _ = writer.set_read_timeout(None);
    let Some((host, upstream, ip)) = connect_target(sh, &mut writer, &head) else { return };
    let entry = |decision: &str, up, down| Entry { host: Some(host.clone()), addr: Some(ip.to_string()), up, down, ..Entry::new("proxy", decision) };
    let Some(ca) = &sh.cfg.ca else {
        if writer.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").is_err() {
            return;
        }
        sh.log.write(&entry("allowed", 0, 0));
        let (up, down) = tunnel(reader, writer, upstream);
        sh.log.write(&entry("closed", up, down));
        return;
    };

    // The site first: with a certificate that doesn't verify there is nothing to tunnel to.
    let Ok(raw) = upstream.try_clone() else { return };
    let site = match tls::connect(sh.net.tls(), &host, upstream) {
        Ok(site) => site,
        Err(e) => {
            let why = format!("can't verify {host}: {e:#}");
            return refuse(sh, &mut writer, entry(&format!("failed:tls: {e:#}"), 0, 0), 502, &why);
        }
    };
    if writer.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").is_err() {
        return;
    }
    // A guest that doesn't trust the box CA fails here, and nothing reaches the site.
    let _ = writer.set_read_timeout(Some(HEAD_TIMEOUT));
    let guest = writer.try_clone().map_err(anyhow::Error::from).and_then(|w| tls::accept(ca, &host, reader, w));
    let _ = writer.set_read_timeout(None);
    match guest {
        Ok(guest) => {
            sh.log.write(&entry("allowed", 0, 0));
            let (up, down) = inspect::serve(guest.clone(), site.clone(), &Ctx { shared: sh, host: &host });
            let _ = guest.finish();
            let _ = site.finish();
            sh.log.write(&entry("closed", up, down));
        }
        Err(e) => sh.log.write(&entry(&format!("failed:tls: {e:#}"), 0, 0)),
    }
    let _ = raw.shutdown(Shutdown::Both);
    let _ = writer.shutdown(Shutdown::Both);
}

/// The upstream connection a CONNECT request asks for. If the request is refused, say so to the
/// guest and in the log, and return nothing.
fn connect_target(sh: &Shared, writer: &mut UnixStream, head: &Head) -> Option<(String, TcpStream, IpAddr)> {
    let Some((method, target, _)) = head.parts() else {
        refuse(sh, writer, Entry::new("proxy", "blocked:bad-request"), 400, "Bad request");
        return None;
    };
    // Only the method is logged for other requests: the rest of a plain proxy request is a URL.
    if method != "CONNECT" {
        let method = method.chars().filter(|c| c.is_ascii_graphic()).take(16).collect();
        refuse(sh, writer, Entry { method: Some(method), ..Entry::new("proxy", "blocked:not-connect") }, 405, "CONNECT only");
        return None;
    }
    let Some((host, port)) = split_target(target) else {
        refuse(sh, writer, Entry::new("proxy", "blocked:bad-target"), 400, "Bad CONNECT target");
        return None;
    };
    let mut blocked = |decision: &str, status, why: &str| {
        refuse(sh, writer, Entry { host: Some(host.clone()), ..Entry::new("proxy", decision) }, status, why);
    };
    if port != HTTPS_PORT {
        blocked("blocked:port", 403, "Only port 443 is allowed");
    } else if !sh.allow.allows(&host) {
        blocked("blocked:policy", 403, "Not allowed by the box policy");
    } else {
        match sh.net.connect(&host) {
            Ok((upstream, ip)) => return Some((host, upstream, ip)),
            Err(refusal) => {
                let status = if refusal.decision().starts_with("blocked") { 403 } else { 502 };
                blocked(refusal.decision(), status, &refusal.message());
            }
        }
    }
    None
}

fn refuse(sh: &Shared, writer: &mut UnixStream, entry: Entry, status: u16, why: &str) {
    sh.log.write(&entry);
    let reason = http::reason(status);
    let allow = if status == 405 { "Allow: CONNECT\r\n" } else { "" };
    // `why` may carry another library's words; keep them to one line.
    let why: String = why.chars().filter(|c| !c.is_control()).collect();
    let _ = write!(writer, "HTTP/1.1 {status} {reason}: {why}\r\n{allow}Content-Length: 0\r\nConnection: close\r\n\r\n");
    let _ = writer.flush();
}

/// Copy bytes both ways until both sides are done; the bytes sent up and down.
fn tunnel(guest_in: BufReader<UnixStream>, guest: UnixStream, upstream: TcpStream) -> (u64, u64) {
    let (Ok(mut guest_out), Ok(mut upstream_in), Ok(mut upstream_out)) = (guest.try_clone(), upstream.try_clone(), upstream.try_clone()) else {
        return (0, 0);
    };
    let down = thread::spawn(move || {
        let (bytes, result) = copy(&mut upstream_in, &mut guest_out);
        end(&result, &upstream_in, &guest_out);
        bytes
    });
    let mut guest_in = guest_in;
    let (up, result) = copy(&mut guest_in, &mut upstream_out);
    end(&result, guest_in.get_ref(), &upstream_out);
    (up, down.join().unwrap_or(0))
}

/// Shutting down one end of a connection, whatever kind it is.
trait Socket {
    fn close(&self, how: Shutdown);
}

impl Socket for UnixStream {
    fn close(&self, how: Shutdown) {
        let _ = self.shutdown(how);
    }
}

impl Socket for TcpStream {
    fn close(&self, how: Shutdown) {
        let _ = self.shutdown(how);
    }
}

/// After one direction ends: pass the end of the stream on, or after an error close both sides.
fn end(result: &io::Result<()>, source: &impl Socket, sink: &impl Socket) {
    if result.is_ok() {
        sink.close(Shutdown::Write);
    } else {
        source.close(Shutdown::Both);
        sink.close(Shutdown::Both);
    }
}

fn copy(from: &mut impl Read, to: &mut impl Write) -> (u64, io::Result<()>) {
    let (mut buf, mut total) = ([0u8; 16 * 1024], 0u64);
    loop {
        match from.read(&mut buf) {
            Ok(0) => return (total, Ok(())),
            Ok(n) => match to.write_all(&buf[..n]) {
                Ok(()) => total += n as u64,
                Err(e) => return (total, Err(e)),
            },
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return (total, Err(e)),
        }
    }
}

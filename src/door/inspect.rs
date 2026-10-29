// STUB: replaced at merge by Agent Rules' inspect.rs. It only has to keep the signature the
// proxy calls: `serve(guest, upstream, &Ctx) -> (bytes up, bytes down)`. This one reads no
// requests and applies no rules: it copies decrypted bytes both ways.

use std::io::{self, Read, Write};
use std::thread;

use super::Shared;
use super::tls::Tls;

#[allow(dead_code)] // the real inspect uses them
pub struct Ctx<'a> {
    pub shared: &'a Shared,
    /// The site the guest asked to reach (the CONNECT target), lower case.
    pub host: &'a str,
}

/// Serve the guest's HTTP/1.1 requests (already decrypted) to the site (already connected and
/// verified) until either side closes. Returns the bytes sent up and down.
pub fn serve(guest: Tls, upstream: Tls, _ctx: &Ctx) -> (u64, u64) {
    let (mut guest_in, mut upstream_out) = (guest.clone(), upstream.clone());
    let (mut upstream_in, mut guest_out) = (upstream.clone(), guest.clone());
    thread::scope(|scope| {
        let up = scope.spawn(move || {
            let bytes = copy(&mut guest_in, &mut upstream_out);
            let _ = upstream_out.finish();
            bytes
        });
        let down = copy(&mut upstream_in, &mut guest_out);
        let _ = guest_out.finish();
        (up.join().unwrap_or(0), down)
    })
}

fn copy(from: &mut impl Read, to: &mut impl Write) -> u64 {
    let (mut buf, mut total) = ([0u8; 16 * 1024], 0u64);
    loop {
        match from.read(&mut buf) {
            Ok(0) => return total,
            Ok(n) => match to.write_all(&buf[..n]) {
                Ok(()) => total += n as u64,
                Err(_) => return total,
            },
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return total,
        }
    }
}

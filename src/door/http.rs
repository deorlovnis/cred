//! Just enough HTTP/1.1 for the door's two listeners: reading a request head and body, and
//! writing small responses. The guest's connection is the only peer, so nothing here aims to
//! be a general server; anything unusual is refused.

use std::io::{self, BufRead, Read, Write};

/// A request head (line and headers) can't be longer than this.
const MAX_HEAD: usize = 64 * 1024;

pub struct Head {
    /// The request line, e.g. `POST /model/v1/messages HTTP/1.1`.
    pub line: String,
    pub headers: Vec<(String, String)>,
}

impl Head {
    /// The request line's method, target and version.
    pub fn parts(&self) -> Option<(&str, &str, &str)> {
        let mut parts = self.line.split(' ');
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(m), Some(t), Some(v), None) if !m.is_empty() && !t.is_empty() && v.starts_with("HTTP/") => Some((m, t, v)),
            _ => None,
        }
    }

    /// The first header with this name (any case).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }

    /// Whether the connection stays open after the response.
    pub fn keep_alive(&self) -> bool {
        let wants = |token: &str| {
            self.headers
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
                .any(|(_, v)| v.split(',').any(|t| t.trim().eq_ignore_ascii_case(token)))
        };
        match self.parts() {
            Some((_, _, "HTTP/1.0")) => wants("keep-alive"),
            _ => !wants("close"),
        }
    }
}

fn invalid(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why.to_string())
}

fn is_token(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Read a line of at most `room` bytes, without its line ending; `None` at a clean end.
fn read_line(r: &mut impl BufRead, room: usize) -> io::Result<Option<String>> {
    let mut raw = Vec::new();
    let n = r.by_ref().take(room as u64 + 1).read_until(b'\n', &mut raw)?;
    if n == 0 {
        return Ok(None);
    }
    if n > room {
        return Err(invalid("line too long"));
    }
    if !raw.ends_with(b"\n") {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    let text = String::from_utf8_lossy(&raw);
    Ok(Some(text.trim_end_matches(['\r', '\n']).to_string()))
}

/// Read a request head. `None` if the peer closed before sending anything; `InvalidData` if
/// what came isn't a head this door accepts.
pub fn read_head(r: &mut impl BufRead) -> io::Result<Option<Head>> {
    let mut room = MAX_HEAD;
    let mut lines = Vec::new();
    loop {
        let Some(line) = read_line(r, room)? else {
            return if lines.is_empty() { Ok(None) } else { Err(io::ErrorKind::UnexpectedEof.into()) };
        };
        room = room.saturating_sub(line.len() + 2);
        match (line.is_empty(), lines.is_empty()) {
            (true, true) => continue, // stray blank line before a request
            (true, false) => break,
            _ => lines.push(line),
        }
    }
    let line = lines.remove(0);
    let headers = lines
        .iter()
        .map(|l| {
            l.split_once(':')
                .filter(|(name, _)| is_token(name))
                .map(|(name, value)| (name.to_string(), value.trim().to_string()))
                .ok_or_else(|| invalid("bad header line"))
        })
        .collect::<io::Result<Vec<_>>>()?;
    Ok(Some(Head { line, headers }))
}

/// Read the request body, which is `Content-Length` bytes or chunked, up to `max` bytes.
/// A body over the limit is `FileTooLarge`; one that makes no sense is `InvalidData`.
pub fn read_body(r: &mut impl BufRead, head: &Head, max: usize) -> io::Result<Vec<u8>> {
    let lengths: Vec<&str> = head.headers.iter().filter(|(n, _)| n.eq_ignore_ascii_case("content-length")).map(|(_, v)| v.as_str()).collect();
    match (head.header("transfer-encoding"), lengths.as_slice()) {
        (Some(_), [_, ..]) => Err(invalid("both Content-Length and Transfer-Encoding")),
        (Some(te), []) if te.eq_ignore_ascii_case("chunked") => read_chunked(r, max),
        (Some(_), []) => Err(invalid("unsupported Transfer-Encoding")),
        (None, []) => Ok(Vec::new()),
        (None, [first, rest @ ..]) => {
            if rest.iter().any(|l| l != first) || first.is_empty() || !first.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid("bad Content-Length"));
            }
            let len: usize = first.parse().map_err(|_| io::Error::from(io::ErrorKind::FileTooLarge))?;
            if len > max {
                return Err(io::ErrorKind::FileTooLarge.into());
            }
            let mut body = vec![0; len];
            r.read_exact(&mut body)?;
            Ok(body)
        }
    }
}

fn read_chunked(r: &mut impl BufRead, max: usize) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line = read_line(r, 1024)?.ok_or(io::ErrorKind::UnexpectedEof)?;
        let size = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size, 16).map_err(|_| invalid("bad chunk size"))?;
        if size == 0 {
            // Trailers, up to the blank line.
            while !read_line(r, 8192)?.ok_or(io::ErrorKind::UnexpectedEof)?.is_empty() {}
            return Ok(body);
        }
        if body.len().saturating_add(size) > max {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        let start = body.len();
        body.resize(start + size, 0);
        r.read_exact(&mut body[start..])?;
        if !read_line(r, 2)?.ok_or(io::ErrorKind::UnexpectedEof)?.is_empty() {
            return Err(invalid("chunk not followed by a line break"));
        }
    }
}

/// Write a complete response with a body of known length.
pub fn respond(w: &mut impl Write, status: u16, content_type: &str, body: &[u8], keep_alive: bool) -> io::Result<()> {
    let reason = reason(status);
    let connection = if keep_alive { "keep-alive" } else { "close" };
    write!(w, "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n", body.len())?;
    w.write_all(body)?;
    w.flush()
}

pub fn reason(status: u16) -> &'static str {
    ureq::http::StatusCode::from_u16(status).ok().and_then(|s| s.canonical_reason()).unwrap_or("Status")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn head(text: &str) -> io::Result<Option<Head>> {
        read_head(&mut Cursor::new(text.as_bytes().to_vec()))
    }

    #[test]
    fn reads_a_head() {
        let h = head("POST /model/v1/messages?x=1 HTTP/1.1\r\nHost: cred.internal\r\nX-Api-Key:  cred-managed \r\n\r\nbody").unwrap().unwrap();
        assert_eq!(h.parts(), Some(("POST", "/model/v1/messages?x=1", "HTTP/1.1")));
        assert_eq!(h.header("x-api-key"), Some("cred-managed"));
        assert_eq!(h.header("HOST"), Some("cred.internal"));
        assert!(h.keep_alive());
    }

    #[test]
    fn leaves_the_body_unread_and_skips_blank_lines_before_a_request() {
        let mut r = Cursor::new(b"\r\nGET / HTTP/1.1\r\n\r\nrest".to_vec());
        let h = read_head(&mut r).unwrap().unwrap();
        assert_eq!(h.parts(), Some(("GET", "/", "HTTP/1.1")));
        let mut rest = String::new();
        r.read_to_string(&mut rest).unwrap();
        assert_eq!(rest, "rest");
    }

    #[test]
    fn a_clean_close_is_no_request_and_a_cut_head_is_an_error() {
        assert!(head("").unwrap().is_none());
        assert!(head("GET / HTTP/1.1\r\nHost: x").is_err());
        assert!(head("GET / HTTP/1.1\r\nHost: x\r\n").is_err());
    }

    #[test]
    fn refuses_malformed_heads() {
        assert!(head("GET / HTTP/1.1\r\nBad Header: x\r\n\r\n").is_err());
        assert!(head("GET / HTTP/1.1\r\n folded: x\r\n\r\n").is_err());
        assert!(head("GET / HTTP/1.1\r\nno colon\r\n\r\n").is_err());
        let long = format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(MAX_HEAD));
        assert!(head(&long).is_err());
        let many = format!("GET / HTTP/1.1\r\n{}\r\n", "X-A: b\r\n".repeat(MAX_HEAD / 8));
        assert!(head(&many).is_err());
    }

    #[test]
    fn request_lines_need_three_parts() {
        for line in ["GET /", "GET / HTTP/1.1 extra", "GET  HTTP/1.1", "GET / FTP/1.1"] {
            assert_eq!(head(&format!("{line}\r\n\r\n")).unwrap().unwrap().parts(), None, "{line}");
        }
    }

    #[test]
    fn keep_alive_follows_version_and_connection_header() {
        let ka = |text: &str| head(text).unwrap().unwrap().keep_alive();
        assert!(ka("GET / HTTP/1.1\r\n\r\n"));
        assert!(!ka("GET / HTTP/1.1\r\nConnection: close\r\n\r\n"));
        assert!(!ka("GET / HTTP/1.1\r\nConnection: keep-alive, Close\r\n\r\n"));
        assert!(!ka("GET / HTTP/1.0\r\n\r\n"));
        assert!(ka("GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n"));
    }

    fn body(text: &str, max: usize) -> io::Result<Vec<u8>> {
        let mut r = Cursor::new(text.as_bytes().to_vec());
        let h = read_head(&mut r).unwrap().unwrap();
        read_body(&mut r, &h, max)
    }

    #[test]
    fn reads_a_body_by_length() {
        assert_eq!(body("POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello!", 100).unwrap(), b"hello");
        assert_eq!(body("POST / HTTP/1.1\r\nContent-Length: 0\r\n\r\n", 100).unwrap(), b"");
        assert_eq!(body("GET / HTTP/1.1\r\n\r\n", 100).unwrap(), b"");
        assert_eq!(body("POST / HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\nhi", 100).unwrap(), b"hi");
    }

    #[test]
    fn reads_a_chunked_body() {
        let text = "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nTrailer: x\r\n\r\n";
        assert_eq!(body(text, 100).unwrap(), b"hello world");
    }

    #[test]
    fn refuses_bad_bodies() {
        let kind = |text: &str, max| body(text, max).unwrap_err().kind();
        assert_eq!(kind("POST / HTTP/1.1\r\nContent-Length: 101\r\n\r\n", 100), io::ErrorKind::FileTooLarge);
        assert_eq!(kind("POST / HTTP/1.1\r\nContent-Length: 99999999999999999999999\r\n\r\n", 100), io::ErrorKind::FileTooLarge);
        assert_eq!(kind("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nhello!!!\r\n8\r\nhello!!!\r\n0\r\n\r\n", 10), io::ErrorKind::FileTooLarge);
        for bad in [
            "POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
            "POST / HTTP/1.1\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "POST / HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n",
            "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
            "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhiXX0\r\n\r\n",
        ] {
            assert_eq!(kind(bad, 100), io::ErrorKind::InvalidData, "{bad}");
        }
        assert!(body("POST / HTTP/1.1\r\nContent-Length: 10\r\n\r\nshort", 100).is_err());
    }

    #[test]
    fn responds_with_length_and_connection() {
        let mut out = Vec::new();
        respond(&mut out, 404, "text/plain", b"nope", false).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(text.contains("Content-Length: 4\r\n") && text.contains("Connection: close\r\n"));
        assert!(text.ends_with("\r\n\r\nnope"));
    }
}

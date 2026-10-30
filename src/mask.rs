//! Masking for anything an agent sees: a resource's stored values, and anything shaped like a
//! JWT (tokens the site itself puts in a response).

use aho_corasick::{AhoCorasick, MatchKind};

pub const MASK: &str = "********";

/// Values shorter than this aren't masked: they'd blank out ordinary text, and no real
/// secret is that short.
const MIN_LEN: usize = 4;

pub struct Masker {
    ac: Option<AhoCorasick>,
    values: Vec<Vec<u8>>,
}

impl Masker {
    pub fn new(values: impl IntoIterator<Item = String>) -> Self {
        let values: Vec<String> = values.into_iter().filter(|v| v.len() >= MIN_LEN).collect();
        let ac = (!values.is_empty()).then(|| AhoCorasick::builder().match_kind(MatchKind::LeftmostLongest).build(&values).ok()).flatten();
        Self { ac, values: values.into_iter().map(String::into_bytes).collect() }
    }

    pub fn mask(&self, text: &str) -> String {
        let text = match &self.ac {
            Some(ac) => ac.replace_all(text, &vec![MASK; ac.patterns_len()]),
            None => text.to_string(),
        };
        mask_jwts(&text)
    }
}

/// Masking for a body that arrives in pieces, with the same result as masking the whole at once.
/// A value or token can be split across pieces, so `push` holds back the end of what it has seen
/// for as long as that end could still become part of one, and no longer: the end of an event
/// in a stream is let through at once.
pub struct Stream<'a> {
    masker: &'a Masker,
    held: Vec<u8>,
}

/// The longest run of token characters held back as a possible start of a JWT. A longer run
/// is let through (a token that long isn't a JWT).
const MAX_JWT_HOLD: usize = 8192;

impl<'a> Stream<'a> {
    pub fn new(masker: &'a Masker) -> Self {
        Self { masker, held: Vec::new() }
    }

    /// The masked bytes that can be sent now, given the next piece.
    pub fn push(&mut self, piece: &[u8]) -> Vec<u8> {
        self.held.extend_from_slice(piece);
        let cut = self.held.len() - self.hold().min(self.held.len());
        let mut out = Vec::with_capacity(cut);
        let mut done = 0;
        if let Some(ac) = &self.masker.ac {
            for m in ac.find_iter(&self.held[..]) {
                if m.start() >= cut {
                    break;
                }
                out.extend_from_slice(&self.held[done..m.start()]);
                out.extend_from_slice(MASK.as_bytes());
                done = m.end();
            }
        }
        let end = cut.max(done);
        out.extend_from_slice(&self.held[done..end]);
        self.held.drain(..end);
        mask_jwts_bytes(&out)
    }

    /// The rest, once nothing more comes.
    pub fn finish(&mut self) -> Vec<u8> {
        let rest = std::mem::take(&mut self.held);
        match &self.masker.ac {
            Some(ac) => mask_jwts_bytes(&ac.replace_all_bytes(&rest, &vec![MASK; ac.patterns_len()])),
            None => mask_jwts_bytes(&rest),
        }
    }

    /// How many bytes at the end could be the start of something to mask: the longest end that
    /// is the beginning of a value, or a run of token characters that has begun like a JWT.
    fn hold(&self) -> usize {
        let held = &self.held;
        let value = self.masker.values.iter().filter_map(|v| (1..v.len()).rev().find(|&k| held.ends_with(&v[..k]))).max().unwrap_or(0);
        let run = held.iter().rev().take_while(|b| is_token(**b)).count();
        let tail = &held[held.len() - run..];
        let jwt = match tail.windows(3).position(|w| w == b"eyJ") {
            Some(at) if run - at <= MAX_JWT_HOLD => run - at,
            Some(_) => 0,
            None if tail.ends_with(b"ey") => 2,
            None if tail.ends_with(b"e") => 1,
            None => 0,
        };
        value.max(jwt)
    }
}

fn is_token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.'
}

/// Replace every run of three base64url segments starting with "eyJ" (a JSON header).
fn mask_jwts(text: &str) -> String {
    // Only ASCII is cut out and put in, so what was valid text still is.
    String::from_utf8(mask_jwts_bytes(text.as_bytes())).unwrap_or_else(|_| text.to_string())
}

fn mask_jwts_bytes(bytes: &[u8]) -> Vec<u8> {
    let (mut out, mut copied, mut from) = (Vec::with_capacity(bytes.len()), 0, 0);
    while let Some(offset) = bytes[from..].windows(3).position(|w| w == b"eyJ") {
        let start = from + offset;
        match jwt_end(bytes, start) {
            Some(end) => {
                out.extend_from_slice(&bytes[copied..start]);
                out.extend_from_slice(MASK.as_bytes());
                (copied, from) = (end, end);
            }
            None => from = start + 3,
        }
    }
    out.extend_from_slice(&bytes[copied..]);
    out
}

fn jwt_end(bytes: &[u8], start: usize) -> Option<usize> {
    let segment_end = |mut i: usize| {
        while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'-' || bytes[i] == b'_') {
            i += 1;
        }
        i
    };
    let end1 = segment_end(start);
    if end1 - start < 10 || bytes.get(end1) != Some(&b'.') {
        return None;
    }
    let end2 = segment_end(end1 + 1);
    if end2 - (end1 + 1) < 10 || bytes.get(end2) != Some(&b'.') {
        return None;
    }
    Some(segment_end(end2 + 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    const JWT: &str = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl";

    #[test]
    fn masks_values_and_jwts() {
        let m = Masker::new(["s3cret-value".to_string(), "ab".to_string()]);
        let out = m.mask(&format!("token={JWT}; key s3cret-value; ab stays; eyJshort.x.y stays"));
        assert_eq!(out, "token=********; key ********; ab stays; eyJshort.x.y stays");
    }

    #[test]
    fn keeps_text_without_secrets() {
        assert_eq!(Masker::new([]).mask("plain ünïcode text"), "plain ünïcode text");
    }

    /// Feed `text` to a stream in the given pieces.
    fn streamed(m: &Masker, text: &str, cuts: &[usize]) -> String {
        let mut stream = Stream::new(m);
        let (mut out, mut at) = (Vec::new(), 0);
        for &cut in cuts.iter().chain([&text.len()]) {
            out.extend(stream.push(&text.as_bytes()[at..cut]));
            at = cut;
        }
        out.extend(stream.finish());
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn a_stream_masks_like_the_whole_however_it_is_cut() {
        let m = Masker::new(["s3cret-value".to_string(), "s3cret-value-longer".to_string(), "abcd".to_string()]);
        let text = format!("a s3cret-value b s3cret-value-longer c abcdabcd d {JWT} e s3cret-valu f eyJ x ab abc");
        let whole = m.mask(&text);
        assert_eq!(whole, format!("a {MASK} b {MASK} c {MASK}{MASK} d {MASK} e s3cret-valu f eyJ x ab abc"));
        for i in 0..=text.len() {
            assert_eq!(streamed(&m, &text, &[i]), whole, "cut at {i}");
        }
        for i in (0..text.len()).step_by(3) {
            for j in (i..text.len()).step_by(7) {
                assert_eq!(streamed(&m, &text, &[i, j]), whole, "cuts at {i} and {j}");
            }
        }
        let bytes: Vec<usize> = (1..text.len()).collect();
        assert_eq!(streamed(&m, &text, &bytes), whole, "one byte at a time");
    }

    #[test]
    fn a_stream_lets_the_end_of_an_event_through_at_once() {
        let m = Masker::new(["s3cret-value".to_string()]);
        let mut stream = Stream::new(&m);
        assert_eq!(stream.push(b"event: ping\ndata: 1\n\n"), b"event: ping\ndata: 1\n\n");
        // Only what could still become the value is held back.
        assert_eq!(stream.push(b"data: s3cr"), b"data: ");
        assert_eq!(stream.push(b"et-value\n\n"), b"********\n\n");
        assert!(stream.finish().is_empty());
        let mut stream = Stream::new(&m);
        assert_eq!(stream.push(b"data: s3cr"), b"data: ");
        assert_eq!(stream.finish(), b"s3cr", "a value that never completes is let through at the end");
    }

    #[test]
    fn a_stream_does_not_hold_a_long_run_of_token_characters_forever() {
        let m = Masker::new([]);
        let text = format!("eyJ{}", "a".repeat(MAX_JWT_HOLD + 10));
        let mut stream = Stream::new(&m);
        assert!(!stream.push(text.as_bytes()).is_empty());
    }
}

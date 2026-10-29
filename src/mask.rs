//! Masking for anything an agent sees: a resource's stored values, and anything shaped like a
//! JWT (tokens the site itself puts in a response).

use aho_corasick::{AhoCorasick, MatchKind};

pub const MASK: &str = "********";

/// Values shorter than this aren't masked: they'd blank out ordinary text, and no real
/// secret is that short.
const MIN_LEN: usize = 4;

pub struct Masker(Option<AhoCorasick>);

impl Masker {
    pub fn new(values: impl IntoIterator<Item = String>) -> Self {
        let values: Vec<String> = values.into_iter().filter(|v| v.len() >= MIN_LEN).collect();
        let ac = (!values.is_empty())
            .then(|| AhoCorasick::builder().match_kind(MatchKind::LeftmostLongest).build(&values).ok())
            .flatten();
        Self(ac)
    }

    pub fn mask(&self, text: &str) -> String {
        let text = match &self.0 {
            Some(ac) => ac.replace_all(text, &vec![MASK; ac.patterns_len()]),
            None => text.to_string(),
        };
        mask_jwts(&text)
    }
}

/// Replace every run of three base64url segments starting with "eyJ" (a JSON header).
fn mask_jwts(text: &str) -> String {
    let bytes = text.as_bytes();
    let (mut out, mut copied, mut from) = (String::with_capacity(text.len()), 0, 0);
    while let Some(offset) = text[from..].find("eyJ") {
        let start = from + offset;
        match jwt_end(bytes, start) {
            Some(end) => {
                out.push_str(&text[copied..start]);
                out.push_str(MASK);
                (copied, from) = (end, end);
            }
            None => from = start + 3,
        }
    }
    out.push_str(&text[copied..]);
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

    #[test]
    fn masks_values_and_jwts() {
        let m = Masker::new(["s3cret-value".to_string(), "ab".to_string()]);
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl";
        let out = m.mask(&format!("token={jwt}; key s3cret-value; ab stays; eyJshort.x.y stays"));
        assert_eq!(out, "token=********; key ********; ab stays; eyJshort.x.y stays");
    }

    #[test]
    fn keeps_text_without_secrets() {
        assert_eq!(Masker::new([]).mask("plain ünïcode text"), "plain ünïcode text");
    }
}

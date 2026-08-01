use openssl::sha::Sha256;

/// Relaxed header canonicalization per RFC 6376 §3.4.2.
pub fn canonicalize_header(name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + value.len() + 3);
    out.extend(name.iter().map(u8::to_ascii_lowercase));
    out.push(b':');
    let mut pending_wsp = false;
    let mut index = 0;
    while index < value.len() {
        match value[index] {
            b' ' | b'\t' => pending_wsp = true,
            b'\r' if value.get(index + 1) == Some(&b'\n') => {
                index += 1;
                pending_wsp = true;
            }
            b'\r' | b'\n' => pending_wsp = true,
            byte => {
                if pending_wsp && out.last() != Some(&b':') {
                    out.push(b' ');
                }
                pending_wsp = false;
                out.push(byte);
            }
        }
        index += 1;
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Relaxed body canonicalization per RFC 6376 §3.4.4.
///
/// Accumulates canonicalized output in a small internal buffer and flushes to
/// the SHA-256 hasher in chunks rather than one update per emitted byte.
pub struct BodyCanonicalizer {
    hasher: Sha256,
    pending_wsp: bool,
    pending_empty_lines: usize,
    line_has_content: bool,
    emitted_content: bool,
    saw_cr: bool,
    /// Small buffer for batching canonicalized bytes before hashing.
    buf: Vec<u8>,
}

/// Flush buffer size — large enough to amortize OpenSSL calls, small enough
/// to keep memory bounded.
const FLUSH_THRESHOLD: usize = 512;

impl Default for BodyCanonicalizer {
    fn default() -> Self {
        Self {
            hasher: Sha256::new(),
            pending_wsp: false,
            pending_empty_lines: 0,
            line_has_content: false,
            emitted_content: false,
            saw_cr: false,
            buf: Vec::with_capacity(FLUSH_THRESHOLD),
        }
    }
}

impl BodyCanonicalizer {
    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            if self.saw_cr {
                self.saw_cr = false;
                self.end_line();
                if byte == b'\n' {
                    continue;
                }
            }
            match byte {
                b'\r' => self.saw_cr = true,
                b'\n' => self.end_line(),
                b' ' | b'\t' => self.pending_wsp = true,
                _ => {
                    if !self.line_has_content && self.pending_empty_lines > 0 {
                        for _ in 0..self.pending_empty_lines {
                            self.emit(b"\r\n");
                        }
                        self.pending_empty_lines = 0;
                    }
                    if self.pending_wsp {
                        self.emit(b" ");
                        self.pending_wsp = false;
                    }
                    self.emit(&[byte]);
                    self.line_has_content = true;
                    self.emitted_content = true;
                }
            }
        }
    }

    fn end_line(&mut self) {
        self.pending_wsp = false;
        if self.line_has_content {
            self.emit(b"\r\n");
            self.line_has_content = false;
        } else {
            self.pending_empty_lines = self.pending_empty_lines.saturating_add(1);
        }
    }

    /// Buffer a canonicalized byte slice, flushing to the hasher when the
    /// buffer reaches `FLUSH_THRESHOLD`.
    fn emit(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        if self.buf.len() >= FLUSH_THRESHOLD {
            self.flush_buf();
        }
    }

    fn flush_buf(&mut self) {
        if !self.buf.is_empty() {
            self.hasher.update(&self.buf);
            self.buf.clear();
        }
    }

    pub fn finish(mut self) -> [u8; 32] {
        if self.saw_cr {
            self.end_line();
        } else if self.line_has_content {
            self.pending_wsp = false;
            self.emit(b"\r\n");
        }
        if !self.emitted_content {
            self.emit(b"\r\n");
        }
        self.flush_buf();
        self.hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::base64;

    fn body(parts: &[&[u8]]) -> String {
        let mut c = BodyCanonicalizer::default();
        for part in parts {
            c.update(part);
        }
        base64::encode_block(&c.finish())
    }

    #[test]
    fn relaxed_header() {
        assert_eq!(
            canonicalize_header(b"SUBJect", b"  hello\r\n\tworld  "),
            b"subject:hello world\r\n"
        );
    }

    #[test]
    fn rfc6376_relaxed_canonicalization_examples() {
        assert_eq!(canonicalize_header(b"A", b" X\r\n Y\tZ  "), b"a:X Y Z\r\n");
        assert_eq!(body(&[b" C \r\nD \t E\r\n\r\n"]), body(&[b" C\r\nD E\r\n"]));
    }

    #[test]
    fn body_accepts_non_utf8_bytes() {
        assert_eq!(
            body(&[&[0xff, b' ', b'\n']]),
            body(&[&[0xff, b'\r', b'\n']])
        );
    }

    #[test]
    fn relaxed_body_is_chunk_independent() {
        let expected = body(&[b" C \r\nD \t E\r\n\r\n".as_slice()]);
        assert_eq!(
            expected,
            body(&[b" C \r", b"\nD ", b"\t E\r\n", b"\r", b"\n"])
        );
    }

    #[test]
    fn empty_body_is_one_crlf() {
        let mut sha = Sha256::new();
        sha.update(b"\r\n");
        let expected = base64::encode_block(&sha.finish());
        assert_eq!(body(&[]), expected);
        assert_eq!(body(&[b"\r\n\r\n"]), expected);
    }

    #[test]
    fn keeps_leading_empty_lines_before_content() {
        assert_eq!(body(&[b"\r\nA"]), body(&[b"\r", b"\n", b"A"]));
        assert_ne!(body(&[b"\r\nA"]), body(&[b"A"]));
    }

    /// Chunk-boundary equivalence: splitting input at CR/LF and WSP
    /// boundaries must produce the same hash as feeding the whole thing.
    /// This guards the buffered-hash refactor.
    #[test]
    fn chunk_boundary_equivalence() {
        let full = body(&[b" C \r\nD \t E\r\n\r\n"]);

        // Split at CR boundary
        assert_eq!(full, body(&[b" C \r", b"\nD \t E\r\n\r\n"]));
        // Split at LF boundary
        assert_eq!(full, body(&[b" C \r\n", b"D \t E\r\n\r\n"]));
        // Split at WSP boundary
        assert_eq!(full, body(&[b" C \r\nD ", b"\t E\r\n\r\n"]));
        // Split at WSP within WSP run
        assert_eq!(full, body(&[b" C \r\nD \t", b" E\r\n\r\n"]));
        // Split at trailing empty-line boundary
        assert_eq!(full, body(&[b" C \r\nD \t E\r\n", b"\r\n"]));
        // Single-byte chunks
        let single_bytes: Vec<&[u8]> = b" C \r\nD \t E\r\n\r\n"
            .iter()
            .map(std::slice::from_ref)
            .collect();
        assert_eq!(full, body(&single_bytes));
    }
}

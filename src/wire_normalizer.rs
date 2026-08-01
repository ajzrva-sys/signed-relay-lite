//! Bounded chunk-independent streaming wire normalizer.
//!
//! Converts LF, bare CR, or mixed line endings into canonical CRLF wire
//! form.  Supports incremental writes and enforces a byte-size limit.
//! Non-UTF-8 body bytes are preserved exactly.

/// Errors produced by the wire normalizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizeError {
    /// The normalized output would exceed the configured byte limit.
    OutputLimitExceeded,
}

/// Streaming state machine that normalizes arbitrary line endings to CRLF.
///
/// Feeds are chunk-independent: the same result is produced regardless of
/// how the input bytes are split across calls.  A single terminal CRLF is
/// ensured without introducing an extra blank body line.
pub struct WireNormalizer {
    buf: Vec<u8>,
    limit: usize,
    pending_cr: bool,
}

impl WireNormalizer {
    /// Create a new normalizer with the given output byte limit.
    pub fn new(limit: usize) -> Self {
        Self {
            buf: Vec::new(),
            limit,
            pending_cr: false,
        }
    }

    /// Write a chunk of input bytes.
    ///
    /// Line endings are normalized to CRLF on the fly.  Returns
    /// [`NormalizeError::OutputLimitExceeded`] if the normalized output
    /// already exceeds `limit` or would exceed it after this chunk.
    pub fn write(&mut self, chunk: &[u8]) -> Result<(), NormalizeError> {
        for &b in chunk {
            match b {
                b'\n' => {
                    if self.pending_cr {
                        // The preceding \r already emitted CRLF.
                        // Consume this LF silently.
                        self.pending_cr = false;
                    } else {
                        // Bare LF → CRLF.
                        self.push(b'\r')?;
                        self.push(b'\n')?;
                    }
                }
                b'\r' => {
                    // Bare CR: emit CRLF.  Set pending_cr so a
                    // following LF in the next chunk is consumed
                    // without double-emitting.
                    self.push(b'\r')?;
                    self.push(b'\n')?;
                    self.pending_cr = true;
                }
                other => {
                    self.pending_cr = false;
                    self.push(other)?;
                }
            }
        }
        Ok(())
    }

    /// Finish the stream and return the canonical CRLF-terminated message.
    ///
    /// If the last byte was a CR (already emitted as CRLF via `write`),
    /// no additional CRLF is appended.  Otherwise a terminal CRLF is
    /// appended to ensure the message ends properly.
    pub fn finish(mut self) -> Result<Vec<u8>, NormalizeError> {
        // Always ensure terminal CRLF.
        if self.buf.len() < 2
            || self.buf[self.buf.len() - 2] != b'\r'
            || self.buf[self.buf.len() - 1] != b'\n'
        {
            self.push(b'\r')?;
            self.push(b'\n')?;
        }
        Ok(self.buf)
    }

    /// Push a single byte, checking the limit with checked arithmetic.
    fn push(&mut self, b: u8) -> Result<(), NormalizeError> {
        let new_len = self
            .buf
            .len()
            .checked_add(1)
            .ok_or(NormalizeError::OutputLimitExceeded)?;
        if new_len > self.limit {
            return Err(NormalizeError::OutputLimitExceeded);
        }
        self.buf.push(b);
        Ok(())
    }
}

/// Convenience one-shot normalizer.
///
/// Normalizes all chunks and returns the canonical CRLF-terminated wire
/// bytes, or an error if the limit is exceeded.
pub fn normalize(chunks: &[&[u8]], limit: usize) -> Result<Vec<u8>, NormalizeError> {
    let mut norm = WireNormalizer::new(limit);
    for chunk in chunks {
        norm.write(chunk)?;
    }
    norm.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generous limit for tests that don't exercise the boundary.
    const BIG_LIMIT: usize = 1024;

    /// Chunk independence: different chunk splits produce the same result.
    #[test]
    fn normalization_is_chunk_independent() {
        let expected = normalize(&[b"A\r\nB\nC\rD"], BIG_LIMIT).unwrap();
        assert_eq!(
            expected,
            normalize(&[b"A\r", b"\nB\n", b"C\r", b"D"], BIG_LIMIT).unwrap()
        );
        assert_eq!(expected, b"A\r\nB\r\nC\r\nD\r\n");
    }

    #[test]
    fn empty_input_produces_empty_body_with_terminal_crlf() {
        let out = normalize(&[], BIG_LIMIT).unwrap();
        assert_eq!(out, b"\r\n");
    }

    #[test]
    fn final_cr_produces_crlf() {
        // "A\r" → "A\r\n" (the bare CR is normalized; finish adds terminal CRLF
        // but it's already there from the CR normalization).
        let out = normalize(&[b"A\r"], BIG_LIMIT).unwrap();
        assert_eq!(out, b"A\r\n");
    }

    #[test]
    fn crlf_split_across_chunks() {
        let out = normalize(&[b"A\r", b"\nB"], BIG_LIMIT).unwrap();
        assert_eq!(out, b"A\r\nB\r\n");
    }

    #[test]
    fn lone_lf_input() {
        let out = normalize(&[b"A\nB\n"], BIG_LIMIT).unwrap();
        assert_eq!(out, b"A\r\nB\r\n");
    }

    #[test]
    fn bare_cr_input() {
        let out = normalize(&[b"A\rB\rC"], BIG_LIMIT).unwrap();
        assert_eq!(out, b"A\r\nB\r\nC\r\n");
    }

    #[test]
    fn mixed_endings() {
        let out = normalize(&[b"A\r\nB\nC\rD"], BIG_LIMIT).unwrap();
        assert_eq!(out, b"A\r\nB\r\nC\r\nD\r\n");
    }

    #[test]
    fn non_utf8_body_preserved() {
        let out = normalize(&[&[0xff, 0xfe, b'\n', 0x80]], BIG_LIMIT).unwrap();
        assert_eq!(out, &[0xff, 0xfe, b'\r', b'\n', 0x80, b'\r', b'\n']);
    }

    #[test]
    fn already_canonical_crlf_unchanged() {
        let out = normalize(&[b"A\r\nB\r\n"], BIG_LIMIT).unwrap();
        assert_eq!(out, b"A\r\nB\r\n");
    }

    #[test]
    fn exactly_one_final_crlf_no_extra_blank_line() {
        // "A\r\n" already ends with CRLF, finish must not add another.
        let out = normalize(&[b"A\r\n"], BIG_LIMIT).unwrap();
        assert_eq!(out, b"A\r\n");

        // "A\nB\n" → each LF becomes CRLF, terminal CRLF already present.
        let out = normalize(&[b"A\nB\n"], BIG_LIMIT).unwrap();
        assert_eq!(out, b"A\r\nB\r\n");
    }

    #[test]
    fn normalized_size_exactly_at_limit_accepted() {
        // "A\n" normalizes to "A\r\n" = 3 bytes.  Limit = 3 → ok.
        let out = normalize(&[b"A\n"], 3).unwrap();
        assert_eq!(out, b"A\r\n");
    }

    #[test]
    fn expansion_one_byte_over_limit_rejected() {
        // "A\n" normalizes to "A\r\n" = 3 bytes.  Limit = 2 → error.
        let err = normalize(&[b"A\n"], 2).unwrap_err();
        assert_eq!(err, NormalizeError::OutputLimitExceeded);
    }

    #[test]
    fn empty_input_respects_limit() {
        // Empty input → "\r\n" = 2 bytes.  Limit = 1 → error.
        let err = normalize(&[], 1).unwrap_err();
        assert_eq!(err, NormalizeError::OutputLimitExceeded);
    }

    #[test]
    fn non_utf8_bytes_not_converted() {
        // Verify no UTF-8 conversion: raw bytes pass through.
        let input: &[u8] = &[0x80, 0xff, 0x00, 0x01];
        let out = normalize(&[input], BIG_LIMIT).unwrap();
        assert_eq!(out, &[0x80, 0xff, 0x00, 0x01, b'\r', b'\n']);
    }
}

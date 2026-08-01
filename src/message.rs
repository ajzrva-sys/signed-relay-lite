//! Bounded immutable RFC 5321 wire-message parser.

use crate::dkim::BodyCanonicalizer;
use std::ops::Range;

/// Errors produced during message parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Bare `\n` found where CRLF is required.
    BareLf,
    /// Bare `\r` found not followed by `\n`.
    BareCr,
    /// No blank line (`\r\n\r\n`) separating headers from body.
    MissingSeparator,
    /// Message does not end with CRLF.
    MissingTerminalCrlf,
    /// A header line has an empty name (nothing before the colon).
    EmptyHeaderName,
    /// A header name contains a byte not allowed by RFC 5322.
    InvalidHeaderNameByte(u8),
    /// A continuation (folding) line appeared before any header.
    ContinuationBeforeFirstHeader,
    /// NUL byte encountered in the header block.
    NulInHeaders,
    /// Too many headers.
    TooManyHeaders,
    /// Header block exceeds byte limit.
    HeaderBlockTooLarge,
}

/// Limits on message parsing resources.
pub struct Limits {
    /// Maximum number of headers allowed.
    pub max_headers: usize,
    /// Maximum total header block size in bytes.
    pub max_header_bytes: usize,
}

impl Limits {
    /// Generous defaults for testing.
    pub fn testing() -> Self {
        Self {
            max_headers: 64,
            max_header_bytes: 64 * 1024,
        }
    }
}

/// Byte range into the owning [`Message::bytes`].
pub struct HeaderRange {
    pub name: Range<usize>,
    pub value: Range<usize>,
}

/// A parsed, immutable wire-format email message.
///
/// All header name/value data is stored as index ranges into `bytes`;
/// no per-header owned strings are created.
pub struct Message {
    bytes: Vec<u8>,
    headers: Vec<HeaderRange>,
    body_offset: usize,
    body_hash: [u8; 32],
}

impl Message {
    /// Parse a wire-format message (RFC 5321: headers CRLF body CRLF).
    ///
    /// Rejects bare LF, bare CR, missing separator, missing terminal CRLF,
    /// empty header names, invalid header-name bytes, NUL in headers,
    /// continuation before first header, and limit overflows.
    ///
    /// Body bytes are fed through [`BodyCanonicalizer`] to produce the
    /// DKIM body hash. Non-UTF-8 body content is accepted.
    pub fn parse(bytes: Vec<u8>, limits: Limits) -> Result<Self, ParseError> {
        // Reject bare LF anywhere.
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'\n' && (i == 0 || bytes[i - 1] != b'\r') {
                return Err(ParseError::BareLf);
            }
        }

        // Reject bare CR: every CR must be followed by LF.
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'\r' && (i + 1 >= bytes.len() || bytes[i + 1] != b'\n') {
                return Err(ParseError::BareCr);
            }
        }

        // Message must end with CRLF.
        if bytes.len() < 2 || bytes[bytes.len() - 2] != b'\r' || bytes[bytes.len() - 1] != b'\n' {
            return Err(ParseError::MissingTerminalCrlf);
        }

        // Find the header/body separator: \r\n\r\n.
        let sep = find_separator(&bytes).ok_or(ParseError::MissingSeparator)?;
        // sep is the index of the first byte of the \r\n\r\n quadruple.
        // body_offset is after the blank line (sep + 4), but the body
        // excludes the trailing terminal CRLF at the end of the message.
        let body_offset = sep + 4;

        // Header block is bytes[0..sep+2]: includes headers + their trailing
        // CRLF, plus the first \r\n of the blank line.
        let header_block_end = sep + 2;
        let header_block = &bytes[..header_block_end];

        // Check NUL in header block.
        for &b in header_block {
            if b == 0 {
                return Err(ParseError::NulInHeaders);
            }
        }

        // Parse header lines.
        let mut headers: Vec<HeaderRange> = Vec::new();
        let mut pos = 0;
        while pos < header_block.len() {
            let line_end = header_block[pos..]
                .windows(2)
                .position(|w| w == b"\r\n")
                .map(|p| pos + p)
                .unwrap_or(header_block.len());
            let line = &header_block[pos..line_end];

            if !line.is_empty() && (line[0] == b' ' || line[0] == b'\t') {
                // Continuation line.
                if headers.is_empty() {
                    return Err(ParseError::ContinuationBeforeFirstHeader);
                }
                let prev = headers.last_mut().unwrap();
                prev.value.end = line_end;
            } else {
                // New header.
                let colon_pos = line
                    .iter()
                    .position(|&b| b == b':')
                    .ok_or(ParseError::EmptyHeaderName)?;
                if colon_pos == 0 {
                    return Err(ParseError::EmptyHeaderName);
                }

                for &b in &line[..colon_pos] {
                    if !is_valid_header_name_byte(b) {
                        return Err(ParseError::InvalidHeaderNameByte(b));
                    }
                }

                if headers.len() >= limits.max_headers {
                    return Err(ParseError::TooManyHeaders);
                }

                headers.push(HeaderRange {
                    name: pos..pos + colon_pos,
                    value: pos + colon_pos + 1..line_end,
                });
            }

            pos = line_end + 2;
        }

        // Check header byte limit (header block = bytes[0..sep+2]).
        if sep + 2 > limits.max_header_bytes {
            return Err(ParseError::HeaderBlockTooLarge);
        }

        // Hash the exact retained body representation, including its required
        // terminal CRLF. Relaxed canonicalization handles trailing empty lines.
        let body_data = &bytes[body_offset..];
        let mut canonicalizer = BodyCanonicalizer::default();
        canonicalizer.update(body_data);
        let body_hash = canonicalizer.finish();

        Ok(Message {
            bytes,
            headers,
            body_offset,
            body_hash,
        })
    }

    /// Borrowed slice of header name bytes for the i-th header.
    pub fn header_name(&self, i: usize) -> &[u8] {
        &self.bytes[self.headers[i].name.clone()]
    }

    /// Borrowed slice of header value bytes for the i-th header.
    pub fn header_value(&self, i: usize) -> &[u8] {
        &self.bytes[self.headers[i].value.clone()]
    }

    /// Number of parsed headers.
    pub fn header_count(&self) -> usize {
        self.headers.len()
    }

    /// Offset into `bytes` where the body begins.
    pub fn body_offset(&self) -> usize {
        self.body_offset
    }

    /// Exact retained body bytes, including the required terminal CRLF.
    pub fn body(&self) -> &[u8] {
        &self.bytes[self.body_offset..]
    }

    /// DKIM body hash.
    pub fn body_hash(&self) -> [u8; 32] {
        self.body_hash
    }

    /// Raw message bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Iterate over headers as borrowed [`crate::dkim::HeaderRef`].
    pub fn header_refs(&self) -> impl Iterator<Item = crate::dkim::HeaderRef<'_>> {
        self.headers.iter().map(move |hr| crate::dkim::HeaderRef {
            name: &self.bytes[hr.name.clone()],
            value: &self.bytes[hr.value.clone()],
        })
    }
}

/// Find the position of `\r\n\r\n` in the byte slice.
fn find_separator(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Is this byte valid in an RFC 5322 header name?
///
/// Allowed: 0x21-0x39, 0x3B-0x7E.
fn is_valid_header_name_byte(b: u8) -> bool {
    matches!(b, 0x21..=0x39 | 0x3B..=0x7E)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_folded_header_as_one_field() {
        let bytes = b"From: a@example.com\r\nSubject: one\r\n\ttwo\r\n\r\nbody\r\n";
        let message = Message::parse(bytes.to_vec(), Limits::testing()).unwrap();
        assert_eq!(message.header_count(), 2);
        assert_eq!(message.header_value(1), b" one\r\n\ttwo");
    }

    #[test]
    fn rejects_bare_lf() {
        assert!(matches!(
            Message::parse(b"From: a@example.com\n\nbody\n".to_vec(), Limits::testing()),
            Err(ParseError::BareLf)
        ));
    }

    #[test]
    fn rejects_bare_cr() {
        assert!(matches!(
            Message::parse(
                b"From: a@example.com\r\rbody\r\r".to_vec(),
                Limits::testing()
            ),
            Err(ParseError::BareCr)
        ));
    }

    #[test]
    fn rejects_missing_separator() {
        // Valid CRLF pairs, terminal CRLF present, but no \r\n\r\n separator.
        assert!(matches!(
            Message::parse(b"From: a@example.com\r\n".to_vec(), Limits::testing()),
            Err(ParseError::MissingSeparator)
        ));
    }

    #[test]
    fn rejects_missing_terminal_crlf() {
        // No terminal CRLF at all
        assert!(matches!(
            Message::parse(
                b"From: a@example.com\r\n\r\nbody".to_vec(),
                Limits::testing()
            ),
            Err(ParseError::MissingTerminalCrlf)
        ));
        // Just LF at end
        assert!(matches!(
            Message::parse(
                b"From: a@example.com\r\n\r\nbody\n".to_vec(),
                Limits::testing()
            ),
            Err(ParseError::BareLf)
        ));
    }

    #[test]
    fn rejects_empty_header_name() {
        assert!(matches!(
            Message::parse(b": value\r\n\r\nbody\r\n".to_vec(), Limits::testing()),
            Err(ParseError::EmptyHeaderName)
        ));
    }

    #[test]
    fn rejects_invalid_header_name_byte() {
        // Space in header name (before colon)
        assert!(matches!(
            Message::parse(
                b"Bad Name: value\r\n\r\nbody\r\n".to_vec(),
                Limits::testing()
            ),
            Err(ParseError::InvalidHeaderNameByte(b' '))
        ));
    }

    #[test]
    fn rejects_continuation_before_first_header() {
        assert!(matches!(
            Message::parse(b" continuation\r\n\r\nbody\r\n".to_vec(), Limits::testing()),
            Err(ParseError::ContinuationBeforeFirstHeader)
        ));
    }

    #[test]
    fn rejects_nul_in_headers() {
        assert!(matches!(
            Message::parse(
                b"From: a@example.com\r\nBad\x00: val\r\n\r\nbody\r\n".to_vec(),
                Limits::testing()
            ),
            Err(ParseError::NulInHeaders)
        ));
    }

    #[test]
    fn rejects_header_count_boundary() {
        // Exactly at limit (1 header) should succeed.
        let msg = b"A: v\r\n\r\nbody\r\n";
        let limits = Limits {
            max_headers: 1,
            max_header_bytes: 64 * 1024,
        };
        assert!(Message::parse(msg.to_vec(), limits).is_ok());

        // One over limit should fail.
        let msg = b"A: v\r\nB: w\r\n\r\nbody\r\n";
        let limits = Limits {
            max_headers: 1,
            max_header_bytes: 64 * 1024,
        };
        assert!(matches!(
            Message::parse(msg.to_vec(), limits),
            Err(ParseError::TooManyHeaders)
        ));
    }

    #[test]
    fn rejects_header_byte_boundary() {
        // "A: v\r\n" = 6 bytes header block, then "\r\n\r\nbody\r\n".
        // Header block = "A: v\r\n" = 6 bytes, separator at pos 6.
        let msg = b"A: v\r\n\r\nbody\r\n";
        // max_header_bytes = 6 (the header block). sep=6 so 6 <= 6 is ok.
        let limits = Limits {
            max_headers: 64,
            max_header_bytes: 6,
        };
        assert!(Message::parse(msg.to_vec(), limits).is_ok());

        // One under: max_header_bytes = 5 should fail.
        let limits = Limits {
            max_headers: 64,
            max_header_bytes: 5,
        };
        assert!(matches!(
            Message::parse(msg.to_vec(), limits),
            Err(ParseError::HeaderBlockTooLarge)
        ));
    }

    #[test]
    fn accepts_body_non_utf8() {
        let mut msg = b"From: a@example.com\r\n\r\n".to_vec();
        msg.extend_from_slice(&[0xff, 0xfe, 0x80, b'\r', b'\n']);
        let message = Message::parse(msg, Limits::testing()).unwrap();
        assert_eq!(message.body(), &[0xff, 0xfe, 0x80, b'\r', b'\n']);
    }

    #[test]
    fn preserves_supplied_bytes_exactly() {
        let bytes = b"From: a@example.com\r\nSubject: hi\r\n\r\nbody here\r\n";
        let message = Message::parse(bytes.to_vec(), Limits::testing()).unwrap();
        assert_eq!(message.as_bytes(), bytes.as_slice());
    }

    #[test]
    fn body_slice_includes_required_terminal_crlf() {
        let bytes = b"From: a@example.com\r\n\r\nbody\r\n";
        let message = Message::parse(bytes.to_vec(), Limits::testing()).unwrap();
        assert_eq!(message.body(), b"body\r\n");
    }

    #[test]
    fn body_with_crlf_only() {
        // Body is a single CRLF following the header/body separator.
        let bytes = b"From: a@example.com\r\n\r\n\r\n";
        let message = Message::parse(bytes.to_vec(), Limits::testing()).unwrap();
        assert_eq!(message.body(), b"\r\n");
    }
}

// ── Sendmail wire normalization ───────────────────────────────────────

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
mod normalizer_tests {
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

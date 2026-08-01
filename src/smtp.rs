//! Bounded strict SMTP reply parser.
//!
//! Parses single-line and multiline SMTP replies (RFC 5321 §4.2) from any
//! `BufRead` source with per-line and aggregate limits to prevent
//! unbounded memory growth.
//!
//! # Wire format
//!
//! ```text
//! 3DIGIT SP text CRLF          (single-line / terminating line)
//! 3DIGIT "-" text CRLF          (continuation line)
//! ```
//!
//! Multiline replies consist of one or more continuation lines followed
//! by exactly one terminating line.  All lines must share the same
//! 3-digit reply code.
//!
//! # Limits
//!
//! * **Per-line**: the `max_line_len` parameter caps each line's content
//!   (excluding CRLF).  A line of exactly `max_line_len` bytes is accepted.
//! * **Aggregate**: [`MAX_REPLY_LINES`] caps the number of lines in any
//!   single reply, preventing an infinite continuation sequence from
//!   growing the result `Vec` without bound.

use std::io::{self, BufRead};

// ── Constants ──────────────────────────────────────────────────────────

/// Maximum number of lines allowed in a single SMTP reply.
///
/// Derived from practical SMTP servers; prevents unbounded Vec growth
/// for infinite continuation sequences.  Checked arithmetic is used
/// when combining this with `max_line_len` to avoid overflow.
const MAX_REPLY_LINES: usize = 256;

// ── Public types ───────────────────────────────────────────────────────

/// A parsed SMTP reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmtpReply {
    /// The 3-digit reply code (100–599).
    pub code: u16,
    /// Diagnostic text for each line, with the code and separator stripped.
    pub lines: Vec<Vec<u8>>,
}

/// Errors produced during SMTP reply parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SmtpError {
    /// An I/O error occurred while reading from the stream.
    Io(String),
    /// A line's content (excluding CRLF) exceeds `max_line_len`.
    LineTooLong,
    /// A bare `\n` was found without a preceding `\r`.
    BareLf,
    /// A `\r` was found not immediately followed by `\n`.
    BareCr,
    /// The first 3 bytes of a line are not all ASCII digits.
    InvalidCode,
    /// The byte after the 3-digit code is neither SP nor '-'.
    InvalidSeparator,
    /// A multiline reply contains lines with different reply codes.
    InconsistentCode,
    /// The stream ended before a terminating line was received.
    Eof,
    /// The number of lines exceeds [`MAX_REPLY_LINES`].
    TooManyLines,
}

impl From<io::Error> for SmtpError {
    fn from(e: io::Error) -> Self {
        SmtpError::Io(e.to_string())
    }
}

// ── Parser ─────────────────────────────────────────────────────────────

/// Parse one SMTP reply from `reader`.
///
/// `max_line_len` caps each line's content (excluding CRLF).
/// Returns the parsed [`SmtpReply`] or a [`SmtpError`].
pub fn read_reply(reader: &mut impl BufRead, max_line_len: usize) -> Result<SmtpReply, SmtpError> {
    // Derive aggregate byte limit with checked arithmetic.
    let _aggregate_bytes = max_line_len
        .checked_add(2) // room for CRLF
        .and_then(|per_line| per_line.checked_mul(MAX_REPLY_LINES))
        .ok_or(SmtpError::LineTooLong)?;

    let mut lines: Vec<Vec<u8>> = Vec::new();
    let mut code: Option<u16> = None;
    let mut line_buf = Vec::with_capacity(max_line_len.min(1024));

    loop {
        // ── Check aggregate line count before reading ──
        if lines.len() >= MAX_REPLY_LINES {
            return Err(SmtpError::TooManyLines);
        }

        // ── Read one line byte-by-byte ──
        line_buf.clear();
        let mut found_crlf = false;

        loop {
            let byte = {
                let buf = reader.fill_buf()?;
                if buf.is_empty() {
                    // EOF
                    break;
                }
                let b = buf[0];
                reader.consume(1);
                b
            };

            match byte {
                b'\r' => {
                    // Must be followed by \n.
                    let next = {
                        let buf = reader.fill_buf()?;
                        if buf.is_empty() {
                            return Err(SmtpError::BareCr);
                        }
                        let b = buf[0];
                        reader.consume(1);
                        b
                    };
                    if next != b'\n' {
                        return Err(SmtpError::BareCr);
                    }
                    found_crlf = true;
                    break;
                }
                b'\n' => {
                    return Err(SmtpError::BareLf);
                }
                _ => {
                    if line_buf.len() >= max_line_len {
                        // Still consume until CRLF to leave stream in a
                        // clean state, but return the error after.
                        drain_until_crlf(reader)?;
                        return Err(SmtpError::LineTooLong);
                    }
                    line_buf.push(byte);
                }
            }
        }

        if !found_crlf {
            // EOF before any CRLF.
            if line_buf.is_empty() && lines.is_empty() {
                return Err(SmtpError::Eof);
            }
            return Err(SmtpError::Eof);
        }

        // ── Parse the line: 3DIGIT (SP|"-") text ──
        if line_buf.len() < 4 {
            // Minimum: 3 digits + 1 separator
            return Err(SmtpError::InvalidCode);
        }

        // Validate 3-digit code.
        if !line_buf[..3].iter().all(|b| b.is_ascii_digit()) {
            return Err(SmtpError::InvalidCode);
        }
        let line_code: u16 = ((line_buf[0] - b'0') as u16) * 100
            + ((line_buf[1] - b'0') as u16) * 10
            + ((line_buf[2] - b'0') as u16);

        // Validate separator.
        let separator = line_buf[3];
        let is_last = match separator {
            b' ' => true,
            b'-' => false,
            _ => return Err(SmtpError::InvalidSeparator),
        };

        // Consistent code check.
        match code {
            None => code = Some(line_code),
            Some(prev) if prev != line_code => return Err(SmtpError::InconsistentCode),
            _ => {}
        }

        // Strip code+separator; push diagnostic text.
        let text = if line_buf.len() > 4 {
            line_buf[4..].to_vec()
        } else {
            Vec::new()
        };
        lines.push(text);

        if is_last {
            return Ok(SmtpReply {
                code: code.unwrap(),
                lines,
            });
        }
    }
}

/// Drain bytes from `reader` until CRLF or EOF, discarding them.
fn drain_until_crlf(reader: &mut impl BufRead) -> Result<(), SmtpError> {
    let mut prev_was_cr = false;
    loop {
        let buf = reader.fill_buf()?;
        if buf.is_empty() {
            return Ok(());
        }
        for (i, &byte) in buf.iter().enumerate() {
            if byte == b'\n' && prev_was_cr {
                reader.consume(i + 1);
                return Ok(());
            }
            prev_was_cr = byte == b'\r';
        }
        let len = buf.len();
        reader.consume(len);
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn reader(bytes: &[u8]) -> io::BufReader<Cursor<&[u8]>> {
        io::BufReader::new(Cursor::new(bytes))
    }

    // ── Single-line ────────────────────────────────────────────────

    #[test]
    fn single_line_reply() {
        let reply = read_reply(&mut reader(b"220 ready\r\n"), 4096).unwrap();
        assert_eq!(reply.code, 220);
        assert_eq!(reply.lines.len(), 1);
        assert_eq!(reply.lines[0], b"ready");
    }

    // ── Multiline ──────────────────────────────────────────────────

    #[test]
    fn multiline_reply() {
        let data = b"250-Hello\r\n250-PIPELINING\r\n250 OK\r\n";
        let reply = read_reply(&mut reader(data), 4096).unwrap();
        assert_eq!(reply.code, 250);
        assert_eq!(reply.lines.len(), 3);
        assert_eq!(reply.lines[0], b"Hello");
        assert_eq!(reply.lines[1], b"PIPELINING");
        assert_eq!(reply.lines[2], b"OK");
    }

    // ── Extension text preserved ───────────────────────────────────

    #[test]
    fn preserves_extension_text_without_code_or_separator() {
        let data = b"250-SIZE 52428800\r\n250-8BITMIME\r\n250 HELP\r\n";
        let reply = read_reply(&mut reader(data), 4096).unwrap();
        assert_eq!(reply.code, 250);
        assert_eq!(reply.lines[0], b"SIZE 52428800");
        assert_eq!(reply.lines[1], b"8BITMIME");
        assert_eq!(reply.lines[2], b"HELP");
    }

    // ── Error: inconsistent multiline code ─────────────────────────

    #[test]
    fn reject_inconsistent_multiline_code() {
        let data = b"250-Hello\r\n251 OK\r\n";
        let err = read_reply(&mut reader(data), 4096).unwrap_err();
        assert_eq!(err, SmtpError::InconsistentCode);
    }

    // ── Error: non-digit code ──────────────────────────────────────

    #[test]
    fn reject_non_digit_code() {
        let data = b"abc ready\r\n";
        let err = read_reply(&mut reader(data), 4096).unwrap_err();
        assert_eq!(err, SmtpError::InvalidCode);
    }

    // ── Error: bad separator ───────────────────────────────────────

    #[test]
    fn reject_separator_not_space_or_hyphen() {
        let data = b"220xready\r\n";
        let err = read_reply(&mut reader(data), 4096).unwrap_err();
        assert_eq!(err, SmtpError::InvalidSeparator);
    }

    // ── Error: bare LF ────────────────────────────────────────────

    #[test]
    fn reject_bare_lf() {
        let data = b"220 ready\n";
        let err = read_reply(&mut reader(data), 4096).unwrap_err();
        assert_eq!(err, SmtpError::BareLf);
    }

    // ── Error: bare CR ────────────────────────────────────────────

    #[test]
    fn reject_bare_cr() {
        // Bare \r in continuation line (not followed by \n).
        let data = b"250-foo\rbar\r\n";
        let err = read_reply(&mut reader(data), 4096).unwrap_err();
        assert_eq!(err, SmtpError::BareCr);
    }

    // ── Error: EOF before terminating line ─────────────────────────

    #[test]
    fn reject_eof_before_terminating_line() {
        let data = b"250-Hello\r\n250-PIPELINING\r\n";
        let err = read_reply(&mut reader(data), 4096).unwrap_err();
        assert_eq!(err, SmtpError::Eof);
    }

    // ── Per-line limit: exactly 4096 accepted ──────────────────────

    #[test]
    fn accept_line_exactly_max_line_len() {
        // "220 " is 4 bytes; fill the rest up to exactly max_line_len.
        let text_len = 4096 - 4; // code+separator already uses 4 bytes
        let content = vec![b'a'; text_len];
        let mut data = b"220 ".to_vec();
        data.extend_from_slice(&content);
        data.extend_from_slice(b"\r\n");
        let reply = read_reply(&mut reader(&data), 4096).unwrap();
        assert_eq!(reply.code, 220);
        assert_eq!(reply.lines[0].len(), text_len);
    }

    // ── Per-line limit: 4097 rejected ──────────────────────────────

    #[test]
    fn reject_line_exceeding_max_line_len() {
        // 4097 bytes total excluding CRLF → rejected.
        let text_len = 4097 - 4; // code+separator uses 4, total = 4097
        let content = vec![b'a'; text_len];
        let mut data = b"220 ".to_vec();
        data.extend_from_slice(&content);
        data.extend_from_slice(b"\r\n");
        let err = read_reply(&mut reader(&data), 4096).unwrap_err();
        assert_eq!(err, SmtpError::LineTooLong);
    }

    // ── Empty diagnostic ───────────────────────────────────────────

    #[test]
    fn empty_diagnostic() {
        let data = b"220 \r\n";
        let reply = read_reply(&mut reader(data), 4096).unwrap();
        assert_eq!(reply.code, 220);
        assert_eq!(reply.lines.len(), 1);
        assert_eq!(reply.lines[0], b"");
    }

    // ── No unbounded allocation before line limit ──────────────────

    #[test]
    fn does_not_allocate_beyond_line_limit() {
        // Feed many bytes without CRLF; parser should reject at
        // max_line_len without buffering the entire stream.
        let content = vec![b'x'; 10_000];
        let mut data = b"220 ".to_vec();
        data.extend_from_slice(&content);
        data.extend_from_slice(b"\r\n");
        let err = read_reply(&mut reader(&data), 64).unwrap_err();
        assert_eq!(err, SmtpError::LineTooLong);
    }

    // ── Aggregate multiline bound ──────────────────────────────────

    #[test]
    fn reject_infinite_multiline_sequence() {
        // More continuation lines than MAX_REPLY_LINES → rejected.
        let mut data = Vec::new();
        for _ in 0..(MAX_REPLY_LINES + 10) {
            data.extend_from_slice(b"250-line\r\n");
        }
        let err = read_reply(&mut reader(&data), 4096).unwrap_err();
        assert_eq!(err, SmtpError::TooManyLines);
    }

    #[test]
    fn accept_exactly_max_reply_lines() {
        // MAX_REPLY_LINES continuation lines + 1 terminating line → ok.
        let mut data = Vec::new();
        for _ in 0..MAX_REPLY_LINES - 1 {
            data.extend_from_slice(b"250-line\r\n");
        }
        data.extend_from_slice(b"250 OK\r\n");
        let reply = read_reply(&mut reader(&data), 4096).unwrap();
        assert_eq!(reply.code, 250);
        assert_eq!(reply.lines.len(), MAX_REPLY_LINES);
    }
}

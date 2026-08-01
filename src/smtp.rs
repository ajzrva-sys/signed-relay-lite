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

use std::io::{self, BufRead, Read, Write};
use std::net::TcpStream;

use crate::relay::{DeliveryResult, Envelope};

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

// ── SMTP command encoding ─────────────────────────────────────────────

/// Write a `MAIL FROM:<sender>\r\n` command to `w`.
///
/// Because `envelope` was constructed via [`Envelope::new`], the sender
/// is guaranteed to contain only printable ASCII bytes with no CR, LF,
/// `<`, `>`, or spaces — making command injection impossible.
pub fn write_mail_from(w: &mut impl Write, envelope: &Envelope) -> io::Result<()> {
    w.write_all(b"MAIL FROM:<")?;
    w.write_all(envelope.sender())?;
    w.write_all(b">\r\n")
}

/// Write one `RCPT TO:<addr>\r\n` command per recipient to `w`.
///
/// Same injection safety guarantees as [`write_mail_from`].
pub fn write_rcpt_to_list(w: &mut impl Write, envelope: &Envelope) -> io::Result<()> {
    for rcpt in envelope.recipients() {
        w.write_all(b"RCPT TO:<")?;
        w.write_all(rcpt)?;
        w.write_all(b">\r\n")?;
    }
    Ok(())
}

// ── DATA dot transparency ─────────────────────────────────────────────

/// Stream dot-stuffed message data followed by the terminating `.\r\n`.
///
/// RFC 5321 §4.5.2 requires that any line in the message data beginning
/// with `.` has an additional `.` prepended (dot-stuffing).  The
/// transmission ends with a line containing only `.\r\n`.
///
/// This writer scans for dots at line-start positions and writes
/// contiguous spans between them, avoiding a second full-message
/// allocation.
///
/// # Canonical input assumption
///
/// Retained messages end with `\r\n` (canonical CRLF form). The
/// function adds exactly `.\r\n` after the (possibly stuffed) message
/// bytes. Empty data is accepted; non-empty data without terminal CRLF is
/// rejected before any bytes are written so the terminator cannot become
/// part of an unterminated body line.
pub fn write_data(w: &mut impl Write, message: &[u8]) -> io::Result<()> {
    if !message.is_empty() && !message.ends_with(b"\r\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SMTP DATA must be empty or end with CRLF",
        ));
    }

    let mut last = 0; // start of the current unwritten span

    for i in 0..message.len() {
        if message[i] == b'.' {
            let is_line_start =
                i == 0 || (i >= 2 && message[i - 2] == b'\r' && message[i - 1] == b'\n');
            if is_line_start {
                // Flush the span up to and including this dot.
                w.write_all(&message[last..=i])?;
                // Write the extra dot (dot-stuffing).
                w.write_all(b".")?;
                last = i + 1;
            }
        }
    }

    // Flush remaining bytes.
    w.write_all(&message[last..])?;
    // Terminating dot-line.
    w.write_all(b".\r\n")
}

/// Convenience wrapper: dot-stuff `message` into a new `Vec<u8>`.
///
/// Delegates to [`write_data`].
pub fn encode_data(message: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    // Infallible: Vec writes never fail.
    write_data(&mut buf, message).expect("Vec::write_all is infallible");
    buf
}

// ── Stream trait at the I/O boundary ──────────────────────────────────

/// Combined `Read + Write` trait for SMTP stream objects.
///
/// Plaintext construction is test-stage scaffolding; the API is
/// designed to be adaptable to TLS without a generic framework.
pub trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

/// Concrete boxed stream type for SMTP delivery.
pub type SmtpStream = Box<dyn ReadWrite + Send>;

// ── Delivery state machine ────────────────────────────────────────────

/// Maximum line length for SMTP reply parsing during delivery.
const DELIVERY_MAX_LINE_LEN: usize = 4096;

/// Deliver one signed message to a smarthost over a plaintext TCP
/// connection.
///
/// # Protocol behaviour
///
/// 1. Read `220` greeting.
/// 2. Send `EHLO <client_name>`; require `250`.
/// 3. Send `MAIL FROM:<sender>`; require `250`.
/// 4. Send `RCPT TO:<addr>` per recipient; require all `2xx`.
/// 5. On any non-`2xx` RCPT, send `RSET` and return without `DATA`.
/// 6. Send `DATA`; require `354`.
/// 7. Write `DKIM-Signature: <value>\r\n` followed by the original
///    message through the dot-stuffing writer.
/// 8. Return `Delivered` only after the final `2xx` response.
/// 9. **No `QUIT`** — the caller controls connection shutdown.
pub fn deliver(
    stream: TcpStream,
    client_name: &str,
    envelope: &Envelope,
    dkim_signature: &[u8],
    message: &[u8],
) -> DeliveryResult {
    // Split into independent reader / writer halves.
    let read_stream = stream.try_clone().expect("TcpStream::try_clone failed");
    let mut reader = io::BufReader::new(read_stream);
    let mut writer = stream;

    // 1. Read greeting (220).
    let greeting = match read_reply(&mut reader, DELIVERY_MAX_LINE_LEN) {
        Ok(r) => r,
        Err(e) => {
            return DeliveryResult::temporary_failure(format!("greeting read error: {e:?}"), None);
        }
    };
    if greeting.code != 220 {
        return DeliveryResult::protocol_rejection(
            format!("expected 220 greeting, got {}", greeting.code),
            Some(greeting.code),
        );
    }

    // 2. EHLO.
    if let Err(e) = writer.write_all(format!("EHLO {client_name}\r\n").as_bytes()) {
        return DeliveryResult::temporary_failure(format!("EHLO write error: {e}"), None);
    }
    let _ = writer.flush();
    let ehlo_reply = match read_reply(&mut reader, DELIVERY_MAX_LINE_LEN) {
        Ok(r) => r,
        Err(e) => {
            return DeliveryResult::temporary_failure(format!("EHLO read error: {e:?}"), None);
        }
    };
    if ehlo_reply.code != 250 {
        return DeliveryResult::protocol_rejection(
            format!("EHLO rejected: {}", ehlo_reply.code),
            Some(ehlo_reply.code),
        );
    }

    // 3. MAIL FROM.
    if let Err(e) = write_mail_from(&mut writer, envelope) {
        return DeliveryResult::temporary_failure(format!("MAIL FROM write error: {e}"), None);
    }
    let _ = writer.flush();
    let mail_reply = match read_reply(&mut reader, DELIVERY_MAX_LINE_LEN) {
        Ok(r) => r,
        Err(e) => {
            return DeliveryResult::temporary_failure(format!("MAIL FROM read error: {e:?}"), None);
        }
    };
    if mail_reply.code != 250 {
        return DeliveryResult::protocol_rejection(
            format!("MAIL FROM rejected: {}", mail_reply.code),
            Some(mail_reply.code),
        );
    }

    // 4. RCPT TO — send all, then check all responses are 2xx.
    if let Err(e) = write_rcpt_to_list(&mut writer, envelope) {
        return DeliveryResult::temporary_failure(format!("RCPT TO write error: {e}"), None);
    }
    let _ = writer.flush();
    let mut any_non_2xx = false;
    let mut first_bad_code: u16 = 0;
    for _ in envelope.recipients() {
        let rcpt_reply = match read_reply(&mut reader, DELIVERY_MAX_LINE_LEN) {
            Ok(r) => r,
            Err(e) => {
                return DeliveryResult::temporary_failure(
                    format!("RCPT TO read error: {e:?}"),
                    None,
                );
            }
        };
        if rcpt_reply.code >= 300 {
            any_non_2xx = true;
            if first_bad_code == 0 {
                first_bad_code = rcpt_reply.code;
            }
        }
    }

    // 5. On any non-2xx RCPT → RSET, no DATA.
    if any_non_2xx {
        let _ = writer.write_all(b"RSET\r\n");
        let _ = writer.flush();
        let _ = read_reply(&mut reader, DELIVERY_MAX_LINE_LEN);
        return DeliveryResult::protocol_rejection(
            format!("recipient rejected: {first_bad_code}"),
            Some(first_bad_code),
        );
    }

    // 6. DATA — require 354.
    if let Err(e) = writer.write_all(b"DATA\r\n") {
        return DeliveryResult::temporary_failure(format!("DATA write error: {e}"), None);
    }
    let _ = writer.flush();
    let data_reply = match read_reply(&mut reader, DELIVERY_MAX_LINE_LEN) {
        Ok(r) => r,
        Err(e) => {
            return DeliveryResult::temporary_failure(format!("DATA read error: {e:?}"), None);
        }
    };
    if data_reply.code != 354 {
        return DeliveryResult::protocol_rejection(
            format!("DATA rejected: {}", data_reply.code),
            Some(data_reply.code),
        );
    }

    // 7. Write DKIM-Signature header + dot-stuffed message.
    if writer.write_all(b"DKIM-Signature: ").is_err()
        || writer.write_all(dkim_signature).is_err()
        || writer.write_all(b"\r\n").is_err()
    {
        return DeliveryResult::temporary_failure("DKIM header write error", None);
    }
    if let Err(e) = write_data(&mut writer, message) {
        return DeliveryResult::temporary_failure(format!("body write error: {e}"), None);
    }
    let _ = writer.flush();

    // 8. Read final response — Delivered only after 2xx.
    let final_reply = match read_reply(&mut reader, DELIVERY_MAX_LINE_LEN) {
        Ok(r) => r,
        Err(e) => {
            return DeliveryResult::ambiguous(format!("final response read error: {e:?}"));
        }
    };
    if (200..300).contains(&final_reply.code) {
        let diag = final_reply
            .lines
            .first()
            .map(|l| String::from_utf8_lossy(l).to_string())
            .unwrap_or_default();
        DeliveryResult::delivered(diag, Some(final_reply.code))
    } else {
        DeliveryResult::protocol_rejection(
            format!("final response: {}", final_reply.code),
            Some(final_reply.code),
        )
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

    // ── encode_data: dot transparency ───────────────────────────────

    #[test]
    fn dot_stuffs_only_at_line_start() {
        let message = b"Header: x\r\n\r\n.one\r\ntwo.three\r\n..four\r\n";
        assert_eq!(
            encode_data(message),
            b"Header: x\r\n\r\n..one\r\ntwo.three\r\n...four\r\n.\r\n"
        );
    }

    #[test]
    fn dot_at_first_byte() {
        // Single dot as first byte of message → stuff it.
        assert_eq!(encode_data(b".hello\r\n"), b"..hello\r\n.\r\n");
    }

    #[test]
    fn consecutive_leading_dots() {
        // Multiple consecutive lines each starting with a dot → each stuffed.
        assert_eq!(encode_data(b".one\r\n.two\r\n"), b"..one\r\n..two\r\n.\r\n");
    }

    #[test]
    fn dot_in_middle_unchanged() {
        // Dot in the middle of a line must not be stuffed.
        assert_eq!(encode_data(b"hello.world\r\n"), b"hello.world\r\n.\r\n");
    }

    #[test]
    fn no_dots_passthrough() {
        assert_eq!(encode_data(b"plain line\r\n"), b"plain line\r\n.\r\n");
    }

    #[test]
    fn canonical_empty_body() {
        // Empty body = just the terminating dot.
        assert_eq!(encode_data(b""), b".\r\n");
    }

    #[test]
    fn nonempty_data_without_terminal_crlf_is_rejected() {
        let mut output = Vec::new();
        let error = write_data(&mut output, b"unterminated").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(output.is_empty());
    }

    #[test]
    fn dot_stuffing_streaming_to_writer() {
        // Verify streaming write_data works via a short-write writer.
        let message = b".line1\r\nline2\r\n..line3\r\n";
        let mut buf = Vec::new();
        write_data(&mut buf, message).unwrap();
        assert_eq!(buf, b"..line1\r\nline2\r\n...line3\r\n.\r\n");
    }

    #[test]
    fn write_data_io_error_propagation() {
        // A writer that always fails: write_data must propagate, not panic.
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "fail"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let result = write_data(&mut FailingWriter, b".x\r\n");
        assert!(result.is_err());
    }

    // ── MAIL FROM / RCPT TO command encoding ───────────────────────

    #[test]
    fn mail_from_normal_sender() {
        let env = Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();
        let mut buf = Vec::new();
        write_mail_from(&mut buf, &env).unwrap();
        assert_eq!(buf, b"MAIL FROM:<sender@example.com>\r\n");
    }

    #[test]
    fn mail_from_empty_reverse_path() {
        let env = Envelope::new(b"", vec![b"rcpt@example.com".to_vec()]).unwrap();
        let mut buf = Vec::new();
        write_mail_from(&mut buf, &env).unwrap();
        assert_eq!(buf, b"MAIL FROM:<>\r\n");
    }

    #[test]
    fn rcpt_to_normal_recipient() {
        let env = Envelope::new(
            b"sender@example.com",
            vec![b"a@example.com".to_vec(), b"b@example.com".to_vec()],
        )
        .unwrap();
        let mut buf = Vec::new();
        write_rcpt_to_list(&mut buf, &env).unwrap();
        assert_eq!(
            buf,
            b"RCPT TO:<a@example.com>\r\nRCPT TO:<b@example.com>\r\n"
        );
    }

    #[test]
    fn injection_blocked_by_envelope_validation() {
        // Envelope::new rejects CR/LF, so injection is impossible.
        assert!(Envelope::new(
            b"bad\r\nInjected: header",
            vec![b"rcpt@example.com".to_vec()]
        )
        .is_err());
        assert!(Envelope::new(
            b"sender@example.com",
            vec![b"bad\r\nRCPT TO:injected".to_vec()]
        )
        .is_err());
    }
}

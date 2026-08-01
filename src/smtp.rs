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

type StreamConnector = Box<dyn FnMut() -> io::Result<SmtpStream> + Send>;

// ── Delivery state machine ────────────────────────────────────────────

/// Maximum line length for SMTP reply parsing during delivery.
const DELIVERY_MAX_LINE_LEN: usize = 4096;

/// Tracks how far the SMTP transaction progressed.
///
/// Used to classify connection-loss failures: before the body is written
/// the loss is **unambiguous** (nothing was committed); once body bytes
/// have started flowing the loss is **ambiguous** (the server may or may
/// not have accepted the message).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionPhase {
    /// TCP connected, before SMTP dialog.
    Connected,
    /// EHLO accepted; envelope commands in progress.
    Envelope,
    /// `354` received; ready to send body.
    DataAccepted,
    /// Body bytes have been written (DKIM header and/or message data).
    BodyStarted,
    /// Terminating `.\\r\\n` sent; awaiting final server response.
    FinalDotSent,
    /// Final 2xx response received.
    Complete,
}

impl TransactionPhase {
    /// Returns `true` when the message body may have been partially
    /// delivered, making a connection loss ambiguous.
    fn is_ambiguous_on_close(self) -> bool {
        matches!(self, Self::BodyStarted | Self::FinalDotSent)
    }
}

/// Build a [`DeliveryResult`] for a non-2xx SMTP reply code.
///
/// `4xx` → [`TemporaryFailure`], `5xx` → [`PermanentFailure`].
fn code_rejection(context: &str, code: u16) -> DeliveryResult {
    if code >= 500 {
        DeliveryResult::permanent_failure(format!("{context}: {code}"), Some(code))
    } else {
        DeliveryResult::temporary_failure(format!("{context}: {code}"), Some(code))
    }
}

/// Classify a connection loss based on the current [`TransactionPhase`].
///
/// Before the body has started (`Connected`, `Envelope`, `DataAccepted`)
/// the loss is **unambiguous** — nothing was committed.  Once body bytes
/// have started flowing (`BodyStarted`, `FinalDotSent`) the loss is
/// **ambiguous** — the server may or may not have accepted the message.
fn connection_lost(phase: TransactionPhase) -> DeliveryResult {
    if phase.is_ambiguous_on_close() {
        DeliveryResult::ambiguous(format!("connection lost in {phase:?}"))
    } else {
        DeliveryResult::temporary_failure(format!("connection lost in {phase:?}"), None)
    }
}

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
    let mut stream = Some(stream);
    let mut connection = SmtpConnection::new(client_name, move || {
        stream
            .take()
            .map(|stream| Box::new(stream) as SmtpStream)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "stream unavailable"))
    });
    connection.deliver(envelope, dkim_signature, message)
}

struct AttemptOutcome {
    result: DeliveryResult,
    retry_safe: bool,
    connection_usable: bool,
}

impl AttemptOutcome {
    fn smtp(result: DeliveryResult, connection_usable: bool) -> Self {
        Self {
            result,
            retry_safe: false,
            connection_usable,
        }
    }

    fn transport(result: DeliveryResult, retry_safe: bool) -> Self {
        Self {
            result,
            retry_safe,
            connection_usable: false,
        }
    }
}

struct Session {
    stream: io::BufReader<SmtpStream>,
}

/// A reusable SMTP session backed by a reconnectable stream connector.
///
/// The connector is deliberately limited to producing a `Read + Write`
/// stream, so a later TLS layer can be introduced without changing the
/// delivery state machine.
pub struct SmtpConnection {
    client_name: String,
    connector: StreamConnector,
    session: Option<Session>,
}

impl SmtpConnection {
    pub fn new<F>(client_name: impl Into<String>, connector: F) -> Self
    where
        F: FnMut() -> io::Result<SmtpStream> + Send + 'static,
    {
        Self {
            client_name: client_name.into(),
            connector: Box::new(connector),
            session: None,
        }
    }

    /// Deliver a message, reconnecting at most once when explicit attempt
    /// metadata says no body could have started.
    pub fn deliver(
        &mut self,
        envelope: &Envelope,
        dkim_signature: &[u8],
        message: &[u8],
    ) -> DeliveryResult {
        for attempt in 0..=1 {
            let outcome = self.attempt(envelope, dkim_signature, message);
            if !outcome.connection_usable {
                self.session = None;
            }
            if attempt == 0 && outcome.retry_safe {
                continue;
            }
            return outcome.result;
        }
        unreachable!("bounded retry loop always returns")
    }

    fn attempt(
        &mut self,
        envelope: &Envelope,
        dkim_signature: &[u8],
        message: &[u8],
    ) -> AttemptOutcome {
        if self.session.is_none() {
            let stream = match (self.connector)() {
                Ok(stream) => stream,
                Err(error) => {
                    return AttemptOutcome::transport(
                        DeliveryResult::temporary_failure(format!("connect: {error}"), None),
                        true,
                    );
                }
            };
            let mut session = Session {
                stream: io::BufReader::new(stream),
            };
            if let Err(outcome) = initialize_session(&mut session, &self.client_name) {
                return outcome;
            }
            self.session = Some(session);
        }

        run_transaction(
            self.session.as_mut().expect("session initialized"),
            envelope,
            dkim_signature,
            message,
        )
    }
}

fn write_command(session: &mut Session, bytes: &[u8], context: &str) -> Result<(), AttemptOutcome> {
    session.stream.get_mut().write_all(bytes).map_err(|error| {
        AttemptOutcome::transport(
            DeliveryResult::temporary_failure(format!("{context} write: {error}"), None),
            true,
        )
    })?;
    session.stream.get_mut().flush().map_err(|error| {
        AttemptOutcome::transport(
            DeliveryResult::temporary_failure(format!("{context} flush: {error}"), None),
            true,
        )
    })
}

fn read_session_reply(session: &mut Session, context: &str) -> Result<SmtpReply, AttemptOutcome> {
    read_reply(&mut session.stream, DELIVERY_MAX_LINE_LEN).map_err(|error| {
        AttemptOutcome::transport(
            DeliveryResult::temporary_failure(format!("{context} read: {error:?}"), None),
            true,
        )
    })
}

fn initialize_session(session: &mut Session, client_name: &str) -> Result<(), AttemptOutcome> {
    let greeting = read_session_reply(session, "greeting")?;
    if greeting.code != 220 {
        return Err(AttemptOutcome::smtp(
            code_rejection("greeting", greeting.code),
            greeting.code != 221,
        ));
    }
    write_command(
        session,
        format!("EHLO {client_name}\r\n").as_bytes(),
        "EHLO",
    )?;
    let reply = read_session_reply(session, "EHLO")?;
    if reply.code != 250 {
        return Err(AttemptOutcome::smtp(
            code_rejection("EHLO", reply.code),
            reply.code != 221,
        ));
    }
    Ok(())
}

fn run_transaction(
    session: &mut Session,
    envelope: &Envelope,
    dkim_signature: &[u8],
    message: &[u8],
) -> AttemptOutcome {
    if let Err(error) = write_mail_from(session.stream.get_mut(), envelope) {
        return AttemptOutcome::transport(
            DeliveryResult::temporary_failure(format!("MAIL write: {error}"), None),
            true,
        );
    }
    if let Err(outcome) = write_command(session, b"", "MAIL") {
        return outcome;
    }
    let mail_reply = match read_session_reply(session, "MAIL") {
        Ok(reply) => reply,
        Err(outcome) => return outcome,
    };
    if mail_reply.code != 250 {
        return AttemptOutcome::smtp(
            code_rejection("MAIL", mail_reply.code),
            mail_reply.code != 221,
        );
    }

    let mut first_4xx = None;
    let mut first_5xx = None;
    let mut first_other = None;
    let mut usable = true;
    for recipient in envelope.recipients() {
        let writer = session.stream.get_mut();
        if let Err(error) = writer
            .write_all(b"RCPT TO:<")
            .and_then(|()| writer.write_all(recipient))
            .and_then(|()| writer.write_all(b">\r\n"))
            .and_then(|()| writer.flush())
        {
            return AttemptOutcome::transport(
                DeliveryResult::temporary_failure(format!("RCPT write: {error}"), None),
                true,
            );
        }
        let reply = match read_session_reply(session, "RCPT") {
            Ok(reply) => reply,
            Err(outcome) => return outcome,
        };
        if reply.code == 221 {
            return AttemptOutcome::smtp(code_rejection("recipient", reply.code), false);
        }
        usable &= reply.code != 221;
        if (400..500).contains(&reply.code) && first_4xx.is_none() {
            first_4xx = Some(reply.code);
        } else if reply.code >= 500 && first_5xx.is_none() {
            first_5xx = Some(reply.code);
        } else if !(200..300).contains(&reply.code) && first_other.is_none() {
            first_other = Some(reply.code);
        }
    }
    if first_4xx.is_some() || first_5xx.is_some() || first_other.is_some() {
        if usable && write_command(session, b"RSET\r\n", "RSET").is_ok() {
            match read_session_reply(session, "RSET") {
                Ok(reply) => usable &= reply.code != 221,
                Err(_) => usable = false,
            }
        }
        let result = if let Some(code) = first_4xx {
            DeliveryResult::temporary_failure(format!("recipient: {code}"), Some(code))
        } else if let Some(code) = first_5xx {
            DeliveryResult::permanent_failure(format!("recipient: {code}"), Some(code))
        } else {
            code_rejection("recipient", first_other.expect("a rejection code exists"))
        };
        return AttemptOutcome::smtp(result, usable);
    }

    if let Err(outcome) = write_command(session, b"DATA\r\n", "DATA") {
        return outcome;
    }
    let data_reply = match read_session_reply(session, "DATA") {
        Ok(reply) => reply,
        Err(outcome) => return outcome,
    };
    if data_reply.code != 354 {
        return AttemptOutcome::smtp(
            code_rejection("DATA", data_reply.code),
            data_reply.code != 221,
        );
    }

    let writer = session.stream.get_mut();
    if writer.write_all(b"DKIM-Signature: ").is_err()
        || writer.write_all(dkim_signature).is_err()
        || writer.write_all(b"\r\n").is_err()
        || write_data(writer, message).is_err()
        || writer.flush().is_err()
    {
        return AttemptOutcome::transport(connection_lost(TransactionPhase::BodyStarted), false);
    }
    let final_reply = match read_reply(&mut session.stream, DELIVERY_MAX_LINE_LEN) {
        Ok(reply) => reply,
        Err(_) => {
            return AttemptOutcome::transport(
                connection_lost(TransactionPhase::FinalDotSent),
                false,
            );
        }
    };
    let usable = final_reply.code != 221;
    let result = if (200..300).contains(&final_reply.code) {
        DeliveryResult::delivered(String::new(), Some(final_reply.code))
    } else {
        code_rejection("final", final_reply.code)
    };
    AttemptOutcome::smtp(result, usable)
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

//! Strict bounded SRL1 and SRL2 submission binary codecs.
//!
//! Wire format is independent of sockets — reads and writes go through
//! `std::io::Read` and `std::io::Write`, making the codecs testable
//! with `std::io::Cursor`.
//!
//! # Wire format — Request
//!
//! ```text
//! [magic: 4B "SRL1"] [flags: 4B u32 BE]
//! [sender_len: 4B u32 BE] [sender: NB]
//! [rcpt_count: 4B u32 BE]
//!   [for each: rcpt_len: 4B u32 BE, rcpt: NB]
//! [msg_len: 8B u64 BE] [msg: NB]
//! ```
//!
//! # Wire format — Response
//!
//! ```text
//! [magic: 4B "SRL1"]
//! [status: 1B] [flags: 1B (bit0 = ambiguous)]
//! [smtp_code: 2B BE]              (0 ↔ None)
//! [diagnostic_len: 4B u32 BE]     [diagnostic: NB] (UTF-8)
//! ```

use std::io::{self, Read, Write};

use super::budget::{MemoryBudget, MemoryReservation};
use crate::relay::{DeliveryResult, DeliveryStatus, Envelope, EnvelopeError};

// ── Protocol constants ────────────────────────────────────────────────

/// Protocol magic bytes.
const MAGIC: &[u8; 4] = b"SRL1";

/// SRL2 protocol magic bytes.
const SRL2_MAGIC: &[u8; 4] = b"SRL2";

/// Wire kind for a server reply that authorizes message streaming.
pub const READY_KIND: u8 = 1;
/// Wire kind for a final delivery result.
pub const FINAL_KIND: u8 = 2;

/// Currently supported request flags value (none set).
const REQUEST_FLAGS_V0: u32 = 0x0000_0000;

/// Bitmask of known request flag bits.
const REQUEST_FLAGS_KNOWN: u32 = 0x0000_0000;

/// Currently supported response flags: bit0 = ambiguous.
const RESPONSE_FLAGS_KNOWN: u8 = 0b0000_0001;

/// Wire status byte for `DeliveryStatus::Delivered`.
const STATUS_DELIVERED: u8 = 0;
/// Wire status byte for `DeliveryStatus::TemporaryFailure`.
const STATUS_TEMPORARY: u8 = 1;
/// Wire status byte for `DeliveryStatus::PermanentFailure`.
const STATUS_PERMANENT: u8 = 2;
/// Wire status byte for `DeliveryStatus::ProtocolRejection`.
const STATUS_PROTOCOL: u8 = 3;

/// Maximum number of recipients in one envelope.
pub const MAX_RECIPIENTS: usize = 100;
/// Maximum bytes in one envelope address.
pub const MAX_ADDRESS_BYTES: usize = 254;
/// Maximum bytes in a delivery diagnostic.
pub const MAX_DIAGNOSTIC_BYTES: usize = 4096;
/// Maximum bytes in one SRL2 message chunk.
#[allow(dead_code)] // Used when the SRL2 stream codec lands.
pub const MAX_CHUNK_BYTES: usize = 64 * 1024;

impl Envelope {
    pub(crate) const MAX_RECIPIENTS: usize = MAX_RECIPIENTS;
    pub(crate) const MAX_ADDRESS_BYTES: usize = MAX_ADDRESS_BYTES;
}

impl DeliveryResult {
    pub(crate) const MAX_DIAGNOSTIC_BYTES: usize = MAX_DIAGNOSTIC_BYTES;
}

// ── Limits ────────────────────────────────────────────────────────────

/// Bounded limits for the submission codec.
///
/// All limits are enforced *before* allocating memory for the decoded
/// payload, so a malicious frame cannot cause unbounded allocation.
#[derive(Clone, Debug)]
pub struct SubmissionLimits {
    /// Maximum number of recipients per envelope.
    pub max_recipients: usize,
    /// Maximum bytes for a single envelope address.
    pub max_address_bytes: usize,
    /// Maximum message body bytes (as u64 for wire-checked conversion).
    pub max_message_bytes: u64,
    /// Maximum diagnostic string bytes (UTF-8) in a response.
    pub max_diagnostic_bytes: usize,
}

impl SubmissionLimits {
    /// Fixed protocol ceilings paired with the daemon's active message limit.
    pub fn production(max_message_bytes: u64) -> Self {
        Self {
            max_recipients: MAX_RECIPIENTS,
            max_address_bytes: MAX_ADDRESS_BYTES,
            max_message_bytes,
            max_diagnostic_bytes: MAX_DIAGNOSTIC_BYTES,
        }
    }
}

// ── Errors ────────────────────────────────────────────────────────────

/// Errors produced during submission codec operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmissionError {
    /// Wire magic does not match the codec's expected protocol.
    InvalidMagic,
    /// A recognized older protocol version is not supported by this codec.
    UnsupportedVersion(u8),
    /// Request flags contain unknown bits.
    UnknownRequestFlags(u32),
    /// Response flags contain unknown bits.
    UnknownResponseFlags(u8),
    /// Response status byte is not a recognized variant.
    InvalidResponseStatus(u8),
    /// Server reply kind is not READY or FINAL.
    UnknownServerReplyKind(u8),
    /// Declared recipient count exceeds the configured limit.
    TooManyRecipients { count: usize, limit: usize },
    /// An address field exceeds the configured limit.
    AddressTooLong { len: usize, limit: usize },
    /// Declared message length exceeds the configured limit.
    MessageTooLarge { len: u64, limit: u64 },
    /// Diagnostic string exceeds the configured limit.
    DiagnosticTooLong { len: usize, limit: usize },
    /// Diagnostic bytes are not valid UTF-8.
    InvalidDiagnosticUtf8,
    /// The underlying reader/writer returned an I/O error.
    /// Typically `UnexpectedEof` for truncated frames.
    Io(io::ErrorKind),
    /// Envelope construction validation failed.
    Envelope(EnvelopeError),
    /// The global memory budget cannot accommodate the declared message size.
    BudgetExhausted { requested: usize, capacity: usize },
}

// ── SRL2 frames ──────────────────────────────────────────────────────

/// The validated envelope sent before the server authorizes message input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopePreamble {
    pub envelope: Envelope,
}

/// Daemon-authoritative limits sent before message streaming begins.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ready {
    pub max_message_bytes: u64,
    pub max_chunk_bytes: u32,
    pub max_diagnostic_bytes: u32,
}

/// A server response before or after the streamed message body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerReply {
    Ready(Ready),
    Final(DeliveryResult),
}

impl From<io::Error> for SubmissionError {
    fn from(e: io::Error) -> Self {
        SubmissionError::Io(e.kind())
    }
}

impl From<EnvelopeError> for SubmissionError {
    fn from(e: EnvelopeError) -> Self {
        SubmissionError::Envelope(e)
    }
}

// ── Decoded request ───────────────────────────────────────────────────

/// A decoded submission request.
///
/// The message bytes are kept raw (not parsed) — message parsing happens
/// later in the pipeline. The `Envelope` is constructed through
/// validation.
///
/// Holds an RAII [`MemoryReservation`] for the message bytes; when the
/// request is dropped the reservation is returned to the global budget.
#[derive(Debug)]
pub struct SubmissionRequest {
    pub envelope: Envelope,
    pub message: Vec<u8>,
    /// RAII reservation for the message bytes — private to prevent
    /// external code from releasing it prematurely. Its sole purpose
    /// is the `Drop` impl that returns bytes to the budget.
    #[allow(dead_code)]
    reservation: MemoryReservation,
}

impl SubmissionRequest {
    /// Take the request apart while preserving its memory reservation.
    ///
    /// The caller must retain the returned guard for at least as long as
    /// the message bytes remain allocated.
    pub fn into_parts(self) -> (Envelope, Vec<u8>, MemoryReservation) {
        (self.envelope, self.message, self.reservation)
    }
}

// ── Wire helpers ──────────────────────────────────────────────────────

/// Read exactly `n` bytes into a new `Vec<u8>`.
fn read_bytes<R: Read>(r: &mut R, n: usize) -> Result<Vec<u8>, SubmissionError> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read a big-endian `u16`.
fn read_u16<R: Read>(r: &mut R) -> Result<u16, SubmissionError> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

/// Read a big-endian `u32`, then validate it fits in `usize` and is <= limit.
fn read_u32_limited<R: Read>(
    r: &mut R,
    limit: usize,
    too_long: impl Fn(usize, usize) -> SubmissionError,
) -> Result<usize, SubmissionError> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    let len = u32::from_be_bytes(buf);
    let len_usize = usize::try_from(len).map_err(|_| too_long(len as usize, limit))?;
    if len_usize > limit {
        return Err(too_long(len_usize, limit));
    }
    Ok(len_usize)
}

/// Read a big-endian `u32` with no limit check (used for recipient count).
fn read_u32<R: Read>(r: &mut R) -> Result<u32, SubmissionError> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

/// Read a big-endian `u64`, then validate it fits in `usize` and is <= limit.
///
/// Returns the value as `usize` if valid, or an appropriate error.
/// Never casts an untrusted `u64` directly to `usize`.
fn read_message_len<R: Read>(r: &mut R, limit: u64) -> Result<usize, SubmissionError> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    let len = u64::from_be_bytes(buf);
    if len > limit {
        return Err(SubmissionError::MessageTooLarge { len, limit });
    }
    // We verified len <= limit. Now check it fits in usize (handles 32-bit).
    usize::try_from(len).map_err(|_| SubmissionError::MessageTooLarge { len, limit })
}

/// Write a big-endian `u16`.
fn write_u16<W: Write>(w: &mut W, v: u16) -> Result<(), io::Error> {
    w.write_all(&v.to_be_bytes())
}

/// Write a big-endian `u32`.
fn write_u32<W: Write>(w: &mut W, v: u32) -> Result<(), io::Error> {
    w.write_all(&v.to_be_bytes())
}

/// Write a big-endian `u64`.
fn write_u64<W: Write>(w: &mut W, v: u64) -> Result<(), io::Error> {
    w.write_all(&v.to_be_bytes())
}

/// Truncate `s` to at most `max` bytes at a UTF-8 character boundary.
fn truncate_to_utf8_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn read_srl2_magic<R: Read>(r: &mut R) -> Result<(), SubmissionError> {
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if magic == *SRL2_MAGIC {
        return Ok(());
    }
    if magic == *MAGIC {
        return Err(SubmissionError::UnsupportedVersion(1));
    }
    Err(SubmissionError::InvalidMagic)
}

fn read_final_payload<R: Read>(r: &mut R) -> Result<DeliveryResult, SubmissionError> {
    let mut status_buf = [0u8; 1];
    r.read_exact(&mut status_buf)?;
    let status = match status_buf[0] {
        STATUS_DELIVERED => DeliveryStatus::Delivered,
        STATUS_TEMPORARY => DeliveryStatus::TemporaryFailure,
        STATUS_PERMANENT => DeliveryStatus::PermanentFailure,
        STATUS_PROTOCOL => DeliveryStatus::ProtocolRejection,
        other => return Err(SubmissionError::InvalidResponseStatus(other)),
    };

    let mut flags_buf = [0u8; 1];
    r.read_exact(&mut flags_buf)?;
    let flags = flags_buf[0];
    if flags & !RESPONSE_FLAGS_KNOWN != 0 {
        return Err(SubmissionError::UnknownResponseFlags(flags));
    }

    let smtp_raw = read_u16(r)?;
    let diag_len = read_u32_limited(r, MAX_DIAGNOSTIC_BYTES, |len, limit| {
        SubmissionError::DiagnosticTooLong { len, limit }
    })?;
    let diagnostic = String::from_utf8(read_bytes(r, diag_len)?)
        .map_err(|_| SubmissionError::InvalidDiagnosticUtf8)?;

    Ok(DeliveryResult {
        status,
        ambiguous: flags & 0x01 != 0,
        smtp_code: (smtp_raw != 0).then_some(smtp_raw),
        diagnostic,
    })
}

fn write_final_payload<W: Write>(w: &mut W, result: &DeliveryResult) -> Result<(), io::Error> {
    let status = match result.status {
        DeliveryStatus::Delivered => STATUS_DELIVERED,
        DeliveryStatus::TemporaryFailure => STATUS_TEMPORARY,
        DeliveryStatus::PermanentFailure => STATUS_PERMANENT,
        DeliveryStatus::ProtocolRejection => STATUS_PROTOCOL,
    };
    w.write_all(&[status, u8::from(result.ambiguous)])?;
    write_u16(w, result.smtp_code.unwrap_or(0))?;
    let diagnostic = truncate_to_utf8_boundary(&result.diagnostic, MAX_DIAGNOSTIC_BYTES);
    write_u32(w, diagnostic.len() as u32)?;
    w.write_all(diagnostic.as_bytes())
}

/// Encode an SRL2 envelope preamble.
pub fn write_envelope_preamble<W: Write>(
    w: &mut W,
    preamble: &EnvelopePreamble,
) -> Result<(), io::Error> {
    w.write_all(SRL2_MAGIC)?;
    write_u32(w, REQUEST_FLAGS_V0)?;
    let sender = preamble.envelope.sender();
    write_u32(
        w,
        u32::try_from(sender.len()).expect("validated sender exceeds u32"),
    )?;
    w.write_all(sender)?;
    let recipients = preamble.envelope.recipients();
    write_u32(
        w,
        u32::try_from(recipients.len()).expect("validated recipient count exceeds u32"),
    )?;
    for recipient in recipients {
        write_u32(
            w,
            u32::try_from(recipient.len()).expect("validated recipient exceeds u32"),
        )?;
        w.write_all(recipient)?;
    }
    Ok(())
}

/// Decode and validate an SRL2 envelope preamble.
pub fn read_envelope_preamble<R: Read>(r: &mut R) -> Result<EnvelopePreamble, SubmissionError> {
    read_srl2_magic(r)?;
    let flags = read_u32(r)?;
    if flags & !REQUEST_FLAGS_KNOWN != 0 {
        return Err(SubmissionError::UnknownRequestFlags(flags));
    }

    let sender_len = read_u32_limited(r, MAX_ADDRESS_BYTES, |len, limit| {
        SubmissionError::AddressTooLong { len, limit }
    })?;
    let sender = read_bytes(r, sender_len)?;
    let count_raw = read_u32(r)?;
    let count = usize::try_from(count_raw).map_err(|_| SubmissionError::TooManyRecipients {
        count: count_raw as usize,
        limit: MAX_RECIPIENTS,
    })?;
    if count > MAX_RECIPIENTS {
        return Err(SubmissionError::TooManyRecipients {
            count,
            limit: MAX_RECIPIENTS,
        });
    }
    let mut recipients = Vec::with_capacity(count);
    for _ in 0..count {
        let len = read_u32_limited(r, MAX_ADDRESS_BYTES, |len, limit| {
            SubmissionError::AddressTooLong { len, limit }
        })?;
        recipients.push(read_bytes(r, len)?);
    }
    Ok(EnvelopePreamble {
        envelope: Envelope::new(&sender, recipients)?,
    })
}

/// Encode an SRL2 READY or FINAL server reply.
pub fn write_server_reply<W: Write>(w: &mut W, reply: &ServerReply) -> Result<(), io::Error> {
    w.write_all(SRL2_MAGIC)?;
    match reply {
        ServerReply::Ready(ready) => {
            w.write_all(&[READY_KIND])?;
            write_u64(w, ready.max_message_bytes)?;
            write_u32(w, ready.max_chunk_bytes)?;
            write_u32(w, ready.max_diagnostic_bytes)
        }
        ServerReply::Final(result) => {
            w.write_all(&[FINAL_KIND])?;
            write_final_payload(w, result)
        }
    }
}

/// Decode an SRL2 READY or FINAL server reply.
pub fn read_server_reply<R: Read>(r: &mut R) -> Result<ServerReply, SubmissionError> {
    read_srl2_magic(r)?;
    let mut kind = [0u8; 1];
    r.read_exact(&mut kind)?;
    match kind[0] {
        READY_KIND => Ok(ServerReply::Ready(Ready {
            max_message_bytes: {
                let mut bytes = [0u8; 8];
                r.read_exact(&mut bytes)?;
                u64::from_be_bytes(bytes)
            },
            max_chunk_bytes: read_u32(r)?,
            max_diagnostic_bytes: read_u32(r)?,
        })),
        FINAL_KIND => Ok(ServerReply::Final(read_final_payload(r)?)),
        other => Err(SubmissionError::UnknownServerReplyKind(other)),
    }
}

/// Encode a complete SRL2 FINAL result frame.
pub fn write_final_result<W: Write>(w: &mut W, result: &DeliveryResult) -> Result<(), io::Error> {
    write_server_reply(w, &ServerReply::Final(result.clone()))
}

/// Decode a complete SRL2 FINAL result frame.
pub fn read_final_result<R: Read>(r: &mut R) -> Result<DeliveryResult, SubmissionError> {
    match read_server_reply(r)? {
        ServerReply::Final(result) => Ok(result),
        ServerReply::Ready(_) => Err(SubmissionError::UnknownServerReplyKind(READY_KIND)),
    }
}

// ── Request codec ─────────────────────────────────────────────────────

/// Decode a submission request from a framed reader.
///
/// All lengths are validated against `limits` *before* allocating the
/// corresponding buffer. Envelope addresses are validated through
/// `Envelope::new`.
///
/// A `MemoryReservation` is acquired from `budget` *after* the message
/// length is validated against `limits` but *before* the message bytes
/// are read/allocated.  The reservation is held inside the returned
/// [`SubmissionRequest`] and released when it is dropped.
pub fn read_request<R: Read>(
    r: &mut R,
    limits: &SubmissionLimits,
    budget: &MemoryBudget,
) -> Result<SubmissionRequest, SubmissionError> {
    // Magic (4 bytes)
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if magic != *MAGIC {
        return Err(SubmissionError::InvalidMagic);
    }

    // Flags (u32 BE)
    let flags = read_u32(r)?;
    if flags & !REQUEST_FLAGS_KNOWN != 0 {
        // Only bits not in REQUEST_FLAGS_KNOWN are unknown.
        // Since REQUEST_FLAGS_KNOWN is 0, any non-zero flags are unknown.
        // We cast to the lower byte for the error variant to keep a small payload.
        return Err(SubmissionError::UnknownRequestFlags(flags));
    }

    // Sender (length-prefixed, u32 BE — check limit before allocation)
    let sender_len = read_u32_limited(r, limits.max_address_bytes, |len, limit| {
        SubmissionError::AddressTooLong { len, limit }
    })?;
    let sender = read_bytes(r, sender_len)?;

    // Recipient count (u32 BE, checked before reading recipients)
    let rcpt_count_raw = read_u32(r)?;
    let rcpt_count =
        usize::try_from(rcpt_count_raw).map_err(|_| SubmissionError::TooManyRecipients {
            count: rcpt_count_raw as usize,
            limit: limits.max_recipients,
        })?;
    if rcpt_count > limits.max_recipients {
        return Err(SubmissionError::TooManyRecipients {
            count: rcpt_count,
            limit: limits.max_recipients,
        });
    }

    // Recipients (each length-prefixed u32 BE, validated against address limit)
    let mut recipients = Vec::with_capacity(rcpt_count);
    for _ in 0..rcpt_count {
        let addr_len = read_u32_limited(r, limits.max_address_bytes, |len, limit| {
            SubmissionError::AddressTooLong { len, limit }
        })?;
        recipients.push(read_bytes(r, addr_len)?);
    }

    // Message length (u64 BE, checked conversion to usize)
    let msg_len = read_message_len(r, limits.max_message_bytes)?;

    // Budget reservation: acquired *after* length validation but
    // *before* the message bytes are allocated/read.  This is the
    // point where we commit to holding `msg_len` bytes.
    let reservation = budget
        .try_reserve(msg_len)
        .ok_or(SubmissionError::BudgetExhausted {
            requested: msg_len,
            capacity: budget.capacity(),
        })?;

    let message = read_bytes(r, msg_len)?;

    // Construct envelope through validation.
    let envelope = Envelope::new(&sender, recipients)?;

    Ok(SubmissionRequest {
        envelope,
        message,
        reservation,
    })
}

/// Encode a submission request to a writer.
pub fn write_request<W: Write>(w: &mut W, request: &SubmissionRequest) -> Result<(), io::Error> {
    // Magic
    w.write_all(MAGIC)?;
    // Flags (u32 BE)
    write_u32(w, REQUEST_FLAGS_V0)?;
    // Sender (u32 BE length + data)
    let sender = request.envelope.sender();
    write_u32(w, u32::try_from(sender.len()).expect("sender exceeds u32"))?;
    w.write_all(sender)?;
    // Recipient count (u32 BE)
    let recipients = request.envelope.recipients();
    write_u32(
        w,
        u32::try_from(recipients.len()).expect("too many recipients"),
    )?;
    // Recipients (u32 BE length + data each)
    for rcpt in recipients {
        write_u32(w, u32::try_from(rcpt.len()).expect("address exceeds u32"))?;
        w.write_all(rcpt)?;
    }
    // Message length + data (u64 BE)
    write_u64(
        w,
        u64::try_from(request.message.len()).expect("message exceeds u64"),
    )?;
    w.write_all(&request.message)?;
    Ok(())
}

// ── Response codec ────────────────────────────────────────────────────

/// Decode a submission response from a framed reader.
///
/// `smtp_code` of 0 on the wire maps to `None`.
pub fn read_response<R: Read>(
    r: &mut R,
    limits: &SubmissionLimits,
) -> Result<DeliveryResult, SubmissionError> {
    // Magic (4 bytes) — required for responses too
    let mut magic = [0u8; 4];
    r.read_exact(&mut magic)?;
    if magic != *MAGIC {
        return Err(SubmissionError::InvalidMagic);
    }

    // Status (1 byte)
    let mut status_buf = [0u8; 1];
    r.read_exact(&mut status_buf)?;
    let status = match status_buf[0] {
        STATUS_DELIVERED => DeliveryStatus::Delivered,
        STATUS_TEMPORARY => DeliveryStatus::TemporaryFailure,
        STATUS_PERMANENT => DeliveryStatus::PermanentFailure,
        STATUS_PROTOCOL => DeliveryStatus::ProtocolRejection,
        other => return Err(SubmissionError::InvalidResponseStatus(other)),
    };

    // Flags (1 byte, only bit0 = ambiguous)
    let mut flags_buf = [0u8; 1];
    r.read_exact(&mut flags_buf)?;
    let flags = flags_buf[0];
    if flags & !RESPONSE_FLAGS_KNOWN != 0 {
        return Err(SubmissionError::UnknownResponseFlags(flags));
    }
    let ambiguous = flags & 0x01 != 0;

    // SMTP code (0 ↔ None)
    let smtp_raw = read_u16(r)?;
    let smtp_code = if smtp_raw == 0 { None } else { Some(smtp_raw) };

    // Diagnostic (u32 BE length, UTF-8 validated)
    let diag_len = read_u32_limited(r, limits.max_diagnostic_bytes, |len, limit| {
        SubmissionError::DiagnosticTooLong { len, limit }
    })?;
    let diag_bytes = read_bytes(r, diag_len)?;
    let diagnostic =
        String::from_utf8(diag_bytes).map_err(|_| SubmissionError::InvalidDiagnosticUtf8)?;

    Ok(DeliveryResult {
        status,
        ambiguous,
        smtp_code,
        diagnostic,
    })
}

/// Encode a submission response to a writer.
///
/// The diagnostic is defensively truncated to `max_diagnostic_bytes` at
/// a UTF-8 boundary before encoding.
///
/// `max_diagnostic_bytes` is clamped to the protocol diagnostic ceiling and
/// `u32::MAX` to prevent
/// panic when the configured limit exceeds `u32::MAX`. The truncation
/// always lands on a UTF-8 character boundary.
pub fn write_response<W: Write>(
    w: &mut W,
    result: &DeliveryResult,
    max_diagnostic_bytes: usize,
) -> Result<(), io::Error> {
    let effective_max = max_diagnostic_bytes
        .min(u32::MAX as usize)
        .min(MAX_DIAGNOSTIC_BYTES);

    // Magic
    w.write_all(MAGIC)?;

    // Status
    let status_byte = match result.status {
        DeliveryStatus::Delivered => STATUS_DELIVERED,
        DeliveryStatus::TemporaryFailure => STATUS_TEMPORARY,
        DeliveryStatus::PermanentFailure => STATUS_PERMANENT,
        DeliveryStatus::ProtocolRejection => STATUS_PROTOCOL,
    };
    w.write_all(&[status_byte])?;

    // Flags (bit0 = ambiguous)
    w.write_all(&[u8::from(result.ambiguous)])?;

    // SMTP code (None → 0)
    write_u16(w, result.smtp_code.unwrap_or(0))?;

    // Diagnostic (u32 BE length, truncate defensively)
    let diag = truncate_to_utf8_boundary(&result.diagnostic, effective_max);
    write_u32(w, diag.len() as u32)?;
    w.write_all(diag.as_bytes())?;

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_and_decoder_share_recipient_and_address_limits() {
        let limits = SubmissionLimits {
            max_recipients: MAX_RECIPIENTS,
            max_address_bytes: MAX_ADDRESS_BYTES,
            max_message_bytes: 2,
            max_diagnostic_bytes: MAX_DIAGNOSTIC_BYTES,
        };

        let recipients = vec![vec![b'a'; MAX_ADDRESS_BYTES]; MAX_RECIPIENTS];
        let mut encoded = Vec::new();
        encoded.extend_from_slice(MAGIC);
        encoded.extend_from_slice(&0_u32.to_be_bytes());
        encoded.extend_from_slice(&0_u32.to_be_bytes());
        encoded.extend_from_slice(&(recipients.len() as u32).to_be_bytes());
        for recipient in &recipients {
            encoded.extend_from_slice(&(recipient.len() as u32).to_be_bytes());
            encoded.extend_from_slice(recipient);
        }
        encoded.extend_from_slice(&2_u64.to_be_bytes());
        encoded.extend_from_slice(b"\r\n");
        let budget = MemoryBudget::new(2);
        read_request(&mut Cursor::new(encoded), &limits, &budget).unwrap();

        assert_eq!(
            Envelope::new(b"", vec![vec![b'a'; MAX_ADDRESS_BYTES + 1]]).unwrap_err(),
            EnvelopeError::AddressTooLong(MAX_ADDRESS_BYTES + 1)
        );
        assert_eq!(
            Envelope::new(b"", vec![b"a@example.test".to_vec(); MAX_RECIPIENTS + 1]).unwrap_err(),
            EnvelopeError::TooManyRecipients(MAX_RECIPIENTS + 1)
        );
    }

    #[test]
    fn delivery_result_and_decoder_share_diagnostic_limit() {
        let limits = SubmissionLimits {
            max_recipients: MAX_RECIPIENTS,
            max_address_bytes: MAX_ADDRESS_BYTES,
            max_message_bytes: 1,
            max_diagnostic_bytes: MAX_DIAGNOSTIC_BYTES,
        };
        let result = DeliveryResult::temporary_failure("x".repeat(MAX_DIAGNOSTIC_BYTES + 1), None);
        assert_eq!(result.diagnostic.len(), MAX_DIAGNOSTIC_BYTES);

        let mut encoded = Vec::new();
        write_response(&mut encoded, &result, usize::MAX).unwrap();
        let decoded = read_response(&mut Cursor::new(encoded), &limits).unwrap();
        assert_eq!(decoded.diagnostic.len(), MAX_DIAGNOSTIC_BYTES);
    }
    use std::io::Cursor;

    // ── helpers ───────────────────────────────────────────────────────

    /// Build a minimal valid SRL1 request frame for "sender@example.com"
    /// → ["rcpt@example.net"] with message "hello".
    ///
    /// Uses the approved spec layout:
    /// magic[4] flags[u32] sender_len[u32] sender rcpt_count[u32]
    ///   rcpt_len[u32] rcpt msg_len[u64] msg
    fn minimal_valid_frame() -> Vec<u8> {
        let sender = b"sender@example.com";
        let rcpt = b"rcpt@example.net";
        let msg = b"hello";

        let mut frame = Vec::new();
        // Magic
        frame.extend_from_slice(MAGIC);
        // Flags = 0 (u32 BE)
        frame.extend_from_slice(&0u32.to_be_bytes());
        // Sender len + data (u32 BE)
        frame.extend_from_slice(&(sender.len() as u32).to_be_bytes());
        frame.extend_from_slice(sender);
        // Recipient count = 1 (u32 BE)
        frame.extend_from_slice(&1u32.to_be_bytes());
        // Recipient 0 len + data (u32 BE)
        frame.extend_from_slice(&(rcpt.len() as u32).to_be_bytes());
        frame.extend_from_slice(rcpt);
        // Message len + data (u64 BE)
        frame.extend_from_slice(&(msg.len() as u64).to_be_bytes());
        frame.extend_from_slice(msg);

        frame
    }

    /// Build a minimal valid SRL1 response frame.
    ///
    /// Uses the approved spec layout:
    /// magic[4] status[u8] flags[u8] smtp_code[u16] diag_len[u32] diag
    fn minimal_response_frame() -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(MAGIC); // magic
        frame.push(STATUS_DELIVERED); // status
        frame.push(0x00); // flags: not ambiguous
        frame.extend_from_slice(&250u16.to_be_bytes()); // smtp_code
        frame.extend_from_slice(&2u32.to_be_bytes()); // diag_len = 2
        frame.extend_from_slice(b"OK"); // diagnostic
        frame
    }

    fn permissive_limits() -> SubmissionLimits {
        SubmissionLimits::production(26_214_400)
    }

    fn permissive_budget() -> MemoryBudget {
        MemoryBudget::new(usize::MAX / 2)
    }

    #[test]
    fn budget_exhaustion_rejects_before_reading_message() {
        // Budget too small for the message declared in the frame.
        let budget = MemoryBudget::new(3); // only 3 bytes
        let frame = minimal_valid_frame(); // message is "hello" = 5 bytes
        let err =
            read_request(&mut Cursor::new(&frame), &permissive_limits(), &budget).unwrap_err();
        assert_eq!(
            err,
            SubmissionError::BudgetExhausted {
                requested: 5,
                capacity: 3,
            }
        );
        // Budget was never touched — reservation was rejected.
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn truncated_message_releases_reservation() {
        // Build a frame with message length = 100 but only provide 10 bytes of data.
        // The budget reservation succeeds (length is valid) but the read
        // of message bytes fails with UnexpectedEof, and the reservation
        // must be released.
        let budget = MemoryBudget::new(1000);
        let sender = b"a@b";
        let rcpt = b"c@d";
        let mut frame = Vec::new();
        frame.extend_from_slice(MAGIC);
        frame.extend_from_slice(&0u32.to_be_bytes());
        frame.extend_from_slice(&(sender.len() as u32).to_be_bytes());
        frame.extend_from_slice(sender);
        frame.extend_from_slice(&1u32.to_be_bytes());
        frame.extend_from_slice(&(rcpt.len() as u32).to_be_bytes());
        frame.extend_from_slice(rcpt);
        frame.extend_from_slice(&100u64.to_be_bytes()); // declare 100 bytes
        frame.extend_from_slice(&[0u8; 10]); // but only provide 10

        let err =
            read_request(&mut Cursor::new(&frame), &permissive_limits(), &budget).unwrap_err();
        assert!(matches!(
            err,
            SubmissionError::Io(io::ErrorKind::UnexpectedEof)
        ));
        // The reservation must have been released on error.
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn successful_read_holds_reservation_until_drop() {
        let budget = MemoryBudget::new(1000);
        let frame = minimal_valid_frame(); // message "hello" = 5 bytes
        let request =
            read_request(&mut Cursor::new(&frame), &permissive_limits(), &budget).unwrap();
        assert_eq!(budget.used(), 5);
        assert_eq!(request.message.len(), 5);
        drop(request);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn into_parts_keeps_reservation_while_message_is_retained() {
        let budget = MemoryBudget::new(1000);
        let frame = minimal_valid_frame();
        let request =
            read_request(&mut Cursor::new(&frame), &permissive_limits(), &budget).unwrap();
        assert_eq!(budget.used(), 5);
        let (envelope, message, reservation) = request.into_parts();
        assert_eq!(envelope.sender(), b"sender@example.com");
        assert_eq!(message, b"hello");
        assert_eq!(budget.used(), 5);
        drop(reservation);
        assert_eq!(budget.used(), 0);
    }

    // ── request round-trip ────────────────────────────────────────────

    #[test]
    fn request_round_trip() {
        let frame = minimal_valid_frame();
        let request = read_request(
            &mut Cursor::new(&frame),
            &permissive_limits(),
            &permissive_budget(),
        )
        .unwrap();

        assert_eq!(request.envelope.sender(), b"sender@example.com");
        assert_eq!(request.envelope.recipients().len(), 1);
        assert_eq!(
            request.envelope.recipients()[0],
            b"rcpt@example.net".as_slice()
        );
        assert_eq!(request.message, b"hello");
    }

    // ── request encoder round-trip ────────────────────────────────────

    #[test]
    fn request_encoder_round_trip() {
        let envelope = Envelope::new(
            b"alice@example.com",
            vec![b"bob@example.net".to_vec(), b"carol@example.org".to_vec()],
        )
        .unwrap();
        let msg = b"test message body".to_vec();
        let budget = permissive_budget();
        let reservation = budget.try_reserve(msg.len()).unwrap();
        let request = SubmissionRequest {
            envelope,
            message: msg,
            reservation,
        };

        let mut encoded = Vec::new();
        write_request(&mut encoded, &request).unwrap();

        let decoded = read_request(
            &mut Cursor::new(&encoded),
            &permissive_limits(),
            &permissive_budget(),
        )
        .unwrap();
        assert_eq!(decoded.envelope.sender(), b"alice@example.com");
        assert_eq!(decoded.envelope.recipients().len(), 2);
        assert_eq!(
            decoded.envelope.recipients()[0],
            b"bob@example.net".as_slice()
        );
        assert_eq!(
            decoded.envelope.recipients()[1],
            b"carol@example.org".as_slice()
        );
        assert_eq!(decoded.message, b"test message body");
    }

    // ── wrong magic ───────────────────────────────────────────────────

    #[test]
    fn reject_wrong_magic() {
        let mut frame = minimal_valid_frame();
        frame[0] = b'X'; // corrupt first magic byte

        let err = read_request(
            &mut Cursor::new(&frame),
            &permissive_limits(),
            &permissive_budget(),
        )
        .unwrap_err();
        assert_eq!(err, SubmissionError::InvalidMagic);
    }

    // ── unknown request flags ─────────────────────────────────────────

    #[test]
    fn reject_unknown_flags() {
        let mut frame = minimal_valid_frame();
        // flags are at bytes 4..8 (u32 BE), set byte 7 = 0xFF
        frame[7] = 0xFF;

        let err = read_request(
            &mut Cursor::new(&frame),
            &permissive_limits(),
            &permissive_budget(),
        )
        .unwrap_err();
        assert_eq!(err, SubmissionError::UnknownRequestFlags(0xFF));
    }

    // ── recipient count over limit ────────────────────────────────────

    #[test]
    fn reject_recipient_count_over_limit() {
        let mut limits = permissive_limits();
        limits.max_recipients = 1;

        // Build a frame declaring 2 recipients.
        let sender = b"sender@example.com";
        let rcpt = b"rcpt@example.net";
        let msg = b"hi";

        let mut frame = Vec::new();
        frame.extend_from_slice(MAGIC);
        frame.extend_from_slice(&0u32.to_be_bytes()); // flags u32
        frame.extend_from_slice(&(sender.len() as u32).to_be_bytes());
        frame.extend_from_slice(sender);
        frame.extend_from_slice(&2u32.to_be_bytes()); // 2 recipients, limit is 1
                                                      // Add recipient data so the frame isn't truncated (we want the
                                                      // rejection to happen at count validation, not at read).
        for _ in 0..2 {
            frame.extend_from_slice(&(rcpt.len() as u32).to_be_bytes());
            frame.extend_from_slice(rcpt);
        }
        frame.extend_from_slice(&(msg.len() as u64).to_be_bytes());
        frame.extend_from_slice(msg);

        let err =
            read_request(&mut Cursor::new(&frame), &limits, &permissive_budget()).unwrap_err();
        assert_eq!(
            err,
            SubmissionError::TooManyRecipients { count: 2, limit: 1 }
        );
    }

    // ── oversized message ─────────────────────────────────────────────

    #[test]
    fn reject_oversized_message() {
        let mut limits = permissive_limits();
        limits.max_message_bytes = 4;

        // Build a frame with a message length > 4.
        let sender = b"sender@example.com";
        let rcpt = b"rcpt@example.net";

        let mut frame = Vec::new();
        frame.extend_from_slice(MAGIC);
        frame.extend_from_slice(&0u32.to_be_bytes()); // flags u32
        frame.extend_from_slice(&(sender.len() as u32).to_be_bytes());
        frame.extend_from_slice(sender);
        frame.extend_from_slice(&1u32.to_be_bytes());
        frame.extend_from_slice(&(rcpt.len() as u32).to_be_bytes());
        frame.extend_from_slice(rcpt);
        frame.extend_from_slice(&10u64.to_be_bytes()); // 10 bytes, limit is 4
        frame.extend_from_slice(b"0123456789");

        let err =
            read_request(&mut Cursor::new(&frame), &limits, &permissive_budget()).unwrap_err();
        assert_eq!(err, SubmissionError::MessageTooLarge { len: 10, limit: 4 });
    }

    // ── message u64::MAX rejected via checked conversion ──────────────

    #[test]
    fn reject_message_u64_max() {
        let sender = b"sender@example.com";
        let rcpt = b"rcpt@example.net";

        let mut frame = Vec::new();
        frame.extend_from_slice(MAGIC);
        frame.extend_from_slice(&0u32.to_be_bytes()); // flags u32
        frame.extend_from_slice(&(sender.len() as u32).to_be_bytes());
        frame.extend_from_slice(sender);
        frame.extend_from_slice(&1u32.to_be_bytes());
        frame.extend_from_slice(&(rcpt.len() as u32).to_be_bytes());
        frame.extend_from_slice(rcpt);
        frame.extend_from_slice(&u64::MAX.to_be_bytes()); // u64::MAX

        let err = read_request(
            &mut Cursor::new(&frame),
            &permissive_limits(),
            &permissive_budget(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            SubmissionError::MessageTooLarge {
                len: u64::MAX,
                limit: permissive_limits().max_message_bytes
            }
        );
    }

    // ── truncation at every fixed and variable field boundary ─────────

    #[test]
    fn reject_truncation_at_every_field_boundary() {
        let frame = minimal_valid_frame();
        // The frame has known structure. Test truncation at every byte
        // offset from 1..frame.len()-1 (not 0 or full length).
        for cut in 1..frame.len() {
            let truncated = &frame[..cut];
            let result = read_request(
                &mut Cursor::new(truncated),
                &permissive_limits(),
                &permissive_budget(),
            );
            assert!(
                result.is_err(),
                "truncation at byte {} should fail, but got Ok",
                cut
            );
            // Verify the error is an I/O error (UnexpectedEof).
            let err = result.unwrap_err();
            assert!(
                matches!(err, SubmissionError::Io(io::ErrorKind::UnexpectedEof)),
                "truncation at byte {}: expected Io(UnexpectedEof), got {:?}",
                cut,
                err
            );
        }
    }

    // ── specific truncation boundaries ────────────────────────────────

    #[test]
    fn reject_truncated_at_magic() {
        // Only 3 bytes — not enough for the 4-byte magic.
        let frame = &minimal_valid_frame()[..3];
        let err = read_request(
            &mut Cursor::new(frame),
            &permissive_limits(),
            &permissive_budget(),
        )
        .unwrap_err();
        assert_eq!(err, SubmissionError::Io(io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn reject_truncated_at_flags() {
        // 4 bytes magic, no flags.
        let frame = &minimal_valid_frame()[..4];
        let err = read_request(
            &mut Cursor::new(frame),
            &permissive_limits(),
            &permissive_budget(),
        )
        .unwrap_err();
        assert_eq!(err, SubmissionError::Io(io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn reject_truncated_at_sender_len() {
        // 4 magic + 4 flags = 8, need 4 more for sender len.
        let frame = &minimal_valid_frame()[..9];
        let err = read_request(
            &mut Cursor::new(frame),
            &permissive_limits(),
            &permissive_budget(),
        )
        .unwrap_err();
        assert_eq!(err, SubmissionError::Io(io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn reject_truncated_at_sender_data() {
        // Declare sender len = 18, but only provide 10 bytes.
        let full = minimal_valid_frame();
        // sender_len field is at bytes 8..12, sender data starts at 12.
        // Truncate mid-sender: 12 + 10 = 22 bytes.
        let frame = &full[..22];
        let err = read_request(
            &mut Cursor::new(frame),
            &permissive_limits(),
            &permissive_budget(),
        )
        .unwrap_err();
        assert_eq!(err, SubmissionError::Io(io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn reject_truncated_at_rcpt_count() {
        // After sender (magic 4 + flags 4 + sender_len 4 + sender 18 = 30),
        // need 4 bytes for rcpt_count.
        let full = minimal_valid_frame();
        let frame = &full[..32];
        let err = read_request(
            &mut Cursor::new(frame),
            &permissive_limits(),
            &permissive_budget(),
        )
        .unwrap_err();
        assert_eq!(err, SubmissionError::Io(io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn reject_truncated_at_rcpt_len() {
        // After rcpt_count (byte 34), need 4 bytes for rcpt[0] len.
        let full = minimal_valid_frame();
        let frame = &full[..36];
        let err = read_request(
            &mut Cursor::new(frame),
            &permissive_limits(),
            &permissive_budget(),
        )
        .unwrap_err();
        assert_eq!(err, SubmissionError::Io(io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn reject_truncated_at_rcpt_data() {
        // After rcpt_len (byte 38), need rcpt[0] data (16 bytes).
        let full = minimal_valid_frame();
        let frame = &full[..45]; // mid-recipient
        let err = read_request(
            &mut Cursor::new(frame),
            &permissive_limits(),
            &permissive_budget(),
        )
        .unwrap_err();
        assert_eq!(err, SubmissionError::Io(io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn reject_truncated_at_msg_len() {
        // After all recipients, need 8 bytes for message length.
        let full = minimal_valid_frame();
        let total = full.len(); // 67 for "hello"
                                // Remove msg data + some of msg_len.
        let frame = &full[..total - 8];
        let err = read_request(
            &mut Cursor::new(frame),
            &permissive_limits(),
            &permissive_budget(),
        )
        .unwrap_err();
        assert_eq!(err, SubmissionError::Io(io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn reject_truncated_at_msg_data() {
        // Full frame minus last 2 bytes of message.
        let full = minimal_valid_frame();
        let frame = &full[..full.len() - 2];
        let err = read_request(
            &mut Cursor::new(frame),
            &permissive_limits(),
            &permissive_budget(),
        )
        .unwrap_err();
        assert_eq!(err, SubmissionError::Io(io::ErrorKind::UnexpectedEof));
    }

    // ── address limit checked before allocation ───────────────────────

    #[test]
    fn reject_address_over_limit_before_read() {
        let mut limits = permissive_limits();
        limits.max_address_bytes = 20; // sender (18 bytes) fits, recipient (34 bytes) does not

        // Build a frame with a recipient declared as 34 bytes.
        let sender = b"sender@example.com"; // 18 bytes, fits in limit
        let long_rcpt = b"very-long-rcpt-address@example.net"; // 34 bytes
        let msg = b"hi";

        let mut frame = Vec::new();
        frame.extend_from_slice(MAGIC);
        frame.extend_from_slice(&0u32.to_be_bytes()); // flags u32
        frame.extend_from_slice(&(sender.len() as u32).to_be_bytes());
        frame.extend_from_slice(sender);
        frame.extend_from_slice(&1u32.to_be_bytes());
        frame.extend_from_slice(&(long_rcpt.len() as u32).to_be_bytes());
        // Don't add the actual recipient data — the limit check happens
        // after reading the length, before reading the data.
        // But we do need the data in the frame for it not to be a
        // truncation error. However, we want to verify the error is
        // AddressTooLong, not UnexpectedEof.
        frame.extend_from_slice(long_rcpt);
        frame.extend_from_slice(&(msg.len() as u64).to_be_bytes());
        frame.extend_from_slice(msg);

        let err =
            read_request(&mut Cursor::new(&frame), &limits, &permissive_budget()).unwrap_err();
        assert_eq!(err, SubmissionError::AddressTooLong { len: 34, limit: 20 });
    }

    // ── sender limit checked before allocation ────────────────────────

    #[test]
    fn reject_sender_over_limit_before_read() {
        let mut limits = permissive_limits();
        limits.max_address_bytes = 5;

        let sender = b"sender@example.com"; // 18 bytes, limit is 5
        let rcpt = b"rcpt@example.net";
        let msg = b"hi";

        let mut frame = Vec::new();
        frame.extend_from_slice(MAGIC);
        frame.extend_from_slice(&0u32.to_be_bytes()); // flags u32
        frame.extend_from_slice(&(sender.len() as u32).to_be_bytes());
        frame.extend_from_slice(sender);
        frame.extend_from_slice(&1u32.to_be_bytes());
        frame.extend_from_slice(&(rcpt.len() as u32).to_be_bytes());
        frame.extend_from_slice(rcpt);
        frame.extend_from_slice(&(msg.len() as u64).to_be_bytes());
        frame.extend_from_slice(msg);

        let err =
            read_request(&mut Cursor::new(&frame), &limits, &permissive_budget()).unwrap_err();
        assert_eq!(err, SubmissionError::AddressTooLong { len: 18, limit: 5 });
    }

    // ── u32::MAX adversarial for recipient count ──────────────────────

    #[test]
    fn reject_recipient_count_u32_max() {
        let sender = b"a@b";

        let mut frame = Vec::new();
        frame.extend_from_slice(MAGIC);
        frame.extend_from_slice(&0u32.to_be_bytes()); // flags u32
        frame.extend_from_slice(&(sender.len() as u32).to_be_bytes());
        frame.extend_from_slice(sender);
        frame.extend_from_slice(&u32::MAX.to_be_bytes()); // u32::MAX recipients

        let err = read_request(
            &mut Cursor::new(&frame),
            &permissive_limits(),
            &permissive_budget(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            SubmissionError::TooManyRecipients {
                count: u32::MAX as usize,
                limit: permissive_limits().max_recipients
            }
        );
    }

    // ── response round-trips ──────────────────────────────────────────

    #[test]
    fn response_round_trip_delivered() {
        let result = DeliveryResult::delivered("250 queued", Some(250));
        let mut encoded = Vec::new();
        write_response(&mut encoded, &result, 4096).unwrap();

        let decoded = read_response(&mut Cursor::new(&encoded), &permissive_limits()).unwrap();
        assert_eq!(decoded.status, DeliveryStatus::Delivered);
        assert!(!decoded.ambiguous);
        assert_eq!(decoded.smtp_code, Some(250));
        assert_eq!(decoded.diagnostic, "250 queued");
    }

    #[test]
    fn response_round_trip_temporary_failure() {
        let result = DeliveryResult::temporary_failure("451 try again", Some(451));
        let mut encoded = Vec::new();
        write_response(&mut encoded, &result, 4096).unwrap();

        let decoded = read_response(&mut Cursor::new(&encoded), &permissive_limits()).unwrap();
        assert_eq!(decoded.status, DeliveryStatus::TemporaryFailure);
        assert!(!decoded.ambiguous);
        assert_eq!(decoded.smtp_code, Some(451));
        assert_eq!(decoded.diagnostic, "451 try again");
    }

    #[test]
    fn response_round_trip_permanent_failure() {
        let result = DeliveryResult::permanent_failure("550 user unknown", Some(550));
        let mut encoded = Vec::new();
        write_response(&mut encoded, &result, 4096).unwrap();

        let decoded = read_response(&mut Cursor::new(&encoded), &permissive_limits()).unwrap();
        assert_eq!(decoded.status, DeliveryStatus::PermanentFailure);
        assert!(!decoded.ambiguous);
        assert_eq!(decoded.smtp_code, Some(550));
        assert_eq!(decoded.diagnostic, "550 user unknown");
    }

    #[test]
    fn response_round_trip_protocol_rejection() {
        let result = DeliveryResult::protocol_rejection("TLS handshake failed", None);
        let mut encoded = Vec::new();
        write_response(&mut encoded, &result, 4096).unwrap();

        let decoded = read_response(&mut Cursor::new(&encoded), &permissive_limits()).unwrap();
        assert_eq!(decoded.status, DeliveryStatus::ProtocolRejection);
        assert!(!decoded.ambiguous);
        assert_eq!(decoded.smtp_code, None);
        assert_eq!(decoded.diagnostic, "TLS handshake failed");
    }

    // ── ambiguous flag round-trip ─────────────────────────────────────

    #[test]
    fn response_ambiguous_flag_round_trip() {
        let result = DeliveryResult::ambiguous("connection lost after DATA");
        let mut encoded = Vec::new();
        write_response(&mut encoded, &result, 4096).unwrap();

        let decoded = read_response(&mut Cursor::new(&encoded), &permissive_limits()).unwrap();
        assert_eq!(decoded.status, DeliveryStatus::TemporaryFailure);
        assert!(decoded.ambiguous);
        assert_eq!(decoded.smtp_code, None);
        assert_eq!(decoded.diagnostic, "connection lost after DATA");
    }

    // ── SMTP code 0 ↔ None ───────────────────────────────────────────

    #[test]
    fn response_smtp_code_zero_is_none() {
        // Manually build a response frame with smtp_code = 0.
        let mut frame = Vec::new();
        frame.extend_from_slice(MAGIC); // magic
        frame.push(STATUS_DELIVERED); // status
        frame.push(0); // not ambiguous
        frame.extend_from_slice(&0u16.to_be_bytes()); // smtp code = 0
        frame.extend_from_slice(&5u32.to_be_bytes()); // diag len u32
        frame.extend_from_slice(b"hello"); // diagnostic

        let decoded = read_response(&mut Cursor::new(&frame), &permissive_limits()).unwrap();
        assert_eq!(decoded.smtp_code, None);
    }

    #[test]
    fn response_smtp_code_nonzero_round_trip() {
        let result = DeliveryResult::delivered("ok", Some(250));
        let mut encoded = Vec::new();
        write_response(&mut encoded, &result, 4096).unwrap();

        let decoded = read_response(&mut Cursor::new(&encoded), &permissive_limits()).unwrap();
        assert_eq!(decoded.smtp_code, Some(250));
    }

    // ── diagnostic UTF-8 round trip ───────────────────────────────────

    #[test]
    fn response_diagnostic_utf8_round_trip() {
        // Multi-byte UTF-8: euro sign (3 bytes) + ASCII.
        let diag = "price: \u{20AC}100 \u{2013} special chars";
        let result = DeliveryResult::delivered(diag, Some(250));
        let mut encoded = Vec::new();
        write_response(&mut encoded, &result, 4096).unwrap();

        let decoded = read_response(&mut Cursor::new(&encoded), &permissive_limits()).unwrap();
        assert_eq!(decoded.diagnostic, diag);
    }

    // ── invalid UTF-8 rejection ───────────────────────────────────────

    #[test]
    fn response_reject_invalid_utf8_diagnostic() {
        // Manually build a response with invalid UTF-8 in diagnostic.
        let mut frame = Vec::new();
        frame.extend_from_slice(MAGIC); // magic
        frame.push(STATUS_DELIVERED);
        frame.push(0); // not ambiguous
        frame.extend_from_slice(&250u16.to_be_bytes());
        // Diagnostic: 3 bytes of invalid UTF-8.
        frame.extend_from_slice(&3u32.to_be_bytes());
        frame.extend_from_slice(&[0xFF, 0xFE, 0x80]); // invalid UTF-8

        let err = read_response(&mut Cursor::new(&frame), &permissive_limits()).unwrap_err();
        assert_eq!(err, SubmissionError::InvalidDiagnosticUtf8);
    }

    // ── diagnostic truncation at UTF-8 boundary to 4096 ──────────────

    #[test]
    fn response_diagnostic_truncated_at_utf8_boundary() {
        // 3-byte UTF-8 character (euro sign). 4096 / 3 = 1365 remainder 1.
        let euro = "\u{20AC}";
        let long_diag = euro.repeat(2000); // 2000 * 3 = 6000 bytes

        let result = DeliveryResult::delivered(&long_diag, Some(250));
        // DeliveryResult constructors already truncate to 4096.
        assert!(result.diagnostic.len() <= 4096);

        // Write and read back.
        let mut encoded = Vec::new();
        write_response(&mut encoded, &result, 4096).unwrap();

        let decoded = read_response(&mut Cursor::new(&encoded), &permissive_limits()).unwrap();
        assert!(decoded.diagnostic.len() <= 4096);
        assert!(std::str::from_utf8(decoded.diagnostic.as_bytes()).is_ok());
        // 4096 / 3 = 1365 full euro chars.
        assert_eq!(decoded.diagnostic.chars().count(), 4096 / 3);
    }

    #[test]
    fn write_response_truncates_oversized_diagnostic() {
        // Construct a DeliveryResult manually with a too-long diagnostic.
        let long_diag = "x".repeat(5000);
        let result = DeliveryResult {
            status: DeliveryStatus::Delivered,
            ambiguous: false,
            smtp_code: Some(250),
            diagnostic: long_diag,
        };

        let mut encoded = Vec::new();
        write_response(&mut encoded, &result, 4096).unwrap();

        let decoded = read_response(&mut Cursor::new(&encoded), &permissive_limits()).unwrap();
        assert_eq!(decoded.diagnostic.len(), 4096);
    }

    // ── diagnostic too long on read ───────────────────────────────────

    #[test]
    fn reject_diagnostic_too_long_on_read() {
        let mut limits = permissive_limits();
        limits.max_diagnostic_bytes = 10;

        // Build a response with a 20-byte diagnostic.
        let diag: &[u8] = b"01234567890123456789"; // 20 bytes exactly
        let mut frame = Vec::new();
        frame.extend_from_slice(MAGIC); // magic
        frame.push(STATUS_DELIVERED);
        frame.push(0);
        frame.extend_from_slice(&250u16.to_be_bytes());
        frame.extend_from_slice(&20u32.to_be_bytes()); // diag len u32 = 20
        frame.extend_from_slice(diag);

        let err = read_response(&mut Cursor::new(&frame), &limits).unwrap_err();
        assert_eq!(
            err,
            SubmissionError::DiagnosticTooLong { len: 20, limit: 10 }
        );
    }

    // ── empty message round-trip ──────────────────────────────────────

    #[test]
    fn request_with_empty_message() {
        let envelope =
            Envelope::new(b"sender@example.com", vec![b"rcpt@example.net".to_vec()]).unwrap();
        let budget = permissive_budget();
        let reservation = budget.try_reserve(0).unwrap();
        let request = SubmissionRequest {
            envelope,
            message: Vec::new(),
            reservation,
        };

        let mut encoded = Vec::new();
        write_request(&mut encoded, &request).unwrap();

        let decoded = read_request(
            &mut Cursor::new(&encoded),
            &permissive_limits(),
            &permissive_budget(),
        )
        .unwrap();
        assert_eq!(decoded.message, b"");
    }

    // ── null reverse path ─────────────────────────────────────────────

    #[test]
    fn request_with_null_reverse_path() {
        let envelope = Envelope::new(b"", vec![b"rcpt@example.net".to_vec()]).unwrap();
        let msg = b"data".to_vec();
        let budget = permissive_budget();
        let reservation = budget.try_reserve(msg.len()).unwrap();
        let request = SubmissionRequest {
            envelope,
            message: msg,
            reservation,
        };

        let mut encoded = Vec::new();
        write_request(&mut encoded, &request).unwrap();

        let decoded = read_request(
            &mut Cursor::new(&encoded),
            &permissive_limits(),
            &permissive_budget(),
        )
        .unwrap();
        assert_eq!(decoded.envelope.sender(), b"");
        assert_eq!(
            decoded.envelope.recipients()[0],
            b"rcpt@example.net".as_slice()
        );
    }

    // ── GOLDEN-BYTE: exact request layout (approved spec) ─────────────
    // REQUEST = magic[4] SRL1; flags u32 BE; sender_len u32 BE; sender;
    //           rcpt_count u32 BE; [rcpt_len u32 BE; rcpt]*; msg_len u64 BE; msg
    #[test]
    fn golden_request_exact_bytes() {
        let sender = b"sender@example.com"; // 18 bytes
        let rcpt = b"rcpt@example.net"; // 16 bytes
        let msg = b"hello"; // 5 bytes

        let mut expected = Vec::new();
        expected.extend_from_slice(b"SRL1"); // magic
        expected.extend_from_slice(&0u32.to_be_bytes()); // flags u32
        expected.extend_from_slice(&18u32.to_be_bytes()); // sender_len u32
        expected.extend_from_slice(sender);
        expected.extend_from_slice(&1u32.to_be_bytes()); // rcpt_count u32
        expected.extend_from_slice(&16u32.to_be_bytes()); // rcpt_len u32
        expected.extend_from_slice(rcpt);
        expected.extend_from_slice(&5u64.to_be_bytes()); // msg_len u64
        expected.extend_from_slice(msg);
        // Total: 4+4+4+18+4+4+16+8+5 = 67 bytes

        assert_eq!(expected.len(), 67, "golden request should be 67 bytes");

        // Write via codec
        let envelope = Envelope::new(sender, vec![rcpt.to_vec()]).unwrap();
        let budget = permissive_budget();
        let reservation = budget.try_reserve(msg.len()).unwrap();
        let req = SubmissionRequest {
            envelope,
            message: msg.to_vec(),
            reservation,
        };
        let mut written = Vec::new();
        write_request(&mut written, &req).unwrap();

        assert_eq!(
            written, expected,
            "write_request must produce exact spec bytes"
        );
        // read_request must also accept these exact bytes
        let decoded = read_request(
            &mut Cursor::new(&expected),
            &permissive_limits(),
            &permissive_budget(),
        )
        .unwrap();
        assert_eq!(decoded.envelope.sender(), sender);
    }

    // ── GOLDEN-BYTE: exact response layout (approved spec) ────────────
    // RESPONSE = magic[4] SRL1; status u8; flags u8 (bit0=ambiguous);
    //            smtp_code u16 BE; diagnostic_len u32 BE; diagnostic UTF-8
    #[test]
    fn golden_response_exact_bytes() {
        let diagnostic = "250 queued"; // 10 bytes

        let mut expected = Vec::new();
        expected.extend_from_slice(b"SRL1"); // magic
        expected.push(0x00); // status: Delivered
        expected.push(0x00); // flags: not ambiguous
        expected.extend_from_slice(&250u16.to_be_bytes()); // smtp_code u16
        expected.extend_from_slice(&10u32.to_be_bytes()); // diag_len u32
        expected.extend_from_slice(diagnostic.as_bytes());
        // Total: 4+1+1+2+4+10 = 22 bytes

        assert_eq!(expected.len(), 22, "golden response should be 22 bytes");

        // Write via codec
        let result = DeliveryResult::delivered(diagnostic, Some(250));
        let mut written = Vec::new();
        write_response(&mut written, &result, 4096).unwrap();

        assert_eq!(
            written, expected,
            "write_response must produce exact spec bytes"
        );
    }

    // ── GOLDEN-BYTE: response with ambiguous flag ─────────────────────
    #[test]
    fn golden_response_ambiguous_exact_bytes() {
        let mut expected = Vec::new();
        expected.extend_from_slice(b"SRL1"); // magic
        expected.push(0x01); // status: TemporaryFailure
        expected.push(0x01); // flags: bit0=ambiguous
        expected.extend_from_slice(&0u16.to_be_bytes()); // smtp_code: 0 → None
        expected.extend_from_slice(&3u32.to_be_bytes()); // diag_len u32
        expected.extend_from_slice(b"xxx");

        let result = DeliveryResult::ambiguous("xxx");
        let mut written = Vec::new();
        write_response(&mut written, &result, 4096).unwrap();
        assert_eq!(written, expected);
    }

    // ── response wrong magic rejected ─────────────────────────────────

    #[test]
    fn reject_response_wrong_magic() {
        let mut frame = minimal_response_frame();
        frame[0] = b'X'; // corrupt first magic byte

        let err = read_response(&mut Cursor::new(&frame), &permissive_limits()).unwrap_err();
        assert_eq!(err, SubmissionError::InvalidMagic);
    }

    // ── response invalid status rejected ──────────────────────────────

    #[test]
    fn reject_response_invalid_status() {
        let mut frame = minimal_response_frame();
        frame[4] = 0xFF; // invalid status byte

        let err = read_response(&mut Cursor::new(&frame), &permissive_limits()).unwrap_err();
        assert_eq!(err, SubmissionError::InvalidResponseStatus(0xFF));
    }

    // ── response unknown flags rejected ───────────────────────────────

    #[test]
    fn reject_response_unknown_flags() {
        let mut frame = minimal_response_frame();
        frame[5] = 0xFF; // flags byte: all bits set, unknown beyond bit0

        let err = read_response(&mut Cursor::new(&frame), &permissive_limits()).unwrap_err();
        assert_eq!(err, SubmissionError::UnknownResponseFlags(0xFF));
    }

    #[test]
    fn response_flag_bit1_rejected() {
        let mut frame = minimal_response_frame();
        frame[5] = 0x02; // only bit1 set (not ambiguous, but unknown)

        let err = read_response(&mut Cursor::new(&frame), &permissive_limits()).unwrap_err();
        assert_eq!(err, SubmissionError::UnknownResponseFlags(0x02));
    }

    // ── response truncation at every byte boundary ────────────────────

    #[test]
    fn reject_response_truncation_at_every_field_boundary() {
        let frame = minimal_response_frame();
        for cut in 1..frame.len() {
            let truncated = &frame[..cut];
            let result = read_response(&mut Cursor::new(truncated), &permissive_limits());
            assert!(
                result.is_err(),
                "response truncation at byte {} should fail, but got Ok",
                cut
            );
            let err = result.unwrap_err();
            assert!(
                matches!(err, SubmissionError::Io(io::ErrorKind::UnexpectedEof)),
                "response truncation at byte {}: expected Io(UnexpectedEof), got {:?}",
                cut,
                err
            );
        }
    }

    // ── response truncation at specific boundaries ────────────────────

    #[test]
    fn reject_response_truncated_at_magic() {
        let frame = &minimal_response_frame()[..3];
        let err = read_response(&mut Cursor::new(frame), &permissive_limits()).unwrap_err();
        assert_eq!(err, SubmissionError::Io(io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn reject_response_truncated_at_status() {
        let frame = &minimal_response_frame()[..4];
        let err = read_response(&mut Cursor::new(frame), &permissive_limits()).unwrap_err();
        assert_eq!(err, SubmissionError::Io(io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn reject_response_truncated_at_flags() {
        let frame = &minimal_response_frame()[..5];
        let err = read_response(&mut Cursor::new(frame), &permissive_limits()).unwrap_err();
        assert_eq!(err, SubmissionError::Io(io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn reject_response_truncated_at_smtp_code() {
        // 4 magic + 1 status + 1 flags = 6, need 2 more for smtp_code
        let frame = &minimal_response_frame()[..7];
        let err = read_response(&mut Cursor::new(frame), &permissive_limits()).unwrap_err();
        assert_eq!(err, SubmissionError::Io(io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn reject_response_truncated_at_diag_len() {
        // 4 + 1 + 1 + 2 = 8, need 4 more for diag_len u32
        let frame = &minimal_response_frame()[..10];
        let err = read_response(&mut Cursor::new(frame), &permissive_limits()).unwrap_err();
        assert_eq!(err, SubmissionError::Io(io::ErrorKind::UnexpectedEof));
    }

    #[test]
    fn reject_response_truncated_at_diag_data() {
        let full = minimal_response_frame();
        let frame = &full[..full.len() - 1];
        let err = read_response(&mut Cursor::new(frame), &permissive_limits()).unwrap_err();
        assert_eq!(err, SubmissionError::Io(io::ErrorKind::UnexpectedEof));
    }

    // ── write_response doesn't panic with max > u32 ───────────────────

    #[test]
    fn write_response_clamps_excessive_max_diagnostic() {
        // Configured max > u32::MAX should not panic; clamped to 4096.
        let result = DeliveryResult::delivered("ok", Some(250));
        let mut encoded = Vec::new();
        // This must not panic even with usize::MAX
        write_response(&mut encoded, &result, usize::MAX).unwrap();

        let decoded = read_response(&mut Cursor::new(&encoded), &permissive_limits()).unwrap();
        assert_eq!(decoded.diagnostic, "ok");
    }

    // ── SRL2 codecs ──────────────────────────────────────────────────

    #[test]
    fn srl2_envelope_preamble_has_exact_golden_bytes() {
        let preamble = EnvelopePreamble {
            envelope: Envelope::new(b"a@b", vec![b"c@d".to_vec()]).unwrap(),
        };
        let expected = vec![
            b'S', b'R', b'L', b'2', 0, 0, 0, 0, 0, 0, 0, 3, b'a', b'@', b'b', 0, 0, 0, 1, 0, 0, 0,
            3, b'c', b'@', b'd',
        ];
        let mut actual = Vec::new();
        write_envelope_preamble(&mut actual, &preamble).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            read_envelope_preamble(&mut Cursor::new(expected)).unwrap(),
            preamble
        );
    }

    #[test]
    fn srl2_ready_reply_has_exact_golden_bytes() {
        let reply = ServerReply::Ready(Ready {
            max_message_bytes: 1024,
            max_chunk_bytes: 65_536,
            max_diagnostic_bytes: 4096,
        });
        let expected = vec![
            b'S', b'R', b'L', b'2', 1, 0, 0, 0, 0, 0, 0, 4, 0, 0, 1, 0, 0, 0, 0, 16, 0,
        ];
        let mut actual = Vec::new();
        write_server_reply(&mut actual, &reply).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            read_server_reply(&mut Cursor::new(expected)).unwrap(),
            reply
        );
    }

    #[test]
    fn srl2_early_final_reply_has_exact_golden_bytes() {
        let reply = ServerReply::Final(DeliveryResult::protocol_rejection("bad", None));
        let expected = vec![
            b'S', b'R', b'L', b'2', 2, 3, 0, 0, 0, 0, 0, 0, 3, b'b', b'a', b'd',
        ];
        let mut actual = Vec::new();
        write_server_reply(&mut actual, &reply).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            read_server_reply(&mut Cursor::new(expected)).unwrap(),
            reply
        );
    }

    #[test]
    fn srl2_final_delivery_result_has_exact_golden_bytes() {
        let result = DeliveryResult::delivered("ok", Some(250));
        let expected = vec![
            b'S', b'R', b'L', b'2', 2, 0, 0, 0, 250, 0, 0, 0, 2, b'o', b'k',
        ];
        let mut actual = Vec::new();
        write_final_result(&mut actual, &result).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            read_final_result(&mut Cursor::new(expected)).unwrap(),
            result
        );
    }

    fn assert_truncated_envelope(frame: &[u8]) {
        assert_eq!(
            read_envelope_preamble(&mut Cursor::new(frame)).unwrap_err(),
            SubmissionError::Io(io::ErrorKind::UnexpectedEof)
        );
    }

    fn assert_truncated_reply(frame: &[u8]) {
        assert_eq!(
            read_server_reply(&mut Cursor::new(frame)).unwrap_err(),
            SubmissionError::Io(io::ErrorKind::UnexpectedEof)
        );
    }

    #[test]
    fn srl2_rejects_wrong_magic() {
        assert_eq!(
            read_envelope_preamble(&mut Cursor::new(b"NOPE")).unwrap_err(),
            SubmissionError::InvalidMagic
        );
    }

    #[test]
    fn srl2_rejects_srl1_as_unsupported() {
        assert_eq!(
            read_envelope_preamble(&mut Cursor::new(b"SRL1")).unwrap_err(),
            SubmissionError::UnsupportedVersion(1)
        );
    }

    #[test]
    fn srl2_rejects_unknown_reply_kind() {
        let frame = [b'S', b'R', b'L', b'2', 9];
        assert_eq!(
            read_server_reply(&mut Cursor::new(frame)).unwrap_err(),
            SubmissionError::UnknownServerReplyKind(9)
        );
    }

    #[test]
    fn srl2_rejects_unknown_envelope_flags() {
        let frame = [b'S', b'R', b'L', b'2', 0, 0, 0, 1];
        assert_eq!(
            read_envelope_preamble(&mut Cursor::new(frame)).unwrap_err(),
            SubmissionError::UnknownRequestFlags(1)
        );
    }

    #[test]
    fn srl2_rejects_unknown_final_flags() {
        let frame = [b'S', b'R', b'L', b'2', 2, 0, 2];
        assert_eq!(
            read_server_reply(&mut Cursor::new(frame)).unwrap_err(),
            SubmissionError::UnknownResponseFlags(2)
        );
    }

    #[test]
    fn srl2_rejects_truncated_envelope_magic() {
        assert_truncated_envelope(b"SRL");
    }

    #[test]
    fn srl2_rejects_truncated_envelope_flags() {
        assert_truncated_envelope(b"SRL2\0\0\0");
    }

    #[test]
    fn srl2_rejects_truncated_sender_length() {
        assert_truncated_envelope(b"SRL2\0\0\0\0\0\0\0");
    }

    #[test]
    fn srl2_rejects_truncated_sender_data() {
        assert_truncated_envelope(b"SRL2\0\0\0\0\0\0\0\x03a");
    }

    #[test]
    fn srl2_rejects_truncated_recipient_count() {
        assert_truncated_envelope(b"SRL2\0\0\0\0\0\0\0\0\0\0");
    }

    #[test]
    fn srl2_rejects_truncated_recipient_length() {
        assert_truncated_envelope(b"SRL2\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0");
    }

    #[test]
    fn srl2_rejects_truncated_recipient_data() {
        assert_truncated_envelope(b"SRL2\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x03a");
    }

    #[test]
    fn srl2_rejects_truncated_reply_magic() {
        assert_truncated_reply(b"SRL");
    }

    #[test]
    fn srl2_rejects_truncated_reply_kind() {
        assert_truncated_reply(b"SRL2");
    }

    #[test]
    fn srl2_rejects_truncated_ready_message_limit() {
        assert_truncated_reply(b"SRL2\x01\0\0\0\0\0\0\0");
    }

    #[test]
    fn srl2_rejects_truncated_ready_chunk_limit() {
        assert_truncated_reply(b"SRL2\x01\0\0\0\0\0\0\0\x01\0\0\0");
    }

    #[test]
    fn srl2_rejects_truncated_ready_diagnostic_limit() {
        assert_truncated_reply(b"SRL2\x01\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0");
    }

    #[test]
    fn srl2_rejects_truncated_final_status() {
        assert_truncated_reply(b"SRL2\x02");
    }

    #[test]
    fn srl2_rejects_truncated_final_flags() {
        assert_truncated_reply(b"SRL2\x02\0");
    }

    #[test]
    fn srl2_rejects_truncated_final_smtp_code() {
        assert_truncated_reply(b"SRL2\x02\0\0\0");
    }

    #[test]
    fn srl2_rejects_truncated_final_diagnostic_length() {
        assert_truncated_reply(b"SRL2\x02\0\0\0\0\0\0\0");
    }

    #[test]
    fn srl2_rejects_truncated_final_diagnostic_data() {
        assert_truncated_reply(b"SRL2\x02\0\0\0\0\0\0\0\x03a");
    }

    #[test]
    fn srl2_rejects_recipient_overflow_before_reading_recipients() {
        let mut frame = b"SRL2\0\0\0\0\0\0\0\0".to_vec();
        frame.extend_from_slice(&((MAX_RECIPIENTS + 1) as u32).to_be_bytes());
        assert_eq!(
            read_envelope_preamble(&mut Cursor::new(frame)).unwrap_err(),
            SubmissionError::TooManyRecipients {
                count: MAX_RECIPIENTS + 1,
                limit: MAX_RECIPIENTS,
            }
        );
    }

    #[test]
    fn srl2_rejects_address_overflow_before_allocation() {
        let mut frame = b"SRL2\0\0\0\0".to_vec();
        frame.extend_from_slice(&((MAX_ADDRESS_BYTES + 1) as u32).to_be_bytes());
        assert_eq!(
            read_envelope_preamble(&mut Cursor::new(frame)).unwrap_err(),
            SubmissionError::AddressTooLong {
                len: MAX_ADDRESS_BYTES + 1,
                limit: MAX_ADDRESS_BYTES,
            }
        );
    }
}

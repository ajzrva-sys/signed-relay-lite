//! Strict bounded SRL2 submission binary codecs.
//!
//! Wire format is independent of sockets — reads and writes go through
//! `std::io::Read` and `std::io::Write`, making the codecs testable
//! with `std::io::Cursor`.

use std::io::{self, Read, Write};

use super::budget::{MemoryBudget, MemoryReservation};
use crate::relay::{DeliveryResult, DeliveryStatus, Envelope, EnvelopeError};

// ── Protocol constants ────────────────────────────────────────────────

/// Legacy magic retained only to report an explicit incompatibility.
const SRL1_MAGIC: &[u8; 4] = b"SRL1";

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
    /// A streamed chunk exceeds the fixed or advertised chunk limit.
    ChunkTooLarge { len: usize, limit: usize },
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

impl SubmissionError {
    /// Whether a pre-delivery failure should invite a later retry.
    pub fn is_temporary(&self) -> bool {
        matches!(self, Self::BudgetExhausted { .. })
    }

    /// Pre-delivery codec failures occur before relay delivery can be attempted.
    pub fn is_ambiguous(&self) -> bool {
        false
    }
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

/// Bytes decoded from an SRL2 chunk stream together with their budget owner.
#[derive(Debug)]
pub struct RetainedMessage {
    bytes: Vec<u8>,
    reservation: MemoryReservation,
}

impl RetainedMessage {
    /// Borrow the retained message bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Bytes charged to the global retained-message budget.
    pub fn reserved_bytes(&self) -> usize {
        self.reservation.bytes()
    }

    /// Take ownership while preserving the reservation guard.
    pub fn into_parts(self) -> (Vec<u8>, MemoryReservation) {
        (self.bytes, self.reservation)
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

/// Write a big-endian `u16`.
fn write_u16<W: Write>(w: &mut W, v: u16) -> Result<(), io::Error> {
    w.write_all(&v.to_be_bytes())
}

/// Write a big-endian `u32`.
fn write_u32<W: Write>(w: &mut W, v: u32) -> Result<(), io::Error> {
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
    if magic == *SRL1_MAGIC {
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
            w.write_all(&ready.max_message_bytes.to_be_bytes())?;
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

// ── SRL2 chunk stream ────────────────────────────────────────────────

/// Decode one terminated SRL2 message chunk stream.
///
/// Each chunk is `[length: u32 BE][payload]`; a zero length terminates the
/// stream. The length is checked against both the advertised chunk maximum
/// and [`MAX_CHUNK_BYTES`] before any payload allocation or read. Retained
/// bytes are charged incrementally before being appended and the returned
/// value keeps that reservation alive.
///
/// The fixed [`MAX_CHUNK_BYTES`] scratch buffer is temporary handler memory,
/// separate from retained-message accounting. A daemon therefore bounds this
/// temporary memory as `MAX_CHUNK_BYTES * max_concurrent_submissions`.
pub fn read_chunk_stream<R: Read>(
    r: &mut R,
    max_message_bytes: u64,
    max_chunk_bytes: u32,
    budget: &MemoryBudget,
) -> Result<RetainedMessage, SubmissionError> {
    let effective_chunk_max = usize::try_from(max_chunk_bytes)
        .unwrap_or(usize::MAX)
        .min(MAX_CHUNK_BYTES);
    let mut bytes = Vec::new();
    let mut reservation = budget
        .try_reserve(0)
        .expect("a zero-byte reservation must always fit");
    let mut scratch = [0_u8; MAX_CHUNK_BYTES];
    let mut cumulative = 0_u64;

    loop {
        let chunk_len_raw = read_u32(r)?;
        if chunk_len_raw == 0 {
            return Ok(RetainedMessage { bytes, reservation });
        }
        let chunk_len =
            usize::try_from(chunk_len_raw).map_err(|_| SubmissionError::ChunkTooLarge {
                len: chunk_len_raw as usize,
                limit: effective_chunk_max,
            })?;
        if chunk_len > effective_chunk_max {
            return Err(SubmissionError::ChunkTooLarge {
                len: chunk_len,
                limit: effective_chunk_max,
            });
        }

        cumulative = cumulative.checked_add(u64::from(chunk_len_raw)).ok_or(
            SubmissionError::MessageTooLarge {
                len: u64::MAX,
                limit: max_message_bytes,
            },
        )?;
        if cumulative > max_message_bytes {
            return Err(SubmissionError::MessageTooLarge {
                len: cumulative,
                limit: max_message_bytes,
            });
        }
        let cumulative_usize =
            usize::try_from(cumulative).map_err(|_| SubmissionError::MessageTooLarge {
                len: cumulative,
                limit: max_message_bytes,
            })?;
        if !reservation.try_grow(chunk_len) {
            return Err(SubmissionError::BudgetExhausted {
                requested: cumulative_usize,
                capacity: budget.capacity(),
            });
        }

        r.read_exact(&mut scratch[..chunk_len])?;
        bytes.extend_from_slice(&scratch[..chunk_len]);
    }
}

/// Encode bytes as a terminated SRL2 message chunk stream.
pub fn write_chunk_stream<W: Write>(
    w: &mut W,
    bytes: &[u8],
    max_chunk_bytes: u32,
) -> Result<(), io::Error> {
    let chunk_max = usize::try_from(max_chunk_bytes)
        .unwrap_or(usize::MAX)
        .min(MAX_CHUNK_BYTES);
    if chunk_max == 0 && !bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "non-empty chunk stream requires a positive chunk maximum",
        ));
    }
    for chunk in bytes.chunks(chunk_max.max(1)) {
        write_u32(
            w,
            u32::try_from(chunk.len()).expect("bounded chunk exceeds u32"),
        )?;
        w.write_all(chunk)?;
    }
    write_u32(w, 0)
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

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

    fn chunk_wire(chunks: &[&[u8]]) -> Vec<u8> {
        let mut wire = Vec::new();
        for chunk in chunks {
            wire.extend_from_slice(&(chunk.len() as u32).to_be_bytes());
            wire.extend_from_slice(chunk);
        }
        wire.extend_from_slice(&0_u32.to_be_bytes());
        wire
    }

    #[test]
    fn chunk_stream_immediate_zero_terminator() {
        let budget = MemoryBudget::new(1);
        let retained =
            read_chunk_stream(&mut Cursor::new(0_u32.to_be_bytes()), 1, 1, &budget).unwrap();
        assert!(retained.bytes().is_empty());
        assert_eq!(retained.reserved_bytes(), 0);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn chunk_stream_exact_max_chunk_and_writer_round_trip() {
        let body = vec![b'x'; MAX_CHUNK_BYTES];
        let mut wire = Vec::new();
        write_chunk_stream(&mut wire, &body, MAX_CHUNK_BYTES as u32).unwrap();
        let budget = MemoryBudget::new(body.len());
        let retained = read_chunk_stream(
            &mut Cursor::new(wire),
            body.len() as u64,
            MAX_CHUNK_BYTES as u32,
            &budget,
        )
        .unwrap();
        assert_eq!(retained.bytes(), body);
        assert_eq!(budget.used(), MAX_CHUNK_BYTES);
    }

    #[test]
    fn chunk_stream_one_over_chunk_max_rejected_before_payload_read() {
        let mut wire = ((MAX_CHUNK_BYTES + 1) as u32).to_be_bytes().to_vec();
        wire.extend_from_slice(b"must-not-be-read");
        let mut reader = Cursor::new(wire);
        let budget = MemoryBudget::new(usize::MAX);
        assert_eq!(
            read_chunk_stream(&mut reader, u64::MAX, MAX_CHUNK_BYTES as u32, &budget).unwrap_err(),
            SubmissionError::ChunkTooLarge {
                len: MAX_CHUNK_BYTES + 1,
                limit: MAX_CHUNK_BYTES
            }
        );
        assert_eq!(reader.position(), 4);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn chunk_stream_cumulative_exact_message_max() {
        let wire = chunk_wire(&[b"abc", b"def"]);
        let budget = MemoryBudget::new(6);
        let retained = read_chunk_stream(&mut Cursor::new(wire), 6, 3, &budget).unwrap();
        assert_eq!(retained.bytes(), b"abcdef");
        assert_eq!(retained.reserved_bytes(), 6);
    }

    #[test]
    fn chunk_stream_cumulative_max_plus_one_uses_checked_arithmetic() {
        let mut wire = chunk_wire(&[b"abcd"]);
        wire.truncate(wire.len() - 4);
        wire.extend_from_slice(&1_u32.to_be_bytes());
        wire.push(b'e');
        let mut reader = Cursor::new(wire);
        let budget = MemoryBudget::new(5);
        assert_eq!(
            read_chunk_stream(&mut reader, 4, 4, &budget).unwrap_err(),
            SubmissionError::MessageTooLarge { len: 5, limit: 4 }
        );
        assert_eq!(reader.position(), 4 + 4 + 4);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn truncated_chunk_payload_releases_all_reservation() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&3_u32.to_be_bytes());
        wire.extend_from_slice(b"abc");
        wire.extend_from_slice(&3_u32.to_be_bytes());
        wire.push(b'd');
        let budget = MemoryBudget::new(6);
        assert_eq!(
            read_chunk_stream(&mut Cursor::new(wire), 6, 3, &budget).unwrap_err(),
            SubmissionError::Io(io::ErrorKind::UnexpectedEof)
        );
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn chunk_stream_budget_exhaustion_is_temporary_and_unambiguous() {
        let budget = MemoryBudget::new(2);
        let error =
            read_chunk_stream(&mut Cursor::new(chunk_wire(&[b"abc"])), 3, 3, &budget).unwrap_err();
        assert_eq!(
            error,
            SubmissionError::BudgetExhausted {
                requested: 3,
                capacity: 2
            }
        );
        assert!(error.is_temporary());
        assert!(!error.is_ambiguous());
    }

    #[test]
    fn malformed_chunk_stream_is_unambiguous() {
        let budget = MemoryBudget::new(8);
        let error = read_chunk_stream(&mut Cursor::new([0_u8; 2]), 8, 4, &budget).unwrap_err();
        assert!(!error.is_ambiguous());
        assert!(!error.is_temporary());
    }

    #[test]
    fn oversized_chunk_stream_is_unambiguous() {
        let budget = MemoryBudget::new(8);
        let error =
            read_chunk_stream(&mut Cursor::new(5_u32.to_be_bytes()), 8, 4, &budget).unwrap_err();
        assert!(!error.is_ambiguous());
        assert!(!error.is_temporary());
    }
}

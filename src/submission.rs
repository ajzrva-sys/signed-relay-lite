//! Strict bounded SRL1 request/response binary codecs.
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

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::SigningConfig;
use crate::message::{Limits as MessageLimits, Message};
use crate::relay::{
    DeliveryJob, DeliveryResult, DeliveryStatus, Envelope, EnvelopeError, RelayPool,
};

// ── Protocol constants ────────────────────────────────────────────────

/// Protocol magic bytes.
const MAGIC: &[u8; 4] = b"SRL1";

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

/// Default maximum message size from the approved plan (25 MiB).
const DEFAULT_MAX_MESSAGE_BYTES: u64 = 26_214_400;

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
    /// Generous defaults for testing / development.
    pub fn permissive() -> Self {
        Self {
            max_recipients: 100,
            max_address_bytes: 254,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            max_diagnostic_bytes: 4096,
        }
    }
}

// ── Errors ────────────────────────────────────────────────────────────

/// Errors produced during submission codec operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmissionError {
    /// Wire magic is not `SRL1`.
    InvalidMagic,
    /// Request flags contain unknown bits.
    UnknownRequestFlags(u32),
    /// Response flags contain unknown bits.
    UnknownResponseFlags(u8),
    /// Response status byte is not a recognized variant.
    InvalidResponseStatus(u8),
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

// ── Memory budget ──────────────────────────────────────────────────

/// RAII guard that holds `bytes` reserved from a [`MemoryBudget`].
///
/// On drop the reserved bytes are returned to the budget. The guard
/// is *not* cloneable — moving it transfers ownership of the
/// reservation; cloning would cause a double-release.
pub struct MemoryReservation {
    inner: Arc<Mutex<usize>>,
    bytes: usize,
}

impl std::fmt::Debug for MemoryReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryReservation")
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

impl Drop for MemoryReservation {
    fn drop(&mut self) {
        let mut used = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *used = used.saturating_sub(self.bytes);
    }
}

/// A global, thread-safe memory budget for retained message payloads.
///
/// The budget bounds the total bytes of in-flight messages regardless
/// of connection count. It is backed by `Arc<Mutex<usize>>` so
/// reservations can be shared across threads.
#[derive(Clone, Debug)]
pub struct MemoryBudget {
    inner: Arc<Mutex<usize>>,
    capacity: usize,
}

impl MemoryBudget {
    /// Create a new budget allowing up to `capacity` bytes.
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(0)),
            capacity,
        }
    }

    /// Try to reserve `bytes` from the budget.
    ///
    /// Returns `Some(MemoryReservation)` on success, or `None` if the
    /// reservation would exceed capacity **or** would cause a
    /// checked-add overflow (defending against `usize::MAX` attacks).
    pub fn try_reserve(&self, bytes: usize) -> Option<MemoryReservation> {
        let mut used = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let new_total = used.checked_add(bytes)?;
        if new_total > self.capacity {
            return None;
        }
        *used = new_total;
        Some(MemoryReservation {
            inner: Arc::clone(&self.inner),
            bytes,
        })
    }

    /// Current bytes in use (snapshot; may change immediately after).
    pub fn used(&self) -> usize {
        *self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Total capacity of this budget.
    pub fn capacity(&self) -> usize {
        self.capacity
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
/// `max_diagnostic_bytes` is clamped to `min(4096, u32::MAX)` to prevent
/// panic when the configured limit exceeds `u32::MAX`. The truncation
/// always lands on a UTF-8 character boundary.
pub fn write_response<W: Write>(
    w: &mut W,
    result: &DeliveryResult,
    max_diagnostic_bytes: usize,
) -> Result<(), io::Error> {
    // Clamp max_diagnostic_bytes to u32::MAX, then to 4096 per plan.
    let effective_max = max_diagnostic_bytes.min(u32::MAX as usize).min(4096);

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

// ── Unix submission server ───────────────────────────────────────────

/// Synchronous, bounded SRL1 server on a Unix-domain socket.
pub struct SubmissionServer {
    listener: UnixListener,
    path: PathBuf,
    created: SocketIdentity,
    timeout: Duration,
    slots: Arc<HandlerSlots>,
    submission_limits: Arc<SubmissionLimits>,
    message_limits: Arc<MessageLimits>,
    budget: MemoryBudget,
    signing: SigningConfig,
    relay: Arc<RelayPool>,
    shutdown: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketIdentity {
    dev: u64,
    ino: u64,
}

impl SocketIdentity {
    fn from(metadata: &fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }
}

#[derive(Debug)]
struct HandlerSlots {
    active: Mutex<usize>,
    changed: Condvar,
    maximum: usize,
}

struct HandlerSlot {
    slots: Arc<HandlerSlots>,
}

impl Drop for HandlerSlot {
    fn drop(&mut self) {
        let mut active = self
            .slots
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *active = active.saturating_sub(1);
        self.slots.changed.notify_one();
    }
}

impl HandlerSlots {
    fn reserve(self: &Arc<Self>, shutdown: &AtomicBool) -> Option<HandlerSlot> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *active >= self.maximum {
            if shutdown.load(Ordering::Acquire) {
                return None;
            }
            let waited = self.changed.wait_timeout(active, Duration::from_millis(25));
            active = match waited {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
        if shutdown.load(Ordering::Acquire) {
            return None;
        }
        *active += 1;
        Some(HandlerSlot {
            slots: Arc::clone(self),
        })
    }
}

impl SubmissionServer {
    /// Bind a server after applying conservative existing-path safety checks.
    #[allow(clippy::too_many_arguments)]
    pub fn bind(
        path: impl AsRef<Path>,
        socket_mode: u32,
        submission_timeout: Duration,
        max_active_handlers: usize,
        submission_limits: SubmissionLimits,
        message_limits: MessageLimits,
        budget: MemoryBudget,
        signing: SigningConfig,
        relay: Arc<RelayPool>,
        shutdown: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "submission socket path must be absolute",
            ));
        }
        if max_active_handlers == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max active handlers must be positive",
            ));
        }
        if submission_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "submission timeout must be positive",
            ));
        }
        if socket_mode == 0 || socket_mode & !0o777 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket mode contains non-permission bits",
            ));
        }

        prepare_socket_path(path)?;
        let listener = UnixListener::bind(path)?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "submission socket path changed during bind",
            ));
        }
        let created = SocketIdentity::from(&metadata);
        if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(socket_mode)) {
            remove_socket_if_identity(path, created);
            return Err(error);
        }
        if let Err(error) = listener.set_nonblocking(true) {
            remove_socket_if_identity(path, created);
            return Err(error);
        }
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket() || SocketIdentity::from(&metadata) != created {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "submission socket path changed during bind",
            ));
        }

        Ok(Self {
            listener,
            path: path.to_owned(),
            created,
            timeout: submission_timeout,
            slots: Arc::new(HandlerSlots {
                active: Mutex::new(0),
                changed: Condvar::new(),
                maximum: max_active_handlers,
            }),
            submission_limits: Arc::new(submission_limits),
            message_limits: Arc::new(message_limits),
            budget,
            signing,
            relay,
            shutdown,
        })
    }

    /// Accept connections until the shared shutdown flag is set.
    ///
    /// Every handler is joined before this method returns. Shutdown never
    /// substitutes a successful result: accepted handlers finish their actual
    /// parse, signing, and relay path (or its bounded timeout) before joining.
    pub fn run(&self) -> io::Result<()> {
        let mut handlers: Vec<JoinHandle<()>> = Vec::new();
        while !self.shutdown.load(Ordering::Acquire) {
            reap_finished_handlers(&mut handlers);
            match self.listener.accept() {
                Ok((stream, _)) => {
                    let Some(slot) = self.slots.reserve(&self.shutdown) else {
                        break;
                    };
                    let timeout = self.timeout;
                    let submission_limits = Arc::clone(&self.submission_limits);
                    let message_limits = Arc::clone(&self.message_limits);
                    let budget = self.budget.clone();
                    let signing = self.signing.clone();
                    let relay = Arc::clone(&self.relay);
                    let handler = thread::Builder::new()
                        .name("submission-handler".to_owned())
                        .spawn(move || {
                            let _slot = slot;
                            handle_stream(
                                stream,
                                timeout,
                                &submission_limits,
                                &message_limits,
                                &budget,
                                &signing,
                                &relay,
                            );
                        });
                    match handler {
                        Ok(handler) => handlers.push(handler),
                        Err(error) => {
                            join_handlers(handlers);
                            self.remove_created_socket();
                            return Err(error);
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    join_handlers(handlers);
                    self.remove_created_socket();
                    return Err(error);
                }
            }
        }
        join_handlers(handlers);
        self.remove_created_socket();
        Ok(())
    }

    fn remove_created_socket(&self) {
        remove_socket_if_identity(&self.path, self.created);
    }
}

impl Drop for SubmissionServer {
    fn drop(&mut self) {
        self.remove_created_socket();
    }
}

fn prepare_socket_path(path: &Path) -> io::Result<()> {
    let original = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !original.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "submission path exists and is not a socket",
        ));
    }
    // SAFETY: geteuid has no preconditions and does not access memory.
    let effective_uid = unsafe { libc::geteuid() };
    if original.uid() != effective_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "existing submission socket is owned by another user",
        ));
    }
    match UnixStream::connect(path) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "existing submission socket is active",
            ));
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) => {}
        Err(error) => return Err(error),
    }
    let current = fs::symlink_metadata(path)?;
    if !current.file_type().is_socket()
        || SocketIdentity::from(&current) != SocketIdentity::from(&original)
    {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "existing submission socket changed during stale check",
        ));
    }
    fs::remove_file(path)
}

fn remove_socket_if_identity(path: &Path, expected: SocketIdentity) {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_socket() && SocketIdentity::from(&metadata) == expected {
            let _ = fs::remove_file(path);
        }
    }
}

fn join_handlers(handlers: Vec<JoinHandle<()>>) {
    for handler in handlers {
        let _ = handler.join();
    }
}

fn reap_finished_handlers(handlers: &mut Vec<JoinHandle<()>>) {
    let mut index = 0;
    while index < handlers.len() {
        if handlers[index].is_finished() {
            let handler = handlers.swap_remove(index);
            let _ = handler.join();
        } else {
            index += 1;
        }
    }
}

fn handle_stream(
    mut stream: UnixStream,
    timeout: Duration,
    submission_limits: &SubmissionLimits,
    message_limits: &MessageLimits,
    budget: &MemoryBudget,
    signing: &SigningConfig,
    relay: &RelayPool,
) {
    let setup = stream
        .set_nonblocking(false)
        .and_then(|()| stream.set_read_timeout(Some(timeout)))
        .and_then(|()| stream.set_write_timeout(Some(timeout)));
    let result = if let Err(error) = setup {
        DeliveryResult::temporary_failure(format!("submission socket setup failed: {error}"), None)
    } else {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            process_request(
                &mut stream,
                submission_limits,
                message_limits,
                budget,
                signing,
                relay,
            )
        })) {
            Ok(result) => result,
            Err(_) => DeliveryResult::temporary_failure("submission handler panicked", None),
        }
    };
    let _ = write_response(&mut stream, &result, submission_limits.max_diagnostic_bytes)
        .and_then(|()| stream.flush());
}

fn process_request(
    stream: &mut UnixStream,
    submission_limits: &SubmissionLimits,
    message_limits: &MessageLimits,
    budget: &MemoryBudget,
    signing: &SigningConfig,
    relay: &RelayPool,
) -> DeliveryResult {
    let request = match read_request(stream, submission_limits, budget) {
        Ok(request) => request,
        Err(error) => {
            return DeliveryResult::protocol_rejection(
                format!("invalid submission frame: {error:?}"),
                None,
            );
        }
    };
    let (envelope, bytes, reservation) = request.into_parts();
    let limits = MessageLimits {
        max_headers: message_limits.max_headers,
        max_header_bytes: message_limits.max_header_bytes,
    };
    let message = match Message::parse(bytes, limits) {
        Ok(message) => message,
        Err(error) => {
            return DeliveryResult::protocol_rejection(format!("invalid message: {error:?}"), None);
        }
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let headers: Vec<_> = message.header_refs().collect();
    let signature = match crate::dkim::sign(signing, &headers, message.body_hash(), timestamp) {
        Ok(signature) => signature,
        Err(error) => return DeliveryResult::protocol_rejection(error, None),
    };
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let job = DeliveryJob {
        envelope,
        message,
        signature,
        result_tx,
    };
    if relay.enqueue(job).is_err() {
        return DeliveryResult::temporary_failure("relay worker queue disconnected", None);
    }
    let result = result_rx.recv().unwrap_or_else(|_| {
        DeliveryResult::temporary_failure("relay worker stopped without a result", None)
    });
    drop(reservation);
    result
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
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
        SubmissionLimits::permissive()
    }

    fn permissive_budget() -> MemoryBudget {
        MemoryBudget::new(usize::MAX / 2)
    }

    // ── MemoryBudget RED tests ────────────────────────────────────────

    #[test]
    fn reservation_is_released_on_drop() {
        let budget = MemoryBudget::new(100);
        let first = budget.try_reserve(80).unwrap();
        assert!(budget.try_reserve(21).is_none());
        drop(first);
        assert!(budget.try_reserve(100).is_some());
    }

    #[test]
    fn zero_reservation_succeeds() {
        let budget = MemoryBudget::new(100);
        let r = budget.try_reserve(0).unwrap();
        assert_eq!(budget.used(), 0);
        drop(r);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn exact_limit_succeeds() {
        let budget = MemoryBudget::new(100);
        let r = budget.try_reserve(100).unwrap();
        assert_eq!(budget.used(), 100);
        drop(r);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn one_over_rejected() {
        let budget = MemoryBudget::new(100);
        assert!(budget.try_reserve(101).is_none());
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn checked_add_overflow_rejected() {
        let budget = MemoryBudget::new(usize::MAX);
        let _r = budget.try_reserve(usize::MAX).unwrap();
        // second reservation would overflow usize — must return None, not panic
        assert!(budget.try_reserve(1).is_none());
    }

    #[test]
    fn poisoned_budget_lock_recovers_without_panicking() {
        use std::thread;

        let budget = MemoryBudget::new(100);
        let poisoned = budget.clone();
        let _ = thread::spawn(move || {
            let _guard = poisoned.inner.lock().unwrap();
            panic!("poison budget lock for recovery test");
        })
        .join();

        let reservation = budget.try_reserve(40).unwrap();
        assert_eq!(budget.used(), 40);
        drop(reservation);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn concurrent_reservations_never_exceed_budget() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let budget = MemoryBudget::new(1000);
        let barrier = Arc::new(Barrier::new(21));
        let handles: Vec<_> = (0..20)
            .map(|_| {
                let b = budget.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let reservation = b.try_reserve(100);
                    // Every thread attempts exactly once, then all wait while
                    // successful guards are still alive. This makes the test
                    // about simultaneous reservations rather than scheduling.
                    barrier.wait();
                    reservation
                })
            })
            .collect();
        barrier.wait();

        let mut successes = 0;
        for h in handles {
            if h.join().unwrap().is_some() {
                successes += 1;
            }
        }
        // At most 10 threads (10 × 100 = 1000) can hold a reservation.
        assert!(successes <= 10);
        // After all threads finish, all reservations are released.
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn drop_releases_exactly_once() {
        let budget = MemoryBudget::new(100);
        {
            let _r1 = budget.try_reserve(30).unwrap();
            let _r2 = budget.try_reserve(40).unwrap();
            assert_eq!(budget.used(), 70);
        }
        // Both dropped — back to zero.
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn moving_reservation_transfers_ownership() {
        let budget = MemoryBudget::new(100);
        let r = budget.try_reserve(50).unwrap();
        assert_eq!(budget.used(), 50);
        // Move into a function — original `r` is consumed.
        let moved = move_reservation(r);
        assert_eq!(budget.used(), 50); // still held
        drop(moved);
        assert_eq!(budget.used(), 0); // released exactly once
    }

    fn move_reservation(r: MemoryReservation) -> MemoryReservation {
        r // move, not copy
    }

    // ── Budget integration into read_request ─────────────────────────

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

    // ── default max_message_bytes ─────────────────────────────────────

    #[test]
    fn default_max_message_bytes_is_26214400() {
        let limits = SubmissionLimits::permissive();
        assert_eq!(limits.max_message_bytes, 26_214_400);
    }
}

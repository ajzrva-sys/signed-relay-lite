//! Delivery result types and bounded workers for signed-relay-lite.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use crate::message::Message;
use crate::smtp::SmtpConnection;

/// Classification of a delivery attempt outcome.
///
/// Immutable and Copy so results can be stored cheaply and compared by value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryStatus {
    /// Remote side accepted the message (250 after final dot).
    Delivered,
    /// Transient issue; safe to retry later (4xx or ambiguous).
    TemporaryFailure,
    /// Permanent refusal; retrying won't help (5xx).
    PermanentFailure,
    /// Remote rejected before DATA or at the protocol level (pre-delivery).
    ProtocolRejection,
}

/// Maximum diagnostic payload in bytes (UTF-8).
const MAX_DIAGNOSTIC_BYTES: usize = 4096;

/// Outcome of a single delivery attempt.
///
/// `diagnostic` is bounded to [`MAX_DIAGNOSTIC_BYTES`] bytes, truncated
/// at the nearest UTF-8 character boundary <= that limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryResult {
    pub status: DeliveryStatus,
    pub ambiguous: bool,
    pub smtp_code: Option<u16>,
    pub diagnostic: String,
}

/// A complete unit of work accepted by a [`RelayPool`].
pub struct DeliveryJob {
    pub envelope: Envelope,
    pub message: Message,
    pub signature: Vec<u8>,
    pub result_tx: SyncSender<DeliveryResult>,
}

/// A fixed set of SMTP delivery workers behind a bounded queue.
pub struct RelayPool {
    sender: Option<SyncSender<DeliveryJob>>,
    workers: Vec<JoinHandle<()>>,
}

/// The relay queue is no longer connected to any worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayPoolClosed;

impl RelayPool {
    /// Start `worker_count` workers and a queue holding at most `queue_capacity` jobs.
    ///
    /// The factory is called independently by each worker, and again after a
    /// panic invalidates that worker's connection. Both sizes must be positive.
    pub fn new<F>(worker_count: usize, queue_capacity: usize, factory: F) -> Self
    where
        F: Fn() -> SmtpConnection + Send + Sync + 'static,
    {
        assert!(worker_count > 0, "relay worker count must be positive");
        assert!(queue_capacity > 0, "relay queue capacity must be positive");

        let (sender, receiver) = mpsc::sync_channel::<DeliveryJob>(queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        let factory = Arc::new(factory);
        let workers = (0..worker_count)
            .map(|_| {
                let receiver = Arc::clone(&receiver);
                let factory = Arc::clone(&factory);
                thread::spawn(move || {
                    let mut connection = None;
                    loop {
                        let job = match receiver.lock() {
                            Ok(receiver) => receiver.recv(),
                            Err(_) => return,
                        };
                        let Ok(job) = job else { return };
                        let result = catch_unwind(AssertUnwindSafe(|| {
                            let connection = connection.get_or_insert_with(|| factory());
                            connection.deliver(
                                &job.envelope,
                                &job.signature,
                                job.message.as_bytes(),
                            )
                        }));
                        let result = match result {
                            Ok(result) => result,
                            Err(_) => {
                                connection = None;
                                DeliveryResult::temporary_failure(
                                    "SMTP delivery worker panicked",
                                    None,
                                )
                            }
                        };
                        let _ = job.result_tx.send(result);
                    }
                })
            })
            .collect();
        Self {
            sender: Some(sender),
            workers,
        }
    }

    /// Enqueue a job, blocking while the bounded queue is full.
    pub fn enqueue(&self, job: DeliveryJob) -> Result<(), RelayPoolClosed> {
        self.sender
            .as_ref()
            .expect("relay pool sender exists until drop")
            .send(job)
            .map_err(|_| RelayPoolClosed)
    }

    /// Enqueue and block until the worker reports the final SMTP result.
    pub fn submit(
        &self,
        envelope: Envelope,
        message: Message,
        signature: Vec<u8>,
    ) -> DeliveryResult {
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        let job = DeliveryJob {
            envelope,
            message,
            signature,
            result_tx,
        };
        if self.enqueue(job).is_err() {
            return DeliveryResult::temporary_failure("relay worker queue disconnected", None);
        }
        result_rx.recv().unwrap_or_else(|_| {
            DeliveryResult::temporary_failure("relay worker stopped without a result", None)
        })
    }
}

impl Drop for RelayPool {
    fn drop(&mut self) {
        self.sender.take();
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

// ── bounded truncation helper ──────────────────────────────────────────

/// Truncate `s` to at most `max` bytes at a UTF-8 character boundary.
/// Returns the (possibly shortened) owned `String`.
fn truncate_to_bytes(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    // Find the last char boundary at or before `max`.
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_owned()
}

impl DeliveryResult {
    /// A confirmed delivery with a 2xx SMTP response.
    pub fn delivered(diagnostic: impl Into<String>, smtp_code: Option<u16>) -> Self {
        Self {
            status: DeliveryStatus::Delivered,
            ambiguous: false,
            smtp_code,
            diagnostic: truncate_to_bytes(&diagnostic.into(), MAX_DIAGNOSTIC_BYTES),
        }
    }

    /// A temporary failure — will be retried.
    pub fn temporary_failure(diagnostic: impl Into<String>, smtp_code: Option<u16>) -> Self {
        Self {
            status: DeliveryStatus::TemporaryFailure,
            ambiguous: false,
            smtp_code,
            diagnostic: truncate_to_bytes(&diagnostic.into(), MAX_DIAGNOSTIC_BYTES),
        }
    }

    /// A permanent failure — the message will not be retried.
    pub fn permanent_failure(diagnostic: impl Into<String>, smtp_code: Option<u16>) -> Self {
        Self {
            status: DeliveryStatus::PermanentFailure,
            ambiguous: false,
            smtp_code,
            diagnostic: truncate_to_bytes(&diagnostic.into(), MAX_DIAGNOSTIC_BYTES),
        }
    }

    /// A protocol-level rejection (e.g. EHLO refused, TLS failed).
    pub fn protocol_rejection(diagnostic: impl Into<String>, smtp_code: Option<u16>) -> Self {
        Self {
            status: DeliveryStatus::ProtocolRejection,
            ambiguous: false,
            smtp_code,
            diagnostic: truncate_to_bytes(&diagnostic.into(), MAX_DIAGNOSTIC_BYTES),
        }
    }

    /// An ambiguous delivery — connection lost mid-session.
    ///
    /// **Always classified as `TemporaryFailure`** because the message may
    /// or may not have been delivered; retrying is the safe default.
    pub fn ambiguous(diagnostic: impl Into<String>) -> Self {
        Self {
            status: DeliveryStatus::TemporaryFailure,
            ambiguous: true,
            smtp_code: None,
            diagnostic: truncate_to_bytes(&diagnostic.into(), MAX_DIAGNOSTIC_BYTES),
        }
    }

    /// Returns `true` when the remote side explicitly accepted the message.
    pub fn is_accepted(&self) -> bool {
        matches!(self.status, DeliveryStatus::Delivered)
    }

    /// Returns `true` when a retry might succeed.
    pub fn is_retriable(&self) -> bool {
        self.ambiguous || matches!(self.status, DeliveryStatus::TemporaryFailure)
    }
}

/// Validated ASCII-only bare addr-spec for an outbound envelope.
///
/// The SMTP client adds `<` and `>` brackets; callers supply the bare
/// address (e.g. `user@example.com`).
///
/// Validation rules:
/// - ASCII printable only (0x20–0x7E), no control bytes, no CR/LF
/// - No spaces, no angle brackets (`<`, `>`)
/// - Maximum 254 bytes per address (RFC 5321)
/// - Sender may be empty (null reverse path `<>`)
/// - At least one recipient required
/// - Maximum 100 recipients
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Envelope {
    sender: Vec<u8>,
    recipients: Vec<Vec<u8>>,
}

/// Maximum bytes for a single envelope address (RFC 5321 §4.5.3.1).
const MAX_ADDRESS_BYTES: usize = 254;

/// Maximum number of recipients per envelope.
const MAX_RECIPIENTS: usize = 100;

/// Validation errors for [`Envelope`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvelopeError {
    /// Address contains a non-ASCII byte, control character, space, or angle bracket.
    InvalidCharacter { addr: Vec<u8>, byte: u8 },
    /// Address exceeds the 254-byte RFC 5321 limit.
    AddressTooLong(usize),
    /// Recipient list is empty.
    NoRecipients,
    /// A recipient address is empty (zero-length bare addr-spec).
    EmptyRecipientAddress,
    /// Too many recipients (exceeds [`MAX_RECIPIENTS`]).
    TooManyRecipients(usize),
}

impl Envelope {
    /// Build a validated envelope from bare addr-spec bytes.
    ///
    /// `sender` may be empty (null reverse path). Each address in
    /// `recipients` must pass the same validation rules.
    pub fn new(sender: &[u8], recipients: Vec<Vec<u8>>) -> Result<Self, EnvelopeError> {
        // Sender: empty is OK (null reverse path); otherwise validate.
        if !sender.is_empty() {
            validate_address(sender)?;
        }

        // Recipients: must be non-empty.
        if recipients.is_empty() {
            return Err(EnvelopeError::NoRecipients);
        }
        if recipients.len() > MAX_RECIPIENTS {
            return Err(EnvelopeError::TooManyRecipients(recipients.len()));
        }
        for rcpt in &recipients {
            if rcpt.is_empty() {
                return Err(EnvelopeError::EmptyRecipientAddress);
            }
            validate_address(rcpt)?;
        }

        Ok(Self {
            sender: sender.to_vec(),
            recipients,
        })
    }

    /// The (possibly empty) reverse-path.
    pub fn sender(&self) -> &[u8] {
        &self.sender
    }

    /// Borrow the validated recipient list.
    pub fn recipients(&self) -> &[Vec<u8>] {
        &self.recipients
    }
}

/// Validate a single bare addr-spec.
///
/// Rules: ASCII printable (0x20–0x7E) only, no control bytes (including
/// CR/LF), no spaces, no angle brackets, max [`MAX_ADDRESS_BYTES`] bytes.
fn validate_address(addr: &[u8]) -> Result<(), EnvelopeError> {
    if addr.len() > MAX_ADDRESS_BYTES {
        return Err(EnvelopeError::AddressTooLong(addr.len()));
    }
    for &b in addr {
        // Reject anything outside printable ASCII range 0x20..=0x7E.
        if !(0x20..=0x7E).contains(&b) {
            return Err(EnvelopeError::InvalidCharacter {
                addr: addr.to_vec(),
                byte: b,
            });
        }
        // Space (0x20) is in the printable range but forbidden in bare addr-spec.
        if b == b' ' {
            return Err(EnvelopeError::InvalidCharacter {
                addr: addr.to_vec(),
                byte: b,
            });
        }
        // Angle brackets are forbidden — caller must not add them.
        if b == b'<' || b == b'>' {
            return Err(EnvelopeError::InvalidCharacter {
                addr: addr.to_vec(),
                byte: b,
            });
        }
    }
    Ok(())
}

// ── tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- constructors ---------------------------------------------------

    #[test]
    fn ambiguous_delivery_is_always_temporary() {
        let result = DeliveryResult::ambiguous("connection closed after DATA");
        assert_eq!(result.status, DeliveryStatus::TemporaryFailure);
        assert!(result.ambiguous);
        assert_eq!(result.smtp_code, None);
    }

    #[test]
    fn delivered_constructor_sets_status_and_code() {
        let r = DeliveryResult::delivered("250 OK", Some(250));
        assert_eq!(r.status, DeliveryStatus::Delivered);
        assert!(!r.ambiguous);
        assert_eq!(r.smtp_code, Some(250));
        assert_eq!(r.diagnostic, "250 OK");
    }

    #[test]
    fn temporary_failure_constructor() {
        let r = DeliveryResult::temporary_failure("451 try again", Some(451));
        assert_eq!(r.status, DeliveryStatus::TemporaryFailure);
        assert!(!r.ambiguous);
        assert_eq!(r.smtp_code, Some(451));
    }

    #[test]
    fn permanent_failure_constructor() {
        let r = DeliveryResult::permanent_failure("550 user unknown", Some(550));
        assert_eq!(r.status, DeliveryStatus::PermanentFailure);
        assert!(!r.ambiguous);
        assert_eq!(r.smtp_code, Some(550));
    }

    #[test]
    fn protocol_rejection_constructor() {
        let r = DeliveryResult::protocol_rejection("TLS handshake failed", None);
        assert_eq!(r.status, DeliveryStatus::ProtocolRejection);
        assert!(!r.ambiguous);
        assert_eq!(r.smtp_code, None);
    }

    // -- classification -------------------------------------------------

    #[test]
    fn is_accepted_only_for_delivered() {
        assert!(DeliveryResult::delivered("ok", Some(250)).is_accepted());
        assert!(!DeliveryResult::temporary_failure("451", Some(451)).is_accepted());
        assert!(!DeliveryResult::permanent_failure("550", Some(550)).is_accepted());
        assert!(!DeliveryResult::protocol_rejection("tls fail", None).is_accepted());
        assert!(!DeliveryResult::ambiguous("mid-session").is_accepted());
    }

    #[test]
    fn is_retriable_for_temporary_and_ambiguous() {
        assert!(DeliveryResult::temporary_failure("451", Some(451)).is_retriable());
        assert!(DeliveryResult::ambiguous("mid-session").is_retriable());
        assert!(!DeliveryResult::delivered("ok", Some(250)).is_retriable());
        assert!(!DeliveryResult::permanent_failure("550", Some(550)).is_retriable());
        assert!(!DeliveryResult::protocol_rejection("tls fail", None).is_retriable());
    }

    // -- diagnostic bounding --------------------------------------------

    #[test]
    fn diagnostic_truncated_at_4096_bytes() {
        // Build a 6000-byte ASCII diagnostic.
        let long = "a".repeat(6000);
        let r = DeliveryResult::temporary_failure(&long, None);
        assert!(
            r.diagnostic.len() <= MAX_DIAGNOSTIC_BYTES,
            "diagnostic should be <= {} bytes, got {}",
            MAX_DIAGNOSTIC_BYTES,
            r.diagnostic.len()
        );
        assert_eq!(r.diagnostic.len(), MAX_DIAGNOSTIC_BYTES);
    }

    #[test]
    fn diagnostic_short_string_preserved() {
        let msg = "short and sweet";
        let r = DeliveryResult::delivered(msg, Some(250));
        assert_eq!(r.diagnostic, msg);
    }

    #[test]
    fn diagnostic_exactly_at_boundary_preserved() {
        let msg = "x".repeat(MAX_DIAGNOSTIC_BYTES);
        let r = DeliveryResult::permanent_failure(&msg, None);
        assert_eq!(r.diagnostic.len(), MAX_DIAGNOSTIC_BYTES);
    }

    #[test]
    fn diagnostic_adversarial_utf8_truncation_boundary() {
        // 3-byte UTF-8 character: U+20AC (euro sign, encoded as 3 bytes).
        // Fill with euro so we have 2048 chars * 3 bytes = 6144 bytes.
        let euro = "\u{20AC}";
        let count = 2048; // 2048 * 3 = 6144 bytes
        let long_euro = euro.repeat(count);
        assert_eq!(long_euro.len(), 6144, "setup sanity check");

        let r = DeliveryResult::temporary_failure(&long_euro, None);

        // Must not exceed the byte budget.
        assert!(
            r.diagnostic.len() <= MAX_DIAGNOSTIC_BYTES,
            "diagnostic bytes must be <= {}, got {}",
            MAX_DIAGNOSTIC_BYTES,
            r.diagnostic.len()
        );

        // Must be a valid UTF-8 string (no truncation mid-codepoint).
        assert!(
            std::str::from_utf8(r.diagnostic.as_bytes()).is_ok(),
            "truncated diagnostic must remain valid UTF-8"
        );

        // 4096 / 3 = 1365 remainder 1, so we expect exactly 1365 full euro chars.
        let expected_chars = MAX_DIAGNOSTIC_BYTES / 3; // 1365
        assert_eq!(r.diagnostic.chars().count(), expected_chars);
    }

    #[test]
    fn diagnostic_multibyte_4byte_boundary() {
        // 4-byte UTF-8 character: U+1F600 (grinning face, 4 bytes).
        let grin = "\u{1F600}";
        let count = 1500; // 1500 * 4 = 6000 bytes
        let long_grin = grin.repeat(count);
        assert_eq!(long_grin.len(), 6000);

        let r = DeliveryResult::permanent_failure(&long_grin, None);

        assert!(r.diagnostic.len() <= MAX_DIAGNOSTIC_BYTES);
        assert!(std::str::from_utf8(r.diagnostic.as_bytes()).is_ok());

        // 4096 / 4 = 1024 exact chars.
        let expected_chars = MAX_DIAGNOSTIC_BYTES / 4; // 1024
        assert_eq!(r.diagnostic.chars().count(), expected_chars);
    }

    // -- enum properties ------------------------------------------------

    #[test]
    fn delivery_status_is_copy() {
        let a = DeliveryStatus::Delivered;
        let b = a; // copy, not move
        assert_eq!(a, b); // `a` still usable
    }

    #[test]
    fn delivery_result_is_clone() {
        let a = DeliveryResult::delivered("ok", Some(250));
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- envelope validation --------------------------------------------

    #[test]
    fn envelope_rejects_command_injection() {
        assert!(Envelope::new(
            b"sender@example.com\r\nDATA",
            vec![b"recipient@example.net".to_vec()]
        )
        .is_err());
    }

    #[test]
    fn envelope_accepts_null_reverse_path() {
        assert!(Envelope::new(b"", vec![b"recipient@example.net".to_vec()]).is_ok());
    }

    #[test]
    fn envelope_rejects_empty_recipients() {
        assert!(Envelope::new(b"sender@example.com", vec![]).is_err());
        assert_eq!(
            Envelope::new(b"sender@example.com", vec![]).unwrap_err(),
            EnvelopeError::NoRecipients
        );
    }

    #[test]
    fn envelope_rejects_non_ascii_bytes() {
        // 0x80 is above printable ASCII range
        assert!(Envelope::new(
            b"sender@example.com",
            vec![b"rcpt@ex\x80ample.net".to_vec()]
        )
        .is_err());
        // Verify the error variant
        match Envelope::new(b"sender@example.com", vec![b"bad\x80".to_vec()]) {
            Err(EnvelopeError::InvalidCharacter { byte: 0x80, .. }) => {}
            other => panic!("expected InvalidCharacter(0x80), got {:?}", other),
        }
    }

    #[test]
    fn envelope_rejects_spaces_in_addresses() {
        assert!(Envelope::new(
            b"sender @example.com",
            vec![b"recipient@example.net".to_vec()]
        )
        .is_err());
        assert!(Envelope::new(
            b"sender@example.com",
            vec![b"recipient @example.net".to_vec()]
        )
        .is_err());
    }

    #[test]
    fn envelope_rejects_angle_brackets() {
        assert!(Envelope::new(
            b"<sender@example.com>",
            vec![b"recipient@example.net".to_vec()]
        )
        .is_err());
        assert!(Envelope::new(
            b"sender@example.com",
            vec![b"<recipient@example.net>".to_vec()]
        )
        .is_err());
    }

    #[test]
    fn envelope_rejects_control_bytes() {
        // NUL
        assert!(Envelope::new(
            b"sender@example.com",
            vec![b"rcpt@exam\x00ple.net".to_vec()]
        )
        .is_err());
        // CR
        assert!(
            Envelope::new(b"sender@example.com", vec![b"rcpt@example.com\r".to_vec()]).is_err()
        );
        // LF
        assert!(
            Envelope::new(b"sender@example.com", vec![b"rcpt@example.com\n".to_vec()]).is_err()
        );
        // TAB (0x09)
        assert!(
            Envelope::new(b"sender@example.com", vec![b"rcpt@exam\tple.net".to_vec()]).is_err()
        );
        // DEL (0x7F)
        assert!(Envelope::new(
            b"sender@example.com",
            vec![b"rcpt@exam\x7Fple.net".to_vec()]
        )
        .is_err());
    }

    #[test]
    fn envelope_rejects_address_over_254_bytes() {
        // 255 bytes → rejected
        let addr_255 = vec![b'a'; 255];
        assert!(
            Envelope::new(b"sender@example.com", vec![addr_255.clone()]).is_err(),
            "255-byte address should be rejected"
        );
    }

    #[test]
    fn envelope_accepts_address_at_254_bytes() {
        // Exactly 254 bytes → accepted
        let addr_254 = vec![b'a'; 254];
        assert!(
            Envelope::new(b"sender@example.com", vec![addr_254]).is_ok(),
            "254-byte address should be accepted"
        );
    }

    #[test]
    fn envelope_rejects_recipient_count_101() {
        let rcpts: Vec<Vec<u8>> = (0..101)
            .map(|i| format!("rcpt{}@example.net", i).into_bytes())
            .collect();
        assert!(
            Envelope::new(b"sender@example.com", rcpts).is_err(),
            "101 recipients should be rejected"
        );
    }

    #[test]
    fn envelope_accepts_recipient_count_100() {
        let rcpts: Vec<Vec<u8>> = (0..100)
            .map(|i| format!("rcpt{}@example.net", i).into_bytes())
            .collect();
        assert!(
            Envelope::new(b"sender@example.com", rcpts).is_ok(),
            "100 recipients should be accepted"
        );
    }

    #[test]
    fn envelope_rejects_empty_recipient_address() {
        // A recipient with an empty bare addr-spec must be rejected.
        let result = Envelope::new(b"sender@example.com", vec![b"".to_vec()]);
        assert!(result.is_err(), "empty recipient address must be rejected");
        assert_eq!(result.unwrap_err(), EnvelopeError::EmptyRecipientAddress,);
    }

    #[test]
    fn envelope_accessors_are_read_only() {
        let env = Envelope::new(
            b"sender@example.com",
            vec![b"rcpt1@example.net".to_vec(), b"rcpt2@example.net".to_vec()],
        )
        .unwrap();
        assert_eq!(env.sender(), b"sender@example.com");
        assert_eq!(env.recipients().len(), 2);
        assert_eq!(env.recipients()[0], b"rcpt1@example.net".as_slice());
        assert_eq!(env.recipients()[1], b"rcpt2@example.net".as_slice());
    }
}

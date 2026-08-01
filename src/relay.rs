//! Delivery result types for signed-relay-lite.

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
}

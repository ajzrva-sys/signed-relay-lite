use openssl::sha::Sha256;

/// Relaxed header canonicalization per RFC 6376 §3.4.2.
pub fn canonicalize_header(name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len() + value.len() + 3);
    out.extend(name.iter().map(u8::to_ascii_lowercase));
    out.push(b':');
    let value_start = out.len();
    let mut pending_wsp = false;
    let mut index = 0;
    while index < value.len() {
        match value[index] {
            b' ' | b'\t' => pending_wsp = true,
            b'\r' if value.get(index + 1) == Some(&b'\n') => {
                index += 1;
                pending_wsp = true;
            }
            b'\r' | b'\n' => pending_wsp = true,
            byte => {
                if pending_wsp && out.len() > value_start {
                    out.push(b' ');
                }
                pending_wsp = false;
                out.push(byte);
            }
        }
        index += 1;
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Relaxed body canonicalization per RFC 6376 §3.4.4.
///
/// Accumulates canonicalized output in a small internal buffer and flushes to
/// the SHA-256 hasher in chunks rather than one update per emitted byte.
pub struct BodyCanonicalizer {
    hasher: Sha256,
    pending_wsp: bool,
    pending_empty_lines: usize,
    line_has_content: bool,
    saw_cr: bool,
    /// Small buffer for batching canonicalized bytes before hashing.
    buf: Vec<u8>,
}

/// Flush buffer size — large enough to amortize OpenSSL calls, small enough
/// to keep memory bounded.
const FLUSH_THRESHOLD: usize = 512;

impl Default for BodyCanonicalizer {
    fn default() -> Self {
        Self {
            hasher: Sha256::new(),
            pending_wsp: false,
            pending_empty_lines: 0,
            line_has_content: false,
            saw_cr: false,
            buf: Vec::with_capacity(FLUSH_THRESHOLD),
        }
    }
}

impl BodyCanonicalizer {
    pub fn update(&mut self, data: &[u8]) {
        for &byte in data {
            if self.saw_cr {
                self.saw_cr = false;
                self.end_line();
                if byte == b'\n' {
                    continue;
                }
            }
            match byte {
                b'\r' => self.saw_cr = true,
                b'\n' => self.end_line(),
                b' ' | b'\t' => self.pending_wsp = true,
                _ => {
                    if !self.line_has_content && self.pending_empty_lines > 0 {
                        for _ in 0..self.pending_empty_lines {
                            self.emit(b"\r\n");
                        }
                        self.pending_empty_lines = 0;
                    }
                    if self.pending_wsp {
                        self.emit(b" ");
                        self.pending_wsp = false;
                    }
                    self.emit(&[byte]);
                    self.line_has_content = true;
                }
            }
        }
    }

    fn end_line(&mut self) {
        self.pending_wsp = false;
        if self.line_has_content {
            self.emit(b"\r\n");
            self.line_has_content = false;
        } else {
            self.pending_empty_lines = self.pending_empty_lines.saturating_add(1);
        }
    }

    /// Buffer a canonicalized byte slice, flushing to the hasher when the
    /// buffer reaches `FLUSH_THRESHOLD`.
    fn emit(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        if self.buf.len() >= FLUSH_THRESHOLD {
            self.flush_buf();
        }
    }

    fn flush_buf(&mut self) {
        if !self.buf.is_empty() {
            self.hasher.update(&self.buf);
            self.buf.clear();
        }
    }

    pub fn finish(mut self) -> [u8; 32] {
        if self.saw_cr {
            self.end_line();
        } else if self.line_has_content {
            self.pending_wsp = false;
            self.emit(b"\r\n");
        }
        self.flush_buf();
        self.hasher.finish()
    }
}

// ── DKIM signing ────────────────────────────────────────────────────

/// Borrowed reference to a message header.
///
/// `name` and `value` are borrowed slices from the retained message bytes.
/// This avoids cloning header values and is designed to work with message
/// header ranges in later tasks.
#[derive(Clone, Debug)]
pub struct HeaderRef<'a> {
    pub name: &'a [u8],
    pub value: &'a [u8],
}

impl HeaderRef<'_> {
    fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name.as_bytes())
    }
}

/// Headers that participate in DKIM signing (in order).
///
/// The `from` header is listed first; the remaining set covers the common
/// headers a relay can observe.  The list matches RFC 6376 recommended
/// practice.
const SIGNED_HEADERS: &[&str] = &[
    "from",
    "sender",
    "reply-to",
    "subject",
    "date",
    "message-id",
    "to",
    "cc",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
    "in-reply-to",
    "references",
];

/// Produce a relaxed/relaxed RSA-SHA256 DKIM signature.
///
/// `timestamp` is an explicit parameter so tests are deterministic;
/// production callers obtain it through a small clock boundary.
///
/// Returns the signature field value as a bounded `Vec<u8>`.
///
/// Errors:
/// - Zero or more than one `From` header present.
/// - `From` domain does not match the configured domain (case-insensitive).
/// - RSA-SHA256 signing failure.
pub fn sign(
    config: &crate::config::SigningConfig,
    headers: &[HeaderRef<'_>],
    body_hash: [u8; 32],
    timestamp: u64,
) -> Result<Vec<u8>, String> {
    // Exactly one From header required.
    let from_headers: Vec<&HeaderRef<'_>> = headers.iter().filter(|h| h.is("from")).collect();
    if from_headers.len() != 1 {
        return Err("message must contain exactly one From header".to_owned());
    }
    // From domain must match configured domain (case-insensitive).
    let from_domain = from_domain(from_headers[0].value)
        .ok_or_else(|| "cannot extract a single From domain".to_owned())?;
    if !from_domain.eq_ignore_ascii_case(&config.domain) {
        return Err(format!(
            "From domain {from_domain} does not match configured domain"
        ));
    }

    // Select the last occurrence of each signed header and build h= list.
    // From is oversigned: its tag appears twice in h= so that any added
    // From header invalidates the signature.
    let mut selected: Vec<&HeaderRef<'_>> = Vec::new();
    let mut h_names: Vec<&str> = Vec::new();
    for &name in SIGNED_HEADERS {
        if let Some(header) = headers.iter().rev().find(|h| h.is(name)) {
            selected.push(header);
            h_names.push(name);
        }
        if name == "from" {
            h_names.push("from"); // Oversign From.
        }
    }

    let body_hash_b64 = openssl::base64::encode_block(&body_hash);
    let unsigned_value = format!(
        "v=1; a=rsa-sha256; c=relaxed/relaxed; d={}; s={}; t={}; h={}; bh={}; b=",
        config.domain,
        config.selector,
        timestamp,
        h_names.join(":"),
        body_hash_b64
    );

    // Sign: canonicalized selected headers + canonicalized DKIM-Signature
    // header (with b= empty, trailing CRLF stripped per RFC 6376 §3.7).
    use openssl::hash::MessageDigest;
    use openssl::sign::Signer;

    let mut signer = Signer::new(MessageDigest::sha256(), config.key.as_ref())
        .map_err(|e| format!("cannot initialize RSA-SHA256 signer: {e}"))?;
    for header in &selected {
        signer
            .update(&canonicalize_header(header.name, header.value))
            .map_err(|e| format!("cannot hash header: {e}"))?;
    }
    signer
        .update(&canonicalize_signature_header(unsigned_value.as_bytes()))
        .map_err(|e| format!("cannot hash DKIM-Signature: {e}"))?;
    let signature = signer
        .sign_to_vec()
        .map_err(|e| format!("RSA-SHA256 signing failed: {e}"))?;

    let folded = fold_signature(&format!(
        "{unsigned_value}{}",
        openssl::base64::encode_block(&signature)
    ));
    Ok(folded.into_bytes())
}

/// Canonicalize the DKIM-Signature header itself for hash input.
///
/// RFC 6376 §3.7: the signature header is relaxed-canonicalized with `b=`
/// (empty value), and the trailing CRLF is stripped because it is the last
/// header in the hash input.
fn canonicalize_signature_header(value: &[u8]) -> Vec<u8> {
    let mut canonical = canonicalize_header(b"DKIM-Signature", value);
    canonical.truncate(canonical.len() - 2);
    canonical
}

/// Extract the domain portion from a From header value.
///
/// Handles angle-addr (`<user@domain>`), bare addr-spec, comments, quoted
/// strings. Returns `None` for multiple addresses, malformed input, or
/// unparseable domain.
fn from_domain(value: &[u8]) -> Option<String> {
    // Unfold legal header folding before validating quoted local parts.
    let mut unfolded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        let byte = value[index];
        if byte == b'\r' {
            if value.get(index + 1) != Some(&b'\n')
                || !matches!(value.get(index + 2), Some(b' ' | b'\t'))
            {
                return None;
            }
            index += 2;
            continue;
        }
        if byte.is_ascii_control() && byte != b'\t' {
            return None;
        }
        unfolded.push(byte);
        index += 1;
    }
    // Strip comments before looking for structural punctuation. Quoted strings
    // and quoted-pairs keep their bytes; punctuation inside them is not syntax.
    let mut mailbox = Vec::with_capacity(value.len());
    let mut quoted = false;
    let mut escaped = false;
    let mut comment_depth = 0usize;
    for &byte in &unfolded {
        if escaped {
            if comment_depth == 0 {
                mailbox.push(byte);
            }
            escaped = false;
            continue;
        }
        if comment_depth > 0 {
            match byte {
                b'\\' => escaped = true,
                b'(' => comment_depth = comment_depth.checked_add(1)?,
                b')' => comment_depth -= 1,
                _ => {}
            }
        } else if quoted {
            mailbox.push(byte);
            match byte {
                b'\\' => escaped = true,
                b'"' => quoted = false,
                _ => {}
            }
        } else {
            match byte {
                b'(' => {
                    comment_depth = 1;
                    mailbox.push(b' ');
                }
                b')' => return None,
                b'"' => {
                    quoted = true;
                    mailbox.push(byte);
                }
                _ => mailbox.push(byte),
            }
        }
    }
    if quoted || escaped || comment_depth != 0 {
        return None;
    }
    let text = std::str::from_utf8(&mailbox).ok()?.trim();
    let mut start = None;
    let mut end = None;
    for (index, byte) in text.bytes().enumerate() {
        if escaped {
            escaped = false;
        } else if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if !quoted {
            match byte {
                b'<' if start.is_none() => start = Some(index),
                b'>' if start.is_some() && end.is_none() => end = Some(index),
                b'<' | b'>' | b',' | b':' | b';' => return None,
                _ => {}
            }
        }
    }
    let address = match (start, end) {
        (Some(start), Some(end)) => {
            // Before angle-addr only a display phrase is allowed; after it only
            // whitespace/comments are allowed. Never discard a second address.
            if !display_name(&text.as_bytes()[..start]) || !text[end + 1..].trim().is_empty() {
                return None;
            }
            text[start + 1..end].trim()
        }
        (None, None) => text,
        _ => return None,
    };
    let mut separator = None;
    for (index, byte) in address.bytes().enumerate() {
        if escaped {
            escaped = false;
        } else if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if !quoted && byte == b'@' && separator.replace(index).is_some() {
            return None;
        }
    }
    let separator = separator?;
    let local = address[..separator].trim();
    let domain = address[separator + 1..].trim().trim_end_matches('.');
    if !local_part(local.as_bytes())
        || domain.is_empty()
        || !domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return None;
    }
    Some(domain.to_ascii_lowercase())
}

fn atom_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&byte)
}

fn local_part(value: &[u8]) -> bool {
    if value.first() == Some(&b'"') {
        let mut escaped = false;
        for (index, &byte) in value.iter().enumerate().skip(1) {
            if byte.is_ascii_control() && byte != b'\t' {
                return false;
            }
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                return index == value.len() - 1;
            }
        }
        false
    } else {
        !value.is_empty()
            && value
                .split(|&byte| byte == b'.')
                .all(|part| !part.is_empty() && part.iter().all(|&byte| atom_byte(byte)))
    }
}

fn display_name(value: &[u8]) -> bool {
    let mut quoted = false;
    let mut escaped = false;
    for &byte in value {
        if escaped {
            if byte.is_ascii_control() {
                return false;
            }
            escaped = false;
        } else if quoted {
            match byte {
                b'\\' => escaped = true,
                b'"' => quoted = false,
                _ if byte.is_ascii_control() && byte != b'\t' => return false,
                _ => {}
            }
        } else if byte == b'"' {
            quoted = true;
        } else if !atom_byte(byte) && byte != b'.' && !byte.is_ascii_whitespace() && byte.is_ascii()
        {
            return false;
        }
    }
    !quoted && !escaped
}

/// Fold a DKIM-Signature field value at 72-column boundaries.
///
/// Inserts `CRLF + TAB` before tokens that would exceed the limit,
/// ensuring the result remains valid per RFC 6376 §3.5.
fn fold_signature(value: &str) -> String {
    const LIMIT: usize = 72;
    let mut out = String::with_capacity(value.len() + value.len() / LIMIT * 3);
    let mut column = 0;
    for token in value.split(' ') {
        let needed = if column == 0 {
            token.len()
        } else {
            token.len() + 1
        };
        if column > 0 && column + needed > LIMIT {
            out.push_str("\r\n\t");
            column = 1;
        } else if column > 0 {
            out.push(' ');
            column += 1;
        }
        out.push_str(token);
        column += token.len();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SigningConfig;
    use openssl::base64;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::sign::Verifier;
    use std::sync::Arc;

    fn body(parts: &[&[u8]]) -> String {
        let mut c = BodyCanonicalizer::default();
        for part in parts {
            c.update(part);
        }
        base64::encode_block(&c.finish())
    }

    #[test]
    fn relaxed_header_preserves_whitespace_after_value_colons() {
        assert_eq!(
            canonicalize_header(b"Subject", b"  Re: \t hello: world  "),
            b"subject:Re: hello: world\r\n"
        );
        assert_eq!(
            canonicalize_header(b"Subject", b"Re:\r\n\t hello"),
            b"subject:Re: hello\r\n"
        );
    }

    #[test]
    fn from_parser_ignores_quoted_and_commented_punctuation() {
        for value in [
            b"alice@EXAMPLE.COM.".as_slice(),
            b"Alice (team) <alice@Example.COM>",
            b"alice (team) @ example.com",
            b"\"folded\r\n \tlocal\"@example.com",
            b"\"display <fake@other.test>\" <alice@example.com>",
            b"Alice (outer (nested) note <fake@other.test>) <alice@example.com>",
            b"Alice (escaped \\) <fake@other.test>) <alice@example.com>",
            b"\"a\\\"b@local\"@Example.COM.",
        ] {
            assert_eq!(
                from_domain(value).as_deref(),
                Some("example.com"),
                "{value:?}"
            );
        }
        assert_eq!(
            from_domain(b"attacker@other.test (note <user@example.com>)").as_deref(),
            Some("other.test")
        );
    }

    #[test]
    fn from_parser_rejects_extra_mailboxes_and_unbalanced_syntax() {
        for value in [
            b"a@example.com, b@example.com".as_slice(),
            b"a@example.com <b@example.com>",
            b"<a@example.com> <b@example.com>",
            b"<a@example.com> b@example.com",
            b"<a@example.com,b@example.com>",
            b"a@example.com b@example.com",
            b"<a@example.com>>",
            b"<<a@example.com>",
            b"a@example.com>",
            b"<a@example.com",
            b"a@example.com (unfinished",
            b"a@example.com )",
            b"\"unfinished <a@example.com>",
            b"\"quoted\" extra@example.com",
            b"a@@example.com",
            b"@example.com",
            b"a..b@example.com",
            b"\"bad\r\nlocal\"@example.com",
            b"\"bad\n local\"@example.com",
        ] {
            assert_eq!(from_domain(value), None, "{value:?}");
        }
    }

    #[test]
    fn relaxed_header() {
        assert_eq!(
            canonicalize_header(b"SUBJect", b"  hello\r\n\tworld  "),
            b"subject:hello world\r\n"
        );
    }

    #[test]
    fn rfc6376_relaxed_canonicalization_examples() {
        assert_eq!(canonicalize_header(b"A", b" X\r\n Y\tZ  "), b"a:X Y Z\r\n");
        assert_eq!(body(&[b" C \r\nD \t E\r\n\r\n"]), body(&[b" C\r\nD E\r\n"]));
    }

    #[test]
    fn body_accepts_non_utf8_bytes() {
        assert_eq!(
            body(&[&[0xff, b' ', b'\n']]),
            body(&[&[0xff, b'\r', b'\n']])
        );
    }

    #[test]
    fn relaxed_body_is_chunk_independent() {
        let expected = body(&[b" C \r\nD \t E\r\n\r\n".as_slice()]);
        assert_eq!(
            expected,
            body(&[b" C \r", b"\nD ", b"\t E\r\n", b"\r", b"\n"])
        );
    }

    #[test]
    fn relaxed_empty_body_hashes_no_bytes() {
        // RFC 6376 section 3.4.4 gives this SHA-256 hash for an empty body.
        const EMPTY_HASH: &str = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        for input in [b"".as_slice(), b"\r\n\r\n", b" \t", b" \t\r\n\t\r\n"] {
            assert_eq!(body(&[input]), EMPTY_HASH);
            for split in 0..=input.len() {
                assert_eq!(body(&[&input[..split], &input[split..]]), EMPTY_HASH);
            }
        }
    }

    #[test]
    fn keeps_leading_empty_lines_before_content() {
        assert_eq!(body(&[b"\r\nA"]), body(&[b"\r", b"\n", b"A"]));
        assert_ne!(body(&[b"\r\nA"]), body(&[b"A"]));
    }

    /// Chunk-boundary equivalence: splitting input at CR/LF and WSP
    /// boundaries must produce the same hash as feeding the whole thing.
    /// This guards the buffered-hash refactor.
    #[test]
    fn chunk_boundary_equivalence() {
        let full = body(&[b" C \r\nD \t E\r\n\r\n"]);

        // Split at CR boundary
        assert_eq!(full, body(&[b" C \r", b"\nD \t E\r\n\r\n"]));
        // Split at LF boundary
        assert_eq!(full, body(&[b" C \r\n", b"D \t E\r\n\r\n"]));
        // Split at WSP boundary
        assert_eq!(full, body(&[b" C \r\nD ", b"\t E\r\n\r\n"]));
        // Split at WSP within WSP run
        assert_eq!(full, body(&[b" C \r\nD \t", b" E\r\n\r\n"]));
        // Split at trailing empty-line boundary
        assert_eq!(full, body(&[b" C \r\nD \t E\r\n", b"\r\n"]));
        // Single-byte chunks
        let single_bytes: Vec<&[u8]> = b" C \r\nD \t E\r\n\r\n"
            .iter()
            .map(std::slice::from_ref)
            .collect();
        assert_eq!(full, body(&single_bytes));
    }

    // ── signing verification tests (RED phase) ──────────────────────

    /// Helper: generate an RSA keypair for tests.
    fn test_key() -> PKey<openssl::pkey::Private> {
        PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
    }

    /// Helper: build a SigningConfig for tests.
    fn test_config(key: &PKey<openssl::pkey::Private>) -> SigningConfig {
        SigningConfig {
            domain: "example.com".into(),
            selector: "test".into(),
            key: Arc::new(key.clone()),
        }
    }

    /// The primary signing verification test: a generated RSA key produces
    /// a signature that OpenSSL can verify, with From oversigning.
    #[test]
    fn generated_signature_verifies_and_oversigns_from() {
        let key = test_key();
        let config = test_config(&key);

        let from = HeaderRef {
            name: b"From",
            value: b"Alice <alice@example.com>",
        };
        let subject = HeaderRef {
            name: b"Subject",
            value: b"A  test",
        };
        let headers = [from, subject];

        let mut body_c = BodyCanonicalizer::default();
        body_c.update(b"hello\n");
        let body_hash = body_c.finish();
        let timestamp: u64 = 1_722_000_000;

        let value_bytes = sign(&config, &headers, body_hash, timestamp).unwrap();
        let value = String::from_utf8(value_bytes).unwrap();

        // From is oversigned: h= includes from:from:...
        assert!(
            value.contains("h=from:from:subject;"),
            "h= should oversign From, got: {value}"
        );

        // Extract and verify the b= signature.
        let b_start = value.find("b=").unwrap() + 2;
        let signature_text: String = value[b_start..]
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .map(char::from)
            .collect();
        let signature = base64::decode_block(&signature_text).unwrap();

        // Reconstruct the unsigned DKIM-Signature header value for verification.
        let unsigned = &value[..b_start];
        let canonicalized_sig = canonicalize_signature_header(unsigned.as_bytes());

        let mut verifier = Verifier::new(openssl::hash::MessageDigest::sha256(), &key).unwrap();
        verifier
            .update(&canonicalize_header(b"From", b"Alice <alice@example.com>"))
            .unwrap();
        verifier
            .update(&canonicalize_header(b"Subject", b"A  test"))
            .unwrap();
        verifier.update(&canonicalized_sig).unwrap();
        assert!(verifier.verify(&signature).unwrap());
    }

    /// Zero From headers must be rejected.
    #[test]
    fn rejects_missing_from_header() {
        let key = test_key();
        let config = test_config(&key);

        let subject = HeaderRef {
            name: b"Subject",
            value: b"test",
        };
        let headers = [subject];
        let body_hash = [0u8; 32];

        let err = sign(&config, &headers, body_hash, 1_722_000_000).unwrap_err();
        assert!(
            err.contains("exactly one From"),
            "error should mention exactly one From, got: {err}"
        );
    }

    /// Duplicate From headers must be rejected.
    #[test]
    fn rejects_duplicate_from_headers() {
        let key = test_key();
        let config = test_config(&key);

        let from1 = HeaderRef {
            name: b"From",
            value: b"alice@example.com",
        };
        let from2 = HeaderRef {
            name: b"from",
            value: b"bob@example.com",
        };
        let headers = [from1, from2];
        let body_hash = [0u8; 32];

        let err = sign(&config, &headers, body_hash, 1_722_000_000).unwrap_err();
        assert!(
            err.contains("exactly one From"),
            "error should mention exactly one From, got: {err}"
        );
    }

    /// From domain must match the configured domain (case-insensitive).
    #[test]
    fn rejects_mismatched_from_domain() {
        let key = test_key();
        let config = test_config(&key);

        let from = HeaderRef {
            name: b"From",
            value: b"alice@other-domain.com",
        };
        let headers = [from];
        let body_hash = [0u8; 32];

        let err = sign(&config, &headers, body_hash, 1_722_000_000).unwrap_err();
        assert!(
            err.contains("does not match"),
            "error should mention domain mismatch, got: {err}"
        );
    }

    /// From domain matching is case-insensitive.
    #[test]
    fn accepts_from_domain_case_insensitive() {
        let key = test_key();
        let config = test_config(&key);

        let from = HeaderRef {
            name: b"From",
            value: b"alice@EXAMPLE.COM",
        };
        let headers = [from];

        let mut body_c = BodyCanonicalizer::default();
        body_c.update(b"hello\n");
        let body_hash = body_c.finish();

        // Should succeed — domain comparison is case-insensitive.
        let result = sign(&config, &headers, body_hash, 1_722_000_000);
        assert!(
            result.is_ok(),
            "case-insensitive domain match should succeed: {result:?}"
        );
    }

    /// Header selection uses the last occurrence of each signed field.
    #[test]
    fn uses_last_occurrence_of_each_signed_header() {
        let key = test_key();
        let config = test_config(&key);

        let from = HeaderRef {
            name: b"From",
            value: b"alice@example.com",
        };
        let subject1 = HeaderRef {
            name: b"Subject",
            value: b"first",
        };
        let subject2 = HeaderRef {
            name: b"Subject",
            value: b"second",
        };
        let headers = [from, subject1, subject2];

        let mut body_c = BodyCanonicalizer::default();
        body_c.update(b"body");
        let body_hash = body_c.finish();
        let timestamp: u64 = 1_722_000_000;

        let value_bytes = sign(&config, &headers, body_hash, timestamp).unwrap();
        let value = String::from_utf8(value_bytes).unwrap();

        // The b= value is the last field; everything before it is the unsigned header.
        let b_start = value.find("b=").unwrap() + 2;
        let signature_text: String = value[b_start..]
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .map(char::from)
            .collect();
        let signature = base64::decode_block(&signature_text).unwrap();

        let unsigned = &value[..b_start];
        let canonicalized_sig = canonicalize_signature_header(unsigned.as_bytes());

        // Verify with "second" (the last occurrence) — should pass.
        let mut verifier = Verifier::new(openssl::hash::MessageDigest::sha256(), &key).unwrap();
        verifier
            .update(&canonicalize_header(b"From", b"alice@example.com"))
            .unwrap();
        verifier
            .update(&canonicalize_header(b"Subject", b"second"))
            .unwrap();
        verifier.update(&canonicalized_sig).unwrap();
        assert!(verifier.verify(&signature).unwrap());

        // Verify with "first" (the earlier occurrence) — should fail.
        let mut verifier2 = Verifier::new(openssl::hash::MessageDigest::sha256(), &key).unwrap();
        verifier2
            .update(&canonicalize_header(b"From", b"alice@example.com"))
            .unwrap();
        verifier2
            .update(&canonicalize_header(b"Subject", b"first"))
            .unwrap();
        verifier2.update(&canonicalized_sig).unwrap();
        assert!(!verifier2.verify(&signature).unwrap());
    }

    /// Signature folding uses CRLF+tab and the folded result still verifies.
    #[test]
    fn folded_signature_uses_crlf_and_verifies() {
        let key = test_key();
        let config = test_config(&key);

        // Use many headers to force folding (each adds to the signature length).
        let from = HeaderRef {
            name: b"From",
            value: b"alice@example.com",
        };
        let to = HeaderRef {
            name: b"To",
            value: b"bob@example.com",
        };
        let cc = HeaderRef {
            name: b"Cc",
            value: b"carol@example.com",
        };
        let subject = HeaderRef {
            name: b"Subject",
            value: b"A moderately long subject line to encourage folding",
        };
        let headers = [from, to, cc, subject];

        let mut body_c = BodyCanonicalizer::default();
        body_c.update(b"hello world\n");
        let body_hash = body_c.finish();
        let timestamp: u64 = 1_722_000_000;

        let value_bytes = sign(&config, &headers, body_hash, timestamp).unwrap();
        let value = String::from_utf8_lossy(&value_bytes);

        // Check that the folded signature contains CRLF+tab continuations.
        assert!(
            value.contains("\r\n\t"),
            "folded signature should contain CRLF+tab, got: {value:?}"
        );

        // Strip all whitespace to extract the raw b= value and verify.
        // Find the LAST "b=" to avoid matching "bh=" substring.
        let b_start = value.rfind("b=").unwrap() + 2;
        let signature_text: String = value[b_start..]
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .map(char::from)
            .collect();
        let signature = base64::decode_block(&signature_text).unwrap();

        // Reconstruct the unsigned value: everything up to and including "b=",
        // then strip folding to get the canonical field value the signer hashed.
        let unsigned = &value[..b_start];
        // Reconstruct the unfolded unsigned value for the signer's hash input.
        let unfolded = unsigned.replace("\r\n\t", " ");
        let canonicalized_sig = canonicalize_signature_header(unfolded.as_bytes());

        let mut verifier = Verifier::new(openssl::hash::MessageDigest::sha256(), &key).unwrap();
        // Headers must be in SIGNED_HEADERS order: from, subject, ..., to, cc.
        verifier
            .update(&canonicalize_header(b"From", b"alice@example.com"))
            .unwrap();
        verifier
            .update(&canonicalize_header(
                b"Subject",
                b"A moderately long subject line to encourage folding",
            ))
            .unwrap();
        verifier
            .update(&canonicalize_header(b"To", b"bob@example.com"))
            .unwrap();
        verifier
            .update(&canonicalize_header(b"Cc", b"carol@example.com"))
            .unwrap();
        verifier.update(&canonicalized_sig).unwrap();
        assert!(verifier.verify(&signature).unwrap());
    }

    // ── adversarial tests ───────────────────────────────────────────

    /// Header name matching is case-insensitive (e.g. "FROM" == "from").
    #[test]
    fn case_insensitive_header_name_matching() {
        let key = test_key();
        let config = test_config(&key);

        let from = HeaderRef {
            name: b"FROM",
            value: b"alice@example.com",
        };
        let subject = HeaderRef {
            name: b"SUBJECT",
            value: b"test",
        };
        let headers = [from, subject];

        let mut body_c = BodyCanonicalizer::default();
        body_c.update(b"body");
        let body_hash = body_c.finish();
        let timestamp: u64 = 1_722_000_000;

        let value_bytes = sign(&config, &headers, body_hash, timestamp).unwrap();
        let value = String::from_utf8(value_bytes).unwrap();

        // Verify it still works with uppercase header names.
        let b_start = value.find("b=").unwrap() + 2;
        let signature_text: String = value[b_start..]
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .map(char::from)
            .collect();
        let signature = base64::decode_block(&signature_text).unwrap();

        let unsigned = &value[..b_start];
        let canonicalized_sig = canonicalize_signature_header(unsigned.as_bytes());

        let mut verifier = Verifier::new(openssl::hash::MessageDigest::sha256(), &key).unwrap();
        verifier
            .update(&canonicalize_header(b"FROM", b"alice@example.com"))
            .unwrap();
        verifier
            .update(&canonicalize_header(b"SUBJECT", b"test"))
            .unwrap();
        verifier.update(&canonicalized_sig).unwrap();
        assert!(verifier.verify(&signature).unwrap());
    }

    /// When multiple occurrences of a signed header exist, the last one
    /// is selected and earlier ones are excluded from the hash.
    #[test]
    fn duplicate_signed_header_selects_last() {
        let key = test_key();
        let config = test_config(&key);

        let from = HeaderRef {
            name: b"From",
            value: b"alice@example.com",
        };
        let to1 = HeaderRef {
            name: b"To",
            value: b"first@example.com",
        };
        let to2 = HeaderRef {
            name: b"To",
            value: b"second@example.com",
        };
        let headers = [from, to1, to2];

        let mut body_c = BodyCanonicalizer::default();
        body_c.update(b"body");
        let body_hash = body_c.finish();
        let timestamp: u64 = 1_722_000_000;

        let value_bytes = sign(&config, &headers, body_hash, timestamp).unwrap();
        let value = String::from_utf8(value_bytes).unwrap();

        let b_start = value.find("b=").unwrap() + 2;
        let signature_text: String = value[b_start..]
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .map(char::from)
            .collect();
        let signature = base64::decode_block(&signature_text).unwrap();

        let unsigned = &value[..b_start];
        let canonicalized_sig = canonicalize_signature_header(unsigned.as_bytes());

        // Verify with "second@example.com" (the last To) — should pass.
        let mut verifier = Verifier::new(openssl::hash::MessageDigest::sha256(), &key).unwrap();
        verifier
            .update(&canonicalize_header(b"From", b"alice@example.com"))
            .unwrap();
        verifier
            .update(&canonicalize_header(b"To", b"second@example.com"))
            .unwrap();
        verifier.update(&canonicalized_sig).unwrap();
        assert!(verifier.verify(&signature).unwrap());

        // Verify with "first@example.com" — should fail.
        let mut verifier2 = Verifier::new(openssl::hash::MessageDigest::sha256(), &key).unwrap();
        verifier2
            .update(&canonicalize_header(b"From", b"alice@example.com"))
            .unwrap();
        verifier2
            .update(&canonicalize_header(b"To", b"first@example.com"))
            .unwrap();
        verifier2.update(&canonicalized_sig).unwrap();
        assert!(!verifier2.verify(&signature).unwrap());
    }
    #[test]
    fn generated_signatures_verify_against_literal_rfc_inputs() {
        let key = test_key();
        let config = test_config(&key);
        let subjects: &[(&[u8], &[u8])] = &[
            (b"hello", b"subject:hello\r\n"),
            (b"Re: hello", b"subject:Re: hello\r\n"),
            (
                b"  Re:\r\n\t hello: \tworld  ",
                b"subject:Re: hello: world\r\n",
            ),
        ];
        let bodies: &[(&[u8], &str)] = &[
            (b"", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="),
            (b"\r\n\r\n", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="),
            (b" \t\r\n\t", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="),
            (b"hello\r\n", "zS7KNTV0HyeorkDDGwxB1AV6enuRKzO5rthkhdHIRnY="),
        ];
        for &(subject, expected_subject) in subjects {
            for &(input, expected_hash) in bodies {
                let mut canonical = BodyCanonicalizer::default();
                for byte in input {
                    canonical.update(std::slice::from_ref(byte));
                }
                let headers = [
                    HeaderRef {
                        name: b"From",
                        value: b"Alice <alice@example.com>",
                    },
                    HeaderRef {
                        name: b"Subject",
                        value: subject,
                    },
                ];
                let value = String::from_utf8(
                    sign(&config, &headers, canonical.finish(), 1_722_000_000).unwrap(),
                )
                .unwrap();
                let unfolded = value.replace("\r\n\t", " ");
                assert!(unfolded.contains("h=from:from:subject;"));
                assert!(unfolded.contains(&format!("bh={expected_hash};")));
                let timestamp = unfolded
                    .split(';')
                    .find_map(|tag| tag.trim().strip_prefix("t="))
                    .unwrap();
                let b_start = unfolded.find("b=").unwrap() + 2;
                let signature = base64::decode_block(&unfolded[b_start..]).unwrap();
                // Literal expected canonical bytes, independent of all production
                // canonicalizers. The timestamp is the only nondeterministic tag.
                let unsigned = format!(
                    "dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=test; t={timestamp}; h=from:from:subject; bh={expected_hash}; b="
                );
                let mut verifier =
                    Verifier::new(openssl::hash::MessageDigest::sha256(), &key).unwrap();
                verifier
                    .update(b"from:Alice <alice@example.com>\r\n")
                    .unwrap();
                verifier.update(expected_subject).unwrap();
                verifier.update(unsigned.as_bytes()).unwrap();
                assert!(
                    verifier.verify(&signature).unwrap(),
                    "subject={subject:?}, body={input:?}"
                );
            }
        }
    }
}

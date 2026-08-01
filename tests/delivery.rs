//! Integration tests for the SMTP delivery state machine.
//!
//! Each test connects to a [`FakeSmarthost`] over real TCP sockets and
//! exercises one behaviour of the [`signed_relay_lite::smtp::deliver`]
//! function.

mod common;

use std::net::TcpStream;
use std::time::Duration;

use common::{FakeSmarthost, ServerResult, SmarthostConfig};
use signed_relay_lite::relay::{DeliveryResult, Envelope};
use signed_relay_lite::smtp::deliver;

const TIMEOUT: Duration = Duration::from_secs(5);

/// Helper: connect to the server, run deliver(), return both results.
fn run_delivery(
    server: FakeSmarthost,
    client_name: &str,
    envelope: &Envelope,
    dkim_signature: &[u8],
    message: &[u8],
) -> (DeliveryResult, ServerResult) {
    let stream = TcpStream::connect(server.addr).expect("connect failed");
    stream.set_read_timeout(Some(TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(TIMEOUT)).unwrap();

    let result = deliver(stream, client_name, envelope, dkim_signature, message);
    let server_result = server.join();
    (result, server_result)
}

// ── Test 1: Read 220 greeting and send exact EHLO ────────────────────

#[test]
fn greeting_and_ehlo() {
    let config = SmarthostConfig::default();
    let server = FakeSmarthost::start(config);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();

    let (result, sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    assert!(!sr.commands.is_empty(), "server received no commands");
    assert_eq!(
        sr.commands[0], b"EHLO test-client\r\n",
        "first command must be EHLO with the supplied client_name"
    );
    assert!(result.is_accepted(), "expected Delivered, got {result:?}");
}

// ── Test 2: Require 250 for MAIL FROM ────────────────────────────────

#[test]
fn mail_from_requires_250() {
    let config = SmarthostConfig {
        mail_from_response: b"550 rejected\r\n".to_vec(),
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start(config);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();

    let (result, sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    // Server received EHLO and MAIL FROM.
    assert!(
        sr.commands.iter().any(|c| c.starts_with(b"MAIL FROM:")),
        "expected MAIL FROM command, got {:?}",
        sr.commands
    );
    // No DATA should have been sent.
    assert!(
        !sr.commands.iter().any(|c| c.starts_with(b"DATA")),
        "DATA must not be sent after MAIL FROM rejection"
    );
    assert!(
        !result.is_accepted(),
        "must not be accepted when MAIL FROM is rejected"
    );
}

// ── Test 3: Issue one RCPT TO per validated recipient ────────────────

#[test]
fn rcpt_to_all_recipients_must_be_2xx() {
    let config = SmarthostConfig::default();
    let server = FakeSmarthost::start(config);
    let envelope = Envelope::new(
        b"sender@example.com",
        vec![
            b"a@example.com".to_vec(),
            b"b@example.com".to_vec(),
            b"c@example.com".to_vec(),
        ],
    )
    .unwrap();

    let (result, sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    // All three RCPT TO commands should appear.
    let rcpt_cmds: Vec<_> = sr
        .commands
        .iter()
        .filter(|c| c.starts_with(b"RCPT TO:"))
        .collect();
    assert_eq!(rcpt_cmds.len(), 3, "expected 3 RCPT TO commands");
    assert_eq!(rcpt_cmds[0], b"RCPT TO:<a@example.com>\r\n");
    assert_eq!(rcpt_cmds[1], b"RCPT TO:<b@example.com>\r\n");
    assert_eq!(rcpt_cmds[2], b"RCPT TO:<c@example.com>\r\n");
    assert!(result.is_accepted());
}

// ── Test 4: On any RCPT non-2xx send RSET and never DATA ────────────

#[test]
fn rcpt_failure_sends_rset_no_data() {
    // Second recipient rejected (550), first accepted.
    let config = SmarthostConfig {
        rcpt_responses: vec![b"250 OK\r\n".to_vec(), b"550 unknown\r\n".to_vec()],
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start(config);
    let envelope = Envelope::new(
        b"sender@example.com",
        vec![b"good@example.com".to_vec(), b"bad@example.com".to_vec()],
    )
    .unwrap();

    let (result, sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    // RSET must be sent.
    assert!(
        sr.commands.iter().any(|c| c.starts_with(b"RSET")),
        "expected RSET after RCPT failure, got {:?}",
        sr.commands
    );
    // DATA must NOT be sent.
    assert!(
        !sr.commands.iter().any(|c| c.starts_with(b"DATA")),
        "DATA must not be sent after any RCPT failure"
    );
    assert!(!result.is_accepted());
}

// ── Test 5: Require 354 before body transmission ─────────────────────

#[test]
fn requires_354_before_body() {
    let config = SmarthostConfig {
        data_go_ahead: b"451 temp error\r\n".to_vec(),
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start(config);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();

    let (result, sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    // DATA was sent but server rejected with 451.
    assert!(
        sr.commands.iter().any(|c| c.starts_with(b"DATA")),
        "expected DATA command"
    );
    // No body should have been sent (no captured message).
    assert!(
        sr.captured_message.is_empty(),
        "body must not be sent after 354 rejection"
    );
    assert!(!result.is_accepted());
}

// ── Test 6: DKIM-Signature header + dot-stuffed message captured ─────

#[test]
fn dkim_signature_and_dot_stuffed_message() {
    let config = SmarthostConfig::default();
    let server = FakeSmarthost::start(config);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();

    // Message with line-leading dots and non-UTF8 bytes.
    let mut message = b"From: sender@example.com\r\n\r\n".to_vec();
    message.extend_from_slice(b".line starting with dot\r\n");
    message.extend_from_slice(b"normal line\r\n");
    message.extend_from_slice(b"..already-stuffed\r\n");
    message.extend_from_slice(&[0xff, 0xfe, 0x80]); // non-UTF8
    message.extend_from_slice(b"\r\n");

    let dkim_sig = b"v=1; a=rsa-sha256; bh=abc; b=def";

    let (result, sr) = run_delivery(server, "test-client", &envelope, dkim_sig, &message);

    assert!(result.is_accepted(), "expected Delivered, got {result:?}");

    // Reconstruct expected captured message:
    //   DKIM-Signature: <sig>\r\n
    //   <original message bytes>
    // The server captures the unstuffed body. The dot-stuffing writer
    // stuffs line-leading dots; the server unstuffs them. So the
    // captured message should equal the DKIM header + original message.
    let mut expected = Vec::new();
    expected.extend_from_slice(b"DKIM-Signature: ");
    expected.extend_from_slice(dkim_sig);
    expected.extend_from_slice(b"\r\n");
    expected.extend_from_slice(&message);

    assert_eq!(
        sr.captured_message, expected,
        "captured message must equal DKIM header + original bytes"
    );
}

// ── Test 7: Return Delivered only after final 2xx ────────────────────

#[test]
fn delivered_only_after_final_2xx() {
    let config = SmarthostConfig {
        data_final_response: b"250 Message accepted for delivery\r\n".to_vec(),
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start(config);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();

    let (result, sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    assert!(result.is_accepted(), "expected Delivered, got {result:?}");
    assert_eq!(result.smtp_code, Some(250));

    // The full command sequence should be present.
    assert!(sr.commands.iter().any(|c| c.starts_with(b"EHLO")));
    assert!(sr.commands.iter().any(|c| c.starts_with(b"MAIL FROM:")));
    assert!(sr.commands.iter().any(|c| c.starts_with(b"RCPT TO:")));
    assert!(sr.commands.iter().any(|c| c.starts_with(b"DATA")));
}

// ── Test 8: No QUIT per message ──────────────────────────────────────

#[test]
fn no_quit_per_message() {
    let config = SmarthostConfig::default();
    let server = FakeSmarthost::start(config);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();

    let (result, sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    assert!(result.is_accepted());
    assert!(
        !sr.commands.iter().any(|c| c.starts_with(b"QUIT")),
        "deliver must not send QUIT; caller controls shutdown"
    );
}

// ── Test 9: Non-UTF8 bytes preserved through delivery ────────────────

#[test]
fn non_utf8_bytes_preserved() {
    let config = SmarthostConfig::default();
    let server = FakeSmarthost::start(config);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();

    let message: Vec<u8> = vec![
        0xff, 0xfe, 0x80, b'\r', b'\n', // raw bytes + CRLF
    ];

    let (result, sr) = run_delivery(server, "test-client", &envelope, b"sig", &message);

    assert!(result.is_accepted());

    let mut expected = Vec::new();
    expected.extend_from_slice(b"DKIM-Signature: sig\r\n");
    expected.extend_from_slice(&message);

    assert_eq!(sr.captured_message, expected);
}

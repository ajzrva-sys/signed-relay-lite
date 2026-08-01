//! Integration tests for the SMTP delivery state machine.
//!
//! Each test connects to a [`FakeSmarthost`] over real TCP sockets and
//! exercises one behaviour of the [`signed_relay_lite::smtp::deliver`]
//! function.

mod common;

use std::net::TcpStream;
use std::time::{Duration, Instant};

use common::{ClosePoint, FakeSmarthost, ServerResult, SmarthostConfig, TestPki};
use signed_relay_lite::relay::{DeliveryResult, DeliveryStatus, Envelope};
use signed_relay_lite::smtp::{deliver, SmtpConnection, SmtpStream};

const TIMEOUT: Duration = Duration::from_secs(5);
const TLS_TIMEOUT: Duration = Duration::from_millis(300);

fn tls_connection(
    server: &FakeSmarthost,
    hostname: &str,
    ca_file: Option<&std::path::Path>,
) -> SmtpConnection {
    SmtpConnection::new_implicit_tls(
        "test-client",
        hostname,
        server.addr.port(),
        TLS_TIMEOUT,
        ca_file,
    )
    .expect("construct TLS connector")
}

fn test_envelope() -> Envelope {
    Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap()
}

#[test]
fn verified_tls_with_trusted_ca_and_matching_hostname_succeeds() {
    let pki = TestPki::localhost();
    let server = FakeSmarthost::start_tls(SmarthostConfig::default(), pki.acceptor());
    let mut connection = tls_connection(&server, "localhost", Some(&pki.ca_file));
    let result = connection.deliver(&test_envelope(), b"secret-signature", b"secret-body\r\n");
    drop(connection);
    let observed = server.join();
    assert!(result.is_accepted(), "{result:?}");
    assert_eq!(observed.captured_messages.len(), 1);
}

#[test]
fn untrusted_tls_certificate_fails_before_smtp_without_leaking_message() {
    let pki = TestPki::localhost();
    let server = FakeSmarthost::start_tls(SmarthostConfig::default(), pki.acceptor());
    let mut connection = tls_connection(&server, "localhost", None);
    let result = connection.deliver(&test_envelope(), b"secret-signature", b"secret-body\r\n");
    drop(connection);
    let observed = server.join();
    assert_eq!(result.status, DeliveryStatus::TemporaryFailure);
    assert!(!result.ambiguous);
    assert!(observed.commands.is_empty());
    assert!(observed.captured_message.is_empty());
}

#[test]
fn trusted_tls_certificate_with_wrong_hostname_fails() {
    let pki = TestPki::localhost();
    let server = FakeSmarthost::start_tls(SmarthostConfig::default(), pki.acceptor());
    let mut connection = tls_connection(&server, "127.0.0.1", Some(&pki.ca_file));
    let result = connection.deliver(&test_envelope(), b"secret-signature", b"secret-body\r\n");
    drop(connection);
    let observed = server.join();
    assert_eq!(result.status, DeliveryStatus::TemporaryFailure);
    assert!(!result.ambiguous);
    assert!(observed.commands.is_empty());
}

#[test]
fn tls_handshake_stall_is_a_bounded_temporary_failure() {
    let server = FakeSmarthost::start_tls_stall(Duration::from_secs(1));
    let mut connection = tls_connection(&server, "localhost", None);
    let started = Instant::now();
    let result = connection.deliver(&test_envelope(), b"secret-signature", b"secret-body\r\n");
    let elapsed = started.elapsed();
    drop(connection);
    let observed = server.join();
    assert_eq!(result.status, DeliveryStatus::TemporaryFailure);
    assert!(!result.ambiguous);
    assert!(elapsed < Duration::from_millis(900), "elapsed {elapsed:?}");
    assert!(observed.commands.is_empty());
}

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

fn persistent_connection(server: &FakeSmarthost) -> SmtpConnection {
    let addr = server.addr;
    SmtpConnection::new("test-client", move || {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(TIMEOUT))?;
        stream.set_write_timeout(Some(TIMEOUT))?;
        Ok(Box::new(stream) as SmtpStream)
    })
}

#[test]
fn two_messages_reuse_one_connection_and_one_ehlo() {
    let server = FakeSmarthost::start(SmarthostConfig::default());
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();
    let mut connection = persistent_connection(&server);

    assert!(connection
        .deliver(&envelope, b"one", b"first\r\n")
        .is_accepted());
    assert!(connection
        .deliver(&envelope, b"two", b"second\r\n")
        .is_accepted());
    drop(connection);
    let result = server.join();

    assert_eq!(result.accepted_connections, 1);
    assert_eq!(
        result
            .commands
            .iter()
            .filter(|line| line.starts_with(b"EHLO "))
            .count(),
        1
    );
    assert_eq!(result.captured_messages.len(), 2);
}

#[test]
fn stale_reused_transport_reconnects_once_before_data() {
    let first = SmarthostConfig {
        close_point: ClosePoint::BeforeMailReply(1),
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start_connections(vec![first, SmarthostConfig::default()]);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();
    let mut connection = persistent_connection(&server);

    assert!(connection
        .deliver(&envelope, b"one", b"first\r\n")
        .is_accepted());
    assert!(connection
        .deliver(&envelope, b"two", b"second\r\n")
        .is_accepted());
    drop(connection);
    let result = server.join();

    assert_eq!(result.accepted_connections, 2);
    assert_eq!(
        result
            .commands
            .iter()
            .filter(|line| line.starts_with(b"EHLO "))
            .count(),
        2
    );
    assert_eq!(result.captured_messages.len(), 2);
}

#[test]
fn failure_after_354_does_not_reconnect() {
    let first = SmarthostConfig {
        close_point: ClosePoint::AfterFinalDot,
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start_connections(vec![first]);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();
    let mut connection = persistent_connection(&server);

    let delivery = connection.deliver(&envelope, b"sig", b"message\r\n");
    drop(connection);
    let result = server.join();
    assert!(delivery.ambiguous);
    assert_eq!(result.accepted_connections, 1);
}

#[test]
fn second_pre_data_transport_failure_stops_without_looping() {
    let first = SmarthostConfig {
        close_point: ClosePoint::BeforeMailReply(0),
        ..SmarthostConfig::default()
    };
    let second = first.clone();
    let server = FakeSmarthost::start_connections(vec![first, second]);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();
    let mut connection = persistent_connection(&server);

    let delivery = connection.deliver(&envelope, b"sig", b"message\r\n");
    drop(connection);
    let result = server.join();
    assert_eq!(delivery.status, DeliveryStatus::TemporaryFailure);
    assert_eq!(result.accepted_connections, 2);
}
#[test]
fn reply_221_marks_session_unusable() {
    let first = SmarthostConfig {
        mail_from_response: b"221 closing\r\n".to_vec(),
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start_connections(vec![first, SmarthostConfig::default()]);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();
    let mut connection = persistent_connection(&server);

    let rejected = connection.deliver(&envelope, b"one", b"first\r\n");
    assert!(!rejected.is_accepted());
    assert!(connection
        .deliver(&envelope, b"two", b"second\r\n")
        .is_accepted());
    drop(connection);
    let result = server.join();
    assert_eq!(result.accepted_connections, 2);
}

#[test]
fn rcpt_221_stops_transaction_and_marks_session_unusable() {
    let first = SmarthostConfig {
        rcpt_responses: vec![b"221 closing\r\n".to_vec()],
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start_connections(vec![first, SmarthostConfig::default()]);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();
    let mut connection = persistent_connection(&server);

    let rejected = connection.deliver(&envelope, b"one", b"first\r\n");
    assert!(!rejected.is_accepted());
    assert!(connection
        .deliver(&envelope, b"two", b"second\r\n")
        .is_accepted());
    drop(connection);
    let result = server.join();

    assert_eq!(result.accepted_connections, 2);
    assert_eq!(
        result
            .commands
            .iter()
            .filter(|line| line.as_slice() == b"DATA\r\n")
            .count(),
        1,
        "the connection that returned 221 must not receive DATA"
    );
}

#[test]
fn smtp_rejection_is_not_automatically_retried() {
    let server = FakeSmarthost::start(SmarthostConfig {
        mail_from_response: b"451 later\r\n".to_vec(),
        ..SmarthostConfig::default()
    });
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();
    let mut connection = persistent_connection(&server);
    let delivery = connection.deliver(&envelope, b"sig", b"message\r\n");
    drop(connection);
    let result = server.join();
    assert_eq!(delivery.smtp_code, Some(451));
    assert_eq!(result.accepted_connections, 1);
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

// ── Task 14: Explicit failure classification ────────────────────────

/// Greeting 4xx → TemporaryFailure, not ambiguous.
#[test]
fn greeting_4xx_is_temporary() {
    let config = SmarthostConfig {
        greeting: b"421 service unavailable\r\n".to_vec(),
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start(config);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();

    let (result, _sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    assert_eq!(result.status, DeliveryStatus::TemporaryFailure);
    assert!(!result.ambiguous);
    assert_eq!(result.smtp_code, Some(421));
}

/// Greeting 5xx → PermanentFailure, not ambiguous.
#[test]
fn greeting_5xx_is_permanent() {
    let config = SmarthostConfig {
        greeting: b"554 banned\r\n".to_vec(),
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start(config);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();

    let (result, _sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    assert_eq!(result.status, DeliveryStatus::PermanentFailure);
    assert!(!result.ambiguous);
    assert_eq!(result.smtp_code, Some(554));
}

/// MAIL FROM 4xx → TemporaryFailure.
#[test]
fn mail_from_4xx_is_temporary() {
    let config = SmarthostConfig {
        mail_from_response: b"452 insufficient system storage\r\n".to_vec(),
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start(config);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();

    let (result, _sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    assert_eq!(result.status, DeliveryStatus::TemporaryFailure);
    assert!(!result.ambiguous);
    assert_eq!(result.smtp_code, Some(452));
}

/// MAIL FROM 5xx → PermanentFailure.
#[test]
fn mail_from_5xx_is_permanent() {
    let config = SmarthostConfig {
        mail_from_response: b"550 sender rejected\r\n".to_vec(),
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start(config);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();

    let (result, _sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    assert_eq!(result.status, DeliveryStatus::PermanentFailure);
    assert!(!result.ambiguous);
    assert_eq!(result.smtp_code, Some(550));
}

/// Any RCPT 4xx → TemporaryFailure, RSET, no DATA.
#[test]
fn rcpt_4xx_is_temporary_no_data() {
    let config = SmarthostConfig {
        rcpt_responses: vec![b"452 mailbox full\r\n".to_vec()],
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start(config);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();

    let (result, sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    assert_eq!(result.status, DeliveryStatus::TemporaryFailure);
    assert!(!result.ambiguous);
    assert_eq!(result.smtp_code, Some(452));
    assert!(sr.commands.iter().any(|c| c.starts_with(b"RSET")));
    assert!(!sr.commands.iter().any(|c| c.starts_with(b"DATA")));
}

/// RCPT 5xx with no 4xx → PermanentFailure, RSET, no DATA.
#[test]
fn rcpt_5xx_only_is_permanent_no_data() {
    let config = SmarthostConfig {
        rcpt_responses: vec![b"550 user unknown\r\n".to_vec()],
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start(config);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();

    let (result, sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    assert_eq!(result.status, DeliveryStatus::PermanentFailure);
    assert!(!result.ambiguous);
    assert_eq!(result.smtp_code, Some(550));
    assert!(sr.commands.iter().any(|c| c.starts_with(b"RSET")));
    assert!(!sr.commands.iter().any(|c| c.starts_with(b"DATA")));
}

/// Mixed RCPT (4xx + 5xx) → TemporaryFailure (4xx presence wins).
#[test]
fn mixed_rcpt_4xx_and_5xx_is_temporary() {
    let config = SmarthostConfig {
        rcpt_responses: vec![
            b"452 mailbox full\r\n".to_vec(),
            b"550 user unknown\r\n".to_vec(),
        ],
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start(config);
    let envelope = Envelope::new(
        b"sender@example.com",
        vec![b"full@example.com".to_vec(), b"bad@example.com".to_vec()],
    )
    .unwrap();

    let (result, sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    assert_eq!(result.status, DeliveryStatus::TemporaryFailure);
    assert!(!result.ambiguous);
    assert_eq!(result.smtp_code, Some(452));
    assert!(!sr.commands.iter().any(|c| c.starts_with(b"DATA")));
}

/// Connection closes before 354/body → TemporaryFailure, unambiguous.
#[test]
fn close_before_354_is_temporary_unambiguous() {
    let config = SmarthostConfig {
        close_point: ClosePoint::BeforeData,
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start(config);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();

    let (result, _sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    assert_eq!(result.status, DeliveryStatus::TemporaryFailure);
    assert!(!result.ambiguous, "before 354 must be unambiguous");
    assert_eq!(result.smtp_code, None);
}

/// Connection closes during body → TemporaryFailure, ambiguous.
#[test]
fn close_during_body_is_temporary_ambiguous() {
    let config = SmarthostConfig {
        close_point: ClosePoint::DuringData,
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start(config);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();

    let (result, _sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    assert_eq!(result.status, DeliveryStatus::TemporaryFailure);
    assert!(result.ambiguous, "during body must be ambiguous");
}

/// Connection closes after final dot before reply → TemporaryFailure, ambiguous.
#[test]
fn close_after_final_dot_is_temporary_ambiguous() {
    let config = SmarthostConfig {
        close_point: ClosePoint::AfterFinalDot,
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start(config);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();

    let (result, _sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    assert_eq!(result.status, DeliveryStatus::TemporaryFailure);
    assert!(result.ambiguous, "after final dot must be ambiguous");
}

/// Final 4xx → TemporaryFailure, not ambiguous (reply exists).
#[test]
fn final_4xx_is_temporary_unambiguous() {
    let config = SmarthostConfig {
        data_final_response: b"452 insufficient storage\r\n".to_vec(),
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start(config);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();

    let (result, _sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    assert_eq!(result.status, DeliveryStatus::TemporaryFailure);
    assert!(!result.ambiguous, "final 4xx is not ambiguous");
    assert_eq!(result.smtp_code, Some(452));
}

/// Final 5xx → PermanentFailure.
#[test]
fn final_5xx_is_permanent() {
    let config = SmarthostConfig {
        data_final_response: b"550 message rejected\r\n".to_vec(),
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start(config);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();

    let (result, _sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    assert_eq!(result.status, DeliveryStatus::PermanentFailure);
    assert!(!result.ambiguous);
    assert_eq!(result.smtp_code, Some(550));
}

/// DATA 4xx → TemporaryFailure, no body sent.
#[test]
fn data_4xx_is_temporary() {
    let config = SmarthostConfig {
        data_go_ahead: b"451 temp error\r\n".to_vec(),
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start(config);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();

    let (result, sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    assert_eq!(result.status, DeliveryStatus::TemporaryFailure);
    assert!(!result.ambiguous);
    assert_eq!(result.smtp_code, Some(451));
    assert!(sr.captured_message.is_empty());
}

/// DATA 5xx → PermanentFailure, no body sent.
#[test]
fn data_5xx_is_permanent() {
    let config = SmarthostConfig {
        data_go_ahead: b"550 policy violation\r\n".to_vec(),
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start(config);
    let envelope =
        Envelope::new(b"sender@example.com", vec![b"rcpt@example.com".to_vec()]).unwrap();

    let (result, sr) = run_delivery(server, "test-client", &envelope, b"sig", b"msg\r\n");

    assert_eq!(result.status, DeliveryStatus::PermanentFailure);
    assert!(!result.ambiguous);
    assert_eq!(result.smtp_code, Some(550));
    assert!(sr.captured_message.is_empty());
}

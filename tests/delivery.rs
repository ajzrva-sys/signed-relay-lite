//! Integration tests for the SMTP delivery state machine.
//!
//! Each test connects to a [`FakeSmarthost`] over real TCP sockets and
//! exercises one behaviour of the [`signed_relay_lite::smtp::deliver`]
//! function.

mod common;

use std::io::{self, BufRead, BufReader, Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use common::{
    ClosePoint, FakeSmarthost, FinalResponseGate, ServerResult, SmarthostConfig, TestPki,
};
use openssl::hash::{hash, MessageDigest};
use openssl::pkey::{PKey, Public};
use openssl::rsa::Rsa;
use openssl::sign::Verifier;
use signed_relay_lite::config::{Secret, SigningConfig};
use signed_relay_lite::message::{Limits, Message};
use signed_relay_lite::relay::{DeliveryJob, DeliveryResult, DeliveryStatus, Envelope, RelayPool};
use signed_relay_lite::smtp::{deliver, SmtpConnection, SmtpStream};
use signed_relay_lite::submission::{
    read_server_reply, MemoryBudget, ServerReply, SubmissionLimits, SubmissionServer,
    SubmissionServerConfig,
};

const TIMEOUT: Duration = Duration::from_secs(5);
const TLS_TIMEOUT: Duration = Duration::from_millis(300);
static NEXT_E2E_SOCKET: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[derive(Clone, Copy)]
struct RawHeader<'a> {
    name: &'a [u8],
    value: &'a [u8],
}

fn split_message(message: &[u8]) -> Option<(Vec<RawHeader<'_>>, &[u8], usize)> {
    let separator = message.windows(4).position(|bytes| bytes == b"\r\n\r\n")?;
    let block = &message[..separator + 2];
    let mut headers = Vec::new();
    let mut start = 0;
    let mut index = 0;
    while index + 1 < block.len() {
        if &block[index..index + 2] == b"\r\n" {
            let next = index + 2;
            if next < block.len() && matches!(block[next], b' ' | b'\t') {
                index = next;
                continue;
            }
            let field = &block[start..index];
            let colon = field.iter().position(|byte| *byte == b':')?;
            headers.push(RawHeader {
                name: &field[..colon],
                value: &field[colon + 1..],
            });
            start = next;
            index = next;
        } else {
            index += 1;
        }
    }
    Some((headers, &message[separator + 4..], separator + 4))
}

fn relaxed_header(name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut output: Vec<u8> = name.iter().map(u8::to_ascii_lowercase).collect();
    output.push(b':');
    let mut whitespace = false;
    for &byte in value {
        match byte {
            b' ' | b'\t' | b'\r' | b'\n' => whitespace = true,
            _ => {
                if whitespace && output.last() != Some(&b':') {
                    output.push(b' ');
                }
                whitespace = false;
                output.push(byte);
            }
        }
    }
    output.extend_from_slice(b"\r\n");
    output
}

fn relaxed_body(body: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut nonempty_lines = Vec::new();
    for line in body
        .strip_suffix(b"\r\n")
        .unwrap_or(body)
        .split(|byte| *byte == b'\n')
    {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let mut canonical = Vec::new();
        let mut whitespace = false;
        for &byte in line {
            if matches!(byte, b' ' | b'\t') {
                whitespace = true;
            } else {
                if whitespace && !canonical.is_empty() {
                    canonical.push(b' ');
                }
                whitespace = false;
                canonical.push(byte);
            }
        }
        nonempty_lines.push(canonical);
    }
    while nonempty_lines.last().is_some_and(Vec::is_empty) {
        nonempty_lines.pop();
    }
    for line in nonempty_lines {
        output.extend_from_slice(&line);
        output.extend_from_slice(b"\r\n");
    }
    if output.is_empty() {
        output.extend_from_slice(b"\r\n");
    }
    output
}

fn unfolded(value: &[u8]) -> Vec<u8> {
    value
        .iter()
        .copied()
        .filter(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        .collect()
}

fn tag<'a>(value: &'a [u8], wanted: &[u8]) -> Option<&'a [u8]> {
    value.split(|byte| *byte == b';').find_map(|part| {
        let equals = part.iter().position(|byte| *byte == b'=')?;
        let name = part[..equals]
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        name.eq_ignore_ascii_case(wanted)
            .then_some(&part[equals + 1..])
    })
}

fn signature_without_b(value: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(value.len());
    let mut offset = 0;
    for part in value.split_inclusive(|byte| *byte == b';') {
        let equals = part.iter().position(|byte| *byte == b'=')?;
        let name: Vec<_> = part[..equals]
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace() && *byte != b';')
            .collect();
        if name.eq_ignore_ascii_case(b"b") {
            output.extend_from_slice(&part[..equals + 1]);
            output.extend(
                part[equals + 1..]
                    .iter()
                    .copied()
                    .filter(|byte| byte.is_ascii_whitespace() || *byte == b';'),
            );
            output.extend_from_slice(&value[offset + part.len()..]);
            return Some(output);
        }
        output.extend_from_slice(part);
        offset += part.len();
    }
    None
}

fn verify_captured_dkim(message: &[u8], public_key: &PKey<Public>, selector: &str) -> bool {
    (|| -> Option<bool> {
        let (headers, body, _) = split_message(message)?;
        let dkim = headers
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(b"DKIM-Signature"))?;
        let required = [
            (b"v".as_slice(), b"1".as_slice()),
            (b"a".as_slice(), b"rsa-sha256".as_slice()),
            (b"c".as_slice(), b"relaxed/relaxed".as_slice()),
            (b"d".as_slice(), b"example.com".as_slice()),
            (b"s".as_slice(), selector.as_bytes()),
        ];
        for (name, expected) in required {
            if unfolded(tag(dkim.value, name)?) != expected {
                return Some(false);
            }
        }
        let h = unfolded(tag(dkim.value, b"h")?);
        let bh = unfolded(tag(dkim.value, b"bh")?);
        let signature = unfolded(tag(dkim.value, b"b")?);
        if h != b"from:from:subject:to:content-type" || bh.is_empty() || signature.is_empty() {
            return Some(false);
        }
        let expected_body_hash = hash(MessageDigest::sha256(), &relaxed_body(body)).ok()?;
        if openssl::base64::decode_block(std::str::from_utf8(&bh).ok()?).ok()?
            != expected_body_hash.as_ref()
        {
            return Some(false);
        }

        let originals: Vec<_> = headers
            .iter()
            .copied()
            .filter(|header| !header.name.eq_ignore_ascii_case(b"DKIM-Signature"))
            .collect();
        let mut used = vec![false; originals.len()];
        let mut signed_data = Vec::new();
        for name in h.split(|byte| *byte == b':') {
            if let Some(index) = (0..originals.len())
                .rev()
                .find(|&index| !used[index] && originals[index].name.eq_ignore_ascii_case(name))
            {
                used[index] = true;
                signed_data.extend_from_slice(&relaxed_header(
                    originals[index].name,
                    originals[index].value,
                ));
            }
        }
        let empty_b = signature_without_b(dkim.value)?;
        let mut canonical_signature = relaxed_header(b"DKIM-Signature", &empty_b);
        canonical_signature.truncate(canonical_signature.len() - 2);
        signed_data.extend_from_slice(&canonical_signature);

        let decoded_signature =
            openssl::base64::decode_block(std::str::from_utf8(&signature).ok()?).ok()?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), public_key).ok()?;
        verifier.update(&signed_data).ok()?;
        verifier.verify(&decoded_signature).ok()
    })()
    .unwrap_or(false)
}

fn srl2_request(message: &[u8]) -> Vec<u8> {
    let sender = b"sender@example.com";
    let recipient = b"recipient@example.net";
    let mut frame = b"SRL2".to_vec();
    frame.extend_from_slice(&0_u32.to_be_bytes());
    frame.extend_from_slice(&(sender.len() as u32).to_be_bytes());
    frame.extend_from_slice(sender);
    frame.extend_from_slice(&1_u32.to_be_bytes());
    frame.extend_from_slice(&(recipient.len() as u32).to_be_bytes());
    frame.extend_from_slice(recipient);
    frame.extend_from_slice(&(message.len() as u32).to_be_bytes());
    frame.extend_from_slice(message);
    frame.extend_from_slice(&0_u32.to_be_bytes());
    frame
}

fn first_header_end(message: &[u8]) -> Option<usize> {
    let mut offset = 0;
    loop {
        let relative = message[offset..]
            .windows(2)
            .position(|bytes| bytes == b"\r\n")?;
        let end = offset + relative + 2;
        if !matches!(message.get(end), Some(b' ' | b'\t')) {
            return Some(end);
        }
        offset = end;
    }
}

fn mutate_tag(message: &[u8], name: &[u8]) -> Vec<u8> {
    let mut changed = message.to_vec();
    let end = first_header_end(message).unwrap();
    let value = &message[b"DKIM-Signature:".len()..end - 2];
    let needle = [name, b"="].concat();
    let start = value
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(&needle))
        .unwrap()
        + b"DKIM-Signature:".len()
        + needle.len();
    let target = (start..end)
        .find(|&index| changed[index].is_ascii_alphanumeric())
        .unwrap();
    changed[target] = if changed[target] == b'A' { b'B' } else { b'A' };
    changed
}

#[test]
fn end_to_end_submission_waits_for_final_250_and_dkim_verifies() {
    let signing_key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let public_key = PKey::public_key_from_pem(&signing_key.public_key_to_pem().unwrap()).unwrap();
    let signing = SigningConfig {
        domain: "example.com".to_owned(),
        selector: "e2e".to_owned(),
        key: Arc::new(signing_key),
    };
    let pki = TestPki::localhost();
    let gate = FinalResponseGate::new();
    let fake = FakeSmarthost::start_tls(
        SmarthostConfig {
            final_response_gate: Some(gate.clone()),
            data_final_response: b"250 queued after verification gate\r\n".to_vec(),
            ..SmarthostConfig::default()
        },
        pki.acceptor(),
    );
    let relay = Arc::new(RelayPool::new(1, 1, {
        let port = fake.addr.port();
        let ca_file = pki.ca_file.clone();
        move || {
            SmtpConnection::new_implicit_tls(
                "e2e-client",
                "localhost",
                port,
                Duration::from_secs(2),
                Some(&ca_file),
            )
            .unwrap()
        }
    }));
    let socket = PathBuf::from(format!(
        "/tmp/signed-relay-lite-e2e-{}-{}.sock",
        std::process::id(),
        NEXT_E2E_SOCKET.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&socket);
    let shutdown = Arc::new(AtomicBool::new(false));
    let limits = SubmissionLimits {
        max_recipients: 4,
        max_address_bytes: 254,
        max_message_bytes: 64 * 1024,
        max_diagnostic_bytes: 4096,
    };
    let server = SubmissionServer::bind(
        &socket,
        SubmissionServerConfig {
            max_message_bytes: limits.max_message_bytes as usize,
            submission_timeout: Duration::from_secs(2),
            max_active_handlers: 1,
            socket_mode: 0o600,
        },
        Limits::testing(),
        MemoryBudget::new(1024 * 1024),
        signing,
        Arc::clone(&relay),
        Arc::clone(&shutdown),
    )
    .unwrap();
    let server_thread = thread::spawn(move || server.run().unwrap());

    let mut original = b"From: Sender <sender@example.com>\r\n\
Subject: earlier subject\r\n\
Subject: signed subject\r\n\
\tcontinued value\r\n\
To: Recipient <recipient@example.net>\r\n\
Content-Type: application/octet-stream\r\n\
\r\n\
first line with trailing spaces   \r\n\
second\t\tline\t \r\n\
.one leading dot\r\n"
        .to_vec();
    original.extend_from_slice(&[0xff, 0xfe, b' ', b'\t', b'\r', b'\n']);
    original.extend_from_slice(b"\r\n");

    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
    let client_socket = socket.clone();
    let client_limits = limits.clone();
    let request = srl2_request(&original);
    let client = thread::spawn(move || {
        let mut stream = UnixStream::connect(client_socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(&request).unwrap();
        let _ = client_limits;
        let ServerReply::Ready(_) = read_server_reply(&mut stream).unwrap() else {
            panic!("server did not authorize message stream");
        };
        let ServerReply::Final(result) = read_server_reply(&mut stream).unwrap() else {
            panic!("server did not return FINAL");
        };
        result_tx.send(result).unwrap();
    });

    gate.wait_until_captured();
    assert!(result_rx.recv_timeout(Duration::from_millis(100)).is_err());
    gate.release();
    let delivery = result_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(delivery.status, DeliveryStatus::Delivered);
    assert_eq!(delivery.smtp_code, Some(250));
    client.join().unwrap();

    shutdown.store(true, Ordering::Release);
    server_thread.join().unwrap();
    drop(relay);
    let observed = fake.join();
    let captured = observed.captured_messages.first().unwrap();
    let dkim_end = first_header_end(captured).unwrap();
    assert_eq!(&captured[dkim_end..], original.as_slice());
    assert!(captured
        .windows(b"\r\n.one leading dot\r\n".len())
        .any(|window| { window == b"\r\n.one leading dot\r\n" }));
    assert!(captured.windows(2).any(|window| window == [0xff, 0xfe]));

    let mut corrupted_body = captured.clone();
    *corrupted_body.last_mut().unwrap() ^= 1;
    assert!(!verify_captured_dkim(&corrupted_body, &public_key, "e2e"));
    assert!(verify_captured_dkim(captured, &public_key, "e2e"));
    assert!(!verify_captured_dkim(
        &mutate_tag(captured, b"bh"),
        &public_key,
        "e2e"
    ));
    assert!(!verify_captured_dkim(
        &mutate_tag(captured, b"b"),
        &public_key,
        "e2e"
    ));
    let mut duplicate_from = captured.clone();
    let insertion = duplicate_from
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap()
        + 2;
    duplicate_from.splice(
        insertion..insertion,
        b"From: attacker@example.com\r\n".iter().copied(),
    );
    assert!(!verify_captured_dkim(&duplicate_from, &public_key, "e2e"));
    assert!(!socket.exists());
}

struct ScriptedStream {
    replies: Cursor<Vec<u8>>,
}

impl Read for ScriptedStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.replies.read(buffer)
    }
}

impl Write for ScriptedStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn scripted_connection() -> SmtpConnection {
    SmtpConnection::new("test-client", || {
        Ok(Box::new(ScriptedStream {
            replies: Cursor::new(
                b"220 ready\r\n250 hello\r\n250 sender\r\n250 recipient\r\n354 data\r\n250 queued\r\n"
                    .to_vec(),
            ),
        }) as SmtpStream)
    })
}

fn test_message() -> Message {
    Message::parse(
        b"From: sender@example.com\r\n\r\nbody\r\n".to_vec(),
        Limits::testing(),
    )
    .unwrap()
}

#[test]
fn dropping_relay_pool_joins_idle_workers() {
    let pool = RelayPool::new(4, 4, scripted_connection);
    drop(pool);
}

#[test]
fn relay_submit_waits_for_real_tcp_final_reply() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (at_final_dot_tx, at_final_dot_rx) = std::sync::mpsc::sync_channel(1);
    let (release_final_tx, release_final_rx) = std::sync::mpsc::sync_channel(1);
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"220 ready\r\n").unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = Vec::new();
        for reply in [
            b"250 hello\r\n".as_slice(),
            b"250 sender\r\n",
            b"250 recipient\r\n",
            b"354 data\r\n",
        ] {
            line.clear();
            reader.read_until(b'\n', &mut line).unwrap();
            stream.write_all(reply).unwrap();
        }
        loop {
            line.clear();
            reader.read_until(b'\n', &mut line).unwrap();
            if line == b".\r\n" {
                break;
            }
        }
        at_final_dot_tx.send(()).unwrap();
        release_final_rx.recv().unwrap();
        stream.write_all(b"250 queued\r\n").unwrap();
    });
    let pool = Arc::new(RelayPool::new(1, 1, move || {
        SmtpConnection::new("test-client", move || {
            let stream = TcpStream::connect(address)?;
            stream.set_read_timeout(Some(TIMEOUT))?;
            stream.set_write_timeout(Some(TIMEOUT))?;
            Ok(Box::new(stream) as SmtpStream)
        })
    }));
    let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);
    let submitter = {
        let pool = Arc::clone(&pool);
        thread::spawn(move || {
            let result = pool.submit(test_envelope(), test_message(), b"sig".to_vec());
            finished_tx.send(result).unwrap();
        })
    };

    at_final_dot_rx.recv_timeout(TIMEOUT).unwrap();
    assert!(finished_rx
        .recv_timeout(Duration::from_millis(100))
        .is_err());
    release_final_tx.send(()).unwrap();
    assert!(finished_rx.recv_timeout(TIMEOUT).unwrap().is_accepted());
    submitter.join().unwrap();
    drop(pool);
    server.join().unwrap();
}

#[test]
fn four_relay_workers_process_four_submissions_concurrently() {
    struct BarrierStream {
        replies: Cursor<Vec<u8>>,
        start: Arc<Barrier>,
        first_read: bool,
    }
    impl Read for BarrierStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.first_read {
                self.first_read = false;
                self.start.wait();
            }
            self.replies.read(buffer)
        }
    }
    impl Write for BarrierStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            Ok(buffer.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let start = Arc::new(Barrier::new(4));
    let pool = Arc::new(RelayPool::new(4, 4, {
        let start = Arc::clone(&start);
        move || {
            let start = Arc::clone(&start);
            SmtpConnection::new("test-client", move || {
                Ok(Box::new(BarrierStream {
                    replies: Cursor::new(
                        b"220 ready\r\n250 hello\r\n250 sender\r\n250 recipient\r\n354 data\r\n250 queued\r\n"
                            .to_vec(),
                    ),
                    start: Arc::clone(&start),
                    first_read: true,
                }) as SmtpStream)
            })
        }
    }));
    let submissions: Vec<_> = (0..4)
        .map(|_| {
            let pool = Arc::clone(&pool);
            thread::spawn(move || pool.submit(test_envelope(), test_message(), b"sig".to_vec()))
        })
        .collect();

    for submission in submissions {
        assert!(submission.join().unwrap().is_accepted());
    }
}

#[test]
fn bounded_relay_queue_backpressures_above_capacity() {
    let worker_gate = Arc::new(Barrier::new(2));
    let pool = Arc::new(RelayPool::new(1, 1, {
        let worker_gate = Arc::clone(&worker_gate);
        move || {
            worker_gate.wait();
            scripted_connection()
        }
    }));
    let make_job = || {
        let (result_tx, _result_rx) = std::sync::mpsc::sync_channel(1);
        DeliveryJob {
            envelope: test_envelope(),
            message: test_message(),
            signature: b"sig".to_vec(),
            result_tx,
        }
    };

    pool.enqueue(make_job()).unwrap();
    pool.enqueue(make_job()).unwrap();

    let (finished_tx, finished_rx) = std::sync::mpsc::sync_channel(1);
    let blocked_submitter = {
        let pool = Arc::clone(&pool);
        thread::spawn(move || {
            let (result_tx, _result_rx) = std::sync::mpsc::sync_channel(1);
            pool.enqueue(DeliveryJob {
                envelope: test_envelope(),
                message: test_message(),
                signature: b"sig".to_vec(),
                result_tx,
            })
            .unwrap();
            finished_tx.send(()).unwrap();
        })
    };
    assert!(finished_rx
        .recv_timeout(Duration::from_millis(100))
        .is_err());

    worker_gate.wait();
    finished_rx.recv_timeout(TIMEOUT).unwrap();
    blocked_submitter.join().unwrap();
}

#[test]
fn panicking_worker_delivery_reports_failure_and_recreates_connection() {
    let should_panic = Arc::new(AtomicBool::new(true));
    let pool = RelayPool::new(1, 1, {
        let should_panic = Arc::clone(&should_panic);
        move || {
            if should_panic.swap(false, Ordering::SeqCst) {
                SmtpConnection::new("test-client", || -> io::Result<SmtpStream> {
                    panic!("connector panic")
                })
            } else {
                scripted_connection()
            }
        }
    });

    let first = pool.submit(test_envelope(), test_message(), b"sig".to_vec());
    assert_eq!(first.status, DeliveryStatus::TemporaryFailure);
    assert!(!first.is_accepted());

    let second = pool.submit(test_envelope(), test_message(), b"sig".to_vec());
    assert!(second.is_accepted(), "{second:?}");
}

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

fn authenticated_tls_connection(server: &FakeSmarthost, pki: &TestPki) -> SmtpConnection {
    SmtpConnection::new_implicit_tls_with_auth(
        "test-client",
        "localhost",
        server.addr.port(),
        TLS_TIMEOUT,
        Some(&pki.ca_file),
        "alice".to_owned(),
        Secret::new(b"s3cret".to_vec()),
    )
    .expect("construct authenticated TLS connector")
}

#[test]
fn tls_auth_plain_occurs_after_ehlo_and_before_mail() {
    let pki = TestPki::localhost();
    let server = FakeSmarthost::start_tls(
        SmarthostConfig {
            ehlo_response: b"250-localhost\r\n250-aUtH login PLAIN\r\n250 OK\r\n".to_vec(),
            ..SmarthostConfig::default()
        },
        pki.acceptor(),
    );
    let mut connection = authenticated_tls_connection(&server, &pki);
    let result = connection.deliver(&test_envelope(), b"sig", b"body\r\n");
    drop(connection);
    let observed = server.join();

    assert!(result.is_accepted(), "{result:?}");
    assert_eq!(observed.commands[0], b"EHLO test-client\r\n");
    assert_eq!(observed.commands[1], b"AUTH PLAIN AGFsaWNlAHMzY3JldA==\r\n");
    assert!(observed.commands[2].starts_with(b"MAIL FROM:"));
}

#[test]
fn tls_without_credentials_omits_auth() {
    let pki = TestPki::localhost();
    let server = FakeSmarthost::start_tls(
        SmarthostConfig {
            ehlo_response: b"250-localhost\r\n250 AUTH PLAIN\r\n".to_vec(),
            ..SmarthostConfig::default()
        },
        pki.acceptor(),
    );
    let mut connection = tls_connection(&server, "localhost", Some(&pki.ca_file));
    assert!(connection
        .deliver(&test_envelope(), b"sig", b"body\r\n")
        .is_accepted());
    drop(connection);
    let observed = server.join();
    assert!(!observed
        .commands
        .iter()
        .any(|command| command.starts_with(b"AUTH ")));
}

#[test]
fn tls_auth_reply_is_classified_and_diagnostics_are_redacted() {
    for (response, expected) in [
        (
            b"454 temporary auth failure\r\n".as_slice(),
            DeliveryStatus::TemporaryFailure,
        ),
        (
            b"535 permanent auth failure\r\n".as_slice(),
            DeliveryStatus::PermanentFailure,
        ),
    ] {
        let pki = TestPki::localhost();
        let server = FakeSmarthost::start_tls(
            SmarthostConfig {
                ehlo_response: b"250-localhost\r\n250 AUTH PLAIN\r\n".to_vec(),
                auth_response: response.to_vec(),
                ..SmarthostConfig::default()
            },
            pki.acceptor(),
        );
        let mut connection = authenticated_tls_connection(&server, &pki);
        let result = connection.deliver(&test_envelope(), b"sig", b"body\r\n");
        drop(connection);
        let observed = server.join();
        assert_eq!(result.status, expected, "{result:?}");
        assert!(!result.diagnostic.contains("alice"));
        assert!(!result.diagnostic.contains("s3cret"));
        assert!(!result.diagnostic.contains("AGFsaWNlAHMzY3JldA=="));
        assert!(!observed
            .commands
            .iter()
            .any(|command| command.starts_with(b"MAIL ")));
    }
}

#[test]
fn tls_auth_requires_advertised_plain_without_sending_credentials() {
    let pki = TestPki::localhost();
    let server = FakeSmarthost::start_tls(SmarthostConfig::default(), pki.acceptor());
    let mut connection = authenticated_tls_connection(&server, &pki);
    let result = connection.deliver(&test_envelope(), b"sig", b"body\r\n");
    drop(connection);
    let observed = server.join();
    assert_eq!(result.status, DeliveryStatus::PermanentFailure);
    assert_eq!(observed.commands, vec![b"EHLO test-client\r\n".to_vec()]);
}

#[test]
fn tls_auth_is_once_per_session_not_per_message() {
    let pki = TestPki::localhost();
    let config = SmarthostConfig {
        ehlo_response: b"250-localhost\r\n250 AUTH PLAIN\r\n".to_vec(),
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start_tls(config, pki.acceptor());
    let mut connection = authenticated_tls_connection(&server, &pki);
    assert!(connection
        .deliver(&test_envelope(), b"one", b"first\r\n")
        .is_accepted());
    assert!(connection
        .deliver(&test_envelope(), b"two", b"second\r\n")
        .is_accepted());
    drop(connection);
    let observed = server.join();
    assert_eq!(
        observed
            .commands
            .iter()
            .filter(|command| command.starts_with(b"AUTH "))
            .count(),
        1
    );
}

#[test]
fn tls_auth_repeats_after_reconnect() {
    let pki = TestPki::localhost();
    let config = SmarthostConfig {
        ehlo_response: b"250-localhost\r\n250 AUTH PLAIN\r\n".to_vec(),
        ..SmarthostConfig::default()
    };
    let server = FakeSmarthost::start_tls_connections(
        vec![
            SmarthostConfig {
                close_point: ClosePoint::AfterDataReply,
                ..config.clone()
            },
            config,
        ],
        pki.acceptor(),
    );
    let mut connection = authenticated_tls_connection(&server, &pki);
    assert!(connection
        .deliver(&test_envelope(), b"one", b"first\r\n")
        .is_accepted());
    assert!(connection
        .deliver(&test_envelope(), b"two", b"second\r\n")
        .is_accepted());
    drop(connection);
    let observed = server.join();
    assert_eq!(observed.accepted_connections, 2);
    assert_eq!(
        observed
            .commands
            .iter()
            .filter(|command| command.starts_with(b"AUTH "))
            .count(),
        2
    );
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

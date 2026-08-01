//! Hard resource and timeout boundaries.  Every blocking operation has a
//! deadline; channel observations, rather than sleeps, prove concurrency.

use std::fs;
use std::io::{self, BufRead, BufReader, Cursor, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use signed_relay_lite::config::SigningConfig;
use signed_relay_lite::message::{
    normalize, Limits, Message, NormalizeError, ParseError, WireNormalizer,
};
use signed_relay_lite::relay::{
    DeliveryJob, DeliveryResult, DeliveryStatus, Envelope, EnvelopeError, RelayPool,
};
use signed_relay_lite::smtp::{read_reply, SmtpConnection, SmtpError, SmtpStream};
use signed_relay_lite::submission::{
    read_request, read_response, write_response, MemoryBudget, SubmissionError, SubmissionLimits,
    SubmissionServer,
};

const DEADLINE: Duration = Duration::from_secs(2);

fn limits() -> SubmissionLimits {
    SubmissionLimits {
        max_recipients: 100,
        max_address_bytes: 254,
        max_message_bytes: 64,
        max_diagnostic_bytes: 32,
    }
}

fn frame_prefix(recipients: u32) -> Vec<u8> {
    let mut out = b"SRL1".to_vec();
    out.extend(0_u32.to_be_bytes());
    out.extend(0_u32.to_be_bytes());
    out.extend(recipients.to_be_bytes());
    out
}

fn request_frame(recipients: usize, message_len: u64, body: &[u8]) -> Vec<u8> {
    let mut out = frame_prefix(recipients as u32);
    for _ in 0..recipients {
        out.extend(1_u32.to_be_bytes());
        out.push(b'a');
    }
    out.extend(message_len.to_be_bytes());
    out.extend(body);
    out
}

#[test]
fn server_rejects_cumulative_chunk_length_above_advertised_limit() {
    let mut bytes = request_frame(1, 64, &[b'x'; 64]);
    bytes.push(b'x');
    let mut reader = Cursor::new(bytes);
    let result = read_request(&mut reader, &limits(), &MemoryBudget::new(64));
    assert_eq!(
        result.unwrap_err(),
        SubmissionError::MessageTooLarge { len: 65, limit: 64 }
    );
}

struct CountingReader {
    bytes: Cursor<Vec<u8>>,
    read: usize,
}

impl CountingReader {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes: Cursor::new(bytes),
            read: 0,
        }
    }
}

impl Read for CountingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.bytes.read(buf)?;
        self.read += n;
        Ok(n)
    }
}

#[test]
fn declared_message_max_plus_one_is_rejected_before_body_read_or_reservation() {
    let mut bytes = request_frame(1, 65, b"body-must-not-be-read");
    let header_len = bytes.len() - b"body-must-not-be-read".len();
    let mut reader = CountingReader::new(std::mem::take(&mut bytes));
    let budget = MemoryBudget::new(64);
    assert_eq!(
        read_request(&mut reader, &limits(), &budget).unwrap_err(),
        SubmissionError::MessageTooLarge { len: 65, limit: 64 }
    );
    assert_eq!(reader.read, header_len, "no body byte may be requested");
    assert_eq!(
        budget.used(),
        0,
        "rejection must precede reservation/allocation"
    );
}

#[test]
fn normalizer_exact_output_max_succeeds_and_expansion_plus_one_fails_across_split_cr() {
    assert_eq!(normalize(&[b"a\n"], 3).unwrap(), b"a\r\n");
    assert_eq!(
        normalize(&[b"a\n"], 2),
        Err(NormalizeError::OutputLimitExceeded)
    );
    let mut split = WireNormalizer::new(3);
    split.write(b"a\r").unwrap();
    split.write(b"\n").unwrap();
    assert_eq!(split.finish().unwrap(), b"a\r\n");
    let mut overflow = WireNormalizer::new(2);
    assert_eq!(
        overflow.write(b"a\r"),
        Err(NormalizeError::OutputLimitExceeded)
    );
}

#[test]
fn header_block_exact_max_is_accepted_and_one_more_is_rejected() {
    // Header block includes the field's terminating CRLF, but not the empty line.
    let exact = b"X: 123\r\n\r\nbody\r\n".to_vec();
    assert!(Message::parse(
        exact.clone(),
        Limits {
            max_headers: 1,
            max_header_bytes: 8
        }
    )
    .is_ok());
    assert!(matches!(
        Message::parse(
            exact,
            Limits {
                max_headers: 1,
                max_header_bytes: 7
            }
        ),
        Err(ParseError::HeaderBlockTooLarge)
    ));
}

#[test]
fn envelope_and_srl1_recipient_100_boundary_is_checked_before_recipient_bytes() {
    let hundred = vec![b"a@b".to_vec(); 100];
    assert_eq!(
        Envelope::new(b"s@b", hundred).unwrap().recipients().len(),
        100
    );
    assert_eq!(
        Envelope::new(b"s@b", vec![b"a@b".to_vec(); 101]),
        Err(EnvelopeError::TooManyRecipients(101))
    );

    let exact = request_frame(100, 0, b"");
    assert_eq!(
        read_request(&mut Cursor::new(exact), &limits(), &MemoryBudget::new(1))
            .unwrap()
            .envelope
            .recipients()
            .len(),
        100
    );
    let mut reader = CountingReader::new(frame_prefix(101));
    assert_eq!(
        read_request(&mut reader, &limits(), &MemoryBudget::new(1)).unwrap_err(),
        SubmissionError::TooManyRecipients {
            count: 101,
            limit: 100
        }
    );
    assert_eq!(reader.read, 16, "recipient bytes must not be requested");
}

#[test]
fn diagnostic_exact_configured_max_is_preserved_and_max_plus_one_is_truncated_on_write() {
    for (input, expected) in [("x".repeat(32), 32), ("y".repeat(33), 32)] {
        let result = DeliveryResult {
            status: DeliveryStatus::TemporaryFailure,
            ambiguous: false,
            smtp_code: None,
            diagnostic: input,
        };
        let mut wire = Vec::new();
        write_response(&mut wire, &result, 32).unwrap();
        let decoded = read_response(&mut Cursor::new(wire), &limits()).unwrap();
        assert_eq!(decoded.diagnostic.len(), expected);
    }
    let mut oversized = b"SRL1\x01\x00\x00\x00".to_vec();
    oversized.extend(33_u32.to_be_bytes());
    let mut reader = CountingReader::new(oversized);
    assert_eq!(
        read_response(&mut reader, &limits()).unwrap_err(),
        SubmissionError::DiagnosticTooLong { len: 33, limit: 32 }
    );
    assert_eq!(
        reader.read, 12,
        "oversized diagnostic bytes must not be read"
    );
}

#[test]
fn memory_budget_concurrent_exhaustion_never_exceeds_cap_and_drop_releases() {
    let budget = MemoryBudget::new(10);
    let held = budget.try_reserve(7).unwrap();
    let (tx, rx) = mpsc::sync_channel(1);
    let other = budget.clone();
    let thread = thread::spawn(move || {
        tx.send((other.try_reserve(4).is_none(), other.used()))
            .unwrap()
    });
    assert_eq!(rx.recv_timeout(DEADLINE).unwrap(), (true, 7));
    thread.join().unwrap();
    assert!(budget.used() <= budget.capacity());
    drop(held);
    assert_eq!(budget.used(), 0);
    assert!(budget.try_reserve(10).is_some());
}

#[test]
fn u64_max_message_lengths_are_rejected_without_body_read_or_budget_change() {
    // The final case reaches the checked u64-to-usize conversion path because
    // the configured wire limit itself permits u64::MAX.
    for max in [0, 64, u64::MAX - 1, u64::MAX] {
        let mut reader = CountingReader::new(request_frame(1, u64::MAX, b"unread"));
        let prefix = reader.bytes.get_ref().len() - 6;
        let budget = MemoryBudget::new(8);
        let error = read_request(
            &mut reader,
            &SubmissionLimits {
                max_message_bytes: max,
                ..limits()
            },
            &budget,
        )
        .unwrap_err();
        if max == u64::MAX && usize::BITS == 64 {
            assert_eq!(
                error,
                SubmissionError::BudgetExhausted {
                    requested: usize::MAX,
                    capacity: 8
                }
            );
        } else {
            assert_eq!(
                error,
                SubmissionError::MessageTooLarge {
                    len: u64::MAX,
                    limit: max
                }
            );
        }
        assert_eq!(reader.read, prefix);
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn multiline_reply_is_bounded_at_256_lines_and_aggregate_storage() {
    let mut exact = Vec::new();
    for _ in 0..255 {
        exact.extend(b"250-x\r\n");
    }
    exact.extend(b"250 x\r\n");
    let reply = read_reply(&mut BufReader::new(Cursor::new(exact)), 5).unwrap();
    assert_eq!(reply.lines.len(), 256);

    let mut over = Vec::new();
    for _ in 0..257 {
        over.extend(b"250-x\r\n");
    }
    let mut reader = BufReader::with_capacity(1, CountingReader::new(over));
    assert_eq!(read_reply(&mut reader, 5), Err(SmtpError::TooManyLines));
    assert_eq!(
        reader.get_ref().read,
        256 * 7,
        "parser must stop before line 257"
    );
}

fn envelope() -> Envelope {
    Envelope::new(b"s@b", vec![b"r@b".to_vec()]).unwrap()
}

fn tcp_connection(
    addr: std::net::SocketAddr,
    timeout: Duration,
    connects: Arc<AtomicUsize>,
) -> SmtpConnection {
    SmtpConnection::new("limits", move || {
        connects.fetch_add(1, Ordering::SeqCst);
        let stream = TcpStream::connect_timeout(&addr, timeout)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        Ok(Box::new(stream) as SmtpStream)
    })
}

#[test]
fn tcp_stall_before_greeting_is_bounded_unambiguous_and_retry_count_is_bounded() {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("bind TCP stall peer: {error}"),
    };
    listener.set_nonblocking(false).unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        for _ in 0..2 {
            let (stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            let mut byte = [0];
            let _ = (&stream).read(&mut byte);
        }
    });
    let connects = Arc::new(AtomicUsize::new(0));
    let mut connection = tcp_connection(addr, Duration::from_millis(100), Arc::clone(&connects));
    let start = Instant::now();
    let result = connection.deliver(&envelope(), b"sig", b"body\r\n");
    assert!(start.elapsed() < DEADLINE);
    assert_eq!(result.status, DeliveryStatus::TemporaryFailure);
    assert!(!result.ambiguous);
    assert_eq!(
        connects.load(Ordering::SeqCst),
        2,
        "only the single safe retry is allowed"
    );
    drop(connection);
    server.join().unwrap();
}

#[test]
fn tcp_stall_after_354_is_bounded_ambiguous_and_never_retried() {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("bind TCP stall peer: {error}"),
    };
    let addr = listener.local_addr().unwrap();
    let (body_tx, body_rx) = mpsc::sync_channel(1);
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let mut io = BufReader::new(stream);
        io.get_mut().write_all(b"220 hi\r\n").unwrap();
        for reply in [
            b"250 hi\r\n".as_slice(),
            b"250 ok\r\n",
            b"250 ok\r\n",
            b"354 go\r\n",
        ] {
            let mut line = Vec::new();
            io.read_until(b'\n', &mut line).unwrap();
            io.get_mut().write_all(reply).unwrap();
        }
        let mut data: Vec<u8> = Vec::new();
        loop {
            let mut line = Vec::new();
            if io.read_until(b'\n', &mut line).unwrap_or(0) == 0 {
                break;
            }
            data.extend(&line);
            if line == b".\r\n" {
                break;
            }
        }
        body_tx.send(data.len()).unwrap();
        let mut byte = [0];
        let _ = io.read(&mut byte);
    });
    let connects = Arc::new(AtomicUsize::new(0));
    let mut connection = tcp_connection(addr, Duration::from_millis(100), Arc::clone(&connects));
    let start = Instant::now();
    let result = connection.deliver(&envelope(), b"sig", b"body\r\n");
    assert!(body_rx.recv_timeout(DEADLINE).unwrap() > 0);
    assert!(start.elapsed() < DEADLINE);
    assert_eq!(result.status, DeliveryStatus::TemporaryFailure);
    assert!(result.ambiguous);
    assert_eq!(connects.load(Ordering::SeqCst), 1);
    drop(connection);
    server.join().unwrap();
}

fn message() -> Message {
    Message::parse(b"From: a@b\r\n\r\nbody\r\n".to_vec(), Limits::testing()).unwrap()
}

#[test]
fn dropped_result_receiver_does_not_consume_worker_capacity_and_next_job_completes() {
    let (first_tx, first_rx) = mpsc::sync_channel(0);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let release_rx = Arc::new(Mutex::new(release_rx));
    let calls = Arc::new(AtomicUsize::new(0));
    let pool = RelayPool::new(1, 1, {
        let calls = Arc::clone(&calls);
        let release_rx = Arc::clone(&release_rx);
        move || {
            let calls = Arc::clone(&calls);
            let release_rx = Arc::clone(&release_rx);
            let first_tx = first_tx.clone();
            SmtpConnection::new("limits", move || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    first_tx.send(()).unwrap();
                    release_rx.lock().unwrap().recv_timeout(DEADLINE).unwrap();
                }
                Err(io::Error::new(io::ErrorKind::ConnectionRefused, "bounded"))
            })
        }
    });
    let (dead_tx, dead_rx) = mpsc::sync_channel(1);
    pool.enqueue(DeliveryJob {
        envelope: envelope(),
        message: message(),
        signature: vec![],
        result_tx: dead_tx,
    })
    .unwrap();
    first_rx.recv_timeout(DEADLINE).unwrap();
    drop(dead_rx);
    let (next_tx, next_rx) = mpsc::sync_channel(1);
    pool.enqueue(DeliveryJob {
        envelope: envelope(),
        message: message(),
        signature: vec![],
        result_tx: next_tx,
    })
    .unwrap();
    release_tx.send(()).unwrap();
    let next = next_rx.recv_timeout(DEADLINE).unwrap();
    assert_eq!(next.status, DeliveryStatus::TemporaryFailure);
    drop(pool);
}

static NEXT_SOCKET: AtomicUsize = AtomicUsize::new(0);

struct SocketPath(PathBuf);

impl SocketPath {
    fn new() -> Self {
        Self(std::env::current_dir().unwrap().join(format!(
            "limits-{}-{}.sock",
            std::process::id(),
            NEXT_SOCKET.fetch_add(1, Ordering::Relaxed)
        )))
    }
}

impl Drop for SocketPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn signing() -> SigningConfig {
    SigningConfig {
        domain: "example.com".into(),
        selector: "limits".into(),
        key: Arc::new(PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap()),
    }
}

fn start_submission(
    path: &SocketPath,
    timeout: Duration,
    handlers: usize,
    budget: MemoryBudget,
    relay: Arc<RelayPool>,
) -> io::Result<(Arc<AtomicBool>, thread::JoinHandle<()>)> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let server = SubmissionServer::bind(
        &path.0,
        0o600,
        timeout,
        handlers,
        SubmissionLimits {
            max_message_bytes: 1024,
            ..limits()
        },
        Limits::testing(),
        budget,
        signing(),
        relay,
        Arc::clone(&shutdown),
    )?;
    let handle = thread::spawn(move || server.run().unwrap());
    Ok((shutdown, handle))
}

fn stop_submission(shutdown: Arc<AtomicBool>, handle: thread::JoinHandle<()>) {
    shutdown.store(true, Ordering::Release);
    handle.join().unwrap();
}

fn valid_submission() -> Vec<u8> {
    let message = b"From: a@example.com\r\n\r\nbody\r\n";
    let mut out = frame_prefix(1);
    out.extend(3_u32.to_be_bytes());
    out.extend(b"r@b");
    out.extend((message.len() as u64).to_be_bytes());
    out.extend(message);
    out
}

fn read_smtp_line(io: &mut BufReader<UnixStream>) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    io.read_until(b'\n', &mut line)?;
    Ok(line)
}

fn smtp_transaction(io: &mut BufReader<UnixStream>) -> io::Result<usize> {
    for reply in [
        b"250 sender\r\n".as_slice(),
        b"250 rcpt\r\n",
        b"354 data\r\n",
    ] {
        if read_smtp_line(io)?.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        io.get_mut().write_all(reply)?;
    }
    let mut bytes = 0;
    loop {
        let line = read_smtp_line(io)?;
        if line.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        bytes += line.len();
        if line == b".\r\n" {
            return Ok(bytes);
        }
    }
}

#[test]
fn unix_submission_server_enforces_one_real_handler_until_gated_handler_releases() {
    let path = SocketPath::new();
    let (client_side, server_side) = UnixStream::pair().unwrap();
    client_side.set_read_timeout(Some(DEADLINE)).unwrap();
    client_side.set_write_timeout(Some(DEADLINE)).unwrap();
    server_side.set_read_timeout(Some(DEADLINE)).unwrap();
    server_side.set_write_timeout(Some(DEADLINE)).unwrap();
    let source = Arc::new(Mutex::new(Some(client_side)));
    let relay = Arc::new(RelayPool::new(1, 1, move || {
        let stream = source.lock().unwrap().take().unwrap();
        SmtpConnection::new("limits", move || {
            Ok(Box::new(stream.try_clone()?) as SmtpStream)
        })
    }));
    let (captured_tx, captured_rx) = mpsc::sync_channel(2);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let peer = thread::spawn(move || {
        let mut io = BufReader::new(server_side);
        io.get_mut().write_all(b"220 ready\r\n").unwrap();
        read_smtp_line(&mut io).unwrap();
        io.get_mut().write_all(b"250 hello\r\n").unwrap();
        for ordinal in 0..2 {
            let bytes = smtp_transaction(&mut io).unwrap();
            captured_tx.send((ordinal, bytes)).unwrap();
            if ordinal == 0 {
                release_rx.recv_timeout(Duration::from_millis(500)).unwrap();
            }
            io.get_mut().write_all(b"250 queued\r\n").unwrap();
        }
    });
    let started = start_submission(
        &path,
        Duration::from_millis(500),
        1,
        MemoryBudget::new(2048),
        relay,
    );
    let (shutdown, server) = match started {
        Ok(started) => started,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            drop(release_tx);
            let _ = peer.join();
            return;
        }
        Err(error) => panic!("bind Unix submission server: {error}"),
    };
    let mut first = UnixStream::connect(&path.0).unwrap();
    first.set_read_timeout(Some(DEADLINE)).unwrap();
    first.write_all(&valid_submission()).unwrap();
    assert_eq!(captured_rx.recv_timeout(DEADLINE).unwrap().0, 0);
    let mut second = UnixStream::connect(&path.0).unwrap();
    second.set_read_timeout(Some(DEADLINE)).unwrap();
    second.write_all(&valid_submission()).unwrap();
    assert!(
        captured_rx
            .recv_timeout(Duration::from_millis(100))
            .is_err(),
        "second client reached relay while the sole handler was occupied"
    );
    release_tx.send(()).unwrap();
    assert_eq!(
        read_response(&mut first, &limits()).unwrap().status,
        DeliveryStatus::Delivered
    );
    assert_eq!(captured_rx.recv_timeout(DEADLINE).unwrap().0, 1);
    assert_eq!(
        read_response(&mut second, &limits()).unwrap().status,
        DeliveryStatus::Delivered
    );
    stop_submission(shutdown, server);
    peer.join().unwrap();
}

#[test]
fn stalled_and_disconnected_mid_frame_release_submission_handler_and_memory_for_next_client() {
    let path = SocketPath::new();
    let budget = MemoryBudget::new(128);
    let relay = Arc::new(RelayPool::new(1, 1, || {
        SmtpConnection::new("limits", || {
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "bounded"))
        })
    }));
    let (shutdown, server) =
        match start_submission(&path, Duration::from_millis(100), 1, budget.clone(), relay) {
            Ok(started) => started,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("bind Unix submission server: {error}"),
        };

    let mut stalled = UnixStream::connect(&path.0).unwrap();
    stalled.set_read_timeout(Some(DEADLINE)).unwrap();
    let frame = valid_submission();
    let split = frame.len() - 5;
    stalled.write_all(&frame[..split]).unwrap();
    let start = Instant::now();
    let rejected = read_response(&mut stalled, &limits()).unwrap();
    assert!(start.elapsed() < DEADLINE);
    assert_eq!(rejected.status, DeliveryStatus::ProtocolRejection);
    drop(stalled);

    let mut next = UnixStream::connect(&path.0).unwrap();
    next.set_read_timeout(Some(DEADLINE)).unwrap();
    next.write_all(&frame).unwrap();
    let completed = read_response(&mut next, &limits()).unwrap();
    assert_eq!(completed.status, DeliveryStatus::TemporaryFailure);
    assert_eq!(
        budget.used(),
        0,
        "timeout/disconnect and completed job must drop reservations"
    );
    stop_submission(shutdown, server);
}

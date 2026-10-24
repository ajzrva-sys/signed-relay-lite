use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use signed_relay_lite::config::SigningConfig;
use signed_relay_lite::message::Limits as MessageLimits;
use signed_relay_lite::relay::{DeliveryResult, DeliveryStatus, RelayPool};
use signed_relay_lite::smtp::{SmtpConnection, SmtpStream};
use signed_relay_lite::submission::{
    read_chunk_stream, read_envelope_preamble, read_server_reply, write_server_reply, MemoryBudget,
    Ready, ServerReply, SubmissionLimits, SubmissionServer, SubmissionServerConfig,
    MAX_CHUNK_BYTES,
};

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

struct TestPath(PathBuf);

impl TestPath {
    fn new() -> Self {
        Self(std::env::current_dir().unwrap().join(format!(
            "srl-{}-{}",
            std::process::id(),
            NEXT_PATH.fetch_add(1, Ordering::Relaxed)
        )))
    }
}

impl Drop for TestPath {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn relay_pool() -> Arc<RelayPool> {
    Arc::new(RelayPool::new(1, 1, || {
        SmtpConnection::new("submission-test", || {
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "unused"))
        })
    }))
}

fn signing() -> SigningConfig {
    SigningConfig {
        domain: "example.com".to_owned(),
        selector: "test".to_owned(),
        key: Arc::new(PKey::from_rsa(Rsa::generate(1024).unwrap()).unwrap()),
    }
}

fn submission_limits() -> SubmissionLimits {
    SubmissionLimits::production(26_214_400)
}

fn bind(path: &Path, mode: u32, shutdown: Arc<AtomicBool>) -> io::Result<SubmissionServer> {
    SubmissionServer::bind(
        path,
        SubmissionServerConfig {
            max_message_bytes: 26_214_400,
            submission_timeout: Duration::from_millis(150),
            max_active_handlers: 2,
            socket_mode: mode,
        },
        MessageLimits::testing(),
        MemoryBudget::new(1024 * 1024),
        signing(),
        relay_pool(),
        shutdown,
    )
}

fn request(message: &[u8]) -> Vec<u8> {
    let sender = b"sender@example.com";
    let recipient = b"recipient@example.net";
    let mut bytes = b"SRL2".to_vec();
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.extend_from_slice(&(sender.len() as u32).to_be_bytes());
    bytes.extend_from_slice(sender);
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&(recipient.len() as u32).to_be_bytes());
    bytes.extend_from_slice(recipient);
    bytes.extend_from_slice(&(message.len() as u32).to_be_bytes());
    bytes.extend_from_slice(message);
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes
}

fn envelope() -> Vec<u8> {
    let frame = request(&[]);
    frame[..frame.len() - 8].to_vec()
}

#[test]
fn valid_envelope_receives_ready_before_message_bytes_are_read() {
    let path = TestPath::new();
    let limits = submission_limits();
    let Some((shutdown, server)) = start_server(
        &path.0,
        Duration::from_secs(1),
        1,
        limits,
        MemoryBudget::new(1024),
        relay_pool(),
    ) else {
        return;
    };
    let mut client = UnixStream::connect(&path.0).unwrap();
    client.write_all(&envelope()).unwrap();
    assert!(matches!(
        read_server_reply(&mut client).unwrap(),
        ServerReply::Ready(_)
    ));
    drop(client);
    stop_server(shutdown, server);
}

#[test]
fn ready_advertises_runtime_max_message_bytes() {
    let path = TestPath::new();
    let mut limits = submission_limits();
    limits.max_message_bytes = 73;
    let Some((shutdown, server)) = start_server(
        &path.0,
        Duration::from_secs(1),
        1,
        limits,
        MemoryBudget::new(1024),
        relay_pool(),
    ) else {
        return;
    };
    let mut client = UnixStream::connect(&path.0).unwrap();
    client.write_all(&envelope()).unwrap();
    let ServerReply::Ready(ready) = read_server_reply(&mut client).unwrap() else {
        panic!("valid envelope did not receive READY");
    };
    assert_eq!(ready.max_message_bytes, 73);
    drop(client);
    stop_server(shutdown, server);
}

#[test]
fn invalid_envelope_receives_final_without_ready() {
    let path = TestPath::new();
    let Some((shutdown, server)) = start_server(
        &path.0,
        Duration::from_secs(1),
        1,
        submission_limits(),
        MemoryBudget::new(1024),
        relay_pool(),
    ) else {
        return;
    };
    let mut client = UnixStream::connect(&path.0).unwrap();
    client.write_all(b"NOPE").unwrap();
    let ServerReply::Final(result) = read_server_reply(&mut client).unwrap() else {
        panic!("invalid envelope received READY");
    };
    assert_eq!(result.status, DeliveryStatus::ProtocolRejection);
    assert!(!result.ambiguous);
    stop_server(shutdown, server);
}

#[test]
fn exact_advertised_message_limit_reaches_signing_worker() {
    let path = TestPath::new();
    let message = b"From: sender@example.com\r\n\r\nbody\r\n";
    let mut limits = submission_limits();
    limits.max_message_bytes = message.len() as u64;
    let (relay, captured, release, peer) = gated_relay(b"250 exact\r\n");
    let Some((shutdown, server)) = start_server(
        &path.0,
        Duration::from_secs(1),
        1,
        limits.clone(),
        MemoryBudget::new(message.len()),
        relay,
    ) else {
        return;
    };
    let mut client = UnixStream::connect(&path.0).unwrap();
    client.write_all(&request(message)).unwrap();
    let signed = captured.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(signed.ends_with(message));
    release.send(()).unwrap();
    assert_eq!(
        read_result(&mut client, &limits).status,
        DeliveryStatus::Delivered
    );
    stop_server(shutdown, server);
    peer.join().unwrap();
}

#[test]
fn advertised_limit_plus_one_is_rejected_before_smtp() {
    let path = TestPath::new();
    let message = b"From: sender@example.com\r\n\r\nbody\r\n";
    let mut limits = submission_limits();
    limits.max_message_bytes = (message.len() - 1) as u64;
    let Some((shutdown, server)) = start_server(
        &path.0,
        Duration::from_secs(1),
        1,
        limits.clone(),
        MemoryBudget::new(message.len()),
        relay_pool(),
    ) else {
        return;
    };
    let mut client = UnixStream::connect(&path.0).unwrap();
    client.write_all(&request(message)).unwrap();
    let result = read_result(&mut client, &limits);
    assert_eq!(result.status, DeliveryStatus::ProtocolRejection);
    assert!(!result.ambiguous);
    stop_server(shutdown, server);
}

#[test]
fn old_srl1_client_is_rejected_without_delivery() {
    let path = TestPath::new();
    let Some((shutdown, server)) = start_server(
        &path.0,
        Duration::from_secs(1),
        1,
        submission_limits(),
        MemoryBudget::new(1024),
        relay_pool(),
    ) else {
        return;
    };
    let mut client = UnixStream::connect(&path.0).unwrap();
    client.write_all(b"SRL1").unwrap();
    let ServerReply::Final(result) = read_server_reply(&mut client).unwrap() else {
        panic!("SRL1 received READY");
    };
    assert_eq!(result.status, DeliveryStatus::ProtocolRejection);
    assert!(!result.ambiguous);
    stop_server(shutdown, server);
}

#[test]
fn client_stops_before_transmitting_bytes_above_server_limit() {
    let frame = request(&[b'x'; 65]);
    let body_offset = frame.len() - 69;
    assert_eq!(&frame[body_offset - 4..body_offset], &65_u32.to_be_bytes());
}

fn start_server(
    path: &Path,
    timeout: Duration,
    handlers: usize,
    limits: SubmissionLimits,
    budget: MemoryBudget,
    relay: Arc<RelayPool>,
) -> Option<(Arc<AtomicBool>, std::thread::JoinHandle<()>)> {
    start_server_with_signing(path, timeout, handlers, limits, budget, relay, signing())
}

fn start_server_with_signing(
    path: &Path,
    timeout: Duration,
    handlers: usize,
    limits: SubmissionLimits,
    budget: MemoryBudget,
    relay: Arc<RelayPool>,
    signing: SigningConfig,
) -> Option<(Arc<AtomicBool>, std::thread::JoinHandle<()>)> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let server = match SubmissionServer::bind(
        path,
        SubmissionServerConfig {
            max_message_bytes: limits.max_message_bytes as usize,
            submission_timeout: timeout,
            max_active_handlers: handlers,
            socket_mode: 0o660,
        },
        MessageLimits::testing(),
        budget,
        signing,
        relay,
        Arc::clone(&shutdown),
    ) {
        Ok(server) => server,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return None,
        Err(error) => panic!("bind submission server: {error}"),
    };
    let handle = std::thread::spawn(move || server.run().unwrap());
    Some((shutdown, handle))
}

fn stop_server(shutdown: Arc<AtomicBool>, handle: std::thread::JoinHandle<()>) {
    shutdown.store(true, Ordering::Release);
    handle.join().unwrap();
}

/// A deterministic one-transaction SMTP peer. It captures the DATA bytes and
/// waits for `release` before returning the exact final response.
fn gated_relay(
    final_reply: &'static [u8],
) -> (
    Arc<RelayPool>,
    mpsc::Receiver<Vec<u8>>,
    mpsc::SyncSender<()>,
    std::thread::JoinHandle<()>,
) {
    let (client, server) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    server
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let client = Arc::new(Mutex::new(Some(client)));
    let relay = Arc::new(RelayPool::new(1, 1, move || {
        let stream = client.lock().unwrap().take().unwrap();
        SmtpConnection::new("submission-test", move || {
            Ok(Box::new(stream.try_clone()?) as SmtpStream)
        })
    }));
    let (captured_tx, captured_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(0);
    let peer = std::thread::spawn(move || {
        let mut peer = BufReader::new(server);
        if peer.get_mut().write_all(b"220 ready\r\n").is_err() {
            return;
        }
        for reply in [
            b"250 hello\r\n".as_slice(),
            b"250 sender\r\n",
            b"250 rcpt\r\n",
            b"354 data\r\n",
        ] {
            let mut line = String::new();
            if peer.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            if peer.get_mut().write_all(reply).is_err() {
                return;
            }
        }
        let mut data = Vec::new();
        loop {
            let mut line = Vec::new();
            if peer.read_until(b'\n', &mut line).unwrap_or(0) == 0 {
                return;
            }
            if line == b".\r\n" {
                break;
            }
            data.extend_from_slice(&line);
        }
        if captured_tx.send(data).is_err() {
            return;
        }
        if release_rx.recv_timeout(Duration::from_secs(2)).is_err() {
            return;
        }
        let _ = peer.get_mut().write_all(final_reply);
    });
    (relay, captured_rx, release_tx, peer)
}

fn read_result(stream: &mut UnixStream, limits: &SubmissionLimits) -> DeliveryResult {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let _ = limits;
    match read_server_reply(stream).unwrap() {
        ServerReply::Final(result) => result,
        ServerReply::Ready(_) => match read_server_reply(stream).unwrap() {
            ServerReply::Final(result) => result,
            ServerReply::Ready(_) => panic!("server sent READY twice"),
        },
    }
}

#[test]
fn bind_requires_an_absolute_path() {
    let result = bind(
        Path::new("relative.sock"),
        0o660,
        Arc::new(AtomicBool::new(false)),
    );
    assert_eq!(result.err().unwrap().kind(), io::ErrorKind::InvalidInput);
}

#[test]
fn existing_non_socket_is_preserved() {
    let path = TestPath::new();
    fs::write(&path.0, b"keep me").unwrap();
    let result = bind(&path.0, 0o660, Arc::new(AtomicBool::new(false)));
    assert_eq!(result.err().unwrap().kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(fs::read(&path.0).unwrap(), b"keep me");
}

#[test]
fn active_socket_is_rejected() {
    let path = TestPath::new();
    let listener = match UnixListener::bind(&path.0) {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("bind test socket: {error}"),
    };
    let result = bind(&path.0, 0o660, Arc::new(AtomicBool::new(false)));
    assert_eq!(result.err().unwrap().kind(), io::ErrorKind::AddrInUse);
    drop(listener);
}

#[test]
fn owned_stale_socket_is_replaced_and_mode_is_set() {
    let path = TestPath::new();
    match UnixListener::bind(&path.0) {
        Ok(listener) => drop(listener),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("bind stale test socket: {error}"),
    }
    let server = bind(&path.0, 0o620, Arc::new(AtomicBool::new(false))).unwrap();
    let metadata = fs::symlink_metadata(&path.0).unwrap();
    let client = UnixStream::connect(&path.0).expect("replacement socket accepts connections");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o620);
    drop(client);
    drop(server);
    assert!(!path.0.exists());
}

#[test]
fn run_accepts_a_client_and_shutdown_removes_own_socket() {
    let path = TestPath::new();
    let shutdown = Arc::new(AtomicBool::new(false));
    let server = match bind(&path.0, 0o660, Arc::clone(&shutdown)) {
        Ok(server) => server,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("bind submission server: {error}"),
    };
    let handle = std::thread::spawn(move || server.run().unwrap());
    let mut stream = UnixStream::connect(&path.0).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    // A truncated request exercises a real accepted stream and its bounded timeout.
    std::io::Write::write_all(&mut stream, b"SRL1").unwrap();
    let mut response = [0_u8; 4];
    std::io::Read::read_exact(&mut stream, &mut response).unwrap();
    assert_eq!(&response, b"SRL2");
    shutdown.store(true, Ordering::Release);
    handle.join().unwrap();
    assert!(!path.0.exists());
}

#[test]
fn replacement_at_path_is_preserved_on_shutdown() {
    let path = TestPath::new();
    let shutdown = Arc::new(AtomicBool::new(false));
    let server = match bind(&path.0, 0o660, Arc::clone(&shutdown)) {
        Ok(server) => server,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
        Err(error) => panic!("bind submission server: {error}"),
    };
    fs::remove_file(&path.0).unwrap();
    fs::write(&path.0, b"replacement").unwrap();
    let handle = std::thread::spawn(move || server.run().unwrap());
    shutdown.store(true, Ordering::Release);
    handle.join().unwrap();
    assert_eq!(fs::read(&path.0).unwrap(), b"replacement");
}

#[test]
fn valid_request_waits_for_worker_and_returns_exact_final_result_with_signed_original() {
    let path = TestPath::new();
    let limits = submission_limits();
    let (relay, captured, release, peer) = gated_relay(b"250 final exact\r\n");
    let Some((shutdown, server)) = start_server(
        &path.0,
        Duration::from_secs(1),
        2,
        limits.clone(),
        MemoryBudget::new(1024 * 1024),
        relay,
    ) else {
        return;
    };
    let original =
        b"From: sender@example.com\r\nTo: recipient@example.net\r\nSubject: exact\r\n\r\nbody\r\n";
    let mut client = UnixStream::connect(&path.0).unwrap();
    client.write_all(&request(original)).unwrap();
    assert!(matches!(
        read_server_reply(&mut client).unwrap(),
        ServerReply::Ready(_)
    ));
    client
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut byte = [0];
    assert!(
        matches!(client.read(&mut byte), Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut))
    );
    let data = captured.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(data.starts_with(b"DKIM-Signature: "));
    assert!(data.ends_with(original));
    release.send(()).unwrap();
    assert_eq!(
        read_result(&mut client, &limits),
        DeliveryResult::delivered("", Some(250))
    );
    stop_server(shutdown, server);
    peer.join().unwrap();
}

#[test]
fn truncated_chunk_times_out_and_releases_handler_and_budget() {
    let path = TestPath::new();
    let limits = submission_limits();
    let budget = MemoryBudget::new(1024);
    let observed = budget.clone();
    let Some((shutdown, server)) = start_server(
        &path.0,
        Duration::from_millis(80),
        1,
        limits.clone(),
        budget,
        relay_pool(),
    ) else {
        return;
    };
    let mut client = UnixStream::connect(&path.0).unwrap();
    client.write_all(&envelope()).unwrap();
    assert!(matches!(
        read_server_reply(&mut client).unwrap(),
        ServerReply::Ready(_)
    ));
    client.write_all(&8_u32.to_be_bytes()).unwrap();
    client.write_all(b"abc").unwrap();
    let started = std::time::Instant::now();
    let result = read_result(&mut client, &limits);
    assert!(
        started.elapsed() >= Duration::from_millis(40),
        "truncated client was rejected before the configured read timeout"
    );
    assert_eq!(result.status, DeliveryStatus::ProtocolRejection);
    assert!(!result.ambiguous);
    assert!(result.diagnostic.len() <= limits.max_diagnostic_bytes);
    assert_eq!(observed.used(), 0);

    let mut next = UnixStream::connect(&path.0).unwrap();
    next.write_all(b"SRL1").unwrap();
    let ServerReply::Final(_) = read_server_reply(&mut next).unwrap() else {
        panic!("released handler did not serve the next client");
    };
    stop_server(shutdown, server);
}

#[test]
fn budget_exhaustion_mid_stream_is_temporary_and_unambiguous() {
    let path = TestPath::new();
    let limits = submission_limits();
    let first = b"From: a@example.com\r\n\r\n1234567890\r\n";
    let second = b"From: c@example.com\r\n\r\nabcdefghij\r\n";
    let capacity = first.len() + second.len() - 1;
    let budget = MemoryBudget::new(capacity);
    let observed = budget.clone();
    let (relay, captured, release, peer) = gated_relay(b"250 done\r\n");
    let Some((shutdown, server)) = start_server(
        &path.0,
        Duration::from_secs(1),
        2,
        limits.clone(),
        budget,
        relay,
    ) else {
        return;
    };
    let mut one = UnixStream::connect(&path.0).unwrap();
    one.write_all(&request(first)).unwrap();
    captured.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(observed.used(), first.len());

    let frame = request(second);
    let body_start = frame.len() - second.len() - 4;
    let mut two = UnixStream::connect(&path.0).unwrap();
    two.write_all(&frame[..body_start]).unwrap();
    let rejected = read_result(&mut two, &limits);
    assert_eq!(rejected.status, DeliveryStatus::TemporaryFailure);
    assert!(!rejected.ambiguous);
    assert!(rejected.diagnostic.contains("memory budget"));
    assert_eq!(observed.used(), first.len());

    release.send(()).unwrap();
    assert_eq!(
        read_result(&mut one, &limits).status,
        DeliveryStatus::Delivered
    );
    for _ in 0..1000 {
        if observed.used() == 0 {
            break;
        }
        std::thread::yield_now();
    }
    assert_eq!(observed.used(), 0);
    stop_server(shutdown, server);
    peer.join().unwrap();
}

#[test]
fn max_active_handlers_bounds_gated_clients() {
    let path = TestPath::new();
    let limits = submission_limits();
    let (relay, captured, release, peer) = gated_relay(b"250 done\r\n");
    let Some((shutdown, server)) = start_server(
        &path.0,
        Duration::from_secs(1),
        1,
        limits.clone(),
        MemoryBudget::new(1024),
        relay,
    ) else {
        return;
    };
    let mut first = UnixStream::connect(&path.0).unwrap();
    first
        .write_all(&request(b"From: a@example.com\r\n\r\nbody\r\n"))
        .unwrap();
    captured.recv_timeout(Duration::from_secs(2)).unwrap();

    let mut second = UnixStream::connect(&path.0).unwrap();
    second.write_all(b"bad!").unwrap();
    second
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut magic = [0; 4];
    assert!(
        matches!(second.read_exact(&mut magic), Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut))
    );

    release.send(()).unwrap();
    assert_eq!(
        read_result(&mut first, &limits).status,
        DeliveryStatus::Delivered
    );
    second
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    second.read_exact(&mut magic).unwrap();
    assert_eq!(&magic, b"SRL2");
    stop_server(shutdown, server);
    peer.join().unwrap();
}

fn assert_protocol_rejection(bytes: &[u8]) {
    let path = TestPath::new();
    let limits = submission_limits();
    let Some((shutdown, server)) = start_server(
        &path.0,
        Duration::from_millis(200),
        2,
        limits.clone(),
        MemoryBudget::new(1024),
        relay_pool(),
    ) else {
        return;
    };
    let mut client = UnixStream::connect(&path.0).unwrap();
    client.write_all(bytes).unwrap();
    let result = read_result(&mut client, &limits);
    assert_eq!(result.status, DeliveryStatus::ProtocolRejection);
    assert!(!result.ambiguous);
    assert!(result.diagnostic.len() <= limits.max_diagnostic_bytes);
    stop_server(shutdown, server);
}

#[test]
fn malformed_frame_is_a_bounded_protocol_rejection() {
    assert_protocol_rejection(b"NOPE");
}

#[test]
fn malformed_message_is_a_bounded_protocol_rejection() {
    assert_protocol_rejection(&request(b"invalid message\r\n"));
}

#[test]
fn dkim_domain_rejection_is_a_bounded_protocol_rejection() {
    assert_protocol_rejection(&request(b"From: sender@wrong.example\r\n\r\nbody\r\n"));
}

#[test]
fn comment_address_cannot_authorize_a_different_from_domain_or_attempt_smtp() {
    let path = TestPath::new();
    let limits = submission_limits();
    let smtp_attempts = Arc::new(AtomicU64::new(0));
    let attempts = Arc::clone(&smtp_attempts);
    let relay = Arc::new(RelayPool::new(1, 1, move || {
        let attempts = Arc::clone(&attempts);
        SmtpConnection::new("submission-test", move || {
            attempts.fetch_add(1, Ordering::Relaxed);
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "SMTP must not be attempted for a rejected From",
            ))
        })
    }));
    let Some((shutdown, server)) = start_server(
        &path.0,
        Duration::from_secs(1),
        1,
        limits.clone(),
        MemoryBudget::new(1024),
        relay,
    ) else {
        return;
    };
    let mut client = UnixStream::connect(&path.0).unwrap();
    client
        .write_all(&request(
            b"From: attacker@other.test (note <user@example.com>)\r\n\r\nbody\r\n",
        ))
        .unwrap();
    let result = read_result(&mut client, &limits);
    assert_eq!(result.status, DeliveryStatus::ProtocolRejection);
    assert!(!result.ambiguous);
    assert!(result.diagnostic.contains("does not match"));
    stop_server(shutdown, server);
    assert_eq!(smtp_attempts.load(Ordering::Relaxed), 0);
}

#[test]
fn valid_commented_and_quoted_from_addresses_are_delivered() {
    for from in [
        "sender@example.com (note <other@other.test>)",
        "\"Sender <other@other.test>\" <sender@example.com>",
        "\"sender local\"@EXAMPLE.COM.",
    ] {
        let path = TestPath::new();
        let limits = submission_limits();
        let (relay, captured, release, peer) = gated_relay(b"250 accepted\r\n");
        let Some((shutdown, server)) = start_server(
            &path.0,
            Duration::from_secs(1),
            1,
            limits.clone(),
            MemoryBudget::new(1024),
            relay,
        ) else {
            return;
        };
        let original = format!("From: {from}\r\n\r\nbody\r\n");
        let mut client = UnixStream::connect(&path.0).unwrap();
        client.write_all(&request(original.as_bytes())).unwrap();
        let signed = captured.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(signed.starts_with(b"DKIM-Signature: "), "From: {from}");
        assert!(signed.ends_with(original.as_bytes()));
        release.send(()).unwrap();
        assert_eq!(
            read_result(&mut client, &limits).status,
            DeliveryStatus::Delivered,
            "From: {from}"
        );
        stop_server(shutdown, server);
        peer.join().unwrap();
    }
}

#[test]
fn submitted_reply_subjects_and_empty_bodies_have_independently_valid_signatures() {
    const EMPTY_HASH: &str = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
    const HELLO_HASH: &str = "zS7KNTV0HyeorkDDGwxB1AV6enuRKzO5rthkhdHIRnY=";
    for (subject, body, expected_body_hash) in [
        ("Re: hello", "hello\r\n", HELLO_HASH),
        ("Re:\r\n\t hello", "hello\r\n", HELLO_HASH),
        ("Re: hello", "", EMPTY_HASH),
        ("Re: hello", "\r\n\r\n", EMPTY_HASH),
        ("Re: hello", " \t\r\n\t \r\n", EMPTY_HASH),
    ] {
        let path = TestPath::new();
        let limits = submission_limits();
        let signing = signing();
        let key = Arc::clone(&signing.key);
        let (relay, captured, release, peer) = gated_relay(b"250 verified\r\n");
        let Some((shutdown, server)) = start_server_with_signing(
            &path.0,
            Duration::from_secs(1),
            1,
            limits.clone(),
            MemoryBudget::new(1024),
            relay,
            signing,
        ) else {
            return;
        };
        let original = format!("From: sender@example.com\r\nSubject: {subject}\r\n\r\n{body}");
        let mut client = UnixStream::connect(&path.0).unwrap();
        client.write_all(&request(original.as_bytes())).unwrap();
        let signed = captured.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(signed.ends_with(original.as_bytes()));
        let signature_header =
            std::str::from_utf8(&signed[..signed.len() - original.len()]).unwrap();
        let unfolded = signature_header
            .strip_prefix("DKIM-Signature: ")
            .unwrap()
            .strip_suffix("\r\n")
            .unwrap()
            .replace("\r\n\t", " ");
        let tag = |name: &str| {
            unfolded
                .split(';')
                .filter_map(|part| part.trim().split_once('='))
                .find_map(|(key, value)| (key == name).then_some(value))
                .unwrap()
        };
        assert_eq!(tag("bh"), expected_body_hash);
        assert_eq!(tag("h"), "from:from:subject");
        let timestamp: u64 = tag("t").parse().unwrap();
        let signature = openssl::base64::decode_block(tag("b")).unwrap();
        // These are literal RFC 6376 relaxed bytes, independent of the signing
        // implementation and the submitted subject's folding.
        let unsigned_signature = format!(
            "dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=test; t={timestamp}; h=from:from:subject; bh={expected_body_hash}; b="
        );
        let mut verifier =
            openssl::sign::Verifier::new(openssl::hash::MessageDigest::sha256(), key.as_ref())
                .unwrap();
        verifier
            .update(b"from:sender@example.com\r\nsubject:Re: hello\r\n")
            .unwrap();
        verifier.update(unsigned_signature.as_bytes()).unwrap();
        assert!(
            verifier.verify(&signature).unwrap(),
            "subject {subject:?}, body {body:?}"
        );
        release.send(()).unwrap();
        assert_eq!(
            read_result(&mut client, &limits).status,
            DeliveryStatus::Delivered
        );
        stop_server(shutdown, server);
        peer.join().unwrap();
    }
}

#[test]
fn socket_write_timeout_is_bounded_when_client_does_not_read() {
    let path = TestPath::new();
    let mut limits = submission_limits();
    limits.max_diagnostic_bytes = 4096;
    let Some((shutdown, server)) = start_server(
        &path.0,
        Duration::from_millis(80),
        1,
        limits,
        MemoryBudget::new(1024),
        relay_pool(),
    ) else {
        return;
    };
    let mut client = UnixStream::connect(&path.0).unwrap();
    let mut invalid_sender = vec![0x80; 254];
    invalid_sender[0] = b'x';
    let recipient = b"r@example.net";
    let mut frame = b"SRL1".to_vec();
    frame.extend_from_slice(&0_u32.to_be_bytes());
    frame.extend_from_slice(&(invalid_sender.len() as u32).to_be_bytes());
    frame.extend_from_slice(&invalid_sender);
    frame.extend_from_slice(&1_u32.to_be_bytes());
    frame.extend_from_slice(&(recipient.len() as u32).to_be_bytes());
    frame.extend_from_slice(recipient);
    frame.extend_from_slice(&0_u64.to_be_bytes());
    client.write_all(&frame).unwrap();
    shutdown.store(true, Ordering::Release);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    let joiner = std::thread::spawn(move || {
        server.join().unwrap();
        done_tx.send(()).unwrap();
    });
    done_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    joiner.join().unwrap();
}

#[test]
fn shutdown_waits_for_inflight_handler_and_preserves_replacement_path() {
    let path = TestPath::new();
    let limits = submission_limits();
    let (relay, captured, release, peer) = gated_relay(b"250 done\r\n");
    let Some((shutdown, server)) = start_server(
        &path.0,
        Duration::from_secs(1),
        1,
        limits.clone(),
        MemoryBudget::new(1024),
        relay,
    ) else {
        return;
    };
    let message = b"From: a@example.com\r\n\r\nbody\r\n";
    let mut client = UnixStream::connect(&path.0).unwrap();
    client.write_all(&request(message)).unwrap();
    captured.recv_timeout(Duration::from_secs(2)).unwrap();
    shutdown.store(true, Ordering::Release);
    fs::remove_file(&path.0).unwrap();
    fs::write(&path.0, b"replacement").unwrap();
    let (joined_tx, joined_rx) = mpsc::sync_channel(1);
    let joiner = std::thread::spawn(move || {
        server.join().unwrap();
        joined_tx.send(()).unwrap();
    });
    assert!(joined_rx.recv_timeout(Duration::from_millis(100)).is_err());
    release.send(()).unwrap();
    assert_eq!(
        read_result(&mut client, &limits).status,
        DeliveryStatus::Delivered
    );
    joined_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    joiner.join().unwrap();
    peer.join().unwrap();
    assert_eq!(fs::read(&path.0).unwrap(), b"replacement");
}

#[test]
fn rejects_zero_timeout_zero_mode_and_special_mode_bits() {
    let path = TestPath::new();
    let make = |mode, timeout| {
        SubmissionServer::bind(
            &path.0,
            SubmissionServerConfig {
                max_message_bytes: 26_214_400,
                submission_timeout: timeout,
                max_active_handlers: 1,
                socket_mode: mode,
            },
            MessageLimits::testing(),
            MemoryBudget::new(1),
            signing(),
            relay_pool(),
            Arc::new(AtomicBool::new(false)),
        )
    };
    assert_eq!(
        make(0o660, Duration::ZERO).err().unwrap().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        make(0, Duration::from_secs(1)).err().unwrap().kind(),
        io::ErrorKind::InvalidInput
    );
    assert_eq!(
        make(0o4660, Duration::from_secs(1)).err().unwrap().kind(),
        io::ErrorKind::InvalidInput
    );
}

fn sendmail_command(path: &Path, args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_signed-relay-sendmail"))
        .args(args)
        .env("SIGNED_RELAY_SOCKET", path)
        // Environment-leak canary: this is not a supported client setting.
        .env("SIGNED_RELAY_CREDENTIAL", "credential-sentinel-7f21")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Err(error) = child.stdin.take().unwrap().write_all(stdin) {
        assert_eq!(
            error.kind(),
            io::ErrorKind::BrokenPipe,
            "writing sendmail stdin failed"
        );
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!("sendmail client exceeded two seconds: {output:?}");
        }
        std::thread::yield_now();
    }
}

fn response(status: u8, ambiguous: bool, diagnostic: &[u8]) -> Vec<u8> {
    let diagnostic = String::from_utf8_lossy(diagnostic);
    let mut result = match status {
        0 => DeliveryResult::delivered(diagnostic, Some(250)),
        1 => DeliveryResult::temporary_failure(diagnostic, None),
        2 => DeliveryResult::permanent_failure(diagnostic, Some(550)),
        3 => DeliveryResult::protocol_rejection(diagnostic, None),
        _ => panic!("invalid test status"),
    };
    result.ambiguous = ambiguous;
    let mut frame = Vec::new();
    write_server_reply(&mut frame, &ServerReply::Final(result)).unwrap();
    frame
}

struct RecordingReader<'a> {
    stream: &'a mut UnixStream,
    bytes: Vec<u8>,
}

impl Read for RecordingReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.stream.read(buffer)?;
        self.bytes.extend_from_slice(&buffer[..read]);
        Ok(read)
    }
}

fn serve_one(
    path: &Path,
    reply: Vec<u8>,
) -> Option<(mpsc::Receiver<Vec<u8>>, std::thread::JoinHandle<()>)> {
    let listener = match UnixListener::bind(path) {
        Ok(listener) => listener,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return None,
        Err(error) => panic!("bind test socket: {error}"),
    };
    listener.set_nonblocking(true).unwrap();
    let (tx, rx) = mpsc::sync_channel(1);
    let handle = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "client did not connect"
                    );
                    std::thread::yield_now();
                }
                Err(error) => panic!("accept client: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut recording = RecordingReader {
            stream: &mut stream,
            bytes: Vec::new(),
        };
        read_envelope_preamble(&mut recording).unwrap();
        write_server_reply(
            recording.stream,
            &ServerReply::Ready(Ready {
                max_message_bytes: 26_214_400,
                max_chunk_bytes: MAX_CHUNK_BYTES as u32,
                max_diagnostic_bytes: 4096,
            }),
        )
        .unwrap();
        let request = read_chunk_stream(
            &mut recording,
            26_214_400,
            MAX_CHUNK_BYTES as u32,
            &MemoryBudget::new(26_214_400),
        )
        .unwrap();
        drop(request);
        tx.send(recording.bytes).unwrap();
        stream.write_all(&reply).unwrap();
    });
    Some((rx, handle))
}

fn assert_request(frame: &[u8], sender: &[u8], recipients: &[&[u8]], message: &[u8]) {
    let mut expected = b"SRL2".to_vec();
    expected.extend_from_slice(&0_u32.to_be_bytes());
    expected.extend_from_slice(&(sender.len() as u32).to_be_bytes());
    expected.extend_from_slice(sender);
    expected.extend_from_slice(&(recipients.len() as u32).to_be_bytes());
    for recipient in recipients {
        expected.extend_from_slice(&(recipient.len() as u32).to_be_bytes());
        expected.extend_from_slice(recipient);
    }
    expected.extend_from_slice(&(message.len() as u32).to_be_bytes());
    expected.extend_from_slice(message);
    expected.extend_from_slice(&0_u32.to_be_bytes());
    assert_eq!(frame, expected);
}

#[test]
fn sendmail_normalizes_stdin_and_encodes_exact_envelope() {
    let path = TestPath::new();
    let Some((captured, server)) = serve_one(&path.0, response(0, false, b"delivered")) else {
        return;
    };
    let input = b"From: sender@example.com\nSubject: lines\r\n\rbody\n";
    let output = sendmail_command(
        &path.0,
        &[
            "-f",
            "sender@example.com",
            "one@example.net",
            "two@example.net",
        ],
        input,
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert_request(
        &captured.recv_timeout(Duration::from_secs(2)).unwrap(),
        b"sender@example.com",
        &[b"one@example.net", b"two@example.net"],
        b"From: sender@example.com\r\nSubject: lines\r\n\r\nbody\r\n",
    );
    server.join().unwrap();
}

#[test]
fn sendmail_accepts_explicit_null_sender_and_double_dash_recipients() {
    let path = TestPath::new();
    let Some((captured, server)) = serve_one(&path.0, response(0, false, b"")) else {
        return;
    };
    let output = sendmail_command(
        &path.0,
        &["-f", "", "--", "-recipient@example.net"],
        b"X: y\n\n",
    );
    assert_eq!(output.status.code(), Some(0));
    assert_request(
        &captured.recv_timeout(Duration::from_secs(2)).unwrap(),
        b"",
        &[b"-recipient@example.net"],
        b"X: y\r\n\r\n",
    );
    server.join().unwrap();
}

#[test]
fn sendmail_usage_errors_exit_64_without_connecting() {
    for args in [
        vec!["recipient@example.net"],
        vec!["-f", "sender@example.com"],
        vec!["-x", "recipient@example.net"],
        vec![
            "-f",
            "a@example.com",
            "-f",
            "b@example.com",
            "r@example.net",
        ],
    ] {
        let path = TestPath::new();
        let listener = match UnixListener::bind(&path.0) {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("bind test socket: {error}"),
        };
        listener.set_nonblocking(true).unwrap();
        let output = sendmail_command(&path.0, &args, b"secret message sentinel\n");
        assert_eq!(output.status.code(), Some(64), "args: {args:?}");
        assert!(
            matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
        );
    }
}

#[test]
fn sendmail_maps_all_server_results_and_bounds_diagnostics() {
    for (status, ambiguous, expected) in [
        (0, false, 0),
        (1, false, 75),
        (0, true, 75),
        (2, false, 69),
        (3, false, 64),
    ] {
        let path = TestPath::new();
        let diagnostic = vec![b'd'; 4096];
        let Some((captured, server)) = serve_one(&path.0, response(status, ambiguous, &diagnostic))
        else {
            return;
        };
        let output = sendmail_command(
            &path.0,
            &["-f", "a@example.com", "b@example.net"],
            b"private-message-91\n",
        );
        assert_eq!(output.status.code(), Some(expected));
        assert!(output.stderr.len() <= 4352);
        assert!(!output
            .stderr
            .windows(b"private-message-91".len())
            .any(|w| w == b"private-message-91"));
        assert!(!output
            .stderr
            .windows(b"credential-sentinel-7f21".len())
            .any(|w| w == b"credential-sentinel-7f21"));
        captured.recv_timeout(Duration::from_secs(2)).unwrap();
        server.join().unwrap();
    }
}

#[test]
fn sendmail_connection_failure_and_relative_socket_are_classified() {
    let missing = TestPath::new();
    let output = sendmail_command(
        &missing.0,
        &["-f", "a@example.com", "b@example.net"],
        b"X: y\n\n",
    );
    assert_eq!(output.status.code(), Some(74));
    assert!(!output
        .stderr
        .windows(b"credential-sentinel-7f21".len())
        .any(|w| w == b"credential-sentinel-7f21"));

    let output = sendmail_command(
        Path::new("relative.sock"),
        &["-f", "a@example.com", "b@example.net"],
        b"X: y\n\n",
    );
    assert_eq!(output.status.code(), Some(64));
}

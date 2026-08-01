use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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
    read_request, read_response, MemoryBudget, SubmissionLimits, SubmissionServer,
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

fn bind(path: &Path, mode: u32, shutdown: Arc<AtomicBool>) -> io::Result<SubmissionServer> {
    SubmissionServer::bind(
        path,
        mode,
        Duration::from_millis(150),
        2,
        SubmissionLimits::permissive(),
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
    let mut bytes = b"SRL1".to_vec();
    bytes.extend_from_slice(&0_u32.to_be_bytes());
    bytes.extend_from_slice(&(sender.len() as u32).to_be_bytes());
    bytes.extend_from_slice(sender);
    bytes.extend_from_slice(&1_u32.to_be_bytes());
    bytes.extend_from_slice(&(recipient.len() as u32).to_be_bytes());
    bytes.extend_from_slice(recipient);
    bytes.extend_from_slice(&(message.len() as u64).to_be_bytes());
    bytes.extend_from_slice(message);
    bytes
}

fn start_server(
    path: &Path,
    timeout: Duration,
    handlers: usize,
    limits: SubmissionLimits,
    budget: MemoryBudget,
    relay: Arc<RelayPool>,
) -> Option<(Arc<AtomicBool>, std::thread::JoinHandle<()>)> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let server = match SubmissionServer::bind(
        path,
        0o660,
        timeout,
        handlers,
        limits,
        MessageLimits::testing(),
        budget,
        signing(),
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
    read_response(stream, limits).unwrap()
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
    let stale_inode = fs::symlink_metadata(&path.0).unwrap().ino();
    let server = bind(&path.0, 0o620, Arc::new(AtomicBool::new(false))).unwrap();
    let metadata = fs::symlink_metadata(&path.0).unwrap();
    assert_ne!(metadata.ino(), stale_inode);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o620);
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
    assert_eq!(&response, b"SRL1");
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
    let limits = SubmissionLimits::permissive();
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
fn slow_truncated_client_times_out_with_bounded_non_delivered_outcome() {
    let path = TestPath::new();
    let limits = SubmissionLimits::permissive();
    let Some((shutdown, server)) = start_server(
        &path.0,
        Duration::from_millis(80),
        1,
        limits.clone(),
        MemoryBudget::new(1024),
        relay_pool(),
    ) else {
        return;
    };
    let mut client = UnixStream::connect(&path.0).unwrap();
    client.write_all(b"SRL1").unwrap();
    let started = std::time::Instant::now();
    let result = read_result(&mut client, &limits);
    assert!(
        started.elapsed() >= Duration::from_millis(40),
        "truncated client was rejected before the configured read timeout"
    );
    assert_ne!(result.status, DeliveryStatus::Delivered);
    assert!(result.diagnostic.len() <= limits.max_diagnostic_bytes);
    stop_server(shutdown, server);
}

#[test]
fn budget_is_held_through_worker_completion_and_released_afterward() {
    let path = TestPath::new();
    let limits = SubmissionLimits::permissive();
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
    let body_start = frame.len() - second.len();
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
    let limits = SubmissionLimits::permissive();
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
    assert_eq!(&magic, b"SRL1");
    stop_server(shutdown, server);
    peer.join().unwrap();
}

#[test]
fn parse_and_frame_failures_are_bounded_and_never_delivered() {
    let path = TestPath::new();
    let mut limits = SubmissionLimits::permissive();
    limits.max_diagnostic_bytes = 32;
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
    for bytes in [
        b"NOPE".as_slice(),
        request(b"invalid message\r\n").as_slice(),
        request(b"From: sender@wrong.example\r\n\r\nbody\r\n").as_slice(),
    ] {
        let mut client = UnixStream::connect(&path.0).unwrap();
        client.write_all(bytes).unwrap();
        let result = read_result(&mut client, &limits);
        assert_ne!(result.status, DeliveryStatus::Delivered);
        assert!(result.diagnostic.len() <= 32);
    }
    stop_server(shutdown, server);
}

#[test]
fn socket_write_timeout_is_bounded_when_client_does_not_read() {
    let path = TestPath::new();
    let mut limits = SubmissionLimits::permissive();
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
    let limits = SubmissionLimits::permissive();
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
            mode,
            timeout,
            1,
            SubmissionLimits::permissive(),
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
        .env("SIGNED_RELAY_CREDENTIAL", "credential-sentinel-7f21")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
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
    let mut frame = b"SRL1".to_vec();
    frame.push(status);
    frame.push(u8::from(ambiguous));
    frame.extend_from_slice(&0_u16.to_be_bytes());
    frame.extend_from_slice(&(diagnostic.len() as u32).to_be_bytes());
    frame.extend_from_slice(diagnostic);
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
        let limits = SubmissionLimits {
            max_recipients: 100,
            max_address_bytes: 254,
            max_message_bytes: 26_214_400,
            max_diagnostic_bytes: 4096,
        };
        let request =
            read_request(&mut recording, &limits, &MemoryBudget::new(26_214_400)).unwrap();
        drop(request);
        tx.send(recording.bytes).unwrap();
        stream.write_all(&reply).unwrap();
    });
    Some((rx, handle))
}

fn assert_request(frame: &[u8], sender: &[u8], recipients: &[&[u8]], message: &[u8]) {
    let mut expected = b"SRL1".to_vec();
    expected.extend_from_slice(&0_u32.to_be_bytes());
    expected.extend_from_slice(&(sender.len() as u32).to_be_bytes());
    expected.extend_from_slice(sender);
    expected.extend_from_slice(&(recipients.len() as u32).to_be_bytes());
    for recipient in recipients {
        expected.extend_from_slice(&(recipient.len() as u32).to_be_bytes());
        expected.extend_from_slice(recipient);
    }
    expected.extend_from_slice(&(message.len() as u64).to_be_bytes());
    expected.extend_from_slice(message);
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
    assert_eq!(output.status.code(), Some(75));
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

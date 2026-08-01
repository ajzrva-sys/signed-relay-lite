use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
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
    read_response, MemoryBudget, SubmissionLimits, SubmissionServer,
};

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

struct TestPath(PathBuf);

impl TestPath {
    fn new() -> Self {
        Self(Path::new("/private/tmp").join(format!(
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
    let result = read_result(&mut client, &limits);
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
    assert_ne!(rejected.status, DeliveryStatus::Delivered);
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

use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicU64 = AtomicU64::new(0);
const TIMEOUT: Duration = Duration::from_secs(2);

struct Fixture {
    directory: PathBuf,
    config: PathBuf,
    socket: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = std::env::current_dir().unwrap().join(format!(
            "signed-relay-daemon-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let key = directory.join("key.pem");
        let rsa = Rsa::generate(2048).unwrap();
        let key_bytes = PKey::from_rsa(rsa)
            .unwrap()
            .private_key_to_pem_pkcs8()
            .unwrap();
        fs::write(&key, key_bytes).unwrap();
        let socket = directory.join("submission.sock");
        let config = directory.join("relay.conf");
        fs::write(
            &config,
            format!(
                "domain=example.com\nselector=test\nprivate_key={}\nlisten=unix:{}\nrelay_host=localhost\nrelay_port=465\nrelay_tls=implicit\nrelay_username=\nrelay_password_file=\nclient_name=relay.example.com\nrelay_workers=1\nmax_message_bytes=1048576\nglobal_message_memory_bytes=1048576\nmax_concurrent_submissions=2\nsubmission_timeout_seconds=1\ndelivery_timeout_seconds=1\nrequire_fips=false\n",
                key.display(),
                socket.display()
            ),
        )
        .unwrap();
        Self {
            directory,
            config,
            socket,
        }
    }

    fn command(&self) -> Command {
        Command::new(env!("CARGO_BIN_EXE_signed-relay-lite"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn wait_output(mut child: Child) -> Output {
    let deadline = Instant::now() + TIMEOUT;
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!("subprocess exceeded two seconds: {output:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn output(args: &[&str]) -> Output {
    let child = Command::new(env!("CARGO_BIN_EXE_signed-relay-lite"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_output(child)
}

fn wait_for_socket(path: &Path, child: &mut Child) {
    let deadline = Instant::now() + TIMEOUT;
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        assert!(
            child.try_wait().unwrap().is_none(),
            "daemon exited before bind"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    panic!("daemon did not create socket");
}

fn terminate(child: &Child) {
    let result = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
    assert_eq!(result, 0);
}

fn unix_sockets_available(fixture: &Fixture) -> bool {
    let probe = fixture.directory.join("probe.sock");
    match UnixListener::bind(&probe) {
        Ok(listener) => {
            drop(listener);
            let _ = fs::remove_file(probe);
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => false,
        Err(error) => panic!("probe Unix socket: {error}"),
    }
}

#[test]
fn strict_cli_help_and_version() {
    for option in ["--help", "--version"] {
        assert!(output(&[option]).status.success());
    }
    for args in [
        vec![],
        vec!["--unknown"],
        vec!["--config"],
        vec!["--config", "relative.conf"],
        vec!["--help", "extra"],
    ] {
        assert!(!output(&args).status.success(), "accepted {args:?}");
    }
}

#[test]
fn check_config_does_not_bind_or_connect() {
    let fixture = Fixture::new();
    if !unix_sockets_available(&fixture) {
        return;
    }
    let listener = UnixListener::bind(&fixture.socket).unwrap();
    let smtp = TcpListener::bind("127.0.0.1:0").unwrap();
    smtp.set_nonblocking(true).unwrap();
    let port = smtp.local_addr().unwrap().port();
    let config = fs::read_to_string(&fixture.config)
        .unwrap()
        .replace("relay_port=465", &format!("relay_port={port}"));
    fs::write(&fixture.config, config).unwrap();
    let result = output(&["--check-config", fixture.config.to_str().unwrap()]);
    assert!(result.status.success(), "{result:?}");
    assert!(matches!(smtp.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
    drop(listener);
}

#[test]
fn invalid_startup_preserves_existing_path_before_bind() {
    let fixture = Fixture::new();
    fs::write(fixture.directory.join("key.pem"), b"not a key").unwrap();
    fs::write(&fixture.socket, b"sentinel").unwrap();
    let result = output(&["--config", fixture.config.to_str().unwrap()]);
    assert!(!result.status.success());
    assert_eq!(fs::read(&fixture.socket).unwrap(), b"sentinel");
}

#[test]
fn malformed_config_and_required_fips_fail_before_bind() {
    let fixture = Fixture::new();
    fs::write(&fixture.socket, b"sentinel").unwrap();
    let valid = fs::read_to_string(&fixture.config).unwrap();
    fs::write(&fixture.config, format!("{valid}unknown_setting=value\n")).unwrap();
    assert!(!output(&["--config", fixture.config.to_str().unwrap()])
        .status
        .success());
    assert_eq!(fs::read(&fixture.socket).unwrap(), b"sentinel");

    if signed_relay_lite::config::check_fips_environment(true).is_err() {
        fs::write(
            &fixture.config,
            valid.replace("require_fips=false", "require_fips=true"),
        )
        .unwrap();
        assert!(!output(&["--config", fixture.config.to_str().unwrap()])
            .status
            .success());
        assert_eq!(fs::read(&fixture.socket).unwrap(), b"sentinel");
    }
}

#[test]
fn sigterm_stops_daemon_and_removes_socket() {
    let fixture = Fixture::new();
    if !unix_sockets_available(&fixture) {
        return;
    }
    let mut child = fixture
        .command()
        .args(["--config", fixture.config.to_str().unwrap()])
        .spawn()
        .unwrap();
    wait_for_socket(&fixture.socket, &mut child);
    terminate(&child);
    let result = wait_output(child);
    assert!(result.status.success(), "{result:?}");
    assert!(!fixture.socket.exists());
}

#[test]
fn shutdown_never_marks_partial_submission_delivered() {
    let fixture = Fixture::new();
    if !unix_sockets_available(&fixture) {
        return;
    }
    let mut child = fixture
        .command()
        .args(["--config", fixture.config.to_str().unwrap()])
        .spawn()
        .unwrap();
    wait_for_socket(&fixture.socket, &mut child);
    let mut client = UnixStream::connect(&fixture.socket).unwrap();
    client.set_read_timeout(Some(TIMEOUT)).unwrap();
    client.write_all(b"SRL1").unwrap();
    terminate(&child);
    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response);
    if response.len() >= 5 {
        assert_eq!(&response[..4], b"SRL1");
        assert_ne!(response[4], 0, "shutdown fabricated Delivered");
    }
    assert!(wait_output(child).status.success());
}

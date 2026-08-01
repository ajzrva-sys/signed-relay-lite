//! Test-only fake plaintext smarthost for integration tests.
//!
//! Binds `127.0.0.1:0`, records commands, captures unstuffed DATA body,
//! and emits configurable reply sequences.  Every wait is bounded so
//! failed tests cannot hang.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::ssl::{SslAcceptor, SslMethod};
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectAlternativeName};
use openssl::x509::{X509NameBuilder, X509};

/// Global per-test timeout for any network wait.
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

// ── Public types ──────────────────────────────────────────────────────

/// A running fake smarthost.  Dropping it does **not** join the server
/// thread; call [`FakeSmarthost::join`] to consume and collect results.
pub struct FakeSmarthost {
    pub addr: SocketAddr,
    handle: Option<JoinHandle<ServerResult>>,
}

/// Runtime-generated test PKI and its temporary CA trust file.
pub struct TestPki {
    pub ca_file: PathBuf,
    cert: X509,
    key: PKey<Private>,
}

impl TestPki {
    pub fn localhost() -> Self {
        let ca_key =
            PKey::from_rsa(Rsa::generate(2048).expect("generate CA key")).expect("convert CA key");
        let mut ca_name = X509NameBuilder::new().expect("CA name");
        ca_name
            .append_entry_by_text("CN", "test CA")
            .expect("CA CN");
        let ca_name = ca_name.build();
        let mut ca = X509::builder().expect("CA builder");
        ca.set_version(2).expect("CA version");
        set_random_serial(&mut ca);
        ca.set_subject_name(&ca_name).expect("CA subject");
        ca.set_issuer_name(&ca_name).expect("CA issuer");
        ca.set_pubkey(&ca_key).expect("CA public key");
        ca.set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
            .expect("CA not before");
        ca.set_not_after(Asn1Time::days_from_now(1).unwrap().as_ref())
            .expect("CA not after");
        ca.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .expect("CA constraint");
        ca.append_extension(KeyUsage::new().key_cert_sign().crl_sign().build().unwrap())
            .expect("CA key usage");
        ca.sign(&ca_key, MessageDigest::sha256()).expect("sign CA");
        let ca = ca.build();

        let key = PKey::from_rsa(Rsa::generate(2048).expect("generate leaf key"))
            .expect("convert leaf key");
        let mut leaf_name = X509NameBuilder::new().expect("leaf name");
        leaf_name
            .append_entry_by_text("CN", "localhost")
            .expect("leaf CN");
        let leaf_name = leaf_name.build();
        let mut cert = X509::builder().expect("leaf builder");
        cert.set_version(2).expect("leaf version");
        set_random_serial(&mut cert);
        cert.set_subject_name(&leaf_name).expect("leaf subject");
        cert.set_issuer_name(ca.subject_name())
            .expect("leaf issuer");
        cert.set_pubkey(&key).expect("leaf public key");
        cert.set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
            .expect("leaf not before");
        cert.set_not_after(Asn1Time::days_from_now(1).unwrap().as_ref())
            .expect("leaf not after");
        let san = SubjectAlternativeName::new()
            .dns("localhost")
            .build(&cert.x509v3_context(Some(&ca), None))
            .expect("leaf SAN");
        cert.append_extension(san).expect("append leaf SAN");
        cert.sign(&ca_key, MessageDigest::sha256())
            .expect("sign leaf");
        let cert = cert.build();

        let ca_file = std::env::temp_dir().join(format!(
            "signed-relay-lite-test-ca-{}-{}.pem",
            std::process::id(),
            random_serial_u32()
        ));
        std::fs::write(&ca_file, ca.to_pem().expect("encode CA")).expect("write test CA");
        Self { ca_file, cert, key }
    }

    pub fn acceptor(&self) -> SslAcceptor {
        let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls_server())
            .expect("TLS acceptor builder");
        builder.set_certificate(&self.cert).expect("server cert");
        builder.set_private_key(&self.key).expect("server key");
        builder.check_private_key().expect("matching server key");
        builder.build()
    }
}

impl Drop for TestPki {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.ca_file);
    }
}

fn random_serial_u32() -> u32 {
    let mut serial = BigNum::new().expect("serial bignum");
    serial
        .rand(31, MsbOption::MAYBE_ZERO, false)
        .expect("random serial");
    serial.to_dec_str().unwrap().to_string().parse().unwrap()
}

fn set_random_serial(builder: &mut openssl::x509::X509Builder) {
    let mut serial = BigNum::new().expect("serial bignum");
    serial
        .rand(128, MsbOption::MAYBE_ZERO, false)
        .expect("random serial");
    let serial = serial.to_asn1_integer().expect("ASN.1 serial");
    builder.set_serial_number(&serial).expect("set serial");
}

/// The server thread's collected observations.
#[derive(Debug, Default)]
pub struct ServerResult {
    /// Every CRLF-terminated command line received (including the trailing
    /// `\\r\\n`), in order.
    pub commands: Vec<Vec<u8>>,
    /// The unstuffed message bytes captured during DATA (no trailing
    /// `\\r\\n.\\r\\n`).
    pub captured_message: Vec<u8>,
    /// One unstuffed message per completed DATA transaction.
    pub captured_messages: Vec<Vec<u8>>,
    /// Number of TCP connections accepted by the fake.
    pub accepted_connections: usize,
}

/// Where the server should silently drop the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClosePoint {
    /// Complete the full conversation normally.
    #[default]
    Normal,
    /// Close immediately after sending the `354` response.
    BeforeData,
    /// Close while reading DATA body (after first body line).
    DuringData,
    /// Close after receiving the terminating `.\\r\\n`, before sending
    /// the final response.
    AfterFinalDot,
    /// Close after sending the final `250` response.
    AfterDataReply,
    /// Close before replying to the numbered MAIL command (zero based).
    BeforeMailReply(usize),
}

/// Configuration for the fake smarthost's reply behaviour.
#[derive(Debug, Clone)]
pub struct SmarthostConfig {
    /// The greeting sent immediately after accept.
    pub greeting: Vec<u8>,
    /// Reply to the `EHLO` command.
    pub ehlo_response: Vec<u8>,
    /// Reply to the `MAIL FROM` command.
    pub mail_from_response: Vec<u8>,
    /// Per-recipient `RCPT TO` replies.  When exhausted the default is
    /// `250 OK`.
    pub rcpt_responses: Vec<Vec<u8>>,
    /// Reply to the `DATA` command itself (the "go-ahead").
    pub data_go_ahead: Vec<u8>,
    /// Reply sent after the terminating `.\\r\\n`.
    pub data_final_response: Vec<u8>,
    /// Where to simulate a connection drop.
    pub close_point: ClosePoint,
}

impl Default for SmarthostConfig {
    fn default() -> Self {
        Self {
            greeting: b"220 localhost ready\r\n".to_vec(),
            ehlo_response: b"250-localhost\r\n250 OK\r\n".to_vec(),
            mail_from_response: b"250 OK\r\n".to_vec(),
            rcpt_responses: Vec::new(),
            data_go_ahead: b"354 Go ahead\r\n".to_vec(),
            data_final_response: b"250 OK\r\n".to_vec(),
            close_point: ClosePoint::Normal,
        }
    }
}

// ── FakeSmarthost lifecycle ───────────────────────────────────────────

impl FakeSmarthost {
    /// Start the fake smarthost on an ephemeral port.
    pub fn start(config: SmarthostConfig) -> Self {
        Self::start_connections(vec![config])
    }

    /// Start a server with one script for each connection it should accept.
    pub fn start_connections(configs: Vec<SmarthostConfig>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
        let addr = listener.local_addr().expect("local_addr failed");

        let handle = thread::spawn(move || {
            let mut combined = ServerResult::default();
            for config in configs {
                let (stream, _peer) = listener.accept().expect("accept failed");
                stream
                    .set_read_timeout(Some(TEST_TIMEOUT))
                    .expect("set_read_timeout");
                stream
                    .set_write_timeout(Some(TEST_TIMEOUT))
                    .expect("set_write_timeout");
                let result = run_server(stream, &config);
                combined.accepted_connections += 1;
                combined.commands.extend(result.commands);
                combined.captured_message.extend(result.captured_message);
                combined.captured_messages.extend(result.captured_messages);
            }
            combined
        });

        FakeSmarthost {
            addr,
            handle: Some(handle),
        }
    }

    /// Start a one-connection implicit-TLS smarthost.
    pub fn start_tls(config: SmarthostConfig, acceptor: SslAcceptor) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
        let addr = listener.local_addr().expect("local_addr failed");
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept failed");
            stream
                .set_read_timeout(Some(TEST_TIMEOUT))
                .expect("read timeout");
            stream
                .set_write_timeout(Some(TEST_TIMEOUT))
                .expect("write timeout");
            let mut result = ServerResult {
                accepted_connections: 1,
                ..Default::default()
            };
            if let Ok(stream) = acceptor.accept(stream) {
                let smtp = run_server(stream, &config);
                result.commands = smtp.commands;
                result.captured_message = smtp.captured_message;
                result.captured_messages = smtp.captured_messages;
            }
            result
        });
        Self {
            addr,
            handle: Some(handle),
        }
    }

    /// Accept TCP but never speak TLS, to exercise the client handshake deadline.
    pub fn start_tls_stall(stall: Duration) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
        let addr = listener.local_addr().expect("local_addr failed");
        let handle = thread::spawn(move || {
            // The client may safely retry once before SMTP begins. Hold both
            // accepted sockets open without sending a ServerHello.
            let (first, _) = listener.accept().expect("first accept failed");
            let (second, _) = listener.accept().expect("second accept failed");
            thread::sleep(stall);
            drop((first, second));
            ServerResult {
                accepted_connections: 2,
                ..Default::default()
            }
        });
        Self {
            addr,
            handle: Some(handle),
        }
    }

    /// Wait for the server thread to finish and return collected state.
    pub fn join(mut self) -> ServerResult {
        self.handle
            .take()
            .expect("already joined")
            .join()
            .expect("server thread panicked")
    }
}

impl Drop for FakeSmarthost {
    fn drop(&mut self) {
        // If join() was not called, detach the thread.  The server
        // thread has TEST_TIMEOUT and will exit on its own.
    }
}

// ── Server logic ──────────────────────────────────────────────────────

/// Read one CRLF-terminated line from `reader`, including the trailing
/// `\\r\\n`.  Returns `Err(UnexpectedEof)` when the peer closes.
fn read_crlf_line(reader: &mut impl BufRead) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let n = reader.read_until(b'\n', &mut line)?;
        if n == 0 {
            return if line.is_empty() {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed",
                ))
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "incomplete line",
                ))
            };
        }
        if line.ends_with(b"\n") {
            if line.len() >= 2 && line[line.len() - 2] == b'\r' {
                return Ok(line);
            }
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bare LF in command",
            ));
        }
        // Keep reading — line doesn't end with \n yet.
    }
}

fn run_server<S: Read + Write>(stream: S, config: &SmarthostConfig) -> ServerResult {
    let mut reader = BufReader::new(stream);

    let mut result = ServerResult::default();

    // ── Greeting ──────────────────────────────────────────────────
    reader.get_mut().write_all(&config.greeting).unwrap();
    reader.get_mut().flush().unwrap();

    let mut rcpt_idx: usize = 0;
    let mut in_data = false;
    let mut current_message = Vec::new();
    let mut mail_idx = 0;

    loop {
        let line = match read_crlf_line(&mut reader) {
            Ok(l) => l,
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => panic!("server read error: {e}"),
        };

        // ── DATA body capture ────────────────────────────────────
        if in_data {
            if line == b".\r\n" {
                if config.close_point == ClosePoint::AfterFinalDot {
                    break;
                }
                reader
                    .get_mut()
                    .write_all(&config.data_final_response)
                    .unwrap();
                reader.get_mut().flush().unwrap();
                result
                    .captured_messages
                    .push(std::mem::take(&mut current_message));
                in_data = false;
                if config.close_point == ClosePoint::AfterDataReply {
                    break;
                }
                continue;
            }
            // Dot-unstuff: strip a single leading dot.
            if line.len() >= 2 && line[0] == b'.' && line[1] == b'.' {
                result.captured_message.extend_from_slice(&line[1..]);
                current_message.extend_from_slice(&line[1..]);
            } else {
                result.captured_message.extend_from_slice(&line);
                current_message.extend_from_slice(&line);
            }
            if config.close_point == ClosePoint::DuringData {
                break;
            }
            continue;
        }

        // ── Command dispatch ─────────────────────────────────────
        result.commands.push(line.clone());

        if line.starts_with(b"EHLO ") || line.starts_with(b"ehlo ") {
            reader.get_mut().write_all(&config.ehlo_response).unwrap();
            reader.get_mut().flush().unwrap();
        } else if line.starts_with(b"MAIL FROM:") {
            if config.close_point == ClosePoint::BeforeMailReply(mail_idx) {
                break;
            }
            reader
                .get_mut()
                .write_all(&config.mail_from_response)
                .unwrap();
            reader.get_mut().flush().unwrap();
            mail_idx += 1;
        } else if line.starts_with(b"RCPT TO:") {
            let resp = config
                .rcpt_responses
                .get(rcpt_idx)
                .map_or(b"250 OK\r\n".as_slice(), |v| v.as_slice());
            reader.get_mut().write_all(resp).unwrap();
            reader.get_mut().flush().unwrap();
            rcpt_idx += 1;
        } else if line.starts_with(b"DATA") {
            if config.close_point == ClosePoint::BeforeData {
                break;
            }
            reader.get_mut().write_all(&config.data_go_ahead).unwrap();
            reader.get_mut().flush().unwrap();
            in_data = true;
        } else if line.starts_with(b"RSET") {
            reader.get_mut().write_all(b"250 OK\r\n").unwrap();
            reader.get_mut().flush().unwrap();
        } else if line.starts_with(b"QUIT") {
            reader.get_mut().write_all(b"221 Bye\r\n").unwrap();
            reader.get_mut().flush().unwrap();
            break;
        } else {
            reader
                .get_mut()
                .write_all(b"500 Unknown command\r\n")
                .unwrap();
            reader.get_mut().flush().unwrap();
        }
    }

    result
}

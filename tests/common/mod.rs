//! Test-only fake plaintext smarthost for integration tests.
//!
//! Binds `127.0.0.1:0`, records commands, captures unstuffed DATA body,
//! and emits configurable reply sequences.  Every wait is bounded so
//! failed tests cannot hang.

use std::io::{self, BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Global per-test timeout for any network wait.
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

// ── Public types ──────────────────────────────────────────────────────

/// A running fake smarthost.  Dropping it does **not** join the server
/// thread; call [`FakeSmarthost::join`] to consume and collect results.
pub struct FakeSmarthost {
    pub addr: SocketAddr,
    handle: Option<JoinHandle<ServerResult>>,
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
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind failed");
        let addr = listener.local_addr().expect("local_addr failed");

        let handle = thread::spawn(move || {
            let (stream, _peer) = listener.accept().expect("accept failed");
            stream
                .set_read_timeout(Some(TEST_TIMEOUT))
                .expect("set_read_timeout");
            stream
                .set_write_timeout(Some(TEST_TIMEOUT))
                .expect("set_write_timeout");
            run_server(stream, &config)
        });

        FakeSmarthost {
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

fn run_server(stream: TcpStream, config: &SmarthostConfig) -> ServerResult {
    let read_stream = stream.try_clone().expect("try_clone failed");
    let mut reader = BufReader::new(read_stream);
    let mut writer = stream;

    let mut result = ServerResult::default();

    // ── Greeting ──────────────────────────────────────────────────
    writer.write_all(&config.greeting).unwrap();
    writer.flush().unwrap();

    let mut rcpt_idx: usize = 0;
    let mut in_data = false;

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
                writer.write_all(&config.data_final_response).unwrap();
                writer.flush().unwrap();
                in_data = false;
                if config.close_point == ClosePoint::AfterDataReply {
                    break;
                }
                continue;
            }
            // Dot-unstuff: strip a single leading dot.
            if line.len() >= 2 && line[0] == b'.' && line[1] == b'.' {
                result.captured_message.extend_from_slice(&line[1..]);
            } else {
                result.captured_message.extend_from_slice(&line);
            }
            if config.close_point == ClosePoint::DuringData {
                break;
            }
            continue;
        }

        // ── Command dispatch ─────────────────────────────────────
        result.commands.push(line.clone());

        if line.starts_with(b"EHLO ") || line.starts_with(b"ehlo ") {
            writer.write_all(&config.ehlo_response).unwrap();
            writer.flush().unwrap();
        } else if line.starts_with(b"MAIL FROM:") {
            writer.write_all(&config.mail_from_response).unwrap();
            writer.flush().unwrap();
        } else if line.starts_with(b"RCPT TO:") {
            let resp = config
                .rcpt_responses
                .get(rcpt_idx)
                .map_or(b"250 OK\r\n".as_slice(), |v| v.as_slice());
            writer.write_all(resp).unwrap();
            writer.flush().unwrap();
            rcpt_idx += 1;
        } else if line.starts_with(b"DATA") {
            if config.close_point == ClosePoint::BeforeData {
                break;
            }
            writer.write_all(&config.data_go_ahead).unwrap();
            writer.flush().unwrap();
            in_data = true;
        } else if line.starts_with(b"RSET") {
            writer.write_all(b"250 OK\r\n").unwrap();
            writer.flush().unwrap();
        } else if line.starts_with(b"QUIT") {
            writer.write_all(b"221 Bye\r\n").unwrap();
            writer.flush().unwrap();
            break;
        } else {
            writer.write_all(b"500 Unknown command\r\n").unwrap();
            writer.flush().unwrap();
        }
    }

    result
}

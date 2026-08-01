//! Deliberately limited stdin submission client.
//!
//! Supported syntax: `signed-relay-sendmail -f envelope-from [--] recipient...`.
//! This is not a general sendmail command-line compatibility layer.

use std::env;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use signed_relay_lite::message::WireNormalizer;
use signed_relay_lite::relay::{DeliveryResult, DeliveryStatus, Envelope};
use signed_relay_lite::submission::{read_response, SubmissionError, SubmissionLimits};

const EX_OK: i32 = 0;
const EX_USAGE: i32 = 64;
const EX_UNAVAILABLE: i32 = 69;
const EX_TEMPFAIL: i32 = 75;
#[cfg(test)]
const LEGACY_CLIENT_MESSAGE_BYTES: usize = 25 * 1024 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(300);
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let (sender, recipients) = match parse_arguments(env::args_os().skip(1)) {
        Ok(arguments) => arguments,
        Err(context) => return local_error(EX_USAGE, context),
    };
    let envelope = match Envelope::new(&sender, recipients) {
        Ok(envelope) => envelope,
        Err(_) => return local_error(EX_USAGE, "invalid envelope"),
    };

    let socket_path = env::var_os("SIGNED_RELAY_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/run/signed-relay-lite/submit.sock"));
    if !Path::new(&socket_path).is_absolute() {
        return local_error(EX_USAGE, "submission socket path must be absolute");
    }

    let mut stream = match UnixStream::connect(&socket_path) {
        Ok(stream) => stream,
        Err(_) => return local_error(EX_TEMPFAIL, "could not connect to submission service"),
    };
    if stream.set_read_timeout(Some(READ_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(WRITE_TIMEOUT)).is_err()
    {
        return local_error(EX_TEMPFAIL, "could not configure submission connection");
    }
    let result = match submit_message(&mut io::stdin().lock(), &mut stream, &envelope, |stream| {
        stream.shutdown(Shutdown::Write)
    }) {
        Ok(result) => result,
        Err(ClientError::Input(InputError::TooLarge)) => {
            return local_error(EX_USAGE, "message is too large")
        }
        Err(ClientError::Input(InputError::Io)) => {
            return local_error(EX_TEMPFAIL, "could not read message input")
        }
        Err(ClientError::Write) => return local_error(EX_TEMPFAIL, "could not submit message"),
        Err(ClientError::Response(SubmissionError::Io(_))) => {
            return local_error(EX_TEMPFAIL, "submission result was incomplete")
        }
        Err(ClientError::Response(_)) => {
            return local_error(EX_USAGE, "invalid submission response")
        }
    };

    if !result.diagnostic.is_empty() {
        eprintln!("signed-relay-sendmail: {}", result.diagnostic);
    }
    if result.ambiguous {
        return EX_TEMPFAIL;
    }
    match result.status {
        DeliveryStatus::Delivered => EX_OK,
        DeliveryStatus::TemporaryFailure => EX_TEMPFAIL,
        DeliveryStatus::PermanentFailure => EX_UNAVAILABLE,
        DeliveryStatus::ProtocolRejection => EX_USAGE,
    }
}

fn parse_arguments(
    arguments: impl Iterator<Item = OsString>,
) -> Result<(Vec<u8>, Vec<Vec<u8>>), &'static str> {
    let arguments: Vec<OsString> = arguments.collect();
    let mut sender = None;
    let mut recipients = Vec::new();
    let mut after_double_dash = false;
    let mut index = 0;
    while index < arguments.len() {
        let argument = arguments[index].as_os_str().as_bytes();
        if !after_double_dash && argument == b"--" {
            after_double_dash = true;
        } else if !after_double_dash && argument == b"-f" {
            if sender.is_some() {
                return Err("duplicate -f option");
            }
            index += 1;
            let value = arguments.get(index).ok_or("-f requires a value")?;
            sender = Some(value.as_os_str().as_bytes().to_vec());
        } else if !after_double_dash && argument.starts_with(b"-") {
            return Err("unknown option");
        } else {
            recipients.push(argument.to_vec());
        }
        index += 1;
    }
    let sender = sender.ok_or("missing required -f option")?;
    if recipients.is_empty() {
        return Err("at least one recipient is required");
    }
    Ok((sender, recipients))
}

#[derive(Debug)]
enum InputError {
    TooLarge,
    Io,
}

#[derive(Debug)]
enum ClientError {
    Input(InputError),
    Write,
    Response(SubmissionError),
}

fn read_message(input: &mut impl Read, max_message_bytes: usize) -> Result<Vec<u8>, InputError> {
    let mut normalizer = WireNormalizer::new(max_message_bytes);
    let mut chunk = [0_u8; 8192];
    loop {
        let read = input.read(&mut chunk).map_err(|_| InputError::Io)?;
        if read == 0 {
            break;
        }
        normalizer
            .write(&chunk[..read])
            .map_err(|_| InputError::TooLarge)?;
    }
    normalizer.finish().map_err(|_| InputError::TooLarge)
}

fn submit_message<R: Read, S: Read + Write>(
    input: &mut R,
    stream: &mut S,
    envelope: &Envelope,
    shutdown_write: impl FnOnce(&mut S) -> io::Result<()>,
) -> Result<DeliveryResult, ClientError> {
    let legacy_message_bytes = 25 * 1024 * 1024;
    let message = read_message(input, legacy_message_bytes).map_err(ClientError::Input)?;
    write_request(stream, envelope, &message).map_err(|_| ClientError::Write)?;
    stream.flush().map_err(|_| ClientError::Write)?;
    shutdown_write(stream).map_err(|_| ClientError::Write)?;

    let limits = submission_limits(legacy_message_bytes as u64);
    read_response(stream, &limits).map_err(ClientError::Response)
}

fn submission_limits(max_message_bytes: u64) -> SubmissionLimits {
    SubmissionLimits::production(max_message_bytes)
}

fn write_request(stream: &mut impl Write, envelope: &Envelope, message: &[u8]) -> io::Result<()> {
    stream.write_all(b"SRL1")?;
    stream.write_all(&0_u32.to_be_bytes())?;
    write_bytes(stream, envelope.sender())?;
    stream.write_all(&(envelope.recipients().len() as u32).to_be_bytes())?;
    for recipient in envelope.recipients() {
        write_bytes(stream, recipient)?;
    }
    stream.write_all(&(message.len() as u64).to_be_bytes())?;
    stream.write_all(message)
}

fn write_bytes(stream: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)
}

fn local_error(code: i32, context: &str) -> i32 {
    eprintln!("signed-relay-sendmail: {context}");
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_submission_limits_accept_daemon_message_limit() {
        let limits = submission_limits(123_456);
        assert_eq!(limits.max_recipients, 100);
        assert_eq!(limits.max_address_bytes, 254);
        assert_eq!(limits.max_message_bytes, 123_456);
        assert_eq!(limits.max_diagnostic_bytes, 4096);
    }
    use std::cell::Cell;
    use std::io::Cursor;
    use std::rc::Rc;

    use signed_relay_lite::submission::write_response;

    struct CountingGeneratedReader {
        remaining: usize,
        reads: Rc<Cell<usize>>,
    }

    impl CountingGeneratedReader {
        fn new(len: usize, reads: Rc<Cell<usize>>) -> Self {
            Self {
                remaining: len,
                reads,
            }
        }
    }

    impl Read for CountingGeneratedReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.reads.set(self.reads.get() + 1);
            let count = self.remaining.min(buffer.len());
            buffer[..count].fill(b'a');
            self.remaining -= count;
            Ok(count)
        }
    }

    struct FakeDuplex {
        response: Cursor<Vec<u8>>,
        request: Vec<u8>,
        input_reads: Rc<Cell<usize>>,
        response_reads: usize,
    }

    impl FakeDuplex {
        fn delivering(input_reads: Rc<Cell<usize>>) -> Self {
            let mut response = Vec::new();
            write_response(
                &mut response,
                &DeliveryResult::delivered("", Some(250)),
                4096,
            )
            .unwrap();
            Self {
                response: Cursor::new(response),
                request: Vec::new(),
                input_reads,
                response_reads: 0,
            }
        }
    }

    impl Read for FakeDuplex {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.response_reads == 0 {
                assert_eq!(
                    self.input_reads.get(),
                    0,
                    "stdin must remain unread until the first server reply"
                );
            }
            self.response_reads += 1;
            self.response.read(buffer)
        }
    }

    impl Write for FakeDuplex {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.request.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn envelope() -> Envelope {
        Envelope::new(
            b"sender@example.test",
            vec![b"recipient@example.test".to_vec()],
        )
        .unwrap()
    }

    #[test]
    fn client_waits_for_server_limit_before_reading_message() {
        let reads = Rc::new(Cell::new(0));
        let mut input = CountingGeneratedReader::new(1, Rc::clone(&reads));
        let mut peer = FakeDuplex::delivering(Rc::clone(&reads));
        submit_message(&mut input, &mut peer, &envelope(), |_| Ok(())).unwrap();
        assert!(reads.get() > 0, "stdin must be consumed after READY");
    }

    #[test]
    fn client_accepts_a_stream_larger_than_the_removed_25_mib_constant_when_server_allows_it() {
        let reads = Rc::new(Cell::new(0));
        let mut input =
            CountingGeneratedReader::new(LEGACY_CLIENT_MESSAGE_BYTES + 1, Rc::clone(&reads));
        let mut peer = FakeDuplex::delivering(reads);
        let result = submit_message(&mut input, &mut peer, &envelope(), |_| Ok(()));
        assert!(
            result.is_ok(),
            "the daemon-advertised limit must be authoritative"
        );
    }
}

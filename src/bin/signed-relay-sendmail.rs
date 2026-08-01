//! Deliberately limited stdin submission client.
//!
//! Supported syntax: `signed-relay-sendmail -f envelope-from [--] recipient...`.
//! This is not a general sendmail command-line compatibility layer.

use std::env;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use signed_relay_lite::message::{NormalizeWriteError, WireNormalizer};
use signed_relay_lite::relay::{DeliveryResult, DeliveryStatus, Envelope};
use signed_relay_lite::submission::{
    read_server_reply, write_envelope_preamble, EnvelopePreamble, Ready, ServerReply,
    SubmissionError, SubmissionLimits, MAX_CHUNK_BYTES,
};

const EX_OK: i32 = 0;
const EX_USAGE: i32 = 64;
const EX_UNAVAILABLE: i32 = 69;
const EX_IOERR: i32 = 74;
const EX_TEMPFAIL: i32 = 75;
const EX_PROTOCOL: i32 = 76;
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
        Err(_) => return local_error(EX_IOERR, "could not connect to submission service"),
    };
    if stream.set_read_timeout(Some(READ_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(WRITE_TIMEOUT)).is_err()
    {
        return local_error(EX_IOERR, "could not configure submission connection");
    }
    let result = match submit_message(&mut io::stdin().lock(), &mut stream, &envelope) {
        Ok(result) => result,
        Err(ClientError::Input(InputError::TooLarge)) => {
            return local_error(EX_USAGE, "message is too large")
        }
        Err(ClientError::Input(InputError::Io)) => {
            return local_error(EX_IOERR, "could not read message input")
        }
        Err(ClientError::Write) => return local_error(EX_IOERR, "could not submit message"),
        Err(ClientError::Response(SubmissionError::Io(_))) => {
            return local_error(EX_IOERR, "submission result was incomplete")
        }
        Err(ClientError::Response(_)) => {
            return local_error(EX_PROTOCOL, "invalid submission response")
        }
        Err(ClientError::Protocol) => return local_error(EX_PROTOCOL, "invalid submission limits"),
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
    Protocol,
}

fn submit_message<R: Read, S: Read + Write>(
    input: &mut R,
    stream: &mut S,
    envelope: &Envelope,
) -> Result<DeliveryResult, ClientError> {
    write_envelope_preamble(
        stream,
        &EnvelopePreamble {
            envelope: envelope.clone(),
        },
    )
    .map_err(|_| ClientError::Write)?;
    stream.flush().map_err(|_| ClientError::Write)?;
    let ready = match read_server_reply(stream).map_err(ClientError::Response)? {
        ServerReply::Final(result) => return Ok(result),
        ServerReply::Ready(ready) => validate_ready(ready)?,
    };

    let max_message_bytes =
        usize::try_from(ready.max_message_bytes).map_err(|_| ClientError::Protocol)?;
    let mut chunks = ChunkWriter::new(stream, ready.max_chunk_bytes as usize);
    let mut normalizer = WireNormalizer::new(max_message_bytes);
    let mut input_chunk = [0_u8; 8192];
    loop {
        let read = input
            .read(&mut input_chunk)
            .map_err(|_| ClientError::Input(InputError::Io))?;
        if read == 0 {
            break;
        }
        normalizer
            .write_to(&input_chunk[..read], &mut chunks)
            .map_err(map_normalize_error)?;
    }
    normalizer
        .finish_to(&mut chunks)
        .map_err(map_normalize_error)?;
    chunks.finish().map_err(|_| ClientError::Write)?;
    stream.flush().map_err(|_| ClientError::Write)?;

    match read_server_reply(stream).map_err(ClientError::Response)? {
        ServerReply::Final(result)
            if result.diagnostic.len() <= ready.max_diagnostic_bytes as usize =>
        {
            Ok(result)
        }
        ServerReply::Final(_) | ServerReply::Ready(_) => Err(ClientError::Protocol),
    }
}

fn validate_ready(ready: Ready) -> Result<Ready, ClientError> {
    let fixed_diagnostic_ceiling = SubmissionLimits::production(1).max_diagnostic_bytes;
    if ready.max_message_bytes == 0
        || usize::try_from(ready.max_message_bytes).is_err()
        || ready.max_chunk_bytes == 0
        || ready.max_chunk_bytes as usize > MAX_CHUNK_BYTES
        || ready.max_diagnostic_bytes == 0
        || ready.max_diagnostic_bytes as usize > fixed_diagnostic_ceiling
    {
        return Err(ClientError::Protocol);
    }
    Ok(ready)
}

fn map_normalize_error(error: NormalizeWriteError) -> ClientError {
    match error {
        NormalizeWriteError::OutputLimitExceeded => ClientError::Input(InputError::TooLarge),
        NormalizeWriteError::Io(_) => ClientError::Write,
    }
}

struct ChunkWriter<'a, W> {
    stream: &'a mut W,
    chunk: Vec<u8>,
    max_chunk_bytes: usize,
}

impl<'a, W: Write> ChunkWriter<'a, W> {
    fn new(stream: &'a mut W, max_chunk_bytes: usize) -> Self {
        Self {
            stream,
            chunk: Vec::with_capacity(max_chunk_bytes),
            max_chunk_bytes,
        }
    }

    fn write_chunk(&mut self) -> io::Result<()> {
        if !self.chunk.is_empty() {
            self.stream
                .write_all(&(self.chunk.len() as u32).to_be_bytes())?;
            self.stream.write_all(&self.chunk)?;
            self.chunk.clear();
        }
        Ok(())
    }

    fn finish(mut self) -> io::Result<()> {
        self.write_chunk()?;
        self.stream.write_all(&0_u32.to_be_bytes())
    }
}

impl<W: Write> Write for ChunkWriter<'_, W> {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let original_len = bytes.len();
        while !bytes.is_empty() {
            let available = self.max_chunk_bytes - self.chunk.len();
            let take = available.min(bytes.len());
            self.chunk.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.chunk.len() == self.max_chunk_bytes {
                self.write_chunk()?;
            }
        }
        Ok(original_len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.write_chunk()?;
        self.stream.flush()
    }
}

fn local_error(code: i32, context: &str) -> i32 {
    eprintln!("signed-relay-sendmail: {context}");
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::cell::Cell;
    use std::io::Cursor;
    use std::rc::Rc;

    use signed_relay_lite::submission::write_server_reply;

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

    struct ReadSpy {
        inner: Cursor<Vec<u8>>,
        reads: Rc<Cell<usize>>,
    }

    impl ReadSpy {
        fn new(bytes: &[u8], reads: Rc<Cell<usize>>) -> Self {
            Self {
                inner: Cursor::new(bytes.to_vec()),
                reads,
            }
        }
    }

    impl Read for ReadSpy {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.reads.set(self.reads.get() + 1);
            self.inner.read(buffer)
        }
    }

    struct FakeDuplex {
        response: Cursor<Vec<u8>>,
        request: Vec<u8>,
        input_reads: Rc<Cell<usize>>,
        response_reads: usize,
        flushes: usize,
    }

    impl FakeDuplex {
        fn delivering(input_reads: Rc<Cell<usize>>) -> Self {
            let mut response = Vec::new();
            write_server_reply(
                &mut response,
                &ServerReply::Ready(Ready {
                    max_message_bytes: (LEGACY_CLIENT_MESSAGE_BYTES + 1024) as u64,
                    max_chunk_bytes: MAX_CHUNK_BYTES as u32,
                    max_diagnostic_bytes: 4096,
                }),
            )
            .unwrap();
            write_server_reply(
                &mut response,
                &ServerReply::Final(DeliveryResult::delivered("", Some(250))),
            )
            .unwrap();
            Self {
                response: Cursor::new(response),
                request: Vec::new(),
                input_reads,
                response_reads: 0,
                flushes: 0,
            }
        }

        fn replying(input_reads: Rc<Cell<usize>>, replies: &[ServerReply]) -> Self {
            let mut response = Vec::new();
            for reply in replies {
                write_server_reply(&mut response, reply).unwrap();
            }
            Self {
                response: Cursor::new(response),
                request: Vec::new(),
                input_reads,
                response_reads: 0,
                flushes: 0,
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
                assert!(
                    self.flushes > 0,
                    "envelope must be flushed before READY is read"
                );
                assert!(self.request.starts_with(b"SRL2"));
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
            self.flushes += 1;
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

    fn ready(
        max_message_bytes: u64,
        max_chunk_bytes: u32,
        max_diagnostic_bytes: u32,
    ) -> ServerReply {
        ServerReply::Ready(Ready {
            max_message_bytes,
            max_chunk_bytes,
            max_diagnostic_bytes,
        })
    }

    fn assert_rejected_before_stdin(ready: ServerReply) {
        let reads = Rc::new(Cell::new(0));
        let mut input = ReadSpy::new(b"x", Rc::clone(&reads));
        let mut peer = FakeDuplex::replying(reads, &[ready]);
        assert!(matches!(
            submit_message(&mut input, &mut peer, &envelope()),
            Err(ClientError::Protocol)
        ));
        assert_eq!(peer.input_reads.get(), 0);
        let mut preamble = Vec::new();
        write_envelope_preamble(
            &mut preamble,
            &EnvelopePreamble {
                envelope: envelope(),
            },
        )
        .unwrap();
        assert_eq!(peer.request, preamble, "no body frame may be transmitted");
    }

    #[test]
    fn client_waits_for_server_limit_before_reading_message() {
        let reads = Rc::new(Cell::new(0));
        let mut input = ReadSpy::new(b"x", Rc::clone(&reads));
        let mut peer = FakeDuplex::delivering(Rc::clone(&reads));
        submit_message(&mut input, &mut peer, &envelope()).unwrap();
        assert!(reads.get() > 0, "stdin must be consumed after READY");
    }

    #[test]
    fn client_accepts_a_stream_larger_than_the_removed_25_mib_constant_when_server_allows_it() {
        let reads = Rc::new(Cell::new(0));
        let mut input =
            CountingGeneratedReader::new(LEGACY_CLIENT_MESSAGE_BYTES + 1, Rc::clone(&reads));
        let mut peer = FakeDuplex::delivering(reads);
        let result = submit_message(&mut input, &mut peer, &envelope());
        assert!(
            result.is_ok(),
            "the daemon-advertised limit must be authoritative"
        );
    }

    #[test]
    fn early_final_prevents_stdin_reads_and_body_writes() {
        let reads = Rc::new(Cell::new(0));
        let final_result = DeliveryResult::permanent_failure("rejected", Some(550));
        let mut peer = FakeDuplex::replying(
            Rc::clone(&reads),
            &[ServerReply::Final(final_result.clone())],
        );
        let mut input = ReadSpy::new(b"x", reads);
        let result = submit_message(&mut input, &mut peer, &envelope()).unwrap();
        assert_eq!(result, final_result);
        assert_eq!(peer.input_reads.get(), 0);
    }

    #[test]
    fn ready_with_zero_message_limit_is_protocol_error_before_stdin() {
        assert_rejected_before_stdin(ready(0, 1, 1));
    }

    #[test]
    fn ready_with_zero_chunk_limit_is_protocol_error_before_stdin() {
        assert_rejected_before_stdin(ready(1, 0, 1));
    }

    #[test]
    fn ready_with_overlarge_chunk_limit_is_protocol_error_before_stdin() {
        assert_rejected_before_stdin(ready(1, MAX_CHUNK_BYTES as u32 + 1, 1));
    }

    #[test]
    fn ready_with_zero_diagnostic_limit_is_protocol_error_before_stdin() {
        assert_rejected_before_stdin(ready(1, 1, 0));
    }

    #[test]
    fn ready_above_fixed_diagnostic_ceiling_is_protocol_error_before_stdin() {
        assert_rejected_before_stdin(ready(1, 1, 4097));
    }

    #[test]
    fn empty_stdin_writes_canonical_crlf_and_zero_terminator() {
        let reads = Rc::new(Cell::new(0));
        let mut peer = FakeDuplex::replying(
            Rc::clone(&reads),
            &[
                ready(2, 2, 4096),
                ServerReply::Final(DeliveryResult::delivered("", Some(250))),
            ],
        );
        submit_message(&mut io::empty(), &mut peer, &envelope()).unwrap();
        assert!(peer
            .request
            .ends_with(&[0, 0, 0, 2, b'\r', b'\n', 0, 0, 0, 0]));
    }

    #[test]
    fn normalized_output_exactly_at_daemon_limit_is_accepted() {
        let reads = Rc::new(Cell::new(0));
        let mut peer = FakeDuplex::replying(
            reads,
            &[
                ready(3, 3, 4096),
                ServerReply::Final(DeliveryResult::delivered("", Some(250))),
            ],
        );
        submit_message(&mut Cursor::new(b"A\n"), &mut peer, &envelope()).unwrap();
        assert!(peer
            .request
            .ends_with(&[0, 0, 0, 3, b'A', b'\r', b'\n', 0, 0, 0, 0]));
    }

    #[test]
    fn final_diagnostic_above_advertised_limit_is_protocol_error() {
        let reads = Rc::new(Cell::new(0));
        let mut peer = FakeDuplex::replying(
            reads,
            &[
                ready(2, 2, 1),
                ServerReply::Final(DeliveryResult::temporary_failure("xx", None)),
            ],
        );
        assert!(matches!(
            submit_message(&mut io::empty(), &mut peer, &envelope()),
            Err(ClientError::Protocol)
        ));
    }

    #[test]
    fn normalization_expansion_rejects_before_transmitting_limit_plus_one() {
        let reads = Rc::new(Cell::new(0));
        let mut peer = FakeDuplex::replying(reads, &[ready(2, 2, 4096)]);
        let preamble_len = {
            let mut bytes = Vec::new();
            write_envelope_preamble(
                &mut bytes,
                &EnvelopePreamble {
                    envelope: envelope(),
                },
            )
            .unwrap();
            bytes.len()
        };
        assert!(matches!(
            submit_message(&mut Cursor::new(b"A\n"), &mut peer, &envelope()),
            Err(ClientError::Input(InputError::TooLarge))
        ));
        assert_eq!(&peer.request[preamble_len..], &[0, 0, 0, 2, b'A', b'\r']);
    }
}

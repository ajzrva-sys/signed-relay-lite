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
use signed_relay_lite::relay::{DeliveryStatus, Envelope};
use signed_relay_lite::submission::{read_response, SubmissionError, SubmissionLimits};

const EX_OK: i32 = 0;
const EX_USAGE: i32 = 64;
const EX_UNAVAILABLE: i32 = 69;
const EX_TEMPFAIL: i32 = 75;
const MAX_MESSAGE_BYTES: usize = 26_214_400;
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

    let message = match read_message() {
        Ok(message) => message,
        Err(InputError::TooLarge) => return local_error(EX_USAGE, "message is too large"),
        Err(InputError::Io) => return local_error(EX_TEMPFAIL, "could not read message input"),
    };

    let mut stream = match UnixStream::connect(&socket_path) {
        Ok(stream) => stream,
        Err(_) => return local_error(EX_TEMPFAIL, "could not connect to submission service"),
    };
    if stream.set_read_timeout(Some(READ_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(WRITE_TIMEOUT)).is_err()
    {
        return local_error(EX_TEMPFAIL, "could not configure submission connection");
    }
    if write_request(&mut stream, &envelope, &message).is_err()
        || stream.flush().is_err()
        || stream.shutdown(Shutdown::Write).is_err()
    {
        return local_error(EX_TEMPFAIL, "could not submit message");
    }

    let limits = SubmissionLimits {
        max_recipients: 100,
        max_address_bytes: 254,
        max_message_bytes: MAX_MESSAGE_BYTES as u64,
        max_diagnostic_bytes: 4096,
    };
    let result = match read_response(&mut stream, &limits) {
        Ok(result) => result,
        Err(SubmissionError::Io(_)) => {
            return local_error(EX_TEMPFAIL, "submission result was incomplete")
        }
        Err(_) => return local_error(EX_USAGE, "invalid submission response"),
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

enum InputError {
    TooLarge,
    Io,
}

fn read_message() -> Result<Vec<u8>, InputError> {
    let mut normalizer = WireNormalizer::new(MAX_MESSAGE_BYTES);
    let mut input = io::stdin().lock();
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

fn write_request(stream: &mut UnixStream, envelope: &Envelope, message: &[u8]) -> io::Result<()> {
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

fn write_bytes(stream: &mut UnixStream, bytes: &[u8]) -> io::Result<()> {
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)
}

fn local_error(code: i32, context: &str) -> i32 {
    eprintln!("signed-relay-sendmail: {context}");
    code
}

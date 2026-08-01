//! signed-relay-lite daemon binary.

use signed_relay_lite::config::{check_fips_environment, RuntimeConfig};
use signed_relay_lite::message::Limits as MessageLimits;
use signed_relay_lite::relay::RelayPool;
use signed_relay_lite::smtp::SmtpConnection;
use signed_relay_lite::submission::{MemoryBudget, SubmissionLimits, SubmissionServer};
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

static SIGNAL_SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn on_shutdown(_: libc::c_int) {
    SIGNAL_SHUTDOWN.store(true, Ordering::Relaxed);
}

const USAGE: &str = "Usage:\n  signed-relay-lite --config ABS\n  signed-relay-lite --check-config ABS\n  signed-relay-lite --help\n  signed-relay-lite --version\n";

enum Command {
    Serve(PathBuf),
    Check(PathBuf),
    Help,
    Version,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("signed-relay-lite: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    match parse_args(&env::args().collect::<Vec<_>>())? {
        Command::Help => {
            print!("{USAGE}");
            Ok(())
        }
        Command::Version => {
            println!("signed-relay-lite {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Check(path) => validate(path).map(|_| println!("configuration valid")),
        Command::Serve(path) => run_daemon(path),
    }
}

fn parse_args(args: &[String]) -> Result<Command, String> {
    let command = match args.get(1).map(String::as_str) {
        Some("--help") if args.len() == 2 => Command::Help,
        Some("--version") if args.len() == 2 => Command::Version,
        Some("--config") | Some("--check-config") if args.len() == 3 => {
            let path = PathBuf::from(&args[2]);
            if !path.is_absolute() {
                return Err("configuration path must be absolute".to_owned());
            }
            if args[1] == "--config" {
                Command::Serve(path)
            } else {
                Command::Check(path)
            }
        }
        Some(option) if option.starts_with('-') => {
            return Err(format!("unknown or invalid option: {option}"))
        }
        Some(value) => return Err(format!("unexpected argument: {value}")),
        None => return Err("one option is required".to_owned()),
    };
    Ok(command)
}

fn validate(path: PathBuf) -> Result<RuntimeConfig, String> {
    let config = RuntimeConfig::load(&path)?;
    check_fips_environment(config.require_fips)?;
    Ok(config)
}

fn run_daemon(path: PathBuf) -> Result<(), String> {
    SIGNAL_SHUTDOWN.store(false, Ordering::Relaxed);
    let config = Arc::new(validate(path)?);
    let relay_config = Arc::clone(&config);
    let relay = Arc::new(
        RelayPool::try_new(
            config.relay_workers,
            config.max_concurrent_submissions,
            move || smtp_connection(&relay_config),
        )
        .map_err(|error| format!("cannot initialize relay workers: {error}"))?,
    );

    let submission_limits = SubmissionLimits::production(config.max_message_bytes as u64);
    let message_limits = MessageLimits::production(config.max_message_bytes);
    install_signal_handlers()?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let server = SubmissionServer::bind(
        &config.listen,
        0o660,
        config.submission_timeout,
        config.max_concurrent_submissions,
        submission_limits,
        message_limits,
        MemoryBudget::new(config.global_message_memory_bytes),
        config.signing.clone(),
        Arc::clone(&relay),
        Arc::clone(&shutdown),
    )
    .map_err(|error| format!("cannot bind submission socket: {error}"))?;
    let monitor_shutdown = Arc::clone(&shutdown);
    let monitor = thread::spawn(move || {
        while !SIGNAL_SHUTDOWN.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(10));
        }
        monitor_shutdown.store(true, Ordering::Release);
    });
    let result = server
        .run()
        .map_err(|error| format!("submission server failed: {error}"));
    drop(server);
    SIGNAL_SHUTDOWN.store(true, Ordering::Relaxed);
    let _ = monitor.join();
    drop(relay);
    result
}

fn smtp_connection(config: &RuntimeConfig) -> std::io::Result<SmtpConnection> {
    match (&config.relay_username, &config.relay_password) {
        (Some(username), Some(password)) => SmtpConnection::new_implicit_tls_with_auth(
            config.client_name.clone(),
            config.relay_host.clone(),
            config.relay_port,
            config.delivery_timeout,
            None,
            username.clone(),
            password.duplicate(),
        ),
        (None, None) => SmtpConnection::new_implicit_tls(
            config.client_name.clone(),
            config.relay_host.clone(),
            config.relay_port,
            config.delivery_timeout,
            None,
        ),
        _ => unreachable!("configuration validates the authentication pair"),
    }
}

fn install_signal_handlers() -> Result<(), String> {
    // SAFETY: `install_signal` initializes a complete `sigaction` structure
    // and installs only the async-signal-safe `on_shutdown` handler.
    unsafe {
        if install_signal(libc::SIGTERM) || install_signal(libc::SIGINT) {
            return Err("cannot install signal handlers".to_owned());
        }
    }
    Ok(())
}

unsafe fn install_signal(signal: libc::c_int) -> bool {
    // SAFETY: zero is a valid initial representation for `sigaction`; all
    // required fields are populated before the structure is passed to libc.
    let mut action: libc::sigaction = std::mem::zeroed();
    action.sa_sigaction = on_shutdown as *const () as libc::sighandler_t;
    libc::sigemptyset(&mut action.sa_mask);
    action.sa_flags = 0;
    libc::sigaction(signal, &action, std::ptr::null_mut()) != 0
}

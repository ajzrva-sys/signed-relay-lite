//! Unix-domain submission server and request processing.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::budget::MemoryBudget;
use super::protocol::{read_request, write_response, SubmissionError, SubmissionLimits};
use crate::config::SigningConfig;
use crate::message::{Limits as MessageLimits, Message};
use crate::relay::{DeliveryJob, DeliveryResult, RelayPool};

/// Synchronous, bounded SRL1 server on a Unix-domain socket.
pub struct SubmissionServer {
    listener: UnixListener,
    path: PathBuf,
    created: SocketIdentity,
    timeout: Duration,
    slots: Arc<HandlerSlots>,
    submission_limits: Arc<SubmissionLimits>,
    message_limits: Arc<MessageLimits>,
    budget: MemoryBudget,
    signing: SigningConfig,
    relay: Arc<RelayPool>,
    shutdown: Arc<AtomicBool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketIdentity {
    dev: u64,
    ino: u64,
}

impl SocketIdentity {
    fn from(metadata: &fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }
}

#[derive(Debug)]
struct HandlerSlots {
    active: Mutex<usize>,
    changed: Condvar,
    maximum: usize,
}

struct HandlerSlot {
    slots: Arc<HandlerSlots>,
}

impl Drop for HandlerSlot {
    fn drop(&mut self) {
        let mut active = self
            .slots
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *active = active.saturating_sub(1);
        self.slots.changed.notify_one();
    }
}

impl HandlerSlots {
    fn reserve(self: &Arc<Self>, shutdown: &AtomicBool) -> Option<HandlerSlot> {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while *active >= self.maximum {
            if shutdown.load(Ordering::Acquire) {
                return None;
            }
            let waited = self.changed.wait_timeout(active, Duration::from_millis(25));
            active = match waited {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
        if shutdown.load(Ordering::Acquire) {
            return None;
        }
        *active += 1;
        Some(HandlerSlot {
            slots: Arc::clone(self),
        })
    }
}

impl SubmissionServer {
    /// Bind a server after applying conservative existing-path safety checks.
    #[allow(clippy::too_many_arguments)]
    pub fn bind(
        path: impl AsRef<Path>,
        socket_mode: u32,
        submission_timeout: Duration,
        max_active_handlers: usize,
        submission_limits: SubmissionLimits,
        message_limits: MessageLimits,
        budget: MemoryBudget,
        signing: SigningConfig,
        relay: Arc<RelayPool>,
        shutdown: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        let path = path.as_ref();
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "submission socket path must be absolute",
            ));
        }
        if max_active_handlers == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "max active handlers must be positive",
            ));
        }
        if submission_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "submission timeout must be positive",
            ));
        }
        if socket_mode == 0 || socket_mode & !0o777 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket mode contains non-permission bits",
            ));
        }

        prepare_socket_path(path)?;
        let listener = UnixListener::bind(path)?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket() {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "submission socket path changed during bind",
            ));
        }
        let created = SocketIdentity::from(&metadata);
        if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(socket_mode)) {
            remove_socket_if_identity(path, created);
            return Err(error);
        }
        if let Err(error) = listener.set_nonblocking(true) {
            remove_socket_if_identity(path, created);
            return Err(error);
        }
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.file_type().is_socket() || SocketIdentity::from(&metadata) != created {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "submission socket path changed during bind",
            ));
        }

        Ok(Self {
            listener,
            path: path.to_owned(),
            created,
            timeout: submission_timeout,
            slots: Arc::new(HandlerSlots {
                active: Mutex::new(0),
                changed: Condvar::new(),
                maximum: max_active_handlers,
            }),
            submission_limits: Arc::new(submission_limits),
            message_limits: Arc::new(message_limits),
            budget,
            signing,
            relay,
            shutdown,
        })
    }

    /// Accept connections until the shared shutdown flag is set.
    ///
    /// Every handler is joined before this method returns. Shutdown never
    /// substitutes a successful result: accepted handlers finish their actual
    /// parse, signing, and relay path (or its bounded timeout) before joining.
    pub fn run(&self) -> io::Result<()> {
        let mut handlers: Vec<JoinHandle<()>> = Vec::new();
        while !self.shutdown.load(Ordering::Acquire) {
            reap_finished_handlers(&mut handlers);
            match self.listener.accept() {
                Ok((stream, _)) => {
                    let Some(slot) = self.slots.reserve(&self.shutdown) else {
                        break;
                    };
                    let timeout = self.timeout;
                    let submission_limits = Arc::clone(&self.submission_limits);
                    let message_limits = Arc::clone(&self.message_limits);
                    let budget = self.budget.clone();
                    let signing = self.signing.clone();
                    let relay = Arc::clone(&self.relay);
                    let handler = thread::Builder::new()
                        .name("submission-handler".to_owned())
                        .spawn(move || {
                            let _slot = slot;
                            handle_stream(
                                stream,
                                timeout,
                                &submission_limits,
                                &message_limits,
                                &budget,
                                &signing,
                                &relay,
                            );
                        });
                    match handler {
                        Ok(handler) => handlers.push(handler),
                        Err(error) => {
                            join_handlers(handlers);
                            self.remove_created_socket();
                            return Err(error);
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    join_handlers(handlers);
                    self.remove_created_socket();
                    return Err(error);
                }
            }
        }
        join_handlers(handlers);
        self.remove_created_socket();
        Ok(())
    }

    fn remove_created_socket(&self) {
        remove_socket_if_identity(&self.path, self.created);
    }
}

impl Drop for SubmissionServer {
    fn drop(&mut self) {
        self.remove_created_socket();
    }
}

fn prepare_socket_path(path: &Path) -> io::Result<()> {
    let original = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !original.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "submission path exists and is not a socket",
        ));
    }
    // SAFETY: geteuid has no preconditions and does not access memory.
    let effective_uid = unsafe { libc::geteuid() };
    if original.uid() != effective_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "existing submission socket is owned by another user",
        ));
    }
    match UnixStream::connect(path) {
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "existing submission socket is active",
            ));
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) => {}
        Err(error) => return Err(error),
    }
    let current = fs::symlink_metadata(path)?;
    if !current.file_type().is_socket()
        || SocketIdentity::from(&current) != SocketIdentity::from(&original)
    {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "existing submission socket changed during stale check",
        ));
    }
    fs::remove_file(path)
}

fn remove_socket_if_identity(path: &Path, expected: SocketIdentity) {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_socket() && SocketIdentity::from(&metadata) == expected {
            let _ = fs::remove_file(path);
        }
    }
}

fn join_handlers(handlers: Vec<JoinHandle<()>>) {
    for handler in handlers {
        let _ = handler.join();
    }
}

fn reap_finished_handlers(handlers: &mut Vec<JoinHandle<()>>) {
    let mut index = 0;
    while index < handlers.len() {
        if handlers[index].is_finished() {
            let handler = handlers.swap_remove(index);
            let _ = handler.join();
        } else {
            index += 1;
        }
    }
}

fn handle_stream(
    mut stream: UnixStream,
    timeout: Duration,
    submission_limits: &SubmissionLimits,
    message_limits: &MessageLimits,
    budget: &MemoryBudget,
    signing: &SigningConfig,
    relay: &RelayPool,
) {
    let setup = stream
        .set_nonblocking(false)
        .and_then(|()| stream.set_read_timeout(Some(timeout)))
        .and_then(|()| stream.set_write_timeout(Some(timeout)));
    let result = if let Err(error) = setup {
        DeliveryResult::temporary_failure(format!("submission socket setup failed: {error}"), None)
    } else {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            process_request(
                &mut stream,
                submission_limits,
                message_limits,
                budget,
                signing,
                relay,
            )
        })) {
            Ok(result) => result,
            Err(_) => DeliveryResult::temporary_failure("submission handler panicked", None),
        }
    };
    let _ = write_response(&mut stream, &result, submission_limits.max_diagnostic_bytes)
        .and_then(|()| stream.flush());
}

fn process_request(
    stream: &mut UnixStream,
    submission_limits: &SubmissionLimits,
    message_limits: &MessageLimits,
    budget: &MemoryBudget,
    signing: &SigningConfig,
    relay: &RelayPool,
) -> DeliveryResult {
    let request = match read_request(stream, submission_limits, budget) {
        Ok(request) => request,
        Err(SubmissionError::BudgetExhausted {
            requested,
            capacity,
        }) => {
            return DeliveryResult::temporary_failure(
                format!(
                    "submission memory budget exhausted: requested {requested} bytes, capacity {capacity} bytes"
                ),
                None,
            );
        }
        Err(error) => {
            return DeliveryResult::protocol_rejection(
                format!("invalid submission frame: {error:?}"),
                None,
            );
        }
    };
    let (envelope, bytes, reservation) = request.into_parts();
    let limits = MessageLimits {
        max_headers: message_limits.max_headers,
        max_header_bytes: message_limits.max_header_bytes,
    };
    let message = match Message::parse(bytes, limits) {
        Ok(message) => message,
        Err(error) => {
            return DeliveryResult::protocol_rejection(format!("invalid message: {error:?}"), None);
        }
    };
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let headers: Vec<_> = message.header_refs().collect();
    let signature = match crate::dkim::sign(signing, &headers, message.body_hash(), timestamp) {
        Ok(signature) => signature,
        Err(error) => return DeliveryResult::protocol_rejection(error, None),
    };
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    let job = DeliveryJob {
        envelope,
        message,
        signature,
        result_tx,
    };
    if relay.enqueue(job).is_err() {
        return DeliveryResult::temporary_failure("relay worker queue disconnected", None);
    }
    let result = result_rx.recv().unwrap_or_else(|_| {
        DeliveryResult::temporary_failure("relay worker stopped without a result", None)
    });
    drop(reservation);
    result
}

//! Strict bounded SRL1 submission protocol and Unix-domain server.

mod budget;
mod protocol;
mod server;

pub use budget::{MemoryBudget, MemoryReservation};
pub use protocol::{
    read_request, read_response, write_request, write_response, SubmissionError, SubmissionLimits,
    SubmissionRequest,
};
pub use server::SubmissionServer;

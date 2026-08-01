//! Strict bounded SRL1 submission protocol and Unix-domain server.

mod budget;
mod protocol;
mod server;

pub use budget::{MemoryBudget, MemoryReservation};
pub use protocol::{
    read_envelope_preamble, read_final_result, read_request, read_response, read_server_reply,
    write_envelope_preamble, write_final_result, write_request, write_response, write_server_reply,
    EnvelopePreamble, Ready, ServerReply, SubmissionError, SubmissionLimits, SubmissionRequest,
    FINAL_KIND, READY_KIND,
};
pub use server::SubmissionServer;

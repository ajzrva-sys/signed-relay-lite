//! Strict bounded SRL2 submission codecs and Unix-domain server.
//!
//! A client sends an envelope and waits for daemon-authoritative `READY` limits
//! (or an early `FINAL`) before streaming bounded chunks, a zero-length end
//! marker, and receiving `FINAL`. SRL1 frames are intentionally rejected.
//! Retained message bytes are globally budgeted separately from bounded
//! temporary chunk buffers and process memory overhead.

mod budget;
mod protocol;
mod server;

pub use budget::{MemoryBudget, MemoryReservation};
pub use protocol::{
    read_chunk_stream, read_envelope_preamble, read_final_result, read_request, read_response,
    read_server_reply, write_chunk_stream, write_envelope_preamble, write_final_result,
    write_request, write_response, write_server_reply, EnvelopePreamble, Ready, RetainedMessage,
    ServerReply, SubmissionError, SubmissionLimits, SubmissionRequest, FINAL_KIND, MAX_CHUNK_BYTES,
    READY_KIND,
};
pub use server::{SubmissionServer, SubmissionServerConfig};

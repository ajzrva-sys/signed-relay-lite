//! Strict bounded submission codecs and SRL2 Unix-domain server.

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

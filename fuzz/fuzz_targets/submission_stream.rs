#![no_main]

use libfuzzer_sys::fuzz_target;
use signed_relay_lite::relay::{DeliveryResult, DeliveryStatus, Envelope};
use signed_relay_lite::submission::{
    read_chunk_stream, read_envelope_preamble, write_envelope_preamble, write_server_reply,
    EnvelopePreamble, MemoryBudget, Ready, ServerReply, SubmissionError,
};
use std::io::Cursor;

const INPUT_CAP: usize = 2 * 1024;
const MESSAGE_CAP: u64 = 128;
const CHUNK_CAP: u32 = 32;
const BUDGET_CAP: usize = 96;

fn pre_delivery_result(error: &SubmissionError) -> DeliveryResult {
    if error.is_temporary() {
        DeliveryResult::temporary_failure("submission resource limit", None)
    } else {
        DeliveryResult::protocol_rejection("invalid submission stream", None)
    }
}

fn assert_pre_delivery(error: &SubmissionError) {
    assert!(!error.is_ambiguous());
    let result = pre_delivery_result(error);
    assert!(!result.ambiguous);
    assert_ne!(result.status, DeliveryStatus::Delivered);
}

fuzz_target!(|data: &[u8]| {
    if data.len() > INPUT_CAP {
        return;
    }

    // Build a valid public SRL2 envelope so arbitrary bytes can exercise the
    // post-READY chunk state. A raw-input branch also exercises ReadEnvelope
    // rejection without granting delivery semantics.
    let raw_envelope = read_envelope_preamble(&mut Cursor::new(data));
    if let Err(error) = &raw_envelope {
        assert_pre_delivery(error);
    }

    let Ok(envelope) = Envelope::new(b"", vec![b"fuzz@example.test".to_vec()]) else {
        return;
    };
    let mut wire = Vec::with_capacity(64 + data.len());
    if write_envelope_preamble(&mut wire, &EnvelopePreamble { envelope }).is_err() {
        return;
    }
    wire.extend_from_slice(data);

    let mut reader = Cursor::new(wire);
    let envelope = match read_envelope_preamble(&mut reader) {
        Ok(envelope) => envelope,
        Err(error) => {
            assert_pre_delivery(&error);
            return;
        }
    };

    // ReadEnvelope -> Ready: serialize the daemon-authoritative limits to a
    // bounded sink using only the public SRL2 response API.
    let ready = Ready {
        max_message_bytes: MESSAGE_CAP,
        max_chunk_bytes: CHUNK_CAP,
        max_diagnostic_bytes: 64,
    };
    let mut sink = Vec::with_capacity(32);
    if write_server_reply(&mut sink, &ServerReply::Ready(ready.clone())).is_err() {
        return;
    }
    assert!(sink.len() <= 32);

    // Ready -> ReadChunks -> End. Keep the envelope live to model the actual
    // state transition, while retained message ownership is budget checked.
    let _envelope = envelope;
    let budget = MemoryBudget::new(BUDGET_CAP);
    let retained = read_chunk_stream(
        &mut reader,
        ready.max_message_bytes,
        ready.max_chunk_bytes,
        &budget,
    );
    match &retained {
        Ok(message) => {
            assert!(message.bytes().len() <= MESSAGE_CAP as usize);
            assert!(message.bytes().len() <= BUDGET_CAP);
            assert_eq!(message.bytes().len(), message.reserved_bytes());
        }
        Err(error) => assert_pre_delivery(error),
    }
    assert!(budget.used() <= budget.capacity());
    drop(retained);
    assert_eq!(budget.used(), 0);
});

#![no_main]

use libfuzzer_sys::fuzz_target;
use signed_relay_lite::submission::{
    read_chunk_stream, read_envelope_preamble, read_final_result, read_server_reply, MemoryBudget,
};
use std::io::Cursor;

const INPUT_CAP: usize = 4 * 1024;
const MESSAGE_CAP: u64 = 256;
const CHUNK_CAP: u32 = 64;

fn exercise(data: &[u8]) {
    let _ = read_envelope_preamble(&mut Cursor::new(data));
    let _ = read_server_reply(&mut Cursor::new(data));
    let _ = read_final_result(&mut Cursor::new(data));

    let budget = MemoryBudget::new(MESSAGE_CAP as usize);
    let retained = read_chunk_stream(&mut Cursor::new(data), MESSAGE_CAP, CHUNK_CAP, &budget);
    if let Ok(message) = &retained {
        assert!(message.bytes().len() <= MESSAGE_CAP as usize);
        assert_eq!(message.bytes().len(), message.reserved_bytes());
    }
    assert!(budget.used() <= budget.capacity());
    drop(retained);
    assert_eq!(budget.used(), 0);
}

fuzz_target!(|data: &[u8]| {
    if data.len() > INPUT_CAP {
        return;
    }

    // The complete input covers arbitrary kinds, request/response flags,
    // FINAL statuses, chunk lengths, and u32/u64 conversion boundary bytes.
    exercise(data);

    // Use attacker-selected and protocol-field boundaries as truncation points.
    let selected = data
        .first()
        .map_or(0, |byte| usize::from(*byte) % (data.len() + 1));
    for end in [0, 1, 4, 5, 8, 9, 13, 17, 21, selected, data.len()] {
        exercise(&data[..end.min(data.len())]);
    }
});

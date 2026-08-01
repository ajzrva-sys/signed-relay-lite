#![no_main]

use libfuzzer_sys::fuzz_target;
use signed_relay_lite::submission::{
    read_envelope_preamble, read_final_result, read_server_reply,
};
use std::io::Cursor;

const INPUT_CAP: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > INPUT_CAP {
        return;
    }

    let _ = read_envelope_preamble(&mut Cursor::new(data));
    let _ = read_server_reply(&mut Cursor::new(data));
    let _ = read_final_result(&mut Cursor::new(data));
});

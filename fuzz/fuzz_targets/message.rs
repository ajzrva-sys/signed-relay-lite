#![no_main]

use libfuzzer_sys::fuzz_target;
use signed_relay_lite::message::{Limits, Message, NormalizeError, WireNormalizer};

const INPUT_CAP: usize = 64 * 1024;
const OUTPUT_CAP: usize = 16 * 1024;

fn finish_one_chunk(data: &[u8]) -> Result<Vec<u8>, NormalizeError> {
    let mut normalizer = WireNormalizer::new(OUTPUT_CAP);
    normalizer.write(data)?;
    normalizer.finish()
}

fn finish_varied_chunks(data: &[u8]) -> Result<Vec<u8>, NormalizeError> {
    let mut normalizer = WireNormalizer::new(OUTPUT_CAP);
    let mut start = 0;
    while start < data.len() {
        let proposed = start + usize::from(data[start] % 31) + 1;
        let mut end = proposed.min(data.len());
        if let Some(offset) = data[start..end].iter().position(|byte| *byte == b'\r') {
            end = start + offset + 1;
        }
        normalizer.write(&data[start..end])?;
        start = end;
    }
    normalizer.finish()
}

fuzz_target!(|data: &[u8]| {
    if data.len() > INPUT_CAP {
        return;
    }

    let owned = data.to_vec();
    if let Ok(message) = Message::parse(
        owned,
        Limits {
            max_headers: 128,
            max_header_bytes: 16 * 1024,
        },
    ) {
        assert_eq!(message.as_bytes(), data);
    }

    assert_eq!(finish_one_chunk(data), finish_varied_chunks(data));
});

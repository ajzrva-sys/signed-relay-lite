#![no_main]

use libfuzzer_sys::fuzz_target;
use signed_relay_lite::submission::{read_request, MemoryBudget, SubmissionLimits};
use std::io::Cursor;

const INPUT_CAP: usize = 64 * 1024;
const BUDGET_BYTES: usize = 16 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > INPUT_CAP {
        return;
    }

    let limits = SubmissionLimits {
        max_recipients: 16,
        max_address_bytes: 254,
        max_message_bytes: 16 * 1024,
        max_diagnostic_bytes: 1024,
    };
    let budget = MemoryBudget::new(BUDGET_BYTES);
    let mut cursor = Cursor::new(data);

    if let Ok(request) = read_request(&mut cursor, &limits, &budget) {
        let mut frame_len = 4usize + 4 + 4 + request.envelope.sender().len() + 4 + 8;
        for recipient in request.envelope.recipients() {
            frame_len = frame_len.checked_add(4 + recipient.len()).unwrap();
        }
        frame_len = frame_len.checked_add(request.message.len()).unwrap();

        assert_eq!(cursor.position(), frame_len as u64);
        assert!(frame_len <= data.len());
        assert_eq!(budget.used(), request.message.len());
        assert!(budget.used() <= BUDGET_BYTES);
        drop(request);
        assert_eq!(budget.used(), 0);
    } else {
        assert_eq!(budget.used(), 0);
    }
});

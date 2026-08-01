#![no_main]

use libfuzzer_sys::fuzz_target;
use signed_relay_lite::smtp::read_reply;
use std::io::{BufReader, Cursor};

const INPUT_CAP: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > INPUT_CAP {
        return;
    }

    let mut reader = BufReader::with_capacity(1, Cursor::new(data));
    if let Ok(reply) = read_reply(&mut reader, 512) {
        let consumed = reader.into_inner().position() as usize;
        assert!(consumed <= data.len());
        let prefix = &data[..consumed];
        let mut offset = 0;
        let mut diagnostics: Vec<&[u8]> = Vec::new();
        let expected_digits = [
            b'0' + (reply.code / 100) as u8,
            b'0' + ((reply.code / 10) % 10) as u8,
            b'0' + (reply.code % 10) as u8,
        ];

        while offset < prefix.len() {
            let relative_end = prefix[offset..]
                .windows(2)
                .position(|window| window == b"\r\n")
                .expect("successful reply consists of CRLF-terminated lines");
            let end = offset + relative_end;
            let line = &prefix[offset..end];
            assert!(line.len() >= 4);
            assert!(line[..3].iter().all(u8::is_ascii_digit));
            assert_eq!(line[..3], expected_digits);
            assert!(matches!(line[3], b'-' | b' '));
            diagnostics.push(&line[4..]);
            offset = end + 2;
        }

        assert_eq!(offset, prefix.len());
        assert!(!diagnostics.is_empty());
        assert!(diagnostics.len() <= 256);
        assert_eq!(prefix[prefix.len() - 2..], *b"\r\n");
        let last_start = prefix[..prefix.len() - 2]
            .windows(2)
            .rposition(|window| window == b"\r\n")
            .map_or(0, |position| position + 2);
        assert_eq!(prefix[last_start + 3], b' ');
        assert_eq!(reply.lines.len(), diagnostics.len());
        for (returned, stripped) in reply.lines.iter().zip(diagnostics) {
            assert_eq!(returned.as_slice(), stripped);
        }
    }
});

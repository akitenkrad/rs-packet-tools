#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use packet_tools_capture::Capture;

fuzz_target!(|data: &[u8]| {
    let Ok(mut capture) = Capture::from_reader(Cursor::new(data.to_vec())) else {
        return;
    };
    while let Some(record) = capture.next_record() {
        if record.is_err() {
            break;
        }
    }
});

use std::{fs, io::Cursor, path::PathBuf};

use packet_tools_capture::Capture;
use proptest::prelude::*;

proptest! {
    #[test]
    fn mutated_fixtures_never_panic(
        fixture in 0usize..6,
        operation in 0u8..3,
        position in any::<usize>(),
        inserted in proptest::collection::vec(any::<u8>(), 0..16),
        replacement in any::<u8>(),
    ) {
        let mut bytes = fixture_bytes()[fixture].clone();
        match operation {
            0 if !bytes.is_empty() => {
                let index = position % bytes.len();
                bytes[index] = replacement;
            }
            1 => bytes.truncate(position % (bytes.len() + 1)),
            _ => {
                let index = position % (bytes.len() + 1);
                bytes.splice(index..index, inserted);
            }
        }

        if let Ok(mut capture) = Capture::from_reader(Cursor::new(bytes.clone())) {
            drain(&mut capture);
        }

        let temp = tempfile::NamedTempFile::new().unwrap();
        fs::write(temp.path(), bytes).unwrap();
        if let Ok(mut capture) = Capture::open(temp.path()) {
            drain(&mut capture);
        }
    }
}

fn drain(capture: &mut Capture) {
    while let Some(record) = capture.next_record() {
        if record.is_err() {
            break;
        }
    }
}

fn fixture_bytes() -> Vec<Vec<u8>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    [
        "be_nsec.pcap",
        "be_usec.pcap",
        "le_nsec.pcap",
        "le_usec.pcap",
        "le_usec.pcap.gz",
        "multi_iface.pcapng",
    ]
    .iter()
    .map(|name| fs::read(root.join(name)).unwrap())
    .collect()
}

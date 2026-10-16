use std::{collections::BTreeMap, fs, io::Cursor, path::PathBuf};

use packet_tools_capture::{Capture, OpenOptions};
use serde::Deserialize;

#[derive(Deserialize)]
struct Manifest {
    files: BTreeMap<String, ManifestFile>,
}

#[derive(Deserialize)]
struct ManifestFile {
    packet_count: usize,
    packets: Vec<ExpectedPacket>,
}

#[derive(Deserialize)]
struct ExpectedPacket {
    index: u64,
    ts_ns: i64,
    caplen: u32,
    origlen: u32,
    linktype: u16,
    interface: u32,
    first_byte: u8,
}

#[derive(Debug, Eq, PartialEq)]
struct ObservedPacket {
    index: u64,
    ts_ns: Option<i64>,
    caplen: u32,
    origlen: u32,
    linktype: u16,
    interface: u32,
    first_byte: u8,
}

#[test]
fn fixtures_match_manifest_through_all_input_modes() {
    let root = fixture_root();
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();

    for (name, expected_file) in manifest.files {
        let path = root.join(&name);
        let bytes = fs::read(&path).unwrap();
        let expected = expected_file
            .packets
            .into_iter()
            .map(|packet| ObservedPacket {
                index: packet.index,
                ts_ns: Some(packet.ts_ns),
                caplen: packet.caplen,
                origlen: packet.origlen,
                linktype: packet.linktype,
                interface: packet.interface,
                first_byte: packet.first_byte,
            })
            .collect::<Vec<_>>();
        assert_eq!(expected.len(), expected_file.packet_count);

        assert_eq!(
            read_all(Capture::open(&path).unwrap()),
            expected,
            "mmap {name}"
        );
        assert_eq!(
            read_all(Capture::open_with(&path, OpenOptions { mmap: false }).unwrap()),
            expected,
            "stream {name}"
        );
        assert_eq!(
            read_all(Capture::from_reader(Cursor::new(bytes)).unwrap()),
            expected,
            "reader {name}"
        );
    }
}

#[test]
fn legacy_regression_stats_use_the_immediately_previous_timestamp() {
    let mut capture = Capture::open(fixture_root().join("le_usec.pcap")).unwrap();
    while let Some(record) = capture.next_record() {
        record.unwrap();
    }
    assert_eq!(capture.stats().timestamp_regressions, 1);
    assert_eq!(capture.stats().max_regression_ns, 1_000);
}

fn read_all(mut capture: Capture) -> Vec<ObservedPacket> {
    let mut packets = Vec::new();
    while let Some(record) = capture.next_record() {
        let record = record.unwrap();
        packets.push(ObservedPacket {
            index: record.index,
            ts_ns: record.ts_ns,
            caplen: record.caplen,
            origlen: record.origlen,
            linktype: record.linktype.0,
            interface: record.interface,
            first_byte: record.data[0],
        });
    }
    packets
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

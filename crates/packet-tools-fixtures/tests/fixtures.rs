use std::{
    collections::BTreeMap,
    fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    process::Command,
};

use flate2::read::GzDecoder;
use pcap_file::{
    pcap::PcapReader,
    pcapng::{Block, PcapNgReader, blocks::interface_description::InterfaceDescriptionOption},
};
use pcap_parser::{
    LegacyPcapReader, PcapBlockOwned, PcapError, PcapNGReader,
    pcapng::Block as ParserNgBlock,
    traits::{PcapNGPacketBlock, PcapReaderIterator},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const EXPECTED_FILES: [&str; 10] = [
    "app",
    "be_nsec.pcap",
    "be_usec.pcap",
    "flows",
    "le_nsec.pcap",
    "le_usec.pcap",
    "le_usec.pcap.gz",
    "manifest.json",
    "multi_iface.pcapng",
    "reassembly",
];

#[derive(Deserialize)]
struct Manifest {
    files: BTreeMap<String, ManifestFile>,
}

#[derive(Deserialize)]
struct ManifestFile {
    format: String,
    packet_count: usize,
    packets: Vec<ManifestPacket>,
    sha256: String,
}

#[derive(Deserialize)]
struct ManifestPacket {
    index: usize,
    ts_ns: u64,
    caplen: u32,
    origlen: u32,
    linktype: u32,
    interface: u32,
    first_byte: u8,
}

#[derive(Debug, Eq, PartialEq)]
struct ObservedPacket {
    ts_ns: u64,
    caplen: u32,
    origlen: u32,
    linktype: u32,
    interface: u32,
    first_byte: u8,
}

#[test]
fn generator_creates_the_complete_fixture_set() {
    let temp = tempfile::tempdir().unwrap();
    run_generator(temp.path());
    assert_eq!(file_names(temp.path()), EXPECTED_FILES);
}

#[test]
fn committed_fixtures_match_manifest_with_both_external_readers() {
    let root = fixture_root();
    let manifest: Manifest = serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap())
        .expect("manifest must match its documented schema");

    assert_eq!(manifest.files.len(), 9);
    for (name, expected_file) in &manifest.files {
        let stored = fs::read(root.join(name)).unwrap();
        assert_eq!(sha256(&stored), expected_file.sha256, "SHA-256 for {name}");
        let capture = if name.ends_with(".gz") {
            let mut decoded = Vec::new();
            GzDecoder::new(stored.as_slice())
                .read_to_end(&mut decoded)
                .unwrap();
            decoded
        } else {
            stored
        };

        let by_pcap_file = read_with_pcap_file(&capture, &expected_file.format);
        let by_pcap_parser = read_with_pcap_parser(&capture, &expected_file.format);
        assert_packets(name, expected_file, &by_pcap_file);
        assert_packets(name, expected_file, &by_pcap_parser);
        assert_eq!(by_pcap_file, by_pcap_parser, "external readers for {name}");
    }
}

#[test]
fn regeneration_is_byte_for_byte_identical() {
    let committed = fixture_root();
    let temp = tempfile::tempdir().unwrap();
    run_generator(temp.path());

    for name in EXPECTED_FILES {
        if matches!(name, "app" | "flows" | "reassembly") {
            continue;
        }
        assert_eq!(
            fs::read(committed.join(name)).unwrap(),
            fs::read(temp.path().join(name)).unwrap(),
            "regenerated {name} differs"
        );
    }
    assert_eq!(
        fs::read(committed.join("app/scenarios.pcap")).unwrap(),
        fs::read(temp.path().join("app/scenarios.pcap")).unwrap(),
        "regenerated application scenarios differ"
    );
    assert_eq!(
        fs::read(committed.join("flows/scenarios.pcap")).unwrap(),
        fs::read(temp.path().join("flows/scenarios.pcap")).unwrap(),
        "regenerated flow scenarios differ"
    );
    assert_eq!(
        fs::read(committed.join("reassembly/scenarios.pcap")).unwrap(),
        fs::read(temp.path().join("reassembly/scenarios.pcap")).unwrap(),
        "regenerated reassembly scenarios differ"
    );
}

#[test]
fn fixture_invariants_cover_required_edge_cases() {
    let root = fixture_root();
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
    let legacy = &manifest.files["le_usec.pcap"];
    assert_eq!(legacy.packet_count, 19);
    assert!(
        legacy
            .packets
            .iter()
            .any(|packet| packet.caplen < packet.origlen)
    );
    assert_eq!(
        legacy.packets.last().unwrap().ts_ns + 1_000,
        legacy.packets[17].ts_ns
    );
    for requirement in 1..=11 {
        let prefix = format!("{requirement}:");
        assert!(
            legacy
                .packets
                .iter()
                .any(|packet| packet_description(&root, packet.index).starts_with(&prefix)),
            "missing requirement {requirement}"
        );
    }
    let pcapng = &manifest.files["multi_iface.pcapng"];
    assert_eq!(pcapng.packet_count, 22);
    assert_eq!(
        pcapng
            .packets
            .iter()
            .filter(|packet| packet.interface == 1)
            .count(),
        3
    );
    assert!(
        pcapng
            .packets
            .iter()
            .filter(|packet| packet.interface == 1)
            .all(|packet| packet.ts_ns % 1_000 != 0)
    );
    let flows = &manifest.files["flows/scenarios.pcap"];
    assert_eq!(flows.packet_count, 22);
    assert!(
        flows
            .packets
            .windows(2)
            .any(|pair| pair[1].ts_ns < pair[0].ts_ns)
    );
}

fn packet_description(root: &Path, index: usize) -> String {
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
    manifest["files"]["le_usec.pcap"]["packets"][index]["description"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn assert_packets(name: &str, expected_file: &ManifestFile, actual: &[ObservedPacket]) {
    assert_eq!(
        actual.len(),
        expected_file.packet_count,
        "packet count for {name}"
    );
    assert_eq!(expected_file.packets.len(), expected_file.packet_count);
    for (index, (expected, actual)) in expected_file.packets.iter().zip(actual).enumerate() {
        assert_eq!(expected.index, index);
        assert_eq!(
            actual.ts_ns, expected.ts_ns,
            "timestamp for {name} packet {index}"
        );
        assert_eq!(
            actual.caplen, expected.caplen,
            "caplen for {name} packet {index}"
        );
        assert_eq!(
            actual.origlen, expected.origlen,
            "origlen for {name} packet {index}"
        );
        assert_eq!(
            actual.linktype, expected.linktype,
            "linktype for {name} packet {index}"
        );
        assert_eq!(
            actual.interface, expected.interface,
            "interface for {name} packet {index}"
        );
        assert_eq!(
            actual.first_byte, expected.first_byte,
            "first byte for {name} packet {index}"
        );
    }
}

fn read_with_pcap_file(bytes: &[u8], format: &str) -> Vec<ObservedPacket> {
    if format == "pcap" {
        let mut reader = PcapReader::new(Cursor::new(bytes)).unwrap();
        let linktype = u32::from(reader.header().datalink);
        let mut packets = Vec::new();
        while let Some(packet) = reader.next_packet() {
            let packet = packet.unwrap();
            packets.push(ObservedPacket {
                ts_ns: packet.timestamp.as_nanos() as u64,
                caplen: packet.data.len() as u32,
                origlen: packet.orig_len,
                linktype,
                interface: 0,
                first_byte: packet.data[0],
            });
        }
        packets
    } else {
        let mut reader = PcapNgReader::new(Cursor::new(bytes)).unwrap();
        let mut interfaces = Vec::new();
        let mut packets = Vec::new();
        while let Some(block) = reader.next_block() {
            match block.unwrap() {
                Block::InterfaceDescription(interface) => {
                    let exponent = interface
                        .options
                        .iter()
                        .find_map(|option| match option {
                            InterfaceDescriptionOption::IfTsResol(value) => Some(*value),
                            _ => None,
                        })
                        .unwrap_or(6);
                    assert_eq!(exponent & 0x80, 0, "binary pcapng resolutions are not used");
                    interfaces.push((
                        u32::from(interface.linktype),
                        10u64.pow(9 - u32::from(exponent)),
                    ));
                }
                Block::EnhancedPacket(packet) => {
                    let (linktype, multiplier) = interfaces[packet.interface_id as usize];
                    packets.push(ObservedPacket {
                        ts_ns: packet.timestamp.as_nanos() as u64 * multiplier,
                        caplen: packet.data.len() as u32,
                        origlen: packet.original_len,
                        linktype,
                        interface: packet.interface_id,
                        first_byte: packet.data[0],
                    });
                }
                _ => {}
            }
        }
        packets
    }
}

fn read_with_pcap_parser(bytes: &[u8], format: &str) -> Vec<ObservedPacket> {
    if format == "pcap" {
        read_legacy_with_pcap_parser(bytes)
    } else {
        read_pcapng_with_pcap_parser(bytes)
    }
}

fn read_legacy_with_pcap_parser(bytes: &[u8]) -> Vec<ObservedPacket> {
    let mut reader = LegacyPcapReader::new(bytes.len() + 1, Cursor::new(bytes)).unwrap();
    let mut nanosecond = false;
    let mut linktype = 0;
    let mut packets = Vec::new();
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::LegacyHeader(header) => {
                        nanosecond = header.is_nanosecond_precision();
                        linktype = header.network.0 as u32;
                    }
                    PcapBlockOwned::Legacy(packet) => packets.push(ObservedPacket {
                        ts_ns: u64::from(packet.ts_sec) * 1_000_000_000
                            + u64::from(packet.ts_usec) * if nanosecond { 1 } else { 1_000 },
                        caplen: packet.caplen,
                        origlen: packet.origlen,
                        linktype,
                        interface: 0,
                        first_byte: packet.data[0],
                    }),
                    PcapBlockOwned::NG(_) => unreachable!(),
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => reader.refill().unwrap(),
            Err(error) => panic!("pcap-parser failed: {error:?}"),
        }
    }
    packets
}

fn read_pcapng_with_pcap_parser(bytes: &[u8]) -> Vec<ObservedPacket> {
    let mut reader = PcapNGReader::new(bytes.len() + 1, Cursor::new(bytes)).unwrap();
    let mut interfaces = Vec::new();
    let mut packets = Vec::new();
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                match block {
                    PcapBlockOwned::NG(ParserNgBlock::InterfaceDescription(interface)) => {
                        interfaces.push((
                            interface.linktype.0 as u32,
                            interface.ts_resolution().unwrap(),
                        ));
                    }
                    PcapBlockOwned::NG(ParserNgBlock::EnhancedPacket(packet)) => {
                        let (linktype, resolution) = interfaces[packet.if_id as usize];
                        let raw = (u64::from(packet.ts_high) << 32) | u64::from(packet.ts_low);
                        let data = packet.packet_data();
                        packets.push(ObservedPacket {
                            ts_ns: raw * (1_000_000_000 / resolution),
                            caplen: packet.caplen,
                            origlen: packet.origlen,
                            linktype,
                            interface: packet.if_id,
                            first_byte: data[0],
                        });
                    }
                    _ => {}
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => reader.refill().unwrap(),
            Err(error) => panic!("pcap-parser failed: {error:?}"),
        }
    }
    packets
}

fn run_generator(out: &Path) {
    let status = Command::new(env!("CARGO_BIN_EXE_packet-tools-fixtures"))
        .args(["--out", out.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn file_names(path: &Path) -> Vec<String> {
    let mut names = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

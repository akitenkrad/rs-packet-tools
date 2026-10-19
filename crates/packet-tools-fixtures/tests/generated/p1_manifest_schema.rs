use std::{collections::BTreeSet, fs, io::Cursor, path::PathBuf};

use pcap_file::pcapng::{
    Block, PcapNgReader, blocks::interface_description::InterfaceDescriptionOption,
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

fn manifest() -> serde_json::Value {
    serde_json::from_slice(&fs::read(root().join("manifest.json")).unwrap()).unwrap()
}

#[test]
fn manifest_has_one_entry_per_capture_file() {
    let manifest = manifest();
    let names = manifest["files"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        names,
        BTreeSet::from([
            "app/scenarios.pcap",
            "be_nsec.pcap",
            "be_usec.pcap",
            "flows/scenarios.pcap",
            "le_nsec.pcap",
            "le_usec.pcap",
            "le_usec.pcap.gz",
            "multi_iface.pcapng",
            "reassembly/scenarios.pcap",
        ])
    );
}

#[test]
fn manifest_metadata_describes_all_format_variants() {
    let manifest = manifest();
    let files = manifest["files"].as_object().unwrap();
    assert_eq!(files["le_usec.pcap"]["endianness"], "little");
    assert_eq!(files["be_usec.pcap"]["endianness"], "big");
    assert_eq!(files["le_nsec.pcap"]["ts_resolution"], "nanosecond");
    assert_eq!(files["be_nsec.pcap"]["ts_resolution"], "nanosecond");
    assert_eq!(files["le_usec.pcap.gz"]["compressed"], true);
    assert_eq!(files["multi_iface.pcapng"]["format"], "pcapng");
}

#[test]
fn pcapng_interfaces_have_required_linktypes_and_resolutions() {
    let bytes = fs::read(root().join("multi_iface.pcapng")).unwrap();
    let mut reader = PcapNgReader::new(Cursor::new(bytes)).unwrap();
    let mut interfaces = Vec::new();
    while let Some(block) = reader.next_block() {
        if let Block::InterfaceDescription(interface) = block.unwrap() {
            let resolution = interface.options.iter().find_map(|option| match option {
                InterfaceDescriptionOption::IfTsResol(value) => Some(*value),
                _ => None,
            });
            interfaces.push((u32::from(interface.linktype), resolution));
        }
    }
    assert_eq!(interfaces, vec![(1, Some(6)), (101, Some(9))]);
}

#[test]
fn manifest_descriptions_cover_every_required_scenario() {
    let manifest = manifest();
    let packets = manifest["files"]["le_usec.pcap"]["packets"]
        .as_array()
        .unwrap();
    for number in 1..=11 {
        let prefix = format!("{number}:");
        assert!(
            packets
                .iter()
                .any(|packet| packet["description"].as_str().unwrap().starts_with(&prefix))
        );
    }
}

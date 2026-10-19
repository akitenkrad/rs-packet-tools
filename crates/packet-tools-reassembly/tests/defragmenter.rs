use std::time::Duration;

use packet_tools_capture::{LinkType, PacketRecord};
use packet_tools_dissect::{DecodeDepth, Ipv4View, Ipv6View, decode};
use packet_tools_reassembly::{DefragConfig, Defragmenter, IpEventKind, IpPolicy};

fn record(index: u64, ts_ns: i64, bytes: &[u8]) -> PacketRecord<'_> {
    PacketRecord {
        index,
        ts_ns: Some(ts_ns),
        caplen: bytes.len() as u32,
        origlen: bytes.len() as u32,
        linktype: LinkType(101),
        interface: 0,
        data: bytes,
    }
}

fn ipv4_fragment(id: u16, offset: usize, more: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 20];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&u16::try_from(20 + payload.len()).unwrap().to_be_bytes());
    bytes[4..6].copy_from_slice(&id.to_be_bytes());
    let flags_offset = u16::try_from(offset / 8).unwrap() | if more { 0x2000 } else { 0 };
    bytes[6..8].copy_from_slice(&flags_offset.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 1;
    bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
    bytes[16..20].copy_from_slice(&[198, 51, 100, 2]);
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn ipv4_reassembly_returns_a_checksum_correct_raw_datagram_and_conflict_event() {
    let mut defrag = Defragmenter::new(DefragConfig {
        policy: IpPolicy::Last,
        ..DefragConfig::default()
    });
    let first = ipv4_fragment(7, 0, true, &[b'A'; 16]);
    let second = ipv4_fragment(7, 8, false, &[b'B'; 16]);
    let first_record = record(10, 100, &first);
    let first_packet = decode(&first, LinkType(101), DecodeDepth::L4);
    assert!(
        defrag
            .push(&first_record, &first_packet)
            .datagrams
            .is_empty()
    );
    let second_record = record(11, 200, &second);
    let second_packet = decode(&second, LinkType(101), DecodeDepth::L4);
    let output = defrag.push(&second_record, &second_packet);

    assert_eq!(output.datagrams.len(), 1);
    let datagram = &output.datagrams[0];
    assert_eq!(datagram.first_index, 10);
    assert_eq!(datagram.last_index, 11);
    assert_eq!(datagram.fragment_count, 2);
    assert_eq!(
        &datagram.bytes[20..],
        &[&[b'A'; 8][..], &[b'B'; 16][..]].concat()
    );
    let decoded = decode(&datagram.bytes, LinkType(101), DecodeDepth::L4);
    let ip = decoded.layer::<Ipv4View>().unwrap();
    assert_eq!(ip.total_len(), 44);
    assert_eq!(ip.fragment_offset(), 0);
    assert!(!ip.more_fragments());
    assert!(ip.verify_checksum());
    assert!(
        output
            .events
            .iter()
            .any(|event| event.kind == IpEventKind::Overlap)
    );
    assert!(
        output
            .events
            .iter()
            .any(|event| event.kind == IpEventKind::OverlapConflict)
    );
}

fn ipv6_fragment(offset: usize, more: bool, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; 56];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&u16::try_from(16 + payload.len()).unwrap().to_be_bytes());
    bytes[6] = 0;
    bytes[7] = 64;
    bytes[8..24].copy_from_slice(&[0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    bytes[24..40].copy_from_slice(&[0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
    bytes[40] = 44;
    bytes[41] = 0;
    bytes[48] = 58;
    let field = u16::try_from(offset).unwrap() | u16::from(more);
    bytes[50..52].copy_from_slice(&field.to_be_bytes());
    bytes[52..56].copy_from_slice(&99u32.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn ipv6_reassembly_preserves_unfragmentable_extensions_and_removes_fragment_header() {
    let mut defrag = Defragmenter::new(DefragConfig::default());
    for (index, bytes) in [
        ipv6_fragment(0, true, &[1; 16]),
        ipv6_fragment(16, false, &[2; 8]),
    ]
    .into_iter()
    .enumerate()
    {
        let rec = record(index as u64, index as i64, &bytes);
        let packet = decode(&bytes, LinkType(101), DecodeDepth::L4);
        let output = defrag.push(&rec, &packet);
        if index == 1 {
            let datagram = &output.datagrams[0];
            assert_eq!(datagram.bytes.len(), 72);
            assert_eq!(datagram.bytes[40], 58);
            assert_eq!(&datagram.bytes[48..], &[&[1; 16][..], &[2; 8][..]].concat());
            let decoded = decode(&datagram.bytes, LinkType(101), DecodeDepth::L4);
            let ip = decoded.layer::<Ipv6View>().unwrap();
            assert_eq!(ip.payload_len(), 32);
            assert!(ip.fragment().is_none());
            assert_eq!(ip.upper_protocol(), 58);
        }
    }
}

#[test]
fn timeout_uses_maximum_seen_timestamp_when_capture_time_regresses() {
    let mut defrag = Defragmenter::new(DefragConfig {
        timeout: Duration::from_nanos(10),
        ..DefragConfig::default()
    });
    for (index, ts) in [(0, 100), (1, 95), (2, 111)] {
        let bytes = ipv4_fragment(u16::try_from(index + 1).unwrap(), 0, true, &[0; 8]);
        let rec = record(index, ts, &bytes);
        let packet = decode(&bytes, LinkType(101), DecodeDepth::L4);
        let output = defrag.push(&rec, &packet);
        if index == 1 {
            assert!(
                !output
                    .events
                    .iter()
                    .any(|event| event.kind == IpEventKind::Timeout)
            );
        }
        if index == 2 {
            assert!(
                output
                    .events
                    .iter()
                    .any(|event| event.kind == IpEventKind::Timeout)
            );
        }
    }
}

#[test]
fn distant_fragments_charge_payload_ranges_and_respect_the_memory_limit() {
    let limit = 8_000;
    let mut defrag = Defragmenter::new(DefragConfig {
        memory_limit: limit,
        ..DefragConfig::default()
    });
    let mut memory_events = 0;
    for index in 0..100 {
        let bytes = ipv4_fragment(index as u16, 60_000, true, &[b'x'; 1_496]);
        let rec = record(index, index as i64, &bytes);
        let packet = decode(&bytes, LinkType(101), DecodeDepth::L4);
        let output = defrag.push(&rec, &packet);
        memory_events += output
            .events
            .iter()
            .filter(|event| event.kind == IpEventKind::MemoryLimit)
            .count();
        assert!(defrag.estimated_memory_bytes() <= limit);
    }
    assert!(memory_events > 0);
    assert!(defrag.active_len() > 1);
}

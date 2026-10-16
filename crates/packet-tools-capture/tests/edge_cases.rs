use std::io::{Cursor, Write};

use flate2::{Compression as GzLevel, write::GzEncoder};
use packet_tools_capture::{
    Capture, CaptureError, Compression, Container, Endian, OpenOptions, TsResolution,
};

#[derive(Clone, Copy)]
enum Order {
    Little,
    Big,
}

#[test]
fn short_and_unknown_inputs_are_rejected() {
    for bytes in [vec![], vec![1, 2, 3], vec![1, 2, 3, 4]] {
        assert!(matches!(
            Capture::from_reader(Cursor::new(bytes)),
            Err(CaptureError::UnknownFormat { .. })
        ));
    }
    assert!(!OpenOptions::default().mmap);
}

#[test]
fn classic_header_only_is_empty_and_truncated_tail_is_reported_once() {
    let header = pcap_header(Order::Little, false, 64, 1);
    let mut empty = Capture::from_reader(Cursor::new(header.clone())).unwrap();
    assert!(empty.next_record().is_none());
    assert_eq!(empty.stats().packets, 0);
    assert_eq!(empty.stats().sections, 1);

    let mut bytes = header;
    push_u32(&mut bytes, 1, Order::Little);
    push_u32(&mut bytes, 2, Order::Little);
    push_u32(&mut bytes, 4, Order::Little);
    push_u32(&mut bytes, 6, Order::Little);
    bytes.extend_from_slice(&[1, 2, 3, 4]);
    push_u32(&mut bytes, 3, Order::Little);
    bytes.extend_from_slice(&[0; 5]);

    let mut capture = Capture::from_reader(Cursor::new(bytes)).unwrap();
    let first = capture.next_record().unwrap().unwrap();
    assert_eq!(first.data, [1, 2, 3, 4]);
    assert!(matches!(
        capture.next_record(),
        Some(Err(CaptureError::TruncatedRecord { index: 1, .. }))
    ));
    assert!(capture.next_record().is_none());
    assert!(capture.stats().truncated_tail);
    assert_eq!(capture.stats().packets, 1);
}

#[test]
fn classic_rejects_lengths_above_sixty_four_mibibytes() {
    let mut bytes = pcap_header(Order::Big, false, 64, 1);
    for value in [0, 0, 0x0400_0001, 0x0400_0001] {
        push_u32(&mut bytes, value, Order::Big);
    }
    let mut capture = Capture::from_reader(Cursor::new(bytes)).unwrap();
    assert!(matches!(
        capture.next_record(),
        Some(Err(CaptureError::Corrupt { .. }))
    ));
    assert!(capture.next_record().is_none());
}

#[test]
fn pcapng_handles_sections_options_epb_spb_pb_and_skipped_blocks() {
    let mut bytes = Vec::new();
    section_header(&mut bytes, Order::Little);
    idb(
        &mut bytes,
        Order::Little,
        1,
        64,
        Some(0x80 | 10),
        Some(2),
        Some("eth0"),
    );
    epb(&mut bytes, Order::Little, 0, 1_024, &[1, 2], 4);
    block(&mut bytes, Order::Little, 0x1234_5678, &[0, 0, 0, 0]);
    spb(&mut bytes, Order::Little, &[3, 4, 5], 3);

    section_header(&mut bytes, Order::Big);
    idb(&mut bytes, Order::Big, 101, 0, None, None, None);
    pb(&mut bytes, Order::Big, 0, 3_000_000, &[6, 7], 2);

    let mut capture = Capture::from_reader(Cursor::new(bytes)).unwrap();
    let first = copy_record(capture.next_record().unwrap().unwrap());
    let second = copy_record(capture.next_record().unwrap().unwrap());
    let third = copy_record(capture.next_record().unwrap().unwrap());
    assert!(capture.next_record().is_none());

    assert_eq!(first, (0, Some(3_000_000_000), 0, 1, vec![1, 2]));
    assert_eq!(second, (1, None, 0, 1, vec![3, 4, 5]));
    assert_eq!(third, (2, Some(3_000_000_000), 1, 101, vec![6, 7]));
    assert_eq!(capture.stats().sections, 2);
    assert_eq!(capture.stats().packets_without_timestamp, 1);
    assert_eq!(capture.stats().skipped_blocks[&0x1234_5678], 1);
    assert_eq!(capture.interfaces().len(), 2);
    assert_eq!(
        capture.interfaces()[0].ts_resolution,
        TsResolution::Pow2(10)
    );
    assert_eq!(capture.interfaces()[0].ts_offset_secs, 2);
    assert_eq!(capture.interfaces()[0].name.as_deref(), Some("eth0"));
    assert_eq!(capture.interfaces()[1].section, 1);
}

#[test]
fn pcapng_reports_structural_and_interface_errors_once() {
    let mut mismatch = Vec::new();
    section_header(&mut mismatch, Order::Little);
    idb(&mut mismatch, Order::Little, 1, 64, None, None, None);
    let last = mismatch.len() - 4;
    mismatch[last..].copy_from_slice(&12u32.to_le_bytes());
    let mut capture = Capture::from_reader(Cursor::new(mismatch)).unwrap();
    assert!(matches!(
        capture.next_record(),
        Some(Err(CaptureError::Corrupt { .. }))
    ));
    assert!(capture.next_record().is_none());

    let mut unknown = Vec::new();
    section_header(&mut unknown, Order::Little);
    epb(&mut unknown, Order::Little, 9, 0, &[1], 1);
    let mut capture = Capture::from_reader(Cursor::new(unknown)).unwrap();
    assert!(matches!(
        capture.next_record(),
        Some(Err(CaptureError::UnknownInterface { interface: 9, .. }))
    ));
}

#[test]
fn gzip_wrapped_pcapng_is_detected_from_bytes() {
    let mut plain = Vec::new();
    section_header(&mut plain, Order::Little);
    idb(&mut plain, Order::Little, 1, 64, None, None, None);
    epb(&mut plain, Order::Little, 0, 1, &[9], 1);
    let mut encoder = GzEncoder::new(Vec::new(), GzLevel::default());
    encoder.write_all(&plain).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut capture = Capture::from_reader(Cursor::new(compressed)).unwrap();
    assert_eq!(capture.format().container, Container::PcapNg);
    assert_eq!(capture.format().compression, Compression::Gzip);
    assert_eq!(capture.next_record().unwrap().unwrap().data, [9]);
}

#[test]
fn regression_distance_saturates_instead_of_panicking() {
    let mut bytes = Vec::new();
    section_header(&mut bytes, Order::Little);
    idb(&mut bytes, Order::Little, 1, 64, Some(9), None, None);
    epb(&mut bytes, Order::Little, 0, i64::MAX as u64, &[1], 1);
    section_header(&mut bytes, Order::Little);
    idb(
        &mut bytes,
        Order::Little,
        1,
        64,
        Some(9),
        Some(-9_223_372_037),
        None,
    );
    epb(&mut bytes, Order::Little, 0, 145_224_192, &[2], 1);

    let mut capture = Capture::from_reader(Cursor::new(bytes)).unwrap();
    assert!(capture.next_record().unwrap().is_ok());
    assert!(capture.next_record().unwrap().is_ok());
    assert_eq!(capture.stats().timestamp_regressions, 1);
    assert_eq!(capture.stats().max_regression_ns, i64::MAX);
}

#[test]
fn format_reports_classic_endian_and_resolution() {
    let capture = Capture::from_reader(Cursor::new(pcap_header(Order::Big, true, 64, 1))).unwrap();
    assert!(matches!(
        capture.format().container,
        Container::Pcap {
            endian: Endian::Big,
            ts_resolution: TsResolution::Pow10(9)
        }
    ));
}

fn copy_record(
    record: packet_tools_capture::PacketRecord<'_>,
) -> (u64, Option<i64>, u32, u16, Vec<u8>) {
    (
        record.index,
        record.ts_ns,
        record.interface,
        record.linktype.0,
        record.data.to_vec(),
    )
}

fn pcap_header(order: Order, nanos: bool, snaplen: u32, linktype: u32) -> Vec<u8> {
    let mut out = match (order, nanos) {
        (Order::Little, false) => vec![0xd4, 0xc3, 0xb2, 0xa1],
        (Order::Big, false) => vec![0xa1, 0xb2, 0xc3, 0xd4],
        (Order::Little, true) => vec![0x4d, 0x3c, 0xb2, 0xa1],
        (Order::Big, true) => vec![0xa1, 0xb2, 0x3c, 0x4d],
    };
    push_u16(&mut out, 2, order);
    push_u16(&mut out, 4, order);
    push_u32(&mut out, 0, order);
    push_u32(&mut out, 0, order);
    push_u32(&mut out, snaplen, order);
    push_u32(&mut out, linktype, order);
    out
}

fn section_header(out: &mut Vec<u8>, order: Order) {
    let mut body = Vec::new();
    push_u32(&mut body, 0x1a2b_3c4d, order);
    push_u16(&mut body, 1, order);
    push_u16(&mut body, 0, order);
    push_i64(&mut body, -1, order);
    block(out, order, 0x0a0d_0d0a, &body);
}

fn idb(
    out: &mut Vec<u8>,
    order: Order,
    linktype: u16,
    snaplen: u32,
    resolution: Option<u8>,
    offset: Option<i64>,
    name: Option<&str>,
) {
    let mut body = Vec::new();
    push_u16(&mut body, linktype, order);
    push_u16(&mut body, 0, order);
    push_u32(&mut body, snaplen, order);
    if let Some(value) = resolution {
        option(&mut body, order, 9, &[value]);
    }
    if let Some(value) = offset {
        let encoded = match order {
            Order::Little => value.to_le_bytes(),
            Order::Big => value.to_be_bytes(),
        };
        option(&mut body, order, 14, &encoded);
    }
    if let Some(value) = name {
        option(&mut body, order, 2, value.as_bytes());
    }
    option(&mut body, order, 0, &[]);
    block(out, order, 1, &body);
}

fn epb(out: &mut Vec<u8>, order: Order, interface: u32, timestamp: u64, data: &[u8], origlen: u32) {
    let mut body = Vec::new();
    push_u32(&mut body, interface, order);
    push_u32(&mut body, (timestamp >> 32) as u32, order);
    push_u32(&mut body, timestamp as u32, order);
    push_u32(&mut body, data.len() as u32, order);
    push_u32(&mut body, origlen, order);
    padded(&mut body, data);
    block(out, order, 6, &body);
}

fn pb(out: &mut Vec<u8>, order: Order, interface: u16, timestamp: u64, data: &[u8], origlen: u32) {
    let mut body = Vec::new();
    push_u16(&mut body, interface, order);
    push_u16(&mut body, 0, order);
    push_u32(&mut body, (timestamp >> 32) as u32, order);
    push_u32(&mut body, timestamp as u32, order);
    push_u32(&mut body, data.len() as u32, order);
    push_u32(&mut body, origlen, order);
    padded(&mut body, data);
    block(out, order, 2, &body);
}

fn spb(out: &mut Vec<u8>, order: Order, data: &[u8], origlen: u32) {
    let mut body = Vec::new();
    push_u32(&mut body, origlen, order);
    padded(&mut body, data);
    block(out, order, 3, &body);
}

fn option(out: &mut Vec<u8>, order: Order, code: u16, value: &[u8]) {
    push_u16(out, code, order);
    push_u16(out, value.len() as u16, order);
    padded(out, value);
}

fn padded(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(value);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

fn block(out: &mut Vec<u8>, order: Order, kind: u32, body: &[u8]) {
    push_u32(out, kind, order);
    let length = (body.len() + 12) as u32;
    push_u32(out, length, order);
    out.extend_from_slice(body);
    push_u32(out, length, order);
}

fn push_u16(out: &mut Vec<u8>, value: u16, order: Order) {
    match order {
        Order::Little => out.extend_from_slice(&value.to_le_bytes()),
        Order::Big => out.extend_from_slice(&value.to_be_bytes()),
    }
}

fn push_u32(out: &mut Vec<u8>, value: u32, order: Order) {
    match order {
        Order::Little => out.extend_from_slice(&value.to_le_bytes()),
        Order::Big => out.extend_from_slice(&value.to_be_bytes()),
    }
}

fn push_i64(out: &mut Vec<u8>, value: i64, order: Order) {
    match order {
        Order::Little => out.extend_from_slice(&value.to_le_bytes()),
        Order::Big => out.extend_from_slice(&value.to_be_bytes()),
    }
}

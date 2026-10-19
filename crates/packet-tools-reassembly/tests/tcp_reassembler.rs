use packet_tools_capture::{LinkType, PacketRecord};
use packet_tools_dissect::{DecodeDepth, decode};
use packet_tools_reassembly::{
    CloseReason, DeliveryMode, Direction, TcpConfig, TcpEventKind, TcpItem, TcpPolicy,
    TcpReassembler, TcpSegmentBuffer,
};

fn tcp_packet(
    src: [u8; 4],
    dst: [u8; 4],
    ports: (u16, u16),
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = vec![0u8; 40];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&u16::try_from(40 + payload.len()).unwrap().to_be_bytes());
    bytes[8] = 64;
    bytes[9] = 6;
    bytes[12..16].copy_from_slice(&src);
    bytes[16..20].copy_from_slice(&dst);
    bytes[20..22].copy_from_slice(&ports.0.to_be_bytes());
    bytes[22..24].copy_from_slice(&ports.1.to_be_bytes());
    bytes[24..28].copy_from_slice(&seq.to_be_bytes());
    bytes[28..32].copy_from_slice(&ack.to_be_bytes());
    bytes[32] = 0x50;
    bytes[33] = flags;
    bytes[34..36].copy_from_slice(&4096u16.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn push(
    reassembly: &mut TcpReassembler,
    index: u64,
    bytes: &[u8],
) -> packet_tools_reassembly::TcpOutput {
    push_at(reassembly, index, index as i64, bytes)
}

fn push_at(
    reassembly: &mut TcpReassembler,
    index: u64,
    ts_ns: i64,
    bytes: &[u8],
) -> packet_tools_reassembly::TcpOutput {
    let record = PacketRecord {
        index,
        ts_ns: Some(ts_ns),
        caplen: bytes.len() as u32,
        origlen: bytes.len() as u32,
        linktype: LinkType(101),
        interface: 0,
        data: bytes,
    };
    let packet = decode(bytes, LinkType(101), DecodeDepth::L4);
    reassembly.push(&record, &packet)
}

fn handshake(reassembly: &mut TcpReassembler, client_isn: u32) {
    let client = [192, 0, 2, 1];
    let server = [198, 51, 100, 2];
    push(
        reassembly,
        0,
        &tcp_packet(client, server, (1234, 80), client_isn, 0, 0x02, &[]),
    );
    push(
        reassembly,
        1,
        &tcp_packet(
            server,
            client,
            (80, 1234),
            500,
            client_isn.wrapping_add(1),
            0x12,
            &[],
        ),
    );
    push(
        reassembly,
        2,
        &tcp_packet(
            client,
            server,
            (1234, 80),
            client_isn.wrapping_add(1),
            501,
            0x10,
            &[],
        ),
    );
}

fn data(items: &[TcpItem]) -> Vec<(Direction, u64, Vec<u8>)> {
    items
        .iter()
        .filter_map(|item| match item {
            TcpItem::Data(chunk) => Some((chunk.direction, chunk.position, chunk.bytes.to_vec())),
            _ => None,
        })
        .collect()
}

#[test]
fn immediate_delivers_contiguous_bytes_and_reports_late_conflicts() {
    let mut reassembly = TcpReassembler::new(TcpConfig {
        delivery: DeliveryMode::Immediate,
        ..TcpConfig::default()
    });
    handshake(&mut reassembly, 100);
    let first = push(
        &mut reassembly,
        3,
        &tcp_packet(
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            (1234, 80),
            101,
            501,
            0x18,
            b"abc",
        ),
    );
    assert_eq!(
        data(&first.items),
        vec![(Direction::ClientToServer, 0, b"abc".to_vec())]
    );
    let late = push(
        &mut reassembly,
        4,
        &tcp_packet(
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            (1234, 80),
            101,
            501,
            0x18,
            b"axc",
        ),
    );
    assert!(late.items.is_empty());
    assert!(
        late.events
            .iter()
            .any(|event| event.kind == TcpEventKind::LateOverlapConflict)
    );
}

#[test]
fn on_ack_waits_for_the_peer_ack_and_sequence_wrap_is_relative_to_isn() {
    let mut reassembly = TcpReassembler::new(TcpConfig::default());
    handshake(&mut reassembly, u32::MAX);
    let queued = push(
        &mut reassembly,
        3,
        &tcp_packet(
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            (1234, 80),
            0,
            501,
            0x18,
            b"abc",
        ),
    );
    assert!(data(&queued.items).is_empty());
    let acked = push(
        &mut reassembly,
        4,
        &tcp_packet(
            [198, 51, 100, 2],
            [192, 0, 2, 1],
            (80, 1234),
            501,
            3,
            0x10,
            &[],
        ),
    );
    assert_eq!(
        data(&acked.items),
        vec![(Direction::ClientToServer, 0, b"abc".to_vec())]
    );
}

#[test]
fn on_ack_data_keeps_the_data_packet_index_and_timestamp() {
    let mut reassembly = TcpReassembler::new(TcpConfig::default());
    handshake(&mut reassembly, 100);
    let first = tcp_packet(
        [192, 0, 2, 1],
        [198, 51, 100, 2],
        (1234, 80),
        101,
        501,
        0x18,
        b"ab",
    );
    let second = tcp_packet(
        [192, 0, 2, 1],
        [198, 51, 100, 2],
        (1234, 80),
        103,
        501,
        0x18,
        b"cd",
    );
    push_at(&mut reassembly, 30, 3_000, &first);
    push_at(&mut reassembly, 31, 3_100, &second);

    let ack = tcp_packet(
        [198, 51, 100, 2],
        [192, 0, 2, 1],
        (80, 1234),
        501,
        105,
        0x10,
        &[],
    );
    let output = push_at(&mut reassembly, 99, 9_900, &ack);
    let chunk = output
        .items
        .iter()
        .find_map(|item| match item {
            TcpItem::Data(chunk) => Some(chunk),
            _ => None,
        })
        .expect("ack releases data");

    assert_eq!(&*chunk.bytes, b"abcd");
    assert_eq!(chunk.source_at(0).map(|source| source.index), Some(30));
    assert_eq!(chunk.source_at(1).map(|source| source.ts_ns), Some(3_000));
    assert_eq!(chunk.source_at(2).map(|source| source.index), Some(31));
    assert_eq!(chunk.source_at(3).map(|source| source.ts_ns), Some(3_100));
    assert!(chunk.source_at(4).is_none());
}

#[test]
fn capture_end_flushes_gaps_before_later_data() {
    let mut reassembly = TcpReassembler::new(TcpConfig::default());
    handshake(&mut reassembly, 100);
    push(
        &mut reassembly,
        3,
        &tcp_packet(
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            (1234, 80),
            105,
            501,
            0x18,
            b"z",
        ),
    );
    let end = reassembly.finish();
    assert!(end.items.iter().any(|item| matches!(item, TcpItem::Gap(gap) if gap.direction == Direction::ClientToServer && gap.position == 0 && gap.len == 4)));
    assert!(end.items.iter().any(
        |item| matches!(item, TcpItem::Data(chunk) if chunk.position == 4 && &*chunk.bytes == b"z")
    ));
    assert!(end.items.iter().any(
        |item| matches!(item, TcpItem::End(close) if close.reason == CloseReason::EndOfCapture)
    ));
}

#[test]
fn out_of_window_rst_is_ignored() {
    let mut reassembly = TcpReassembler::new(TcpConfig {
        delivery: DeliveryMode::Immediate,
        ..TcpConfig::default()
    });
    handshake(&mut reassembly, 100);
    let output = push(
        &mut reassembly,
        3,
        &tcp_packet(
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            (1234, 80),
            100_000,
            501,
            0x04,
            &[],
        ),
    );
    assert!(
        output
            .events
            .iter()
            .any(|event| event.kind == TcpEventKind::RstIgnored)
    );
    assert!(
        !output
            .items
            .iter()
            .any(|item| matches!(item, TcpItem::End(_)))
    );
}

#[test]
fn far_forward_sequence_is_stored_sparsely_instead_of_allocating_the_gap() {
    let mut buffer = TcpSegmentBuffer::new(TcpPolicy::Bsd, 0);
    buffer.insert(i32::MAX as u32, b"x", 1);
    assert_eq!(buffer.buffered_bytes(), 1);
    assert_eq!(buffer.render(4, b'.'), b"....");
}

#[test]
fn rst_keeps_a_tombstone_and_accounts_for_later_data() {
    let mut reassembly = TcpReassembler::new(TcpConfig {
        delivery: DeliveryMode::Immediate,
        ..TcpConfig::default()
    });
    handshake(&mut reassembly, 100);
    let rst = push(
        &mut reassembly,
        3,
        &tcp_packet(
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            (1234, 80),
            101,
            501,
            0x14,
            &[],
        ),
    );
    assert!(
        rst.items
            .iter()
            .any(|item| matches!(item, TcpItem::End(end) if end.reason == CloseReason::Rst))
    );

    let late = push(
        &mut reassembly,
        4,
        &tcp_packet(
            [198, 51, 100, 2],
            [192, 0, 2, 1],
            (80, 1234),
            501,
            101,
            0x18,
            b"late",
        ),
    );
    assert!(data(&late.items).is_empty());
    assert!(
        !late
            .items
            .iter()
            .any(|item| matches!(item, TcpItem::Start(_)))
    );
    assert!(late.items.iter().any(|item| matches!(
        item,
        TcpItem::PostClose(packet)
            if packet.direction == Direction::ServerToClient && packet.payload_len == 4
    )));
    assert!(late.events.iter().any(|event| {
        event.kind == TcpEventKind::DataAfterClose
            && event.direction == Direction::ServerToClient
            && event.position == 0
            && event.len == 4
    }));
}

#[test]
fn completed_fin_close_keeps_a_tombstone_for_later_data() {
    let mut reassembly = TcpReassembler::new(TcpConfig {
        delivery: DeliveryMode::Immediate,
        ..TcpConfig::default()
    });
    handshake(&mut reassembly, 100);
    let client = [192, 0, 2, 1];
    let server = [198, 51, 100, 2];
    push(
        &mut reassembly,
        3,
        &tcp_packet(client, server, (1234, 80), 101, 501, 0x11, &[]),
    );
    push(
        &mut reassembly,
        4,
        &tcp_packet(server, client, (80, 1234), 501, 102, 0x10, &[]),
    );
    push(
        &mut reassembly,
        5,
        &tcp_packet(server, client, (80, 1234), 501, 102, 0x11, &[]),
    );
    let closed = push(
        &mut reassembly,
        6,
        &tcp_packet(client, server, (1234, 80), 102, 502, 0x10, &[]),
    );
    assert!(
        closed
            .items
            .iter()
            .any(|item| matches!(item, TcpItem::End(end) if end.reason == CloseReason::Fin))
    );

    let late = push(
        &mut reassembly,
        7,
        &tcp_packet(server, client, (80, 1234), 502, 102, 0x18, b"x"),
    );
    assert!(data(&late.items).is_empty());
    assert!(
        late.events
            .iter()
            .any(|event| event.kind == TcpEventKind::DataAfterClose && event.len == 1)
    );
}

#[test]
fn packet_after_close_timeout_starts_a_new_midstream_connection() {
    let mut reassembly = TcpReassembler::new(TcpConfig {
        delivery: DeliveryMode::Immediate,
        closing_timeout: std::time::Duration::from_nanos(10),
        ..TcpConfig::default()
    });
    handshake(&mut reassembly, 100);
    push_at(
        &mut reassembly,
        3,
        3,
        &tcp_packet(
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            (1234, 80),
            101,
            501,
            0x14,
            &[],
        ),
    );
    let after_timeout = push_at(
        &mut reassembly,
        4,
        14,
        &tcp_packet(
            [198, 51, 100, 2],
            [192, 0, 2, 1],
            (80, 1234),
            900,
            0,
            0x18,
            b"new",
        ),
    );
    assert!(after_timeout.items.iter().any(
        |item| matches!(item, TcpItem::Start(start) if start.stream_id == 1 && start.midstream)
    ));
    assert_eq!(
        data(&after_timeout.items),
        vec![(Direction::ClientToServer, 0, b"new".to_vec())]
    );
}

#[test]
fn syn_before_close_timeout_starts_a_new_non_midstream_connection() {
    let mut reassembly = TcpReassembler::new(TcpConfig::default());
    handshake(&mut reassembly, 100);
    push(
        &mut reassembly,
        3,
        &tcp_packet(
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            (1234, 80),
            101,
            501,
            0x14,
            &[],
        ),
    );
    let syn = push(
        &mut reassembly,
        4,
        &tcp_packet(
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            (1234, 80),
            900,
            0,
            0x02,
            &[],
        ),
    );
    assert!(syn.items.iter().any(
        |item| matches!(item, TcpItem::Start(start) if start.stream_id == 1 && !start.midstream)
    ));
}

#[test]
fn keepalives_are_counted_without_delivery_or_overlap_events() {
    let mut reassembly = TcpReassembler::new(TcpConfig {
        delivery: DeliveryMode::Immediate,
        ..TcpConfig::default()
    });
    handshake(&mut reassembly, 100);
    push(
        &mut reassembly,
        3,
        &tcp_packet(
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            (1234, 80),
            101,
            501,
            0x18,
            b"abc",
        ),
    );
    for (index, payload) in [(4, b"x".as_slice()), (5, b"".as_slice())] {
        let keepalive = push(
            &mut reassembly,
            index,
            &tcp_packet(
                [192, 0, 2, 1],
                [198, 51, 100, 2],
                (1234, 80),
                103,
                501,
                0x10,
                payload,
            ),
        );
        assert!(data(&keepalive.items).is_empty());
        assert!(keepalive.events.is_empty());
    }

    let ordinary = push(
        &mut reassembly,
        6,
        &tcp_packet(
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            (1234, 80),
            104,
            501,
            0x18,
            b"z",
        ),
    );
    assert_eq!(
        data(&ordinary.items),
        vec![(Direction::ClientToServer, 3, b"z".to_vec())]
    );

    let end = reassembly.finish();
    assert!(end.items.iter().any(|item| matches!(
        item,
        TcpItem::End(close) if close.directions[0].keepalives == 2
            && close.directions[0].overlaps == 0
            && close.directions[0].overlap_conflicts == 0
    )));
}

#[test]
fn direction_memory_limit_forces_a_gap_and_caps_estimated_allocation() {
    let limit = 4_096;
    let mut reassembly = TcpReassembler::new(TcpConfig {
        delivery: DeliveryMode::Immediate,
        stream_memory: limit,
        memory_limit: 1 << 20,
        ..TcpConfig::default()
    });
    handshake(&mut reassembly, 100);
    let output = push(
        &mut reassembly,
        3,
        &tcp_packet(
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            (1234, 80),
            100_101,
            501,
            0x18,
            &vec![b'x'; 8_192],
        ),
    );
    assert!(
        output
            .events
            .iter()
            .any(|event| event.kind == TcpEventKind::MemoryLimit
                && event.direction == Direction::ClientToServer)
    );
    assert!(output.items.iter().any(
        |item| matches!(item, TcpItem::Gap(gap) if gap.direction == Direction::ClientToServer && gap.position == 0 && gap.len > 0)
    ));
    assert!(reassembly.estimated_memory_bytes() <= limit);
}

#[test]
fn global_memory_limit_charges_ranges_and_evicts_the_oldest_connection() {
    let limit = 6_000;
    let mut reassembly = TcpReassembler::new(TcpConfig {
        delivery: DeliveryMode::Immediate,
        stream_memory: 64 * 1024,
        memory_limit: limit,
        ..TcpConfig::default()
    });
    for (index, port) in [(0, 12_000), (1, 12_001)] {
        push(
            &mut reassembly,
            index * 2,
            &tcp_packet(
                [192, 0, 2, 1],
                [198, 51, 100, 2],
                (port, 80),
                100,
                0,
                0x02,
                &[],
            ),
        );
        let output = push(
            &mut reassembly,
            index * 2 + 1,
            &tcp_packet(
                [192, 0, 2, 1],
                [198, 51, 100, 2],
                (port, 80),
                100_000,
                0,
                0x18,
                &vec![b'x'; 4_000],
            ),
        );
        if index == 1 {
            assert!(
                output
                    .events
                    .iter()
                    .any(|event| event.kind == TcpEventKind::MemoryLimit)
            );
        }
    }
    assert!(reassembly.estimated_memory_bytes() <= limit);
}

#[test]
fn delivered_history_is_bounded_but_preserves_recent_late_conflicts() {
    let limit = 4_096;
    let mut reassembly = TcpReassembler::new(TcpConfig {
        delivery: DeliveryMode::Immediate,
        stream_memory: limit,
        ..TcpConfig::default()
    });
    handshake(&mut reassembly, 100);
    push(
        &mut reassembly,
        3,
        &tcp_packet(
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            (1234, 80),
            101,
            501,
            0x18,
            &vec![b'a'; 16_000],
        ),
    );
    assert!(reassembly.estimated_memory_bytes() <= limit);

    let recent = push(
        &mut reassembly,
        4,
        &tcp_packet(
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            (1234, 80),
            16_099,
            501,
            0x18,
            b"zz",
        ),
    );
    assert!(
        recent
            .events
            .iter()
            .any(|event| event.kind == TcpEventKind::LateOverlapConflict)
    );
    assert!(reassembly.estimated_memory_bytes() <= limit);
}

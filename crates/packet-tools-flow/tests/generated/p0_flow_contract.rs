use std::time::Duration;

use packet_tools_capture::{LinkType, PacketRecord};
use packet_tools_dissect::{DecodeDepth, decode};
use packet_tools_flow::{
    EndReason, FeatureValue, FlowConfig, FlowTable, Policy, Preset, cicflowmeter_columns,
};

fn tcp_packet(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8) -> Vec<u8> {
    let mut bytes = vec![0u8; 54];
    bytes[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&40u16.to_be_bytes());
    bytes[22] = 64;
    bytes[23] = 6;
    bytes[26..30].copy_from_slice(&src);
    bytes[30..34].copy_from_slice(&dst);
    bytes[34..36].copy_from_slice(&sport.to_be_bytes());
    bytes[36..38].copy_from_slice(&dport.to_be_bytes());
    bytes[46] = 0x50;
    bytes[47] = flags;
    bytes[48..50].copy_from_slice(&4096u16.to_be_bytes());
    bytes
}

fn udp_packet(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
    let mut bytes = vec![0u8; 42];
    bytes[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&28u16.to_be_bytes());
    bytes[22] = 64;
    bytes[23] = 17;
    bytes[26..30].copy_from_slice(&src);
    bytes[30..34].copy_from_slice(&dst);
    bytes[34..36].copy_from_slice(&sport.to_be_bytes());
    bytes[36..38].copy_from_slice(&dport.to_be_bytes());
    bytes[38..40].copy_from_slice(&8u16.to_be_bytes());
    bytes
}

#[allow(clippy::too_many_arguments)]
fn icmp_udp_error(
    outer_src: [u8; 4],
    outer_dst: [u8; 4],
    inner_src: [u8; 4],
    inner_dst: [u8; 4],
    sport: u16,
    dport: u16,
    quoted_payload_len: usize,
) -> Vec<u8> {
    let inner_len = 20 + 8 + quoted_payload_len;
    let outer_len = 20 + 8 + inner_len;
    let mut bytes = vec![0u8; 14 + outer_len];
    bytes[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&(outer_len as u16).to_be_bytes());
    bytes[22] = 64;
    bytes[23] = 1;
    bytes[26..30].copy_from_slice(&outer_src);
    bytes[30..34].copy_from_slice(&outer_dst);
    bytes[34] = 3;
    bytes[35] = 3;
    bytes[42] = 0x45;
    bytes[44..46].copy_from_slice(&(inner_len as u16).to_be_bytes());
    bytes[50] = 64;
    bytes[51] = 17;
    bytes[54..58].copy_from_slice(&inner_src);
    bytes[58..62].copy_from_slice(&inner_dst);
    bytes[62..64].copy_from_slice(&sport.to_be_bytes());
    bytes[64..66].copy_from_slice(&dport.to_be_bytes());
    bytes[66..68].copy_from_slice(&((8 + quoted_payload_len) as u16).to_be_bytes());
    bytes
}

#[allow(clippy::too_many_arguments)]
fn push_tcp(
    table: &mut FlowTable,
    index: u64,
    ts_ns: i64,
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    flags: u8,
) -> Vec<packet_tools_flow::Flow> {
    let data = tcp_packet(src, dst, sport, dport, flags);
    let record = PacketRecord {
        index,
        ts_ns: Some(ts_ns),
        caplen: data.len() as u32,
        origlen: data.len() as u32,
        linktype: LinkType(1),
        interface: 0,
        data: &data,
    };
    let packet = decode(&data, record.linktype, DecodeDepth::L4);
    table.push(&record, &packet)
}

fn push_raw(
    table: &mut FlowTable,
    index: u64,
    ts_ns: i64,
    data: &[u8],
) -> Vec<packet_tools_flow::Flow> {
    let record = PacketRecord {
        index,
        ts_ns: Some(ts_ns),
        caplen: data.len() as u32,
        origlen: data.len() as u32,
        linktype: LinkType(1),
        interface: 0,
        data,
    };
    let packet = decode(data, record.linktype, DecodeDepth::L4);
    table.push(&record, &packet)
}

#[test]
fn defaults_match_the_corrected_compatibility_policy() {
    let config = FlowConfig::default();
    assert_eq!(config.policy, Policy::Corrected);
    assert_eq!(config.preset, Preset::CicFlowMeter);
    assert_eq!(config.flow_timeout, Duration::from_secs(120));
    assert_eq!(config.activity_timeout, Duration::from_secs(5));
    assert_eq!(config.idle_timeout, Duration::from_secs(60));
    assert!(!config.vlan_in_key);
}

#[test]
fn empty_table_finishes_without_flows() {
    assert!(FlowTable::default().finish().is_empty());
}

#[test]
fn cicflowmeter_closes_at_the_first_fin() {
    let mut table = FlowTable::new(FlowConfig {
        policy: Policy::CicFlowMeter,
        ..FlowConfig::default()
    });
    let a = [10, 0, 0, 1];
    let b = [10, 0, 0, 2];
    assert!(push_tcp(&mut table, 0, 0, a, b, 1234, 80, 0x02).is_empty());
    let closed = push_tcp(&mut table, 1, 1_000, a, b, 1234, 80, 0x11);
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].end_reason, EndReason::Fin);
    assert_eq!(closed[0].fwd_packets, 2);
    assert!(table.finish().is_empty());
}

#[test]
fn corrected_waits_for_both_fins_and_the_final_ack() {
    let mut table = FlowTable::default();
    let a = [10, 0, 0, 1];
    let b = [10, 0, 0, 2];
    for (index, src, dst, sport, dport, flags) in [
        (0, a, b, 1234, 80, 0x02),
        (1, a, b, 1234, 80, 0x11),
        (2, b, a, 80, 1234, 0x10),
        (3, b, a, 80, 1234, 0x11),
        (4, a, b, 1234, 80, 0x10),
    ] {
        assert!(
            push_tcp(
                &mut table,
                index,
                index as i64 * 1_000,
                src,
                dst,
                sport,
                dport,
                flags
            )
            .is_empty()
        );
    }
    let flows = table.finish();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].end_reason, EndReason::Fin);
    assert_eq!((flows[0].fwd_packets, flows[0].bwd_packets), (3, 2));
}

#[test]
fn corrected_marks_a_reset_flow_as_rst_at_capture_end() {
    let mut table = FlowTable::default();
    let a = [10, 0, 0, 1];
    let b = [10, 0, 0, 2];
    push_tcp(&mut table, 0, 0, a, b, 1234, 80, 0x02);
    push_tcp(&mut table, 1, 1_000, b, a, 80, 1234, 0x14);
    let flows = table.finish();
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].end_reason, EndReason::Rst);
}

#[test]
fn compatibility_timeout_is_strictly_greater_than_the_limit() {
    let mut table = FlowTable::new(FlowConfig {
        flow_timeout: Duration::from_secs(1),
        ..FlowConfig::default()
    });
    let a = [10, 0, 0, 1];
    let b = [10, 0, 0, 2];
    push_tcp(&mut table, 0, 0, a, b, 1234, 80, 0x02);
    assert!(push_tcp(&mut table, 1, 1_000_000_000, b, a, 80, 1234, 0x10).is_empty());
    let closed = push_tcp(&mut table, 2, 1_000_001_000, b, a, 80, 1234, 0x10);
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].end_reason, EndReason::FlowTimeout);
}

#[test]
fn corrected_udp_timeout_starts_with_the_new_packet_direction() {
    let mut table = FlowTable::new(FlowConfig {
        flow_timeout: Duration::from_secs(1),
        ..FlowConfig::default()
    });
    let client = [10, 0, 0, 1];
    let server = [10, 0, 0, 53];
    let first = udp_packet(client, server, 61030, 53);
    let response = udp_packet(server, client, 53, 61030);
    assert!(push_raw(&mut table, 10, 0, &first).is_empty());
    assert_eq!(push_raw(&mut table, 11, 1_000_001_000, &response).len(), 1);

    let flow = table.finish().pop().unwrap();
    assert_eq!(flow.src_ip.to_string(), "10.0.0.53");
    assert_eq!(flow.dst_ip.to_string(), "10.0.0.1");
    assert_eq!((flow.src_port, flow.dst_port), (53, 61030));
    assert_eq!((flow.fwd_packets, flow.bwd_packets), (1, 0));
}

#[test]
fn idle_only_uses_max_seen_time_when_timestamps_regress() {
    let mut table = FlowTable::new(FlowConfig {
        policy: Policy::IdleOnly,
        idle_timeout: Duration::from_secs(1),
        ..FlowConfig::default()
    });
    let a = [10, 0, 0, 1];
    let b = [10, 0, 0, 2];
    push_tcp(&mut table, 0, 2_000_000_000, a, b, 1234, 80, 0x02);
    push_tcp(&mut table, 1, 1_500_000_000, b, a, 80, 1234, 0x12);
    let c = [10, 0, 0, 3];
    let closed = push_tcp(&mut table, 2, 3_000_000_001, a, c, 9999, 53, 0x02);
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].end_reason, EndReason::IdleTimeout);
    assert_eq!((closed[0].fwd_packets, closed[0].bwd_packets), (1, 1));
}

#[test]
fn compatibility_column_contract_excludes_label() {
    assert_eq!(cicflowmeter_columns(Policy::CicFlowMeter).len(), 83);
    assert_eq!(cicflowmeter_columns(Policy::Corrected).len(), 88);
    assert_eq!(cicflowmeter_columns(Policy::IdleOnly).len(), 88);
    assert_eq!(
        cicflowmeter_columns(Policy::CicFlowMeter)[0].original,
        "Flow ID"
    );
    assert_eq!(
        cicflowmeter_columns(Policy::Corrected)[87].original,
        "Total TCP Flow Time"
    );
}

#[test]
fn original_preserves_integer_down_up_ratio_and_first_only_psh_counting() {
    let mut table = FlowTable::new(FlowConfig {
        policy: Policy::CicFlowMeter,
        ..FlowConfig::default()
    });
    let a = [10, 0, 0, 1];
    let b = [10, 0, 0, 2];
    push_tcp(&mut table, 0, 0, a, b, 1234, 80, 0x02);
    push_tcp(&mut table, 1, 1_000, b, a, 80, 1234, 0x18);
    push_tcp(&mut table, 2, 2_000, a, b, 1234, 80, 0x18);
    let flow = table.finish().pop().unwrap();
    assert_eq!(flow.compatibility_values().len(), 83);
    assert_eq!(
        flow.compatibility_value(Policy::CicFlowMeter, "down_up_ratio"),
        Some(&FeatureValue::Float64(0.0))
    );
    assert_eq!(
        flow.compatibility_value(Policy::CicFlowMeter, "fwd_psh_flags"),
        Some(&FeatureValue::UInt64(0))
    );
    assert_eq!(
        flow.compatibility_value(Policy::CicFlowMeter, "bwd_psh_flags"),
        Some(&FeatureValue::UInt64(0))
    );
    assert_eq!(
        flow.compatibility_value(Policy::CicFlowMeter, "psh_flag_count"),
        Some(&FeatureValue::UInt64(2))
    );
}

#[test]
fn corrected_counts_directional_psh_and_uses_fractional_ratio() {
    let mut table = FlowTable::default();
    let a = [10, 0, 0, 1];
    let b = [10, 0, 0, 2];
    push_tcp(&mut table, 0, 0, a, b, 1234, 80, 0x02);
    push_tcp(&mut table, 1, 1_000, b, a, 80, 1234, 0x18);
    push_tcp(&mut table, 2, 2_000, a, b, 1234, 80, 0x18);
    let flow = table.finish().pop().unwrap();
    assert_eq!(flow.compatibility_values().len(), 88);
    assert_eq!(
        flow.compatibility_value(Policy::Corrected, "down_up_ratio"),
        Some(&FeatureValue::Float64(0.5))
    );
    assert_eq!(
        flow.compatibility_value(Policy::Corrected, "fwd_psh_flags"),
        Some(&FeatureValue::UInt64(1))
    );
    assert_eq!(
        flow.compatibility_value(Policy::Corrected, "bwd_psh_flags"),
        Some(&FeatureValue::UInt64(1))
    );
}

#[test]
fn corrected_matches_jnetpcap_discard_for_the_darpa_arp_request() {
    let mut bytes = vec![0u8; 42];
    bytes[..6].copy_from_slice(&[0xff; 6]);
    bytes[6..12].copy_from_slice(&[0x08, 0x00, 0x20, 0x83, 0x4a, 0x82]);
    bytes[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    bytes[14..16].copy_from_slice(&1u16.to_be_bytes());
    bytes[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    bytes[18] = 6;
    bytes[19] = 4;
    bytes[20..22].copy_from_slice(&1u16.to_be_bytes());

    let mut original = FlowTable::new(FlowConfig {
        policy: Policy::CicFlowMeter,
        ..FlowConfig::default()
    });
    push_raw(&mut original, 0, 0, &bytes);
    assert_eq!(
        (original.accepted_packets(), original.discarded_packets()),
        (1, 0)
    );

    let mut corrected = FlowTable::default();
    push_raw(&mut corrected, 0, 0, &bytes);
    assert_eq!(
        (corrected.accepted_packets(), corrected.discarded_packets()),
        (0, 1)
    );
}

#[test]
fn original_counts_the_header_of_a_header_only_embedded_udp_packet() {
    let mut table = FlowTable::new(FlowConfig {
        policy: Policy::CicFlowMeter,
        ..FlowConfig::default()
    });
    let a = [10, 0, 0, 1];
    let b = [10, 0, 0, 2];
    push_raw(&mut table, 0, 0, &udp_packet(a, b, 137, 137));
    push_raw(
        &mut table,
        1,
        1_000,
        &icmp_udp_error(a, b, b, a, 137, 137, 0),
    );

    let flow = table.finish().pop().unwrap();
    assert_eq!(
        flow.compatibility_value(Policy::CicFlowMeter, "fwd_header_length"),
        Some(&FeatureValue::UInt64(16))
    );
    assert_eq!(
        flow.compatibility_value(Policy::CicFlowMeter, "fwd_segment_size_min"),
        Some(&FeatureValue::UInt64(8))
    );
}

#[test]
fn original_counts_the_captured_payload_of_an_embedded_udp_packet() {
    let mut table = FlowTable::new(FlowConfig {
        policy: Policy::CicFlowMeter,
        ..FlowConfig::default()
    });
    let inside = [10, 0, 0, 1];
    let remote = [10, 0, 0, 2];
    for index in 0..2 {
        push_raw(
            &mut table,
            index,
            index as i64 * 1_000,
            &icmp_udp_error(remote, inside, inside, remote, 137, 137, 50),
        );
    }

    let flow = table.finish().pop().unwrap();
    assert_eq!(
        flow.compatibility_value(Policy::CicFlowMeter, "total_fwd_packet_length"),
        Some(&FeatureValue::Float64(100.0))
    );
    assert_eq!(
        flow.compatibility_value(Policy::CicFlowMeter, "fwd_header_length"),
        Some(&FeatureValue::UInt64(16))
    );
}

#[test]
fn idle_only_icmp_echo_identifier_is_part_of_the_key() {
    let mut table = FlowTable::new(FlowConfig {
        policy: Policy::IdleOnly,
        ..FlowConfig::default()
    });
    for (index, identifier) in [7u16, 8].into_iter().enumerate() {
        let mut bytes = vec![0u8; 42];
        bytes[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        bytes[14] = 0x45;
        bytes[16..18].copy_from_slice(&28u16.to_be_bytes());
        bytes[22] = 64;
        bytes[23] = 1;
        bytes[26..30].copy_from_slice(&[10, 0, 0, 1]);
        bytes[30..34].copy_from_slice(&[10, 0, 0, 2]);
        bytes[34] = 8;
        bytes[38..40].copy_from_slice(&identifier.to_be_bytes());
        push_raw(&mut table, index as u64, index as i64 * 1_000, &bytes);
    }
    let flows = table.finish();
    assert_eq!(flows.len(), 2);
}

#[test]
fn minimal_timestamps_and_uid_keep_capture_nanoseconds_under_compatibility_policies() {
    let mut table = FlowTable::default();
    push_tcp(
        &mut table,
        0,
        1_700_000_000_000_001_234,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        0x02,
    );
    let flow = table.finish().pop().unwrap();
    assert_eq!(flow.first_ts_ns, 1_700_000_000_000_001_234);
    assert_eq!(flow.last_ts_ns, 1_700_000_000_000_001_234);
}

#[test]
fn corrected_accepts_ipv4_total_length_zero_tso_frames() {
    let mut bytes = tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 0x18);
    bytes[16..18].copy_from_slice(&0u16.to_be_bytes());

    let mut corrected = FlowTable::default();
    push_raw(&mut corrected, 0, 1_000, &bytes);
    assert_eq!(
        (corrected.accepted_packets(), corrected.discarded_packets()),
        (1, 0)
    );

    let mut original = FlowTable::new(FlowConfig {
        policy: Policy::CicFlowMeter,
        ..FlowConfig::default()
    });
    push_raw(&mut original, 0, 1_000, &bytes);
    assert_eq!(
        (original.accepted_packets(), original.discarded_packets()),
        (0, 1)
    );
}

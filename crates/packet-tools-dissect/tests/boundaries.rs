use packet_tools_capture::LinkType;
use packet_tools_dissect::{
    DecodeDepth, EthernetView, Ipv4View, LayerKind, MalformedKind, TcpOption, TcpView, VlanView,
    decode,
};

#[test]
fn decode_depth_l2_does_not_trim_ethernet_padding() {
    let frame = ethernet_ipv4_udp(4, 14);
    let packet = decode(&frame, LinkType(1), DecodeDepth::L2);
    assert_eq!(packet.layers().collect::<Vec<_>>(), [LayerKind::Ethernet]);
    assert_eq!(packet.payload(), &frame[14..]);
    assert!(packet.trailer().is_empty());
}

#[test]
fn malformed_ip_lengths_leave_ip_out_of_the_index() {
    let mut frame = ethernet_ipv4_udp(4, 0);
    frame[14] = 0x44;
    let packet = decode(&frame, LinkType(1), DecodeDepth::L4);
    assert!(packet.layer::<EthernetView>().is_some());
    assert!(packet.layer::<Ipv4View>().is_none());
    assert_eq!(packet.payload(), &frame[14..]);
    let malformed = packet.malformed().unwrap();
    assert_eq!(malformed.layer, LayerKind::Ipv4);
    assert_eq!(malformed.offset, 14);
    assert_eq!(malformed.kind, MalformedKind::BadHeaderLength);

    frame[14] = 0x45;
    frame[16..18].copy_from_slice(&19u16.to_be_bytes());
    let packet = decode(&frame, LinkType(1), DecodeDepth::L4);
    assert_eq!(packet.malformed().unwrap().kind, MalformedKind::BadLength);
}

#[test]
fn nested_vlan_limit_is_reported_without_panicking() {
    let mut frame = vec![0; 12];
    frame.extend_from_slice(&0x8100u16.to_be_bytes());
    for _ in 0..8 {
        frame.extend_from_slice(&1u16.to_be_bytes());
        frame.extend_from_slice(&0x8100u16.to_be_bytes());
    }
    let packet = decode(&frame, LinkType(1), DecodeDepth::L4);
    assert_eq!(packet.layers().count(), 8);
    assert_eq!(
        packet.malformed().unwrap().kind,
        MalformedKind::TooManyLayers
    );
}

#[test]
fn tcp_flags_include_ns_and_options_are_lazy_views() {
    let mut frame = ethernet_ipv4_tcp_with_options();
    let packet = decode(&frame, LinkType(1), DecodeDepth::L4);
    let tcp = packet.layer::<TcpView>().unwrap();
    assert_eq!(tcp.flags(), 0x112);
    assert!(tcp.ns() && tcp.syn() && tcp.ack_flag());
    assert_eq!(tcp.header_len(), 32);
    assert_eq!(
        tcp.options().collect::<Vec<_>>(),
        [
            TcpOption::MaximumSegmentSize(1460),
            TcpOption::WindowScale(7),
            TcpOption::Noop,
            TcpOption::SackPermitted,
            TcpOption::End,
        ]
    );
    assert!(tcp.verify_checksum(&packet.layer::<Ipv4View>().unwrap()));

    frame.truncate(frame.len() - 1);
    let truncated = decode(&frame, LinkType(1), DecodeDepth::L4);
    assert!(truncated.ip_truncated());
}

#[test]
fn two_vlans_expose_outer_then_inner_tags() {
    let mut frame = vec![0; 12];
    frame.extend_from_slice(&0x88a8u16.to_be_bytes());
    frame.extend_from_slice(&0xa123u16.to_be_bytes());
    frame.extend_from_slice(&0x8100u16.to_be_bytes());
    frame.extend_from_slice(&0x0064u16.to_be_bytes());
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&ethernet_ipv4_udp(0, 0)[14..]);
    let packet = decode(&frame, LinkType(1), DecodeDepth::L4);
    let vlans = packet
        .layers()
        .enumerate()
        .filter_map(|(index, kind)| (kind == LayerKind::Vlan).then_some(index))
        .collect::<Vec<_>>();
    assert_eq!(vlans, [1, 2]);
    assert_eq!(packet.layer::<VlanView>().unwrap().vid(), 0x123);
}

fn ethernet_ipv4_udp(payload_len: usize, padding: usize) -> Vec<u8> {
    let mut frame = vec![0; 12];
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    let total_len = 20 + 8 + payload_len;
    frame.extend_from_slice(&[0x45, 0]);
    frame.extend_from_slice(&(total_len as u16).to_be_bytes());
    frame.extend_from_slice(&[
        0x12, 0x34, 0x40, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
    ]);
    frame.extend_from_slice(&1234u16.to_be_bytes());
    frame.extend_from_slice(&5678u16.to_be_bytes());
    frame.extend_from_slice(&((8 + payload_len) as u16).to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.resize(frame.len() + payload_len, 0x5a);
    frame.resize(frame.len() + padding, 0);
    frame
}

fn ethernet_ipv4_tcp_with_options() -> Vec<u8> {
    let options = [2, 4, 0x05, 0xb4, 3, 3, 7, 1, 4, 2, 0, 0];
    let mut frame = vec![0; 12];
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&[0x45, 0]);
    frame.extend_from_slice(&(20u16 + 20 + options.len() as u16).to_be_bytes());
    frame.extend_from_slice(&[0, 1, 0x40, 0, 64, 6, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2]);
    frame.extend_from_slice(&1234u16.to_be_bytes());
    frame.extend_from_slice(&443u16.to_be_bytes());
    frame.extend_from_slice(&1u32.to_be_bytes());
    frame.extend_from_slice(&2u32.to_be_bytes());
    frame.extend_from_slice(&[0x81, 0x12]);
    frame.extend_from_slice(&4096u16.to_be_bytes());
    frame.extend_from_slice(&[0, 0, 0, 0]);
    frame.extend_from_slice(&options);
    let ip_checksum = checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&frame[26..34]);
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&(32u16).to_be_bytes());
    pseudo.extend_from_slice(&frame[34..]);
    let tcp_checksum = checksum(&pseudo);
    frame[50..52].copy_from_slice(&tcp_checksum.to_be_bytes());
    frame
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        sum += if chunk.len() == 2 {
            u32::from(u16::from_be_bytes([chunk[0], chunk[1]]))
        } else {
            u32::from(chunk[0]) << 8
        };
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
    }
    !(sum as u16)
}

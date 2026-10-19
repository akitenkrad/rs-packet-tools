use packet_tools_capture::LinkType;
use packet_tools_dissect::{
    ArpView, DecodeDepth, EthernetView, Icmpv4View, Icmpv6View, Ipv4View, Ipv6View, LinuxSll2View,
    LinuxSllView, NullView, TcpView, UdpView, VlanView, decode,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..=256)) {
        for linktype in [0, 1, 12, 14, 101, 108, 113, 276] {
            for depth in [DecodeDepth::L2, DecodeDepth::L3, DecodeDepth::L4] {
                exercise(&bytes, LinkType(linktype), depth);
            }
        }
    }
}

fn exercise(data: &[u8], linktype: LinkType, depth: DecodeDepth) {
    let packet = decode(data, linktype, depth);
    let _ = (
        packet.layers().count(),
        packet.payload(),
        packet.trailer(),
        packet.malformed(),
        packet.ip_truncated(),
    );
    if let Some(view) = packet.layer::<EthernetView>() {
        let _ = (view.src(), view.dst(), view.ethertype());
    }
    for view in packet.layers_of::<VlanView>() {
        let _ = (view.pcp(), view.dei(), view.vid(), view.ethertype());
    }
    if let Some(view) = packet.layer::<LinuxSllView>() {
        let _ = (
            view.protocol(),
            view.packet_type(),
            view.address_type(),
            view.address(),
        );
    }
    if let Some(view) = packet.layer::<LinuxSll2View>() {
        let _ = (
            view.protocol(),
            view.packet_type(),
            view.interface_index(),
            view.address_type(),
            view.address(),
        );
    }
    if let Some(view) = packet.layer::<NullView>() {
        let _ = view.family();
    }
    if let Some(view) = packet.layer::<ArpView>() {
        let _ = (
            view.operation(),
            view.sender_mac(),
            view.sender_ipv4(),
            view.target_mac(),
            view.target_ipv4(),
        );
    }
    let ipv4 = packet.layer::<Ipv4View>();
    if let Some(view) = ipv4 {
        let _ = (
            view.ihl(),
            view.header_len(),
            view.dscp(),
            view.ecn(),
            view.total_len(),
            view.id(),
            view.dont_fragment(),
            view.more_fragments(),
            view.fragment_offset(),
            view.ttl(),
            view.protocol(),
            view.checksum(),
            view.src(),
            view.dst(),
            view.options(),
            view.verify_checksum(),
        );
    }
    let ipv6 = packet.layer::<Ipv6View>();
    if let Some(view) = ipv6 {
        let _ = (
            view.traffic_class(),
            view.flow_label(),
            view.payload_len(),
            view.next_header(),
            view.upper_protocol(),
            view.hop_limit(),
            view.src(),
            view.dst(),
            view.fragment(),
        );
    }
    if let Some(view) = packet.layer::<TcpView>() {
        let _ = (
            view.src_port(),
            view.dst_port(),
            view.seq(),
            view.ack(),
            view.header_len(),
            view.flags(),
            view.fin(),
            view.syn(),
            view.rst(),
            view.psh(),
            view.ack_flag(),
            view.urg(),
            view.ece(),
            view.cwr(),
            view.ns(),
            view.window(),
            view.checksum(),
            view.urgent(),
        );
        let _ = view.options().collect::<Vec<_>>();
        if let Some(ip) = ipv4 {
            let _ = view.verify_checksum(&ip);
        }
        if let Some(ip) = ipv6 {
            let _ = view.verify_checksum(&ip);
        }
    }
    if let Some(view) = packet.layer::<UdpView>() {
        let _ = (
            view.src_port(),
            view.dst_port(),
            view.length(),
            view.checksum(),
        );
        if let Some(ip) = ipv4 {
            let _ = view.verify_checksum(&ip);
        }
        if let Some(ip) = ipv6 {
            let _ = view.verify_checksum(&ip);
        }
    }
    if let Some(view) = packet.layer::<Icmpv4View>() {
        let _ = (view.icmp_type(), view.code(), view.checksum());
    }
    if let Some(view) = packet.layer::<Icmpv6View>() {
        let _ = (view.icmp_type(), view.code(), view.checksum());
    }
}

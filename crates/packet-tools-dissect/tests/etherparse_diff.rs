use etherparse::{
    IpHeaders, Ipv4Header, Ipv6Header, LinkExtSlice, LinkSlice, NetSlice, PacketBuilder,
    SlicedPacket, TcpHeader, TransportSlice,
};
use packet_tools_capture::LinkType;
use packet_tools_dissect::{
    DecodeDepth, EthernetView, Icmpv4View, Icmpv6View, Ipv4View, Ipv6View, TcpView, UdpView,
    VlanView, decode,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_048))]

    #[test]
    fn valid_packet_fields_match_etherparse(
        vlan_depth in 0u8..3,
        ipv6 in any::<bool>(),
        transport in 0u8..3,
        src_mac in any::<[u8; 6]>(),
        dst_mac in any::<[u8; 6]>(),
        src4 in any::<[u8; 4]>(),
        dst4 in any::<[u8; 4]>(),
        src6 in any::<[u8; 16]>(),
        dst6 in any::<[u8; 16]>(),
        ttl in any::<u8>(),
        ip_id in any::<u16>(),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
        seq in any::<u32>(),
        ack in any::<u32>(),
        window in any::<u16>(),
        flags in any::<u16>(),
        icmp_type in 200u8..=254,
        icmp_code in any::<u8>(),
        payload in proptest::collection::vec(any::<u8>(), 0..64),
        padding in 0usize..=20,
        outer_vid in 0u16..=4095,
        inner_vid in 0u16..=4095,
    ) {
        let packet_bytes = build_packet(
            vlan_depth, ipv6, transport, src_mac, dst_mac, src4, dst4, src6, dst6,
            ttl, ip_id, src_port, dst_port, seq, ack, window, flags, icmp_type,
            icmp_code, &payload, padding, outer_vid, inner_vid,
        );
        compare(&packet_bytes, vlan_depth, ipv6, transport, padding);
    }
}

#[allow(clippy::too_many_arguments)]
fn build_packet(
    vlan_depth: u8,
    ipv6: bool,
    transport: u8,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src4: [u8; 4],
    dst4: [u8; 4],
    src6: [u8; 16],
    dst6: [u8; 16],
    ttl: u8,
    ip_id: u16,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    window: u16,
    flags: u16,
    icmp_type: u8,
    icmp_code: u8,
    payload: &[u8],
    padding: usize,
    outer_vid: u16,
    inner_vid: u16,
) -> Vec<u8> {
    let ip = if ipv6 {
        IpHeaders::Ipv6(
            Ipv6Header {
                source: src6,
                destination: dst6,
                hop_limit: ttl,
                ..Default::default()
            },
            Default::default(),
        )
    } else {
        IpHeaders::Ipv4(
            Ipv4Header {
                source: src4,
                destination: dst4,
                time_to_live: ttl,
                identification: ip_id,
                ..Default::default()
            },
            Default::default(),
        )
    };
    let network = match vlan_depth {
        0 => PacketBuilder::ethernet2(src_mac, dst_mac).ip(ip),
        1 => PacketBuilder::ethernet2(src_mac, dst_mac)
            .single_vlan(outer_vid.try_into().unwrap())
            .ip(ip),
        2 => PacketBuilder::ethernet2(src_mac, dst_mac)
            .double_vlan(outer_vid.try_into().unwrap(), inner_vid.try_into().unwrap())
            .ip(ip),
        _ => unreachable!(),
    };
    let mut bytes = Vec::new();
    match transport {
        0 => {
            let mut tcp = TcpHeader::new(src_port, dst_port, seq, window);
            tcp.acknowledgment_number = ack;
            tcp.ns = flags & 0x100 != 0;
            tcp.fin = flags & 1 != 0;
            tcp.syn = flags & 2 != 0;
            tcp.rst = flags & 4 != 0;
            tcp.psh = flags & 8 != 0;
            tcp.ack = flags & 0x10 != 0;
            tcp.urg = flags & 0x20 != 0;
            tcp.ece = flags & 0x40 != 0;
            tcp.cwr = flags & 0x80 != 0;
            tcp.set_options_raw(&[2, 4, 0x05, 0xb4, 3, 3, 7, 1, 4, 2, 1, 1])
                .unwrap();
            network.tcp_header(tcp).write(&mut bytes, payload).unwrap();
        }
        1 => network
            .udp(src_port, dst_port)
            .write(&mut bytes, payload)
            .unwrap(),
        2 if ipv6 => network
            .icmpv6_raw(icmp_type, icmp_code, [1, 2, 3, 4])
            .write(&mut bytes, payload)
            .unwrap(),
        2 => network
            .icmpv4_raw(icmp_type, icmp_code, [1, 2, 3, 4])
            .write(&mut bytes, payload)
            .unwrap(),
        _ => unreachable!(),
    }
    bytes.resize(bytes.len() + padding, 0);
    bytes
}

fn compare(bytes: &[u8], vlan_depth: u8, ipv6: bool, transport: u8, padding: usize) {
    let ours = decode(bytes, LinkType(1), DecodeDepth::L4);
    let theirs = SlicedPacket::from_ethernet(bytes).unwrap();
    let ours_eth = ours.layer::<EthernetView>().unwrap();
    let LinkSlice::Ethernet2(theirs_eth) = theirs.link.unwrap() else {
        unreachable!()
    };
    assert_eq!(ours_eth.src(), theirs_eth.source());
    assert_eq!(ours_eth.dst(), theirs_eth.destination());

    let ours_vlans = ours.layers_of::<VlanView>().collect::<Vec<_>>();
    let theirs_vlans = theirs
        .link_exts
        .iter()
        .filter_map(|layer| match layer {
            LinkExtSlice::Vlan(vlan) => Some(vlan),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(ours_vlans.len(), usize::from(vlan_depth));
    assert_eq!(ours_vlans.len(), theirs_vlans.len());
    for (ours, theirs) in ours_vlans.iter().zip(theirs_vlans) {
        assert_eq!(ours.vid(), theirs.vlan_identifier().value());
    }
    assert_eq!(ours.trailer().len(), padding);

    match theirs.net.unwrap() {
        NetSlice::Ipv4(theirs_ip) => {
            assert!(!ipv6);
            let ours_ip = ours.layer::<Ipv4View>().unwrap();
            let header = theirs_ip.header();
            assert_eq!(ours_ip.src().octets(), header.source());
            assert_eq!(ours_ip.dst().octets(), header.destination());
            assert_eq!(ours_ip.ttl(), header.ttl());
            assert_eq!(ours_ip.id(), header.identification());
            assert_eq!(ours_ip.protocol(), header.protocol().0);
        }
        NetSlice::Ipv6(theirs_ip) => {
            assert!(ipv6);
            let ours_ip = ours.layer::<Ipv6View>().unwrap();
            let header = theirs_ip.header();
            assert_eq!(ours_ip.src().octets(), header.source());
            assert_eq!(ours_ip.dst().octets(), header.destination());
            assert_eq!(ours_ip.hop_limit(), header.hop_limit());
            assert_eq!(ours_ip.upper_protocol(), theirs_ip.payload().ip_number.0);
        }
        NetSlice::Arp(_) => unreachable!(),
    }

    match (transport, theirs.transport.unwrap()) {
        (0, TransportSlice::Tcp(theirs_tcp)) => {
            let ours_tcp = ours.layer::<TcpView>().unwrap();
            assert_eq!(ours_tcp.src_port(), theirs_tcp.source_port());
            assert_eq!(ours_tcp.dst_port(), theirs_tcp.destination_port());
            assert_eq!(ours_tcp.seq(), theirs_tcp.sequence_number());
            assert_eq!(ours_tcp.ack(), theirs_tcp.acknowledgment_number());
            assert_eq!(ours_tcp.window(), theirs_tcp.window_size());
            let their_flags = (u16::from(theirs_tcp.ns()) << 8)
                | u16::from(theirs_tcp.fin())
                | (u16::from(theirs_tcp.syn()) << 1)
                | (u16::from(theirs_tcp.rst()) << 2)
                | (u16::from(theirs_tcp.psh()) << 3)
                | (u16::from(theirs_tcp.ack()) << 4)
                | (u16::from(theirs_tcp.urg()) << 5)
                | (u16::from(theirs_tcp.ece()) << 6)
                | (u16::from(theirs_tcp.cwr()) << 7);
            assert_eq!(ours_tcp.flags(), their_flags);
            assert_eq!(ours_tcp.header_len(), theirs_tcp.header_len());
            assert_eq!(ours.payload().len(), theirs_tcp.payload().len());
        }
        (1, TransportSlice::Udp(theirs_udp)) => {
            let ours_udp = ours.layer::<UdpView>().unwrap();
            assert_eq!(ours_udp.src_port(), theirs_udp.source_port());
            assert_eq!(ours_udp.dst_port(), theirs_udp.destination_port());
            assert_eq!(ours_udp.length(), theirs_udp.length());
            assert_eq!(ours.payload().len(), theirs_udp.payload().len());
        }
        (2, TransportSlice::Icmpv4(theirs_icmp)) => {
            let ours_icmp = ours.layer::<Icmpv4View>().unwrap();
            assert_eq!(ours_icmp.icmp_type(), theirs_icmp.type_u8());
            assert_eq!(ours_icmp.code(), theirs_icmp.code_u8());
        }
        (2, TransportSlice::Icmpv6(theirs_icmp)) => {
            let ours_icmp = ours.layer::<Icmpv6View>().unwrap();
            assert_eq!(ours_icmp.icmp_type(), theirs_icmp.type_u8());
            assert_eq!(ours_icmp.code(), theirs_icmp.code_u8());
        }
        _ => panic!("unexpected transport"),
    }
}

use std::{net::Ipv4Addr, path::PathBuf};

use packet_tools_capture::Capture;
use packet_tools_dissect::{
    ArpView, DecodeDepth, EthernetView, Ipv4View, Ipv6View, LayerKind, TcpView, UdpView, VlanView,
    decode,
};

#[test]
fn fixture_scenarios_decode_to_expected_layers_and_lengths() {
    let mut capture = Capture::open(fixture("le_usec.pcap")).unwrap();
    let mut seen = 0;
    while let Some(record) = capture.next_record() {
        let record = record.unwrap();
        let packet = decode(record.data, record.linktype, DecodeDepth::L4);
        match record.index {
            0 => {
                let ethernet = packet.layer::<EthernetView>().unwrap();
                assert_eq!(ethernet.src(), [0x02, 0, 0, 0, 0, 1]);
                assert_eq!(ethernet.dst(), [0x02, 0, 0, 0, 0, 2]);
                let tcp = packet.layer::<TcpView>().unwrap();
                assert_eq!((tcp.src_port(), tcp.dst_port()), (49_152, 80));
                assert!(tcp.syn());
                assert!(tcp.verify_checksum(&packet.layer::<Ipv4View>().unwrap()));
            }
            11 => {
                let ip = packet.layer::<Ipv6View>().unwrap();
                assert_eq!(ip.src().to_string(), "2001:db8::1");
                assert_eq!(ip.dst().to_string(), "2001:db8::2");
                assert_eq!(ip.upper_protocol(), 17);
                let udp = packet.layer::<UdpView>().unwrap();
                assert_eq!((udp.src_port(), udp.dst_port()), (65_400, 65_401));
                assert_eq!(packet.payload(), b"ipv6-udp");
                assert!(udp.verify_checksum(&ip));
            }
            12 => {
                let arp = packet.layer::<ArpView>().unwrap();
                assert_eq!(arp.operation(), 1);
                assert_eq!(arp.sender_mac(), Some([0x02, 0, 0, 0, 0, 1]));
                assert_eq!(arp.sender_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 10)));
                assert_eq!(arp.target_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 1)));
            }
            13 => {
                assert_eq!(packet.layer::<VlanView>().unwrap().vid(), 100);
                assert_eq!(
                    packet.layers().collect::<Vec<_>>(),
                    [
                        LayerKind::Ethernet,
                        LayerKind::Vlan,
                        LayerKind::Ipv4,
                        LayerKind::Udp
                    ]
                );
            }
            14 => {
                assert!(packet.layer::<UdpView>().is_some());
                assert_eq!(packet.layer::<Ipv4View>().unwrap().fragment_offset(), 0);
            }
            15 => {
                assert!(packet.layer::<UdpView>().is_none());
                assert_eq!(packet.layer::<Ipv4View>().unwrap().fragment_offset(), 16);
            }
            16 => {
                assert!(packet.ip_truncated());
                assert!(packet.malformed().is_none());
                assert_eq!(packet.layer::<UdpView>().unwrap().length(), 104);
                assert_eq!(packet.payload().len(), 8);
            }
            17 => {
                assert_eq!(packet.payload(), b"pad!");
                assert_eq!(packet.trailer().len(), 14);
            }
            _ => {}
        }
        seen += 1;
    }
    assert_eq!(seen, 19);
}

#[test]
fn pcapng_raw_packets_keep_timestamps_and_decode_without_l2() {
    let mut capture = Capture::open(fixture("multi_iface.pcapng")).unwrap();
    let mut observed = Vec::new();
    while let Some(record) = capture.next_record() {
        let record = record.unwrap();
        if record.interface == 1 {
            let packet = decode(record.data, record.linktype, DecodeDepth::L4);
            observed.push((
                record.index,
                record.ts_ns,
                packet.layers().collect::<Vec<_>>(),
                packet.layer::<UdpView>().map(|udp| udp.src_port()),
            ));
        }
    }
    assert_eq!(observed.len(), 3);
    assert_eq!(observed[0].0, 19);
    assert_eq!(observed[0].1, Some(1_700_000_000_030_000_123));
    assert_eq!(observed[0].2, [LayerKind::Ipv4, LayerKind::Udp]);
    assert_eq!(observed[0].3, Some(53_000));
    assert_eq!(observed[2].3, Some(65_404));
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

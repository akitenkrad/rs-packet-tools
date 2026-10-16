use std::{fs, io::Cursor, path::PathBuf};

use pcap_file::pcap::PcapReader;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

#[test]
fn legacy_magic_numbers_match_byte_order_and_resolution() {
    for (name, magic) in [
        ("le_usec.pcap", [0xd4, 0xc3, 0xb2, 0xa1]),
        ("be_usec.pcap", [0xa1, 0xb2, 0xc3, 0xd4]),
        ("le_nsec.pcap", [0x4d, 0x3c, 0xb2, 0xa1]),
        ("be_nsec.pcap", [0xa1, 0xb2, 0x3c, 0x4d]),
    ] {
        assert_eq!(fs::read(root().join(name)).unwrap()[..4], magic);
    }
}

#[test]
fn gzip_header_has_no_name_and_zero_mtime() {
    let bytes = fs::read(root().join("le_usec.pcap.gz")).unwrap();
    assert_eq!(&bytes[..3], &[0x1f, 0x8b, 8]);
    assert_eq!(bytes[3] & 0x08, 0, "FNAME must not be present");
    assert_eq!(&bytes[4..8], &[0, 0, 0, 0]);
}

#[test]
fn all_captured_ipv4_headers_have_valid_lengths_and_checksums() {
    let bytes = fs::read(root().join("le_usec.pcap")).unwrap();
    let mut reader = PcapReader::new(Cursor::new(bytes)).unwrap();
    while let Some(packet) = reader.next_packet() {
        let packet = packet.unwrap();
        let data = packet.data.as_ref();
        let ip_offset = match u16::from_be_bytes([data[12], data[13]]) {
            0x0800 => Some(14),
            0x8100 if u16::from_be_bytes([data[16], data[17]]) == 0x0800 => Some(18),
            _ => None,
        };
        if let Some(offset) = ip_offset {
            let ihl = usize::from(data[offset] & 0x0f) * 4;
            assert_eq!(data[offset] >> 4, 4);
            assert_eq!(ihl, 20);
            assert_eq!(checksum(&data[offset..offset + ihl]), 0);
            let total_length =
                usize::from(u16::from_be_bytes([data[offset + 2], data[offset + 3]]));
            assert!(total_length >= ihl);
        }
    }
}

#[test]
fn tcp_headers_have_the_declared_minimum_length() {
    let bytes = fs::read(root().join("le_usec.pcap")).unwrap();
    let mut reader = PcapReader::new(Cursor::new(bytes)).unwrap();
    let mut tcp_packets = 0;
    while let Some(packet) = reader.next_packet() {
        let packet = packet.unwrap();
        let data = packet.data.as_ref();
        if data.len() >= 54 && data[12..14] == [0x08, 0x00] && data[23] == 6 {
            assert_eq!(data[46] >> 4, 5);
            tcp_packets += 1;
        }
    }
    assert_eq!(tcp_packets, 9);
}

#[test]
fn non_http_and_non_dns_transport_ports_are_dynamic() {
    let bytes = fs::read(root().join("le_usec.pcap")).unwrap();
    let mut reader = PcapReader::new(Cursor::new(bytes)).unwrap();
    while let Some(packet) = reader.next_packet() {
        let packet = packet.unwrap();
        let data = packet.data.as_ref();
        if let Some((protocol, offset)) = transport_header(data) {
            let source = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let destination = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
            for port in [source, destination] {
                assert!(
                    matches!(port, 53 | 80) || port >= 49_152,
                    "protocol {protocol} uses non-dynamic port {port}"
                );
            }
        }
    }
}

fn transport_header(data: &[u8]) -> Option<(u8, usize)> {
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    let network_offset = if ethertype == 0x8100 { 18 } else { 14 };
    let ethertype = if ethertype == 0x8100 {
        u16::from_be_bytes([data[16], data[17]])
    } else {
        ethertype
    };
    match ethertype {
        0x0800 => {
            let fragment = u16::from_be_bytes([data[network_offset + 6], data[network_offset + 7]]);
            if fragment & 0x1fff != 0 {
                return None;
            }
            let protocol = data[network_offset + 9];
            if !matches!(protocol, 6 | 17) {
                return None;
            }
            let header_length = usize::from(data[network_offset] & 0x0f) * 4;
            Some((protocol, network_offset + header_length))
        }
        0x86dd if matches!(data[network_offset + 6], 6 | 17) => {
            Some((data[network_offset + 6], network_offset + 40))
        }
        _ => None,
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        sum += u32::from(if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        });
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

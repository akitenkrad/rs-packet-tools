use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use clap::Parser;
use flate2::{Compression, GzBuilder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const BASE_SECONDS: u64 = 1_700_000_000;
const ETHERNET: u32 = 1;
const RAW: u32 = 101;

#[derive(Parser)]
#[command(about = "Generate deterministic packet-tools test fixtures")]
struct Cli {
    /// Directory in which capture files and manifest.json are written.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Clone)]
struct Packet {
    ts_ns: u64,
    data: Vec<u8>,
    origlen: u32,
    description: &'static str,
}

#[derive(Clone, Serialize)]
struct ManifestPacket {
    index: usize,
    ts_ns: u64,
    caplen: u32,
    origlen: u32,
    linktype: u32,
    interface: u32,
    first_byte: u8,
    description: &'static str,
}

#[derive(Serialize)]
struct ManifestFile {
    format: &'static str,
    endianness: &'static str,
    ts_resolution: &'static str,
    compressed: bool,
    packet_count: usize,
    packets: Vec<ManifestPacket>,
    sha256: String,
}

#[derive(Serialize)]
struct Manifest {
    files: BTreeMap<String, ManifestFile>,
}

#[derive(Clone, Copy)]
enum ByteOrder {
    Little,
    Big,
}

#[derive(Clone, Copy)]
enum TimestampResolution {
    Microsecond,
    Nanosecond,
}

fn main() {
    if let Err(error) = generate(&Cli::parse().out) {
        eprintln!("packet-tools-fixtures: {error}");
        std::process::exit(1);
    }
}

fn generate(out: &Path) -> io::Result<()> {
    fs::create_dir_all(out)?;
    let packets = ethernet_packets();
    let mut files = BTreeMap::new();

    for (name, order, resolution, endianness, resolution_name) in [
        (
            "le_usec.pcap",
            ByteOrder::Little,
            TimestampResolution::Microsecond,
            "little",
            "microsecond",
        ),
        (
            "be_usec.pcap",
            ByteOrder::Big,
            TimestampResolution::Microsecond,
            "big",
            "microsecond",
        ),
        (
            "le_nsec.pcap",
            ByteOrder::Little,
            TimestampResolution::Nanosecond,
            "little",
            "nanosecond",
        ),
        (
            "be_nsec.pcap",
            ByteOrder::Big,
            TimestampResolution::Nanosecond,
            "big",
            "nanosecond",
        ),
    ] {
        let bytes = write_pcap(&packets, order, resolution);
        write_file(out, name, &bytes)?;
        files.insert(
            name.to_owned(),
            manifest_file(
                "pcap",
                endianness,
                resolution_name,
                false,
                ethernet_manifest(&packets),
                &bytes,
            ),
        );
    }

    let little_pcap = write_pcap(
        &packets,
        ByteOrder::Little,
        TimestampResolution::Microsecond,
    );
    let gzip = gzip(&little_pcap)?;
    write_file(out, "le_usec.pcap.gz", &gzip)?;
    files.insert(
        "le_usec.pcap.gz".to_owned(),
        manifest_file(
            "pcap",
            "little",
            "microsecond",
            true,
            ethernet_manifest(&packets),
            &gzip,
        ),
    );

    let raw_packets = raw_packets(&packets);
    let pcapng = write_pcapng(&packets, &raw_packets);
    write_file(out, "multi_iface.pcapng", &pcapng)?;
    let mut pcapng_packets = ethernet_manifest(&packets);
    pcapng_packets.extend(raw_manifest(&raw_packets, pcapng_packets.len()));
    files.insert(
        "multi_iface.pcapng".to_owned(),
        manifest_file(
            "pcapng",
            "little",
            "per-interface",
            false,
            pcapng_packets,
            &pcapng,
        ),
    );

    let flows = flow_packets();
    let flow_bytes = write_pcap(&flows, ByteOrder::Little, TimestampResolution::Nanosecond);
    fs::create_dir_all(out.join("flows"))?;
    write_file(out, "flows/scenarios.pcap", &flow_bytes)?;
    files.insert(
        "flows/scenarios.pcap".to_owned(),
        manifest_file(
            "pcap",
            "little",
            "nanosecond",
            false,
            ethernet_manifest(&flows),
            &flow_bytes,
        ),
    );

    let reassembly = reassembly_packets();
    let reassembly_bytes = write_pcap(
        &reassembly,
        ByteOrder::Little,
        TimestampResolution::Nanosecond,
    );
    fs::create_dir_all(out.join("reassembly"))?;
    write_file(out, "reassembly/scenarios.pcap", &reassembly_bytes)?;
    files.insert(
        "reassembly/scenarios.pcap".to_owned(),
        manifest_file(
            "pcap",
            "little",
            "nanosecond",
            false,
            ethernet_manifest(&reassembly),
            &reassembly_bytes,
        ),
    );

    let app = app_packets();
    let app_bytes = write_pcap(&app, ByteOrder::Little, TimestampResolution::Nanosecond);
    fs::create_dir_all(out.join("app"))?;
    write_file(out, "app/scenarios.pcap", &app_bytes)?;
    files.insert(
        "app/scenarios.pcap".to_owned(),
        manifest_file(
            "pcap",
            "little",
            "nanosecond",
            false,
            ethernet_manifest(&app),
            &app_bytes,
        ),
    );

    let mut manifest = serde_json::to_vec_pretty(&Manifest { files })
        .map_err(|error| io::Error::other(error.to_string()))?;
    manifest.push(b'\n');
    write_file(out, "manifest.json", &manifest)
}

fn write_file(out: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    fs::write(out.join(name), bytes)
}

fn manifest_file(
    format: &'static str,
    endianness: &'static str,
    ts_resolution: &'static str,
    compressed: bool,
    packets: Vec<ManifestPacket>,
    bytes: &[u8],
) -> ManifestFile {
    ManifestFile {
        format,
        endianness,
        ts_resolution,
        compressed,
        packet_count: packets.len(),
        packets,
        sha256: sha256(bytes),
    }
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn ethernet_manifest(packets: &[Packet]) -> Vec<ManifestPacket> {
    packets
        .iter()
        .enumerate()
        .map(|(index, packet)| ManifestPacket {
            index,
            ts_ns: packet.ts_ns,
            caplen: packet.data.len() as u32,
            origlen: packet.origlen,
            linktype: ETHERNET,
            interface: 0,
            first_byte: packet.data[0],
            description: packet.description,
        })
        .collect()
}

fn raw_manifest(packets: &[Packet], index_offset: usize) -> Vec<ManifestPacket> {
    packets
        .iter()
        .enumerate()
        .map(|(index, packet)| ManifestPacket {
            index: index_offset + index,
            ts_ns: packet.ts_ns,
            caplen: packet.data.len() as u32,
            origlen: packet.origlen,
            linktype: RAW,
            interface: 1,
            first_byte: packet.data[0],
            description: packet.description,
        })
        .collect()
}

fn gzip(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::default());
    encoder.write_all(bytes)?;
    encoder.finish()
}

fn write_pcap(packets: &[Packet], order: ByteOrder, resolution: TimestampResolution) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(match (order, resolution) {
        (ByteOrder::Little, TimestampResolution::Microsecond) => &[0xd4, 0xc3, 0xb2, 0xa1],
        (ByteOrder::Big, TimestampResolution::Microsecond) => &[0xa1, 0xb2, 0xc3, 0xd4],
        (ByteOrder::Little, TimestampResolution::Nanosecond) => &[0x4d, 0x3c, 0xb2, 0xa1],
        (ByteOrder::Big, TimestampResolution::Nanosecond) => &[0xa1, 0xb2, 0x3c, 0x4d],
    });
    push_u16(&mut out, 2, order);
    push_u16(&mut out, 4, order);
    push_u32(&mut out, 0, order);
    push_u32(&mut out, 0, order);
    push_u32(&mut out, 65_535, order);
    push_u32(&mut out, ETHERNET, order);

    for packet in packets {
        let seconds = packet.ts_ns / 1_000_000_000;
        let remainder = packet.ts_ns % 1_000_000_000;
        let fraction = match resolution {
            TimestampResolution::Microsecond => remainder / 1_000,
            TimestampResolution::Nanosecond => remainder,
        };
        push_u32(&mut out, seconds as u32, order);
        push_u32(&mut out, fraction as u32, order);
        push_u32(&mut out, packet.data.len() as u32, order);
        push_u32(&mut out, packet.origlen, order);
        out.extend_from_slice(&packet.data);
    }
    out
}

fn write_pcapng(ethernet_packets: &[Packet], raw_packets: &[Packet]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut shb = Vec::new();
    shb.extend_from_slice(&0x1a2b_3c4du32.to_le_bytes());
    shb.extend_from_slice(&1u16.to_le_bytes());
    shb.extend_from_slice(&0u16.to_le_bytes());
    shb.extend_from_slice(&(-1i64).to_le_bytes());
    push_pcapng_block(&mut out, 0x0a0d_0d0a, &shb);
    push_idb(&mut out, ETHERNET as u16, 6);
    push_idb(&mut out, RAW as u16, 9);
    for packet in ethernet_packets {
        push_epb(&mut out, 0, packet.ts_ns / 1_000, packet);
    }
    for packet in raw_packets {
        push_epb(&mut out, 1, packet.ts_ns, packet);
    }
    out
}

fn push_idb(out: &mut Vec<u8>, linktype: u16, tsresol: u8) {
    let mut body = Vec::new();
    body.extend_from_slice(&linktype.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&65_535u32.to_le_bytes());
    body.extend_from_slice(&9u16.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.push(tsresol);
    body.extend_from_slice(&[0; 3]);
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    push_pcapng_block(out, 1, &body);
}

fn push_epb(out: &mut Vec<u8>, interface: u32, timestamp: u64, packet: &Packet) {
    let mut body = Vec::new();
    body.extend_from_slice(&interface.to_le_bytes());
    body.extend_from_slice(&((timestamp >> 32) as u32).to_le_bytes());
    body.extend_from_slice(&(timestamp as u32).to_le_bytes());
    body.extend_from_slice(&(packet.data.len() as u32).to_le_bytes());
    body.extend_from_slice(&packet.origlen.to_le_bytes());
    body.extend_from_slice(&packet.data);
    while body.len() % 4 != 0 {
        body.push(0);
    }
    push_pcapng_block(out, 6, &body);
}

fn push_pcapng_block(out: &mut Vec<u8>, block_type: u32, body: &[u8]) {
    let total_length = (body.len() + 12) as u32;
    out.extend_from_slice(&block_type.to_le_bytes());
    out.extend_from_slice(&total_length.to_le_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(&total_length.to_le_bytes());
}

fn push_u16(out: &mut Vec<u8>, value: u16, order: ByteOrder) {
    match order {
        ByteOrder::Little => out.extend_from_slice(&value.to_le_bytes()),
        ByteOrder::Big => out.extend_from_slice(&value.to_be_bytes()),
    }
}

fn push_u32(out: &mut Vec<u8>, value: u32, order: ByteOrder) {
    match order {
        ByteOrder::Little => out.extend_from_slice(&value.to_le_bytes()),
        ByteOrder::Big => out.extend_from_slice(&value.to_be_bytes()),
    }
}

fn ethernet_packets() -> Vec<Packet> {
    let client = [192, 0, 2, 10];
    let server = [198, 51, 100, 20];
    let client_mac = [0x02, 0, 0, 0, 0, 1];
    let server_mac = [0x02, 0, 0, 0, 0, 2];
    let mut packets = Vec::new();
    let mut add = |data: Vec<u8>, origlen: Option<u32>, description: &'static str| {
        let index = packets.len() as u64;
        packets.push(Packet {
            ts_ns: BASE_SECONDS * 1_000_000_000 + index * 1_000_000,
            origlen: origlen.unwrap_or(data.len() as u32),
            data,
            description,
        });
    };
    let tcp = |src: ([u8; 6], [u8; 4]),
               dst: ([u8; 6], [u8; 4]),
               sport: u16,
               dport: u16,
               seq: u32,
               ack: u32,
               flags: u8,
               payload: &[u8]| {
        ethernet(
            dst.0,
            src.0,
            0x0800,
            ipv4(
                src.1,
                dst.1,
                6,
                0x1000,
                0x4000,
                tcp_segment(src.1, dst.1, sport, dport, seq, ack, flags, payload),
            ),
        )
    };
    let c = (client_mac, client);
    let s = (server_mac, server);
    add(
        tcp(c, s, 49_152, 80, 1_000, 0, 0x02, b""),
        None,
        "1: TCP SYN",
    );
    add(
        tcp(s, c, 80, 49_152, 9_000, 1_001, 0x12, b""),
        None,
        "1: TCP SYN-ACK",
    );
    add(
        tcp(c, s, 49_152, 80, 1_001, 9_001, 0x10, b""),
        None,
        "1: TCP ACK",
    );
    let request = b"GET /fixture HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n";
    add(
        tcp(c, s, 49_152, 80, 1_001, 9_001, 0x18, request),
        None,
        "2: HTTP/1.1 GET request",
    );
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
    add(
        tcp(
            s,
            c,
            80,
            49_152,
            9_001,
            1_001 + request.len() as u32,
            0x18,
            response,
        ),
        None,
        "2: HTTP/1.1 200 response",
    );
    add(
        tcp(
            c,
            s,
            49_152,
            80,
            1_001 + request.len() as u32,
            9_001 + response.len() as u32,
            0x11,
            b"",
        ),
        None,
        "3: client FIN-ACK",
    );
    add(
        tcp(
            s,
            c,
            80,
            49_152,
            9_001 + response.len() as u32,
            1_002 + request.len() as u32,
            0x10,
            b"",
        ),
        None,
        "3: server ACK",
    );
    add(
        tcp(
            s,
            c,
            80,
            49_152,
            9_001 + response.len() as u32,
            1_002 + request.len() as u32,
            0x11,
            b"",
        ),
        None,
        "3: server FIN-ACK",
    );
    add(
        tcp(
            c,
            s,
            49_152,
            80,
            1_002 + request.len() as u32,
            9_002 + response.len() as u32,
            0x10,
            b"",
        ),
        None,
        "3: client final ACK",
    );

    let query = dns_query();
    add(
        ethernet(
            server_mac,
            client_mac,
            0x0800,
            ipv4(
                client,
                [192, 0, 2, 53],
                17,
                0x2000,
                0x4000,
                udp_datagram(client, [192, 0, 2, 53], 53_000, 53, &query),
            ),
        ),
        None,
        "4: DNS A query",
    );
    let response = dns_response();
    add(
        ethernet(
            client_mac,
            server_mac,
            0x0800,
            ipv4(
                [192, 0, 2, 53],
                client,
                17,
                0x2001,
                0x4000,
                udp_datagram([192, 0, 2, 53], client, 53, 53_000, &response),
            ),
        ),
        None,
        "4: DNS A response",
    );
    add(
        ethernet(
            server_mac,
            client_mac,
            0x86dd,
            ipv6_udp_packet(
                [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
                65_400,
                65_401,
                b"ipv6-udp",
            ),
        ),
        None,
        "5: IPv6 UDP packet",
    );
    add(
        ethernet(
            [0xff; 6],
            client_mac,
            0x0806,
            arp_request(client_mac, client, [192, 0, 2, 1]),
        ),
        None,
        "6: ARP request",
    );

    let mut vlan = Vec::new();
    vlan.extend_from_slice(&server_mac);
    vlan.extend_from_slice(&client_mac);
    vlan.extend_from_slice(&0x8100u16.to_be_bytes());
    vlan.extend_from_slice(&100u16.to_be_bytes());
    vlan.extend_from_slice(&0x0800u16.to_be_bytes());
    vlan.extend_from_slice(&ipv4(
        client,
        server,
        17,
        0x3000,
        0x4000,
        udp_datagram(client, server, 65_402, 65_403, b"vlan"),
    ));
    add(vlan, None, "7: 802.1Q IPv4 UDP frame");

    let fragment_payload =
        udp_datagram(client, server, 65_404, 65_405, b"fragmented-payload-24byt");
    add(
        ethernet(
            server_mac,
            client_mac,
            0x0800,
            ipv4(
                client,
                server,
                17,
                0x4000,
                0x2000,
                fragment_payload[..16].to_vec(),
            ),
        ),
        None,
        "8: IPv4 fragment 1 of 2",
    );
    add(
        ethernet(
            server_mac,
            client_mac,
            0x0800,
            ipv4(
                client,
                server,
                17,
                0x4000,
                2,
                fragment_payload[16..].to_vec(),
            ),
        ),
        None,
        "8: IPv4 fragment 2 of 2",
    );

    let full = ethernet(
        server_mac,
        client_mac,
        0x0800,
        ipv4(
            client,
            server,
            17,
            0x5000,
            0x4000,
            udp_datagram(client, server, 65_406, 65_407, &[0x5a; 96]),
        ),
    );
    add(
        full[..50].to_vec(),
        Some(full.len() as u32),
        "9: snaplen-truncated IPv4 UDP packet",
    );
    let mut padded = ethernet(
        server_mac,
        client_mac,
        0x0800,
        ipv4(
            client,
            server,
            17,
            0x5001,
            0x4000,
            udp_datagram(client, server, 65_408, 65_409, b"pad!"),
        ),
    );
    padded.resize(60, 0);
    add(padded, None, "10: Ethernet-padded IPv4 UDP frame");
    add(
        ethernet(
            server_mac,
            client_mac,
            0x0800,
            ipv4(
                client,
                server,
                17,
                0x5002,
                0x4000,
                udp_datagram(client, server, 65_410, 65_411, b"time"),
            ),
        ),
        None,
        "11: timestamp moves backward by 1 microsecond",
    );
    let previous = packets[packets.len() - 2].ts_ns;
    packets.last_mut().unwrap().ts_ns = previous - 1_000;
    packets
}

fn flow_packets() -> Vec<Packet> {
    let a = [10, 0, 0, 1];
    let b = [10, 0, 0, 2];
    let a_mac = [0x02, 0, 0, 0, 1, 1];
    let b_mac = [0x02, 0, 0, 0, 1, 2];
    let base = BASE_SECONDS * 1_000_000_000;
    let mut packets = Vec::new();
    let mut add = |offset_ns: u64, data: Vec<u8>, description: &'static str| {
        packets.push(Packet {
            ts_ns: base + offset_ns,
            origlen: data.len() as u32,
            data,
            description,
        });
    };
    let tcp =
        |src: ([u8; 6], [u8; 4]), dst: ([u8; 6], [u8; 4]), sport: u16, dport: u16, flags: u8| {
            ethernet(
                dst.0,
                src.0,
                0x0800,
                ipv4(
                    src.1,
                    dst.1,
                    6,
                    sport,
                    0x4000,
                    tcp_segment(src.1, dst.1, sport, dport, 1, 1, flags, b""),
                ),
            )
        };
    let udp = |sport: u16, dport: u16, payload: &[u8]| {
        ethernet(
            b_mac,
            a_mac,
            0x0800,
            ipv4(
                a,
                b,
                17,
                sport,
                0x4000,
                udp_datagram(a, b, sport, dport, payload),
            ),
        )
    };
    let c = (a_mac, a);
    let s = (b_mac, b);

    add(0, tcp(c, s, 10_001, 80, 0x02), "flow: handshake SYN");
    add(
        1_000_000,
        tcp(s, c, 80, 10_001, 0x12),
        "flow: handshake SYN-ACK",
    );
    add(
        2_000_000,
        tcp(c, s, 10_001, 80, 0x10),
        "flow: handshake ACK",
    );
    add(3_000_000, tcp(c, s, 10_001, 80, 0x11), "flow: first FIN");
    add(
        4_000_000,
        tcp(s, c, 80, 10_001, 0x10),
        "flow: FIN acknowledgement",
    );
    add(5_000_000, tcp(s, c, 80, 10_001, 0x11), "flow: second FIN");
    add(6_000_000, tcp(c, s, 10_001, 80, 0x10), "flow: final ACK");

    add(
        10_000_000,
        tcp(c, s, 10_002, 443, 0x02),
        "flow: one-sided FIN SYN",
    );
    add(
        11_000_000,
        tcp(c, s, 10_002, 443, 0x11),
        "flow: one-sided FIN",
    );
    add(
        12_000_000,
        tcp(s, c, 443, 10_002, 0x10),
        "flow: ACK after one-sided FIN",
    );

    add(20_000_000, tcp(c, s, 10_003, 22, 0x02), "flow: reset SYN");
    add(
        21_000_000,
        tcp(s, c, 22, 10_003, 0x14),
        "flow: reset RST-ACK",
    );

    add(
        30_000_000,
        tcp(c, s, 10_004, 25, 0x02),
        "flow: timeout first packet",
    );
    add(
        120_030_001_000,
        tcp(s, c, 25, 10_004, 0x10),
        "flow: packet beyond 120 second timeout",
    );

    add(
        120_040_000_000,
        udp(20_001, 53, b"active-a"),
        "flow: activity interval start",
    );
    add(
        126_040_000_000,
        udp(20_001, 53, b"active-b"),
        "flow: activity gap exceeds five seconds",
    );
    add(
        126_050_000_000,
        udp(20_002, 123, b"udp"),
        "flow: UDP singleton",
    );

    add(
        126_060_000_000,
        ethernet(
            b_mac,
            a_mac,
            0x0800,
            ipv4(a, b, 1, 0x7001, 0x4000, icmp_echo(8, 7)),
        ),
        "flow: ICMP echo request",
    );
    add(
        126_061_000_000,
        ethernet(
            a_mac,
            b_mac,
            0x0800,
            ipv4(b, a, 1, 0x7002, 0x4000, icmp_echo(0, 7)),
        ),
        "flow: ICMP echo reply",
    );
    add(
        126_070_000_000,
        tcp(c, s, 10_005, 8080, 0x02),
        "flow: TCP singleton",
    );

    add(
        126_080_000_000,
        udp(20_003, 9, b"later"),
        "flow: timestamp regression anchor",
    );
    add(
        126_079_999_123,
        udp(20_003, 9, b"earlier"),
        "flow: timestamp moves backward",
    );
    packets
}

#[derive(Deserialize)]
struct ReassemblyIpVectors {
    ipv4_fragments: Vec<ReassemblyFragment>,
    ipv6_fragments: Vec<ReassemblyFragment>,
}

#[derive(Deserialize)]
struct ReassemblyFragment {
    offset: usize,
    more_fragments: bool,
    fill: char,
    len: usize,
}

#[derive(Deserialize)]
struct ReassemblyTcpVectors {
    cases: Vec<ReassemblyTcpCase>,
}

#[derive(Deserialize)]
struct ReassemblyTcpCase {
    steps: Vec<ReassemblyTcpStep>,
}

#[derive(Deserialize)]
struct ReassemblyTcpStep {
    rel_seq: u32,
    data: String,
}

fn reassembly_packets() -> Vec<Packet> {
    let ip_vectors: ReassemblyIpVectors = serde_json::from_str(include_str!(
        "../../../tests/fixtures/reassembly/sturges_novak_ip.json"
    ))
    .expect("committed IP reassembly vectors");
    let tcp_vectors: ReassemblyTcpVectors = serde_json::from_str(include_str!(
        "../../../tests/fixtures/reassembly/sturges_novak_tcp.json"
    ))
    .expect("committed TCP reassembly vectors");
    let client = [10, 10, 0, 1];
    let server = [10, 10, 0, 2];
    let client_mac = [0x02, 0, 0, 0, 2, 1];
    let server_mac = [0x02, 0, 0, 0, 2, 2];
    let base = BASE_SECONDS * 1_000_000_000 + 200_000_000_000;
    let mut packets = Vec::new();
    let mut add = |data: Vec<u8>, description: &'static str| {
        let ts_ns = base + packets.len() as u64 * 1_000;
        packets.push(Packet {
            ts_ns,
            origlen: data.len() as u32,
            data,
            description,
        });
    };

    for fragment in &ip_vectors.ipv4_fragments {
        let payload = vec![fragment.fill as u8; fragment.len];
        let field = u16::try_from(fragment.offset / 8).unwrap()
            | if fragment.more_fragments { 0x2000 } else { 0 };
        add(
            ethernet(
                server_mac,
                client_mac,
                0x0800,
                ipv4(client, server, 1, 0x9000, field, payload),
            ),
            "reassembly: Sturges-Novak IPv4 fragment",
        );
    }
    let src6 = [0x20, 1, 0xdb, 8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst6 = [0x20, 1, 0xdb, 8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    for fragment in &ip_vectors.ipv6_fragments {
        let payload = vec![fragment.fill as u8; fragment.len];
        add(
            ethernet(
                server_mac,
                client_mac,
                0x86dd,
                ipv6_fragment(
                    src6,
                    dst6,
                    58,
                    0x9000_0001,
                    fragment.offset,
                    fragment.more_fragments,
                    &payload,
                    false,
                ),
            ),
            "reassembly: Sturges-Novak IPv6 fragment",
        );
    }

    for (case_index, case) in tcp_vectors.cases.iter().enumerate() {
        let sport = 20_000 + case_index as u16;
        let client_isn = if case_index % 3 == 2 {
            u32::MAX
        } else {
            1_000 + case_index as u32 * 100
        };
        let server_isn = 50_000 + case_index as u32 * 100;
        for (
            src,
            dst,
            src_mac,
            dst_mac,
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            payload,
            description,
        ) in [
            (
                client,
                server,
                client_mac,
                server_mac,
                sport,
                80,
                client_isn,
                0,
                0x02,
                &b""[..],
                "reassembly: TCP overlap SYN",
            ),
            (
                server,
                client,
                server_mac,
                client_mac,
                80,
                sport,
                server_isn,
                client_isn.wrapping_add(1),
                0x12,
                &b""[..],
                "reassembly: TCP overlap SYN-ACK",
            ),
            (
                client,
                server,
                client_mac,
                server_mac,
                sport,
                80,
                client_isn.wrapping_add(1),
                server_isn.wrapping_add(1),
                0x10,
                &b""[..],
                "reassembly: TCP overlap ACK",
            ),
        ] {
            add(
                ethernet(
                    dst_mac,
                    src_mac,
                    0x0800,
                    ipv4(
                        src,
                        dst,
                        6,
                        sport,
                        0x4000,
                        tcp_segment(src, dst, src_port, dst_port, seq, ack, flags, payload),
                    ),
                ),
                description,
            );
        }
        for step in &case.steps {
            add(
                ethernet(
                    server_mac,
                    client_mac,
                    0x0800,
                    ipv4(
                        client,
                        server,
                        6,
                        sport,
                        0x4000,
                        tcp_segment(
                            client,
                            server,
                            sport,
                            80,
                            client_isn.wrapping_add(step.rel_seq),
                            server_isn.wrapping_add(1),
                            0x18,
                            step.data.as_bytes(),
                        ),
                    ),
                ),
                "reassembly: TCP overlap vector step",
            );
        }
    }

    for (payload, offset, more, description) in [
        (
            vec![0x8f, 0x97, 0x99, b'x', b'x', b'x', b'x', b'x'],
            0,
            true,
            "reassembly: ptacek1998 IPv4 first",
        ),
        (
            vec![b'p', b'h', b'f', b'y', b'y', b'y', b'y', b'y'],
            0,
            true,
            "reassembly: ptacek1998 IPv4 conflicting",
        ),
        (vec![b'!'; 8], 8, false, "reassembly: ptacek1998 IPv4 final"),
    ] {
        let field = u16::try_from(offset / 8).unwrap() | if more { 0x2000 } else { 0 };
        add(
            ethernet(
                server_mac,
                client_mac,
                0x0800,
                ipv4(client, server, 1, 0x9001, field, payload),
            ),
            description,
        );
    }

    let midstream = tcp_segment(client, server, 30_001, 8080, 700, 0, 0x18, b"midstream");
    add(
        ethernet(
            server_mac,
            client_mac,
            0x0800,
            ipv4(client, server, 6, 0x9100, 0x4000, midstream),
        ),
        "reassembly: midstream TCP",
    );
    for (seq, payload, description) in [
        (
            u32::MAX,
            b"W".as_slice(),
            "reassembly: wrap byte before zero",
        ),
        (1, b"Z".as_slice(), "reassembly: reordered byte after zero"),
        (0, b"0".as_slice(), "reassembly: wrap byte at zero"),
        (0, b"0".as_slice(), "reassembly: identical retransmission"),
    ] {
        add(
            ethernet(
                server_mac,
                client_mac,
                0x0800,
                ipv4(
                    client,
                    server,
                    6,
                    0x9101,
                    0x4000,
                    tcp_segment(client, server, 30_002, 8081, seq, 0, 0x18, payload),
                ),
            ),
            description,
        );
    }
    add(
        ethernet(
            server_mac,
            client_mac,
            0x0800,
            ipv4(
                client,
                server,
                6,
                0x9102,
                0x4000,
                tcp_segment(client, server, 30_003, 8082, 10, 0, 0x18, b"gap"),
            ),
        ),
        "reassembly: capture-end gap",
    );
    add(
        ethernet(
            server_mac,
            client_mac,
            0x0800,
            ipv4(
                client,
                server,
                6,
                0x9103,
                0x4000,
                tcp_segment(client, server, 30_004, 8083, 10, 0, 0x04, b""),
            ),
        ),
        "reassembly: in-window RST",
    );
    add(
        ethernet(
            server_mac,
            client_mac,
            0x0800,
            ipv4(
                client,
                server,
                6,
                0x9104,
                0x4000,
                tcp_segment(client, server, 30_005, 8084, 1_000_000, 0, 0x04, b""),
            ),
        ),
        "reassembly: out-of-window RST",
    );

    add(
        ethernet(
            server_mac,
            client_mac,
            0x86dd,
            ipv6_fragment(src6, dst6, 58, 0x9000_0002, 0, true, &[3; 16], true),
        ),
        "reassembly: IPv6 extension fragment first",
    );
    add(
        ethernet(
            server_mac,
            client_mac,
            0x86dd,
            ipv6_fragment(src6, dst6, 58, 0x9000_0002, 16, false, &[4; 8], true),
        ),
        "reassembly: IPv6 extension fragment final",
    );

    let fragmented_tcp = tcp_segment(
        client,
        server,
        30_006,
        8085,
        100,
        0,
        0x18,
        b"fragmented-tcp",
    );
    add(
        ethernet(
            server_mac,
            client_mac,
            0x0800,
            ipv4(
                client,
                server,
                6,
                0x9200,
                0x2000,
                fragmented_tcp[..24].to_vec(),
            ),
        ),
        "reassembly: fragmented TCP first",
    );
    add(
        ethernet(
            server_mac,
            client_mac,
            0x0800,
            ipv4(client, server, 6, 0x9200, 3, fragmented_tcp[24..].to_vec()),
        ),
        "reassembly: fragmented TCP final",
    );

    let mut add_tcp = |src: [u8; 4],
                       dst: [u8; 4],
                       src_mac: [u8; 6],
                       dst_mac: [u8; 6],
                       src_port: u16,
                       dst_port: u16,
                       seq: u32,
                       ack: u32,
                       flags: u8,
                       payload: &[u8],
                       description: &'static str| {
        add(
            ethernet(
                dst_mac,
                src_mac,
                0x0800,
                ipv4(
                    src,
                    dst,
                    6,
                    src_port,
                    0x4000,
                    tcp_segment(src, dst, src_port, dst_port, seq, ack, flags, payload),
                ),
            ),
            description,
        );
    };

    type AddTcp<'a> = dyn FnMut([u8; 4], [u8; 4], [u8; 6], [u8; 6], u16, u16, u32, u32, u8, &[u8], &'static str)
        + 'a;
    let handshake = |add_tcp: &mut AddTcp<'_>, sport: u16, client_isn: u32, server_isn: u32| {
        add_tcp(
            client,
            server,
            client_mac,
            server_mac,
            sport,
            80,
            client_isn,
            0,
            0x02,
            b"",
            "reassembly: lifecycle SYN",
        );
        add_tcp(
            server,
            client,
            server_mac,
            client_mac,
            80,
            sport,
            server_isn,
            client_isn.wrapping_add(1),
            0x12,
            b"",
            "reassembly: lifecycle SYN-ACK",
        );
        add_tcp(
            client,
            server,
            client_mac,
            server_mac,
            sport,
            80,
            client_isn.wrapping_add(1),
            server_isn.wrapping_add(1),
            0x10,
            b"",
            "reassembly: lifecycle ACK",
        );
    };

    handshake(&mut add_tcp, 31_000, 100, 500);
    add_tcp(
        client,
        server,
        client_mac,
        server_mac,
        31_000,
        80,
        101,
        501,
        0x14,
        b"",
        "reassembly: accepted RST before post-close data",
    );
    add_tcp(
        server,
        client,
        server_mac,
        client_mac,
        80,
        31_000,
        501,
        101,
        0x18,
        b"late",
        "reassembly: data after RST close",
    );

    handshake(&mut add_tcp, 31_001, 200, 600);
    for (src, dst, src_mac, dst_mac, sport, dport, seq, ack, flags, description) in [
        (
            client,
            server,
            client_mac,
            server_mac,
            31_001,
            80,
            201,
            601,
            0x11,
            "reassembly: client FIN",
        ),
        (
            server,
            client,
            server_mac,
            client_mac,
            80,
            31_001,
            601,
            202,
            0x10,
            "reassembly: client FIN ACK",
        ),
        (
            server,
            client,
            server_mac,
            client_mac,
            80,
            31_001,
            601,
            202,
            0x11,
            "reassembly: server FIN",
        ),
        (
            client,
            server,
            client_mac,
            server_mac,
            31_001,
            80,
            202,
            602,
            0x10,
            "reassembly: server FIN ACK",
        ),
    ] {
        add_tcp(
            src,
            dst,
            src_mac,
            dst_mac,
            sport,
            dport,
            seq,
            ack,
            flags,
            b"",
            description,
        );
    }
    add_tcp(
        server,
        client,
        server_mac,
        client_mac,
        80,
        31_001,
        602,
        202,
        0x18,
        b"f",
        "reassembly: data after completed FIN close",
    );

    handshake(&mut add_tcp, 31_002, 300, 700);
    add_tcp(
        client,
        server,
        client_mac,
        server_mac,
        31_002,
        80,
        301,
        701,
        0x14,
        b"",
        "reassembly: RST before closing timeout",
    );

    handshake(&mut add_tcp, 31_003, 400, 800);
    add_tcp(
        client,
        server,
        client_mac,
        server_mac,
        31_003,
        80,
        401,
        801,
        0x14,
        b"",
        "reassembly: RST before replacement SYN",
    );
    add_tcp(
        client,
        server,
        client_mac,
        server_mac,
        31_003,
        80,
        900,
        0,
        0x02,
        b"",
        "reassembly: replacement SYN before closing timeout",
    );

    handshake(&mut add_tcp, 31_004, 1_000, 2_000);
    for (seq, flags, payload, description) in [
        (
            1_001,
            0x18,
            b"abc".as_slice(),
            "reassembly: keepalive base data",
        ),
        (
            1_003,
            0x10,
            b"x".as_slice(),
            "reassembly: one-byte keepalive",
        ),
        (1_003, 0x10, b"".as_slice(), "reassembly: empty keepalive"),
        (
            1_004,
            0x18,
            b"z".as_slice(),
            "reassembly: ordinary one-byte data after keepalives",
        ),
    ] {
        add_tcp(
            client,
            server,
            client_mac,
            server_mac,
            31_004,
            80,
            seq,
            2_001,
            flags,
            payload,
            description,
        );
    }

    add_tcp(
        server,
        client,
        server_mac,
        client_mac,
        80,
        31_002,
        900,
        0,
        0x18,
        b"new",
        "reassembly: midstream data after closing timeout",
    );
    drop(add_tcp);
    drop(add);
    let last = packets.len() - 1;
    packets[last].ts_ns = packets[last - 1].ts_ns + 61_000_000_000;
    packets
}

fn app_packets() -> Vec<Packet> {
    let client = [10, 20, 0, 1];
    let server = [10, 20, 0, 2];
    let client_mac = [0x02, 0, 0, 0, 3, 1];
    let server_mac = [0x02, 0, 0, 0, 3, 2];
    let base = BASE_SECONDS * 1_000_000_000 + 400_000_000_000;
    let mut packets = Vec::new();
    let mut tcp = |c2s: bool,
                   client_port: u16,
                   server_port: u16,
                   seq: u32,
                   payload: &[u8],
                   description: &'static str| {
        let (src_ip, dst_ip, src_mac, dst_mac, src_port, dst_port) = if c2s {
            (
                client,
                server,
                client_mac,
                server_mac,
                client_port,
                server_port,
            )
        } else {
            (
                server,
                client,
                server_mac,
                client_mac,
                server_port,
                client_port,
            )
        };
        let data = ethernet(
            dst_mac,
            src_mac,
            0x0800,
            ipv4(
                src_ip,
                dst_ip,
                6,
                client_port,
                0x4000,
                tcp_segment(src_ip, dst_ip, src_port, dst_port, seq, 0, 0x18, payload),
            ),
        );
        packets.push(Packet {
            ts_ns: base + packets.len() as u64 * 1_000_000,
            origlen: data.len() as u32,
            data,
            description,
        });
    };

    let http_request = b"HEAD /head HTTP/1.1\r\nHost: nonstandard.test\r\nUser-Agent: fixture\r\n\r\nGET /cached HTTP/1.1\r\nHost: nonstandard.test\r\n\r\nPOST /chunk HTTP/1.1\r\nHost: nonstandard.test\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";
    tcp(
        true,
        40_000,
        18_080,
        1_000,
        http_request,
        "app: pipelined HTTP requests on nonstandard port",
    );
    tcp(false, 40_000, 18_080, 9_000, b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nHTTP/1.1 304 Not Modified\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nOK\r\n0\r\n\r\n", "app: HEAD, 304, and chunked HTTP responses");

    tcp(
        true,
        40_008,
        18_081,
        1_000,
        b"\0POST /after-keepalive HTTP/1.1\r\nHost: resync.test\r\nContent-Length: 0\r\n\r\n",
        "app: HTTP request after a leading keepalive byte",
    );

    let body_chunk = vec![b'x'; 16_384];
    for part in 0..4 {
        tcp(
            false,
            40_009,
            18_082,
            20_000 + part * body_chunk.len() as u32,
            &body_chunk,
            "app: midstream HTTP response body reaches one-direction probe limit",
        );
    }
    tcp(
        true,
        40_009,
        18_082,
        1_000,
        b"GET /after-body HTTP/1.1\r\nHost: later.test\r\n\r\n",
        "app: HTTP request identifies flow after opposite probe limit",
    );

    let hello = fixture_client_hello();
    let split = 17;
    tcp(
        true,
        40_001,
        444,
        2_000,
        &hello[..split],
        "app: split TLS ClientHello first packet",
    );
    tcp(
        true,
        40_001,
        444,
        2_000 + split as u32,
        &hello[split..],
        "app: split TLS ClientHello second packet",
    );
    let mut heartbeats = vec![24, 3, 2, 0, 8, 1, 0, 10, b'a', b'b', b'c', b'd', b'e'];
    heartbeats.extend_from_slice(&[24, 3, 2, 0, 19, 2, 0, 0]);
    heartbeats.extend_from_slice(&[0; 16]);
    tcp(
        true,
        40_001,
        444,
        2_000 + hello.len() as u32,
        &heartbeats,
        "app: two TLS Heartbeat records in one packet",
    );

    let server_hello = fixture_server_hello_without_extensions();
    tcp(
        false,
        40_010,
        445,
        30_000,
        &server_hello,
        "app: TLS ServerHello without extensions",
    );
    let malformed_hello = [22, 3, 1, 0, 8, 2, 0, 0, 4, 3, 1, 0, 0];
    tcp(
        false,
        40_010,
        445,
        30_000 + server_hello.len() as u32,
        &malformed_hello,
        "app: malformed TLS ServerHello remains visible",
    );

    tcp(
        true,
        40_002,
        21,
        4_000,
        b"USER alice\r\nPASS secret\r\n",
        "app: FTP login commands",
    );
    tcp(
        false,
        40_002,
        21,
        3_000,
        b"220-first line\r\nsecond line\r\n220 ready\r\n",
        "app: FTP multiline response",
    );
    tcp(
        false,
        40_002,
        21,
        3_040,
        b"230 logged in\r\n",
        "app: FTP successful login",
    );

    let mut ssh = b"SSH-2.0-OpenSSH_9.9 fixture\r\n".to_vec();
    ssh.extend_from_slice(&fixture_ssh_kexinit());
    tcp(
        true,
        40_003,
        22,
        5_000,
        &ssh,
        "app: SSH identification and KEXINIT",
    );

    tcp(true, 40_004, 25, 7_000, b"EHLO fixture\r\nMAIL FROM:<a@example.test>\r\nRCPT TO:<b@example.test>\r\nDATA\r\nhello\r\n..dot\r\n.\r\nQUIT\r\n", "app: SMTP commands and DATA");
    tcp(
        false,
        40_004,
        25,
        6_000,
        b"220 mail.fixture ESMTP\r\n",
        "app: SMTP greeting",
    );

    for (seq, byte) in (8_000..).zip(b"login\r\n") {
        tcp(
            true,
            40_005,
            23,
            seq,
            &[*byte],
            "app: Telnet character-at-a-time input",
        );
    }
    tcp(
        false,
        40_005,
        23,
        9_000,
        &[255, 251, 1],
        "app: Telnet IAC WILL negotiation",
    );

    let dns = dns_response();
    let query_tcp = dns_query();
    let mut tcp_query = Vec::new();
    tcp_query.extend_from_slice(&(query_tcp.len() as u16).to_be_bytes());
    tcp_query.extend_from_slice(&query_tcp);
    tcp(
        true,
        40_006,
        53,
        1_000,
        &tcp_query,
        "app: length-prefixed TCP DNS query",
    );
    let mut tcp_dns = Vec::new();
    tcp_dns.extend_from_slice(&(dns.len() as u16).to_be_bytes());
    tcp_dns.extend_from_slice(&dns);
    tcp(
        false,
        40_006,
        53,
        10_000,
        &tcp_dns,
        "app: length-prefixed TCP DNS response",
    );
    tcp(
        true,
        40_007,
        21,
        11_000,
        b"USER before-gap\r\n",
        "app: FTP before TCP gap",
    );
    tcp(
        true,
        40_007,
        21,
        11_030,
        b"discarded-tail\r\nUSER after-gap\r\n",
        "app: FTP resumes after TCP gap",
    );
    drop(tcp);

    let udp = udp_datagram(server, client, 53, 53_000, &dns);
    let data = ethernet(
        client_mac,
        server_mac,
        0x0800,
        ipv4(server, client, 17, 0x9000, 0x4000, udp),
    );
    packets.push(Packet {
        ts_ns: base + packets.len() as u64 * 1_000_000,
        origlen: data.len() as u32,
        data,
        description: "app: compressed UDP DNS response",
    });
    let mut loop_dns = vec![
        0x44, 0x44, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1,
    ];
    let udp = udp_datagram(client, server, 53_001, 53, &loop_dns);
    let data = ethernet(
        server_mac,
        client_mac,
        0x0800,
        ipv4(client, server, 17, 0x9001, 0x4000, udp),
    );
    packets.push(Packet {
        ts_ns: base + packets.len() as u64 * 1_000_000,
        origlen: data.len() as u32,
        data,
        description: "app: DNS compression pointer loop",
    });

    let query = dns_query();
    let fragmented = udp_datagram(client, server, 53_002, 53, &query);
    let first = ethernet(
        server_mac,
        client_mac,
        0x0800,
        ipv4(
            client,
            server,
            17,
            0x9002,
            0x2000,
            fragmented[..24].to_vec(),
        ),
    );
    let second = ethernet(
        server_mac,
        client_mac,
        0x0800,
        ipv4(client, server, 17, 0x9002, 3, fragmented[24..].to_vec()),
    );
    for (data, description) in [
        (first, "app: fragmented UDP DNS first"),
        (second, "app: fragmented UDP DNS final"),
    ] {
        packets.push(Packet {
            ts_ns: base + packets.len() as u64 * 1_000_000,
            origlen: data.len() as u32,
            data,
            description,
        });
    }

    loop_dns.clear();
    packets
}

fn fixture_client_hello() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0x11; 32]);
    body.push(0);
    body.extend_from_slice(&6u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01, 0x13, 0x02, 0xc0, 0x2f]);
    body.push(1);
    body.push(0);
    let mut ext = Vec::new();
    let host = b"fixture.test";
    let mut sni = Vec::new();
    sni.extend_from_slice(&((host.len() + 3) as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni.extend_from_slice(host);
    push_tls_extension(&mut ext, 0, &sni);
    push_tls_extension(&mut ext, 43, &[4, 3, 4, 3, 3]);
    push_tls_extension(&mut ext, 16, &[0, 3, 2, b'h', b'2']);
    push_tls_extension(&mut ext, 10, &[0, 4, 0, 29, 0, 23]);
    push_tls_extension(&mut ext, 11, &[1, 0]);
    push_tls_extension(&mut ext, 13, &[0, 4, 4, 3, 8, 4]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut handshake = vec![
        1,
        ((body.len() >> 16) & 0xff) as u8,
        ((body.len() >> 8) & 0xff) as u8,
        (body.len() & 0xff) as u8,
    ];
    handshake.extend_from_slice(&body);
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

fn fixture_server_hello_without_extensions() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0301u16.to_be_bytes());
    body.extend_from_slice(&[0x11; 32]);
    body.push(32);
    body.extend_from_slice(&[0x22; 32]);
    body.extend_from_slice(&0x002fu16.to_be_bytes());
    body.push(0);

    let mut handshake = vec![2];
    handshake.extend_from_slice(&[
        ((body.len() >> 16) & 0xff) as u8,
        ((body.len() >> 8) & 0xff) as u8,
        (body.len() & 0xff) as u8,
    ]);
    handshake.extend_from_slice(&body);

    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}
fn push_tls_extension(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}
fn fixture_ssh_kexinit() -> Vec<u8> {
    let mut payload = vec![20];
    payload.extend_from_slice(&[0; 16]);
    for value in [
        "curve25519-sha256",
        "ssh-ed25519",
        "aes128-ctr",
        "aes128-ctr",
        "hmac-sha2-256",
        "hmac-sha2-256",
        "none",
        "none",
        "",
        "",
    ] {
        payload.extend_from_slice(&(value.len() as u32).to_be_bytes());
        payload.extend_from_slice(value.as_bytes());
    }
    payload.push(0);
    payload.extend_from_slice(&0u32.to_be_bytes());
    let padding = 8 - ((payload.len() + 5) % 8);
    let packet_len = payload.len() + padding + 1;
    let mut packet = Vec::new();
    packet.extend_from_slice(&(packet_len as u32).to_be_bytes());
    packet.push(padding as u8);
    packet.extend_from_slice(&payload);
    packet.resize(packet.len() + padding, 0);
    packet
}

#[allow(clippy::too_many_arguments)]
fn ipv6_fragment(
    src: [u8; 16],
    dst: [u8; 16],
    upper: u8,
    identification: u32,
    offset: usize,
    more: bool,
    payload: &[u8],
    extension_before_fragment: bool,
) -> Vec<u8> {
    let extension_len = usize::from(extension_before_fragment) * 8;
    let mut packet = Vec::with_capacity(48 + extension_len + payload.len());
    packet.extend_from_slice(&0x6000_0000u32.to_be_bytes());
    packet.extend_from_slice(
        &u16::try_from(extension_len + 8 + payload.len())
            .unwrap()
            .to_be_bytes(),
    );
    packet.push(if extension_before_fragment { 0 } else { 44 });
    packet.push(64);
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    if extension_before_fragment {
        packet.extend_from_slice(&[44, 0, 0, 0, 0, 0, 0, 0]);
    }
    packet.push(upper);
    packet.push(0);
    let field = u16::try_from(offset).unwrap() | u16::from(more);
    packet.extend_from_slice(&field.to_be_bytes());
    packet.extend_from_slice(&identification.to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn icmp_echo(icmp_type: u8, identifier: u16) -> Vec<u8> {
    let mut message = vec![icmp_type, 0, 0, 0];
    message.extend_from_slice(&identifier.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(b"flow");
    let checksum = internet_checksum(&message);
    message[2..4].copy_from_slice(&checksum.to_be_bytes());
    message
}

fn raw_packets(ethernet_packets: &[Packet]) -> Vec<Packet> {
    [9usize, 10, 14]
        .into_iter()
        .enumerate()
        .map(|(raw_index, index)| {
            let source = &ethernet_packets[index];
            Packet {
                ts_ns: BASE_SECONDS * 1_000_000_000
                    + 30_000_000
                    + raw_index as u64 * 1_000_000
                    + 123
                    + raw_index as u64,
                data: source.data[14..].to_vec(),
                origlen: source.origlen - 14,
                description: source.description,
            }
        })
        .collect()
}

fn ethernet(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: Vec<u8>) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&dst);
    frame.extend_from_slice(&src);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(&payload);
    frame
}

fn ipv4(
    src: [u8; 4],
    dst: [u8; 4],
    protocol: u8,
    identification: u16,
    flags_fragment: u16,
    payload: Vec<u8>,
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(20 + payload.len());
    packet.push(0x45);
    packet.push(0);
    packet.extend_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    packet.extend_from_slice(&identification.to_be_bytes());
    packet.extend_from_slice(&flags_fragment.to_be_bytes());
    packet.push(64);
    packet.push(protocol);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    let checksum = internet_checksum(&packet);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet.extend_from_slice(&payload);
    packet
}

#[allow(clippy::too_many_arguments)]
fn tcp_segment(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut segment = Vec::with_capacity(20 + payload.len());
    segment.extend_from_slice(&src_port.to_be_bytes());
    segment.extend_from_slice(&dst_port.to_be_bytes());
    segment.extend_from_slice(&sequence.to_be_bytes());
    segment.extend_from_slice(&acknowledgement.to_be_bytes());
    segment.push(5 << 4);
    segment.push(flags);
    segment.extend_from_slice(&64_240u16.to_be_bytes());
    segment.extend_from_slice(&[0, 0, 0, 0]);
    segment.extend_from_slice(payload);
    let checksum = ipv4_transport_checksum(src_ip, dst_ip, 6, &segment);
    segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    segment
}

fn udp_datagram(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut datagram = Vec::with_capacity(8 + payload.len());
    datagram.extend_from_slice(&src_port.to_be_bytes());
    datagram.extend_from_slice(&dst_port.to_be_bytes());
    datagram.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    datagram.extend_from_slice(&[0, 0]);
    datagram.extend_from_slice(payload);
    let _ = (src_ip, dst_ip);
    datagram
}

fn ipv4_transport_checksum(src: [u8; 4], dst: [u8; 4], protocol: u8, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + segment.len());
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.push(0);
    pseudo.push(protocol);
    pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(segment);
    internet_checksum(&pseudo)
}

fn ipv6_udp_packet(
    src: [u8; 16],
    dst: [u8; 16],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut udp = Vec::with_capacity(8 + payload.len());
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.extend_from_slice(&(udp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    pseudo.extend_from_slice(&udp);
    let checksum = internet_checksum(&pseudo);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());
    let mut packet = Vec::with_capacity(40 + udp.len());
    packet.extend_from_slice(&0x6000_0000u32.to_be_bytes());
    packet.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    packet.push(17);
    packet.push(64);
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    packet.extend_from_slice(&udp);
    packet
}

fn arp_request(src_mac: [u8; 6], src_ip: [u8; 4], target_ip: [u8; 4]) -> Vec<u8> {
    let mut arp = Vec::with_capacity(28);
    arp.extend_from_slice(&1u16.to_be_bytes());
    arp.extend_from_slice(&0x0800u16.to_be_bytes());
    arp.extend_from_slice(&[6, 4]);
    arp.extend_from_slice(&1u16.to_be_bytes());
    arp.extend_from_slice(&src_mac);
    arp.extend_from_slice(&src_ip);
    arp.extend_from_slice(&[0; 6]);
    arp.extend_from_slice(&target_ip);
    arp
}

fn dns_query() -> Vec<u8> {
    let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    dns.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 4, b't', b'e', b's', b't', 0,
    ]);
    dns.extend_from_slice(&1u16.to_be_bytes());
    dns.extend_from_slice(&1u16.to_be_bytes());
    dns
}

fn dns_response() -> Vec<u8> {
    let mut dns = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    dns.extend_from_slice(&[
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 4, b't', b'e', b's', b't', 0,
    ]);
    dns.extend_from_slice(&1u16.to_be_bytes());
    dns.extend_from_slice(&1u16.to_be_bytes());
    dns.extend_from_slice(&0xc00cu16.to_be_bytes());
    dns.extend_from_slice(&1u16.to_be_bytes());
    dns.extend_from_slice(&1u16.to_be_bytes());
    dns.extend_from_slice(&300u32.to_be_bytes());
    dns.extend_from_slice(&4u16.to_be_bytes());
    dns.extend_from_slice(&[203, 0, 113, 7]);
    dns
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(word);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

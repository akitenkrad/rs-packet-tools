use std::{
    fs::File,
    io::{BufReader, Read},
    time::Instant,
};

use ahash::AHashMap;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use packet_tools_capture::Capture;
use packet_tools_dissect::{DecodeDepth, Ipv4View, TcpView, UdpView, decode};
use pcap_file::{
    pcap::PcapReader,
    pcapng::{Block, PcapNgReader},
};

type K = u128;

#[derive(Clone, Copy)]
enum Engine {
    Etherparse,
    PacketTools,
}

struct Args {
    engine: Engine,
    json: bool,
    path: String,
}

fn main() {
    let args = parse_args();
    let started = Instant::now();
    let bytes = File::open(&args.path).unwrap().metadata().unwrap().len();
    let (packets, errors, flows) = match args.engine {
        Engine::Etherparse => run_etherparse(&args.path),
        Engine::PacketTools => run_packet_tools(&args.path),
    };
    let elapsed = started.elapsed().as_secs_f64();
    let pkt_per_sec = packets as f64 / elapsed;
    if args.json {
        println!(
            "{{\"packets\":{packets},\"elapsed_secs\":{elapsed},\"pkt_per_sec\":{pkt_per_sec},\"flows\":{},\"errors\":{errors}}}",
            flows.len()
        );
    } else {
        println!(
            "{}: {packets} pkts {elapsed:.1}s {:.2}M pkt/s {:.0} MB/s(file) flows={} errs={errors}",
            args.path,
            pkt_per_sec / 1e6,
            bytes as f64 / elapsed / 1e6,
            flows.len()
        );
    }
}

fn parse_args() -> Args {
    let mut engine = Engine::Etherparse;
    let mut json = false;
    let mut path = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--engine" => {
                engine = match args.next().as_deref() {
                    Some("etherparse") => Engine::Etherparse,
                    Some("packet-tools") => Engine::PacketTools,
                    _ => panic!("--engine must be etherparse or packet-tools"),
                };
            }
            "--json" => json = true,
            _ if path.is_none() => path = Some(arg),
            _ => panic!("unexpected argument: {arg}"),
        }
    }
    Args {
        engine,
        json,
        path: path.expect("usage: rsbench [--engine etherparse|packet-tools] [--json] INPUT"),
    }
}

fn run_packet_tools(path: &str) -> (u64, u64, AHashMap<K, u64>) {
    let mut capture = Capture::open(path).unwrap();
    let mut packets = 0;
    let mut errors = 0;
    let mut flows = AHashMap::new();
    while let Some(record) = capture.next_record() {
        let record = match record {
            Ok(record) => record,
            Err(_) => {
                errors += 1;
                break;
            }
        };
        packets += 1;
        let packet = decode(record.data, record.linktype, DecodeDepth::L4);
        if let Some(ip) = packet.layer::<Ipv4View>() {
            let protocol = ip.protocol();
            let (source_port, destination_port) = match protocol {
                6 => packet
                    .layer::<TcpView>()
                    .map_or((0, 0), |tcp| (tcp.src_port(), tcp.dst_port())),
                17 => packet
                    .layer::<UdpView>()
                    .map_or((0, 0), |udp| (udp.src_port(), udp.dst_port())),
                _ => (0, 0),
            };
            *flows
                .entry(flow_key(
                    ip.src().octets(),
                    ip.dst().octets(),
                    protocol,
                    source_port,
                    destination_port,
                ))
                .or_default() += u64::from(record.caplen);
        }
    }
    (packets, errors, flows)
}

fn run_etherparse(path: &str) -> (u64, u64, AHashMap<K, u64>) {
    let file = File::open(path).unwrap();
    let reader: Box<dyn Read> = if path.ends_with(".gz") {
        Box::new(flate2::read::MultiGzDecoder::new(BufReader::with_capacity(
            1 << 20,
            file,
        )))
    } else {
        Box::new(file)
    };
    let mut reader = BufReader::with_capacity(1 << 22, reader);
    let mut magic = [0u8; 4];
    {
        use std::io::BufRead;
        let bytes = reader.fill_buf().unwrap();
        magic.copy_from_slice(&bytes[..4]);
    }
    let (mut packets, mut errors) = (0, 0);
    let mut flows = AHashMap::new();
    if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
        let mut capture = PcapNgReader::new(reader).unwrap();
        while let Some(block) = capture.next_block() {
            match block {
                Ok(Block::EnhancedPacket(packet)) => {
                    packets += 1;
                    tally_etherparse(&packet.data, &mut flows, &mut errors);
                }
                Ok(_) => {}
                Err(_) => {
                    errors += 1;
                    break;
                }
            }
        }
    } else {
        let mut capture = PcapReader::new(reader).unwrap();
        while let Some(packet) = capture.next_packet() {
            let packet = match packet {
                Ok(packet) => packet,
                Err(_) => {
                    errors += 1;
                    break;
                }
            };
            packets += 1;
            tally_etherparse(&packet.data, &mut flows, &mut errors);
        }
    }
    (packets, errors, flows)
}

fn tally_etherparse(data: &[u8], flows: &mut AHashMap<K, u64>, errors: &mut u64) {
    match SlicedPacket::from_ethernet(data) {
        Ok(packet) => {
            if let Some(NetSlice::Ipv4(ip)) = packet.net {
                let header = ip.header();
                let (source_port, destination_port) = match packet.transport {
                    Some(TransportSlice::Tcp(tcp)) => (tcp.source_port(), tcp.destination_port()),
                    Some(TransportSlice::Udp(udp)) => (udp.source_port(), udp.destination_port()),
                    _ => (0, 0),
                };
                *flows
                    .entry(flow_key(
                        header.source(),
                        header.destination(),
                        header.protocol().0,
                        source_port,
                        destination_port,
                    ))
                    .or_default() += data.len() as u64;
            }
        }
        Err(_) => *errors += 1,
    }
}

#[inline(always)]
fn flow_key(source: [u8; 4], destination: [u8; 4], protocol: u8, sport: u16, dport: u16) -> K {
    (u128::from(u32::from_be_bytes(source)) << 72)
        | (u128::from(u32::from_be_bytes(destination)) << 40)
        | (u128::from(protocol) << 32)
        | (u128::from(sport) << 16)
        | u128::from(dport)
}

use ahash::AHashMap;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap_file::{
    pcap::PcapReader,
    pcapng::{Block, PcapNgReader},
};
use std::{
    fs::File,
    io::{BufReader, Read},
    time::Instant,
};
type K = ([u8; 4], [u8; 4], u8, u16, u16);
fn tally(data: &[u8], flows: &mut AHashMap<K, u64>, err: &mut u64) {
    match SlicedPacket::from_ethernet(data) {
        Ok(s) => {
            if let Some(NetSlice::Ipv4(ip)) = s.net {
                let h = ip.header();
                let (sp, dp) = match s.transport {
                    Some(TransportSlice::Tcp(t)) => (t.source_port(), t.destination_port()),
                    Some(TransportSlice::Udp(u)) => (u.source_port(), u.destination_port()),
                    _ => (0, 0),
                };
                *flows
                    .entry((h.source(), h.destination(), h.protocol().0, sp, dp))
                    .or_default() += data.len() as u64;
            }
        }
        Err(_) => *err += 1,
    }
}
fn main() {
    let mut args = std::env::args().skip(1);
    let first = args.next().unwrap();
    let (json, path) = if first == "--json" {
        (true, args.next().unwrap())
    } else {
        (false, first)
    };
    let t = Instant::now();
    let f = File::open(&path).unwrap();
    let bytes = f.metadata().unwrap().len();
    let rd: Box<dyn Read> = if path.ends_with(".gz") {
        Box::new(flate2::read::MultiGzDecoder::new(BufReader::with_capacity(
            1 << 20,
            f,
        )))
    } else {
        Box::new(f)
    };
    let mut rd = BufReader::with_capacity(1 << 22, rd);
    let mut magic = [0u8; 4];
    {
        use std::io::BufRead;
        let b = rd.fill_buf().unwrap();
        magic.copy_from_slice(&b[..4]);
    }
    let (mut n, mut err) = (0u64, 0u64);
    let mut flows = AHashMap::new();
    if magic == [0x0a, 0x0d, 0x0d, 0x0a] {
        let mut r = PcapNgReader::new(rd).unwrap();
        while let Some(b) = r.next_block() {
            match b {
                Ok(Block::EnhancedPacket(p)) => {
                    n += 1;
                    tally(&p.data, &mut flows, &mut err)
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!("{e}");
                    break;
                }
            }
        }
    } else {
        let mut r = PcapReader::new(rd).unwrap();
        while let Some(p) = r.next_packet() {
            let Ok(p) = p else { break };
            n += 1;
            tally(&p.data, &mut flows, &mut err)
        }
    }
    let e = t.elapsed().as_secs_f64();
    let pkt_per_sec = n as f64 / e;
    if json {
        println!(
            "{{\"packets\":{n},\"elapsed_secs\":{e},\"pkt_per_sec\":{pkt_per_sec},\"flows\":{},\"errors\":{err}}}",
            flows.len()
        );
    } else {
        println!(
            "{path}: {n} pkts {e:.1}s {:.2}M pkt/s {:.0} MB/s(file) flows={} errs={err}",
            pkt_per_sec / 1e6,
            bytes as f64 / e / 1e6,
            flows.len()
        );
    }
}

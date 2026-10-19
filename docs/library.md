**English** | [日本語](library.ja.md)

# Library

Depend on the facade crate `packet-tools`, which re-exports the other crates as modules (`packet_tools::capture`, `packet_tools::dissect`, ...), or on an individual crate such as `packet-tools-capture`. The crates are not on crates.io yet; use a git dependency:

```toml
[dependencies]
packet-tools = { git = "https://github.com/akitenkrad/rs-packet-tools" }
```

## Reading captures (`packet_tools::capture`)

```rust
use packet_tools::capture::{Capture, CaptureError};

fn main() -> Result<(), CaptureError> {
    let path = std::env::args().nth(1).expect("usage: docex <capture>");
    let mut capture = Capture::open(&path)?; // format is detected from the leading bytes
    let mut bytes = 0u64;
    while let Some(record) = capture.next_record() {
        let record = record?; // borrows from `capture` until the next call
        bytes += record.data.len() as u64;
        if let Some(ts_ns) = record.ts_ns {
            let _ = (record.index, ts_ns, record.linktype, record.interface);
        }
    }
    let stats = capture.stats();
    println!("{:?}: {} packets, {} bytes, {} backward timestamps",
        capture.format(), stats.packets, bytes, stats.timestamp_regressions);
    Ok(())
}
```

- `Capture::open` reads a file through an internal buffer. `Capture::open_with(path, OpenOptions { mmap: true })` memory-maps uncompressed files instead. The buffered reader is the default because it measured faster: each record is lent out one at a time, so mapping the file saves no copies.
- `Capture::from_reader` accepts any `Read`, for example standard input. Gzip is detected there too.
- `next_record` lends each `PacketRecord` until the next call. Copy `record.data` if you need to keep it.

### `PacketRecord`

| Field | Meaning |
|---|---|
| `index` | 0-based position among the packet records of the file |
| `ts_ns` | Nanoseconds since the Unix epoch, as an integer. `None` only for pcapng Simple Packet Blocks, which carry no timestamp |
| `caplen`, `origlen` | Captured length and original length on the wire |
| `linktype` | Link type of the interface (`LinkType(1)` is Ethernet) |
| `interface` | Index into `Capture::interfaces()`, counted across all pcapng sections (always 0 for classic PCAP) |
| `data` | The captured bytes (`caplen` bytes) |

Records are returned in file order and never reordered. `CaptureStats` counts timestamps that are earlier than the one immediately before them.

### Errors

Errors are returned once, after which `next_record` returns `None`. A file that ends in the middle of a record yields `CaptureError::TruncatedRecord` after all complete records; `stats().truncated_tail` is then `true`. Malformed pcapng blocks yield `CaptureError::Corrupt` with the byte offset and a reason. Captured lengths above 64 MiB are rejected as corrupt rather than allocated.

## Decoding L2–L4 (`packet_tools::dissect`)

```rust
use packet_tools::capture::Capture;
use packet_tools::dissect::{decode, DecodeDepth, Ipv4View, TcpView, UdpView};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).expect("usage: docex <capture>");
    let mut capture = Capture::open(&path)?;
    while let Some(record) = capture.next_record() {
        let record = record?;
        let packet = decode(record.data, record.linktype, DecodeDepth::L4);
        let Some(ip) = packet.layer::<Ipv4View>() else { continue };
        if let Some(tcp) = packet.layer::<TcpView>() {
            println!("{} {}:{} -> {}:{} flags={:#05x} payload={}B",
                record.index, ip.src(), tcp.src_port(), ip.dst(), tcp.dst_port(),
                tcp.flags(), packet.payload().len());
        } else if let Some(udp) = packet.layer::<UdpView>() {
            println!("{} {}:{} -> {}:{} udp", record.index, ip.src(), udp.src_port(), ip.dst(), udp.dst_port());
        }
        if let Some(m) = packet.malformed() {
            eprintln!("packet {}: {:?}", record.index, m);
        }
    }
    Ok(())
}
```

`decode(data, linktype, depth)` finds the offsets of the layers up to `depth` (`L2`, `L3` or `L4`) and returns a small `Packet` value without allocating. Header fields are read from the original bytes only when a view's accessor is called.

| Method | Returns |
|---|---|
| `layer::<T>()` | The first layer of view type `T`, or `None` |
| `layers_of::<T>()` | Every layer of type `T` (for example stacked VLAN tags) |
| `layers()` | The `LayerKind` of each decoded layer, outermost first |
| `payload()` | The bytes after the deepest decoded layer, without padding |
| `trailer()` | The bytes after the end of the IP datagram, such as Ethernet padding |
| `malformed()` | Where decoding stopped on a broken header (`layer`, `offset`, `kind`) |
| `ip_truncated()` | Whether the IP length exceeds the captured bytes |

Link types: Ethernet (1), raw IP (101, 12, 14), Linux cooked capture v1 and v2 (113, 276), BSD loopback (0, 108). Views: `EthernetView`, `VlanView`, `LinuxSllView`, `LinuxSll2View`, `NullView`, `ArpView`, `Ipv4View`, `Ipv6View`, `Icmpv4View`, `Icmpv6View`, `TcpView`, `UdpView`. IPv6 extension headers are followed to find the upper-layer protocol (`Ipv6View::upper_protocol`). Checksums are not verified during decoding; call `verify_checksum` on `Ipv4View`, `TcpView` or `UdpView` when you need it.

Lengths and fragments follow the rules of the `packets` table described in the [CLI](cli.md#packets) document.

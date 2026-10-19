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

## Building flows (`packet_tools::flow`)

`FlowTable` consumes decoded packets in capture order and returns flows as soon as the selected
policy closes them. Call `finish()` once to emit the states left at end of capture.

```rust
use packet_tools::capture::Capture;
use packet_tools::dissect::{decode, DecodeDepth};
use packet_tools::flow::{FlowConfig, FlowTable, Policy};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = Capture::open("capture.pcap")?;
    let mut table = FlowTable::new(FlowConfig {
        policy: Policy::Corrected,
        ..FlowConfig::default()
    });
    while let Some(record) = capture.next_record() {
        let record = record?;
        let packet = decode(record.data, record.linktype, DecodeDepth::L4);
        for flow in table.push(&record, &packet) {
            println!("{} {}", flow.flow_uid, flow.end_reason.as_str());
        }
    }
    for flow in table.finish() {
        println!("{} {}", flow.flow_uid, flow.end_reason.as_str());
    }
    Ok(())
}
```

The default configuration is `Corrected`, the `CicFlowMeter` preset, a 120-second flow timeout,
a 5-second activity timeout and a 60-second IdleOnly timeout. `CicFlowMeter` reproduces the
ahlashkari implementation, including its known feature bugs and first-FIN termination.
`Corrected` reproduces the Engelen fork, including its two-FIN/final-ACK state machine and
single-packet flows. Both compatibility policies truncate timestamps to microseconds and retain
capture order. `IdleOnly` uses a normalized key, nanosecond timestamps and expiration relative to
the greatest timestamp seen so far; `vlan_in_key` optionally adds the outer VLAN ID. ICMP echo keys
include type and identifier.

`EndReason` values are `fin`, `rst`, `flow_timeout`, `idle_timeout`, `end_of_capture` and
`icmp_type_code_change`. A policy emits only reasons that its state machine can reach.

### Stable flow identifier

`flow_uid` is 64-bit FNV-1a (offset `0xcbf29ce484222325`, prime `0x100000001b3`). The byte stream is:
IP version; protocol; VLAN-present byte and optional big-endian VLAN; normalized first address and
big-endian port; normalized second address and port; ICMP-type-present byte and optional type;
ICMP-identifier-present byte and optional big-endian identifier; then the first timestamp as signed
big-endian nanoseconds. IPv4 addresses contribute 4 bytes and IPv6 addresses 16 bytes. This format
is fixed so packets and future application tables can calculate the same identifier.

The complete schemas and policy-sensitive features are listed in [Flow columns](flows-columns.md).

## Reassembly (`packet_tools::reassembly`)

`Defragmenter::push(&PacketRecord, &Packet)` accepts decoded packets and returns completed `ReassembledDatagram` values plus typed `IpEvent` values. A completed datagram owns raw-IP bytes suitable for `decode(bytes, LinkType(101), DecodeDepth::L4)`. IPv4 length, fragmentation fields and checksum are repaired; IPv6 keeps extension headers before the Fragment header, removes that header, reconnects the next-header chain and repairs payload length. `DefragConfig` controls policy, VLAN keying, timeout, fragment count, datagram size and memory limits. Fragment payload is stored as sorted, disjoint byte ranges, so an isolated fragment at a large offset does not allocate the missing prefix. `Defragmenter::estimated_memory_bytes` reports the payload capacity plus range metadata charged to the limit.

`TcpReassembler::push` accepts ordinary decoded TCP packets or a decoded completed datagram. Its `TcpItem` output is `Start`, `Data`, `Gap`, `PostClose` or `End`. A `StreamChunk` carries connection ID, direction, zero-based stream position and `Arc<[u8]>`, so an M5 parser can retain a chunk without copying it again. `DeliveryMode::OnAck` is the default; `Immediate` emits each contiguous prefix immediately. TCP payload is stored as sorted, disjoint ranges whose ownership retains the original segment bounds used by the overlap policy. Delivered payload is discarded except for at most the most recent 1 MiB per direction (and no more than half of `stream_memory`) used to detect late conflicting overlaps. This history and range metadata are charged to both memory limits; `TcpReassembler::estimated_memory_bytes` exposes the current estimate. `PostClose` is a statistics-only notification: after an accepted RST or completed two-sided FIN close, the connection remains as a tombstone for `TcpConfig::closing_timeout`; later non-SYN packets are counted but never emitted as `Data`. A SYN without ACK replaces the tombstone, while expiry permits a later packet to start a midstream connection. Zero- or one-byte keepalives at `next_expected - 1` are counted in `DirectionSummary::keepalives` and bypass buffering and overlap detection. Call `finish()` at capture end.

`FragmentBuffer` and `TcpSegmentBuffer` expose the target-policy buffer state directly for protocol conformance tests. Their `interval_count` and `allocated_bytes` methods expose the range count and estimated heap allocation. `FlowIdentityKey::normalized` and `flow_uid` in `packet_tools::flow` are shared with reassembly, ensuring an `IdleOnly` flow and its TCP connection use the same identifier and first-packet timestamp.

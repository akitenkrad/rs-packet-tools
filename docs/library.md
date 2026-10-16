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

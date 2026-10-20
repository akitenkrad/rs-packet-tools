# packet-tools-capture

`packet-tools-capture` reads classic PCAP, pcapng, and gzip-compressed captures from files or streams, detects formats from their bytes, and lends packet records without copying their payloads.

```rust,no_run
use packet_tools_capture::{Capture, CaptureError};

fn main() -> Result<(), CaptureError> {
    let mut capture = Capture::open("capture.pcapng")?;
    while let Some(record) = capture.next_record() {
        let record = record?;
        println!("{}: {} bytes", record.index, record.data.len());
    }
    Ok(())
}
```

Most users should depend on the `packet-tools` facade crate and use `packet_tools::capture`. See the [repository](https://github.com/akitenkrad/rs-packet-tools) and the [API documentation](https://docs.rs/packet-tools-capture).

Licensed under either of Apache-2.0 or MIT at your option.

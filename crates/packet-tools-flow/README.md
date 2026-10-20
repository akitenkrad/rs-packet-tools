# packet-tools-flow

`packet-tools-flow` groups decoded packets into bidirectional flows and computes stable counters or CICFlowMeter-compatible feature sets under selectable flow policies.

```rust,no_run
use packet_tools_capture::{Capture, CaptureError};
use packet_tools_dissect::{decode, DecodeDepth};
use packet_tools_flow::{FlowConfig, FlowTable};

fn main() -> Result<(), CaptureError> {
    let mut capture = Capture::open("capture.pcap")?;
    let mut flows = FlowTable::new(FlowConfig::default());
    while let Some(record) = capture.next_record() {
        let record = record?;
        let packet = decode(record.data, record.linktype, DecodeDepth::L4);
        for flow in flows.push(&record, &packet) {
            println!("{}", flow.flow_uid);
        }
    }
    for flow in flows.finish() {
        println!("{}", flow.flow_uid);
    }
    Ok(())
}
```

Most users should depend on the `packet-tools` facade crate and use `packet_tools::flow`. See the [repository](https://github.com/akitenkrad/rs-packet-tools) and the [API documentation](https://docs.rs/packet-tools-flow).

Licensed under either of Apache-2.0 or MIT at your option.

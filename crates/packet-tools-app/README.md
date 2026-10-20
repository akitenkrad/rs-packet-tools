# packet-tools-app

`packet-tools-app` dispatches reassembled traffic to stateful parsers for DNS, HTTP, TLS, FTP, SSH, SMTP, and Telnet and emits typed application events.

```rust
use packet_tools_app::{AppAnalyzer, Protocol};

let analyzer = AppAnalyzer::new(Protocol::ALL.to_vec());
let output = analyzer.finish();
assert!(output.events.is_empty());
```

Most users should depend on the `packet-tools` facade crate and use `packet_tools::app`. See the [repository](https://github.com/akitenkrad/rs-packet-tools) and the [API documentation](https://docs.rs/packet-tools-app).

Licensed under either of Apache-2.0 or MIT at your option.

# packet-tools-dissect

`packet-tools-dissect` decodes Ethernet, VLAN, Linux cooked capture, loopback, ARP, IPv4, IPv6, ICMP, TCP, and UDP headers into zero-copy typed views.

```rust
use packet_tools_capture::LinkType;
use packet_tools_dissect::{decode, DecodeDepth, Ipv4View};

let frame = [0_u8; 14];
let packet = decode(&frame, LinkType(1), DecodeDepth::L4);
let ipv4 = packet.layer::<Ipv4View>();
assert!(ipv4.is_none());
```

Most users should depend on the `packet-tools` facade crate and use `packet_tools::dissect`. See the [repository](https://github.com/akitenkrad/rs-packet-tools) and the [API documentation](https://docs.rs/packet-tools-dissect).

Licensed under either of Apache-2.0 or MIT at your option.

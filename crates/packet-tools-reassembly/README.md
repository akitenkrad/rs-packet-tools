# packet-tools-reassembly

`packet-tools-reassembly` reconstructs IPv4 and IPv6 datagrams and directional TCP byte streams while applying explicit target policies to overlapping data.

```rust
use packet_tools_reassembly::{FragmentBuffer, IpPolicy};

let mut fragments = FragmentBuffer::new(IpPolicy::Bsd);
assert!(fragments.insert(0, true, b"hello ", 0).complete.is_none());
let datagram = fragments.insert(6, false, b"world", 1).complete.unwrap();
assert_eq!(datagram, b"hello world");
```

Most users should depend on the `packet-tools` facade crate and use `packet_tools::reassembly`. See the [repository](https://github.com/akitenkrad/rs-packet-tools) and the [API documentation](https://docs.rs/packet-tools-reassembly).

Licensed under either of Apache-2.0 or MIT at your option.

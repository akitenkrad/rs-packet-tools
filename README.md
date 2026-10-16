<p align="center"><img src="docs/assets/hero.svg" width="100%"></p>

**English** | [日本語](README.ja.md)

# packet-tools

`packet-tools` is a Rust library and CLI for fast offline analysis of PCAP and pcapng captures. It is meant as a fast alternative to Scapy for research workloads such as intrusion-detection datasets: it extracts per-packet fields, builds bidirectional flows with configurable termination rules and flow features, reassembles IP fragments and TCP streams, parses application-layer protocols (DNS, HTTP/1.x, TLS, FTP, SSH, SMTP, Telnet), and writes the results to Parquet or CSV.

> **Status: early development (M1).** Reading PCAP, pcapng and gzip-compressed captures works (`packet_tools::capture` and `packet-tools validate`). Dissection, flows and application parsing are being implemented milestone by milestone. See [Architecture](docs/architecture.md) for the plan.

## Install

The crates are not published to crates.io yet. Build from source with a recent stable Rust toolchain (1.94 or later):

```sh
git clone https://github.com/akitenkrad/rs-packet-tools.git
cd rs-packet-tools
cargo build --release
cargo run -p packet-tools -- --version
```

## Documentation

- [CLI](docs/cli.md): the `packet-tools` command
- [Library](docs/library.md): reading captures from Rust
- [Architecture](docs/architecture.md): crate layout, design principles and milestones
- [Development](docs/development.md): tests, synthetic fixtures, CI and benchmarks

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.

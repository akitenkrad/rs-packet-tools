# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - Unreleased

### Added

- Read classic PCAP, pcapng, and gzip-compressed captures from buffered, streamed, or memory-mapped input, with format detection based on file contents.
- Decode zero-copy Ethernet, VLAN, Linux cooked capture, loopback, ARP, IPv4, IPv6, ICMP, TCP, and UDP views and export an L2-L4 `packets` table.
- Build bidirectional `flows` with `corrected`, `cicflowmeter`, and `idle-only` grouping and termination policies, plus minimal and CICFlowMeter-compatible feature presets.
- Reproduce the original and corrected CICFlowMeter feature sets, column names, ordering, timestamp formats, and policy-sensitive values.
- Reassemble IPv4 and IPv6 fragments and reconstruct directional TCP streams with selectable target policies for overlapping data.
- Parse DNS, HTTP, TLS, FTP, SSH, SMTP, and Telnet traffic, including JA3, JA3S, and JA4 fingerprints for TLS.
- Write packet, flow, stream, reassembly-event, datagram, and application-layer tables as Snappy-compressed Parquet or CSV.
- Process multiple capture files concurrently with `--jobs` while preserving deterministic output for each input.
- Associate packet rows with the policy-selected flow through the `flow_uid` column.

[0.1.0]: https://github.com/akitenkrad/rs-packet-tools/releases/tag/v0.1.0

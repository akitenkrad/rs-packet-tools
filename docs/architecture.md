**English** | [日本語](architecture.ja.md)

# Architecture

## Why another packet library

Scapy is convenient, but it turns every layer of every packet into a Python object as soon as the packet is read. On our measurements, reading a capture with Scapy without dissecting it runs at 0.6–1.8 million packets per second, while full dissection drops to about 11,000–13,000 packets per second. The cost is in dissection, not in reading the file. A Rust prototype that performs the same 5-tuple aggregation runs at 5.7–19 million packets per second on the same data. See [Development](development.md#benchmarks) for how to reproduce these numbers.

## Design principles

| Scapy | packet-tools |
|---|---|
| One object and one field dictionary per layer | Zero-copy views that borrow the original bytes and decode fields on access |
| Dissects every layer eagerly | Decodes only up to the requested depth (`L2`, `L3`, `L4`, `App`) |
| Picks the next layer by scanning `bind_layers` tables (ports only) | `match` on EtherType and IP protocol for L2–L4; for applications, ports select candidates and the payload confirms them |
| Floating-point timestamps | Integer nanoseconds (`i64`) |
| Falls back to `Raw` on errors | Falls back to `Raw` and records which layer failed, at which offset and why |

Other rules:

- The file format is detected from the magic number, never from the file extension. Some public datasets ship pcapng files named `*.pcap`.
- Packets keep their order in the file. Timestamps that move backwards are counted, not sorted.
- Flow termination is a policy. `corrected` (the default) ends a TCP flow on FINs from both sides or on RST. `cicflowmeter` reproduces CICFlowMeter, including its behaviour of ending a flow at the first FIN, so that results can be compared with published CSV files.
- How overlapping TCP segments and IP fragments are resolved is also a policy (`first`, `last`, `bsd`, `linux`, `windows`), because a monitor and an end host can interpret the same overlap differently.

## Crates

| Crate | Responsibility |
|---|---|
| `packet-tools` | Facade library that re-exports the crates below, and the `packet-tools` CLI |
| `packet-tools-capture` | Reading PCAP, pcapng and gzip-compressed captures; format detection |
| `packet-tools-dissect` | Zero-copy L2–L4 views and a lazily built layer index |
| `packet-tools-flow` | Bidirectional flow table, termination policies and streaming flow features |
| `packet-tools-reassembly` | IPv4/IPv6 defragmentation and TCP stream reassembly |
| `packet-tools-app` | Application-layer parsers and their registration |
| `packet-tools-export` | Writing Parquet and CSV |

Two more workspace members are not published: `packet-tools-fixtures` generates the synthetic test captures, and `bench/rsbench` is the Rust baseline used in the benchmarks.

Data flows through the crates in this order:

```text
capture -> dissect -> flow ----------------------> export
                   \-> reassembly -> app --------> export
           dissect (per-packet fields) ----------> export
```

## Outputs

| Table | One row per | Main columns |
|---|---|---|
| `packets` | Packet | Index in the file, timestamp, captured and original length, selected L2–L4 fields, `flow_uid` |
| `flows` | Flow | `flow_uid`, key, start and end time, termination reason, flow features |
| `streams` | Connection direction | `flow_uid`, endpoints, delivered bytes, gaps, overlaps, close reason and payload hash |
| `dns`, `http`, `tls`, ... | Application event | `flow_uid`, packet index, protocol-specific fields |
| `capture_stats` | File | Packet count, format, link types, backward timestamps, malformed packets |

`flow_uid` joins the tables.

## Milestones

| | Scope |
|---|---|
| M0 | Workspace, synthetic fixtures, CI, benchmarks (done) |
| M1 | `packet-tools-capture`: PCAP, pcapng and gzip reading (done) |
| M2 | `packet-tools-dissect` and the `packets` table (done) |
| M3 | `packet-tools-flow` and the `flows` table (done) |
| M4 | `packet-tools-reassembly` (done) |
| M5 | `packet-tools-app` (done) |
| M6 | Parallel processing and a performance report |

Packet crafting and live capture are out of scope for now. The capture input is designed as a trait so that a live source can be added later.

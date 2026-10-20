**English** | [日本語](architecture.ja.md)

# Architecture

## Why another packet library

Scapy is convenient, but it turns every layer of every packet into a Python object as soon as the packet is read. On our measurements, reading a capture with Scapy without dissecting it runs at 0.6–1.8 million packets per second, while full dissection drops to about 11,000–13,000 packets per second. The cost is in dissection, not in reading the file. A Rust prototype that performs the same 5-tuple aggregation runs at 5.7–19 million packets per second on the same data. [Performance](performance.md) lists these and the later measurements of packet-tools itself, and [Development](development.md#benchmarks) explains how to reproduce them.

## Design principles

| Scapy | packet-tools |
|---|---|
| One object and one field dictionary per layer | Zero-copy views that borrow the original bytes and decode fields on access |
| Dissects every layer eagerly | Decodes only up to the requested depth (`L2`, `L3` or `L4`); reassembly and application parsing are separate stages that run only when requested |
| Picks the next layer by scanning `bind_layers` tables (ports only) | `match` on EtherType and IP protocol for L2–L4; for applications, ports select candidates and the payload confirms them |
| Floating-point timestamps | Integer nanoseconds (`i64`) |
| Falls back to `Raw` on errors | Falls back to `Raw` and records which layer failed, at which offset and why |

Other rules:

- The file format is detected from the magic number, never from the file extension. Some public datasets ship pcapng files named `*.pcap`.
- Packets keep their order in the file. Timestamps that move backwards are counted, not sorted.
- Flow termination is a policy. `corrected` (the default) ends a TCP flow on FINs from both sides or on RST. `cicflowmeter` reproduces CICFlowMeter, including its behaviour of ending a flow at the first FIN, so that results can be compared with published CSV files.
- How overlapping TCP segments and IP fragments are resolved is also a policy (for IP: `first`, `last`, `bsd`, `linux`, `windows`, `solaris`; for TCP: `first`, `last`, `bsd`, `linux`, `old-linux`, `solaris`), because a monitor and an end host can interpret the same overlap differently. See [`streams`](cli.md#streams) for the rules.

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

Two workspace members are not published: `packet-tools-fixtures` generates the synthetic test captures, and `bench/rsbench` is the Rust baseline used in the benchmarks. The excluded standalone crate `bench/ptbench` records benchmark runs with runvault without adding benchmark-only dependencies to workspace CI.

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
| `events`, `datagrams` | Reassembly event, reassembled IP datagram | Packet index, key, range and retained side; fragment count, length and payload hash |
| `dns`, `http`, `tls`, ... | Application event | `flow_uid`, packet index, protocol-specific fields |
| `dispatch` | TCP stream or UDP flow given to the application parsers | `flow_uid`, selected protocol, probe direction and bytes, stop reason |
| `inputs.csv` | Input of a multiple-input run | Input path, output directory, packet count, status and error |

`flow_uid` joins the tables. Per-file capture statistics (packet count, format, link types, backward timestamps, truncated packets) are not a table; `validate` prints them as text or JSON lines.

## Milestones

All milestones of the first release are complete.

| | Scope | Status |
|---|---|---|
| M0 | Workspace, synthetic fixtures, CI, benchmarks | Done |
| M1 | `packet-tools-capture`: PCAP, pcapng and gzip reading | Done |
| M2 | `packet-tools-dissect` and the `packets` table | Done |
| M3 | `packet-tools-flow` and the `flows` table | Done |
| M4 | `packet-tools-reassembly` | Done |
| M5 | `packet-tools-app` | Done |
| M6 | File-level parallelism, packet `flow_uid`, and recorded benchmarks | Done |

Packet crafting and live capture are out of scope. Captures are read from files, or from any `Read` through `Capture::from_reader` (for example standard input in a pipeline).

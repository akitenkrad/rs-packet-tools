**English** | [日本語](cli.ja.md)

# CLI

```text
High-performance packet analysis tools

Usage: packet-tools <COMMAND>

Commands:
  validate  Validate capture containers and summarize their records
  packets   Export one row per packet to Parquet or CSV
  flows     Build bidirectional flows and export one row per completed flow
  streams   Reassemble IP fragments and directional TCP byte streams
  app       Parse reassembled streams and UDP datagrams into application-layer tables
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## Multiple inputs

Every subcommand accepts `--jobs N` (default 1). Workers atomically take the next unprocessed input, and each capture remains single-threaded. `validate` buffers reports and prints them in input order. For the other commands, one input retains the existing file or directory output contract.

With two or more inputs, `-o` is an output directory. It is created when absent and must contain no entries when present. Parquet is the default if `--format` is omitted. Each capture gets a directory named by its full path below the inputs' longest common parent; the input filename is part of that directory, so equal basenames do not collide. For example, `a/week5/tuesday/inside.tcpdump.gz` becomes `OUT/week5/tuesday/inside.tcpdump.gz/`.

Each directory contains `packets.<ext>`, `flows.<ext>`, all three of `streams.<ext>`, `events.<ext>`, and `datagrams.<ext>`, or the normal `app` table set. Multiple-input `streams` rejects `--events`, `--datagrams`, and `--dump-dir`. Duplicate inputs are rejected. `OUT/inputs.csv` records `input_id,input,output_dir,packets,status,error` in argument order. A failed input does not stop the others; after all workers finish, failures are listed on standard error and the process exits with status 1.

`--memory`, `--app-memory`, and `--stream-memory` are limits per job. Approximate total memory can therefore be up to `N` times the selected per-job limits with `--jobs N`. Measured speed-ups and memory use are listed in [Performance](performance.md#file-level-parallelism).

## `validate`

Reads every record of one or more captures and prints a summary per file. It checks that a capture can be read to the end, and it reports what the file contains. It does not dissect packets.

```text
Validate capture containers and summarize their records

Usage: packet-tools validate [OPTIONS] <FILES>...

Arguments:
  <FILES>...  Capture files to validate

Options:
      --json         Emit one JSON object per line
      --mmap         Memory-map uncompressed regular files instead of reading them through a buffer
      --jobs <JOBS>  Number of capture files to process concurrently [default: 1]
  -h, --help         Print help
```

The format is detected from the leading bytes, so a pcapng file named `*.pcap` and a gzip-compressed capture are both handled. Supported inputs: classic PCAP (little- or big-endian, microsecond or nanosecond timestamps), pcapng (any number of sections and interfaces), and either of them compressed with gzip.

```sh
$ packet-tools validate tests/fixtures/multi_iface.pcapng tests/fixtures/le_usec.pcap.gz
tests/fixtures/multi_iface.pcapng format=pcapng packets=22 linktypes=1:19,101:3 regressions=1 max_regression=1.000μs truncated_packets=1 truncated tail=false skipped_blocks=- elapsed=0.000076s pkt/s=290909
tests/fixtures/le_usec.pcap.gz format=pcap-le-usec+gzip packets=19 linktypes=1:19 regressions=1 max_regression=1.000μs truncated_packets=1 truncated tail=false skipped_blocks=- elapsed=0.000338s pkt/s=56199
total files=2 packets=41 regressions=2
```

| Field | Meaning |
|---|---|
| `format` | Container, byte order and timestamp resolution, plus `+gzip` when compressed |
| `packets` | Number of packet records |
| `linktypes` | Packets per link type (`1` is Ethernet, `101` is raw IP) |
| `regressions` | Packets whose timestamp is earlier than that of the packet immediately before them. Packets are never reordered |
| `max_regression` | The largest of those backward steps |
| `truncated_packets` | Packets whose captured length is shorter than their original length |
| `truncated tail` | The file ends in the middle of a record |
| `skipped_blocks` | pcapng blocks that carry no packet (statistics, name resolution, custom blocks), per block type |

With `--json`, each file becomes one JSON object with all counters (including `bytes_captured`, `bytes_original`, `first_ts_ns`, `last_ts_ns`, `min_ts_ns`, `max_ts_ns`, `sections` and `error`), followed by one object with `"type": "total"`.

The exit status is 1 if any file fails to read or ends in the middle of a record, and 0 otherwise. A file that fails is reported with the counters read up to the failure, and the remaining files are still processed.

## `packets`

Writes one row per packet, with the L2–L4 header fields, to Parquet or CSV.

```text
Export one row per packet to Parquet or CSV

Usage: packet-tools packets [OPTIONS] --output <OUTPUT> <INPUTS>...

Arguments:
  <INPUTS>...  Input captures

Options:
      --fields <FIELDS>              Comma-separated output column names
      --format <FORMAT>              Output format; inferred from .parquet or .csv when omitted [possible values: parquet, csv]
      --limit <LIMIT>                Write at most this many packets
      --depth <DEPTH>                Deepest layer to decode [default: l4] [possible values: l2, l3, l4]
      --policy <POLICY>              Flow grouping and termination policy used by flow_uid [default: corrected] [possible values: corrected, cicflowmeter, idle-only]
      --flow-timeout <FLOW_TIMEOUT>  Maximum flow age in seconds for compatibility policies [default: 120]
      --idle-timeout <IDLE_TIMEOUT>  IdleOnly expiration in seconds [default: 60]
      --vlan-in-key                  Include the outermost VLAN identifier in IdleOnly flow keys
      --jobs <JOBS>                  Number of capture files to process concurrently [default: 1]
  -o, --output <OUTPUT>              Output file, or output directory for multiple inputs
  -h, --help                         Print help
```

```sh
$ packet-tools packets --fields index,ip_src,ip_dst,ip_proto,src_port,dst_port,tcp_flags,l4_payload_len,trailer_len \
    -o packets.csv tests/fixtures/le_usec.pcap
$ head -4 packets.csv
index,ip_src,ip_dst,ip_proto,src_port,dst_port,tcp_flags,l4_payload_len,trailer_len
0,192.0.2.10,198.51.100.20,6,49152,80,2,0,0
1,198.51.100.20,192.0.2.10,6,80,49152,18,0,0
2,192.0.2.10,198.51.100.20,6,49152,80,16,0,0
```

Parquet files are compressed with Snappy. In CSV, missing values are empty and booleans are `true` / `false`. All columns are written unless `--fields` is given:

| Column | Type | Content |
|---|---|---|
| `index` | UInt64 | Position of the packet in the file (0-based) |
| `ts_ns` | Int64 | Timestamp in nanoseconds since the Unix epoch |
| `caplen`, `origlen` | UInt32 | Captured and original length |
| `linktype`, `interface` | UInt16, UInt32 | Link type and interface index |
| `eth_src`, `eth_dst` | Utf8 | MAC addresses, `aa:bb:cc:dd:ee:ff` |
| `ethertype` | UInt16 | EtherType after the innermost VLAN tag (null for IEEE 802.3 length fields) |
| `vlan_id`, `vlan_depth` | UInt16, UInt8 | VID of the outermost VLAN tag, and the number of tags |
| `ip_version` | UInt8 | 4 or 6 |
| `ip_src`, `ip_dst` | Utf8 | Addresses; IPv6 in the RFC 5952 compressed form |
| `ip_proto` | UInt8 | IPv4 protocol, or the IPv6 upper-layer protocol after extension headers |
| `ip_ttl` | UInt8 | IPv4 TTL or IPv6 hop limit |
| `ip_len` | UInt32 | IPv4 total length, or 40 + IPv6 payload length |
| `ip_id` | UInt32 | IPv4 identification, or the IPv6 fragment identification |
| `ip_frag_offset` | UInt32 | Fragment offset in bytes |
| `ip_mf`, `ip_df` | Boolean | More-fragments and don't-fragment flags (`ip_df` is null for IPv6) |
| `src_port`, `dst_port` | UInt16 | TCP or UDP ports |
| `tcp_flags` | UInt16 | The 12 TCP flag bits, including NS |
| `tcp_seq`, `tcp_ack`, `tcp_window` | UInt32, UInt32, UInt16 | Raw values (not relative, not scaled) |
| `udp_length` | UInt16 | UDP length field |
| `icmp_type`, `icmp_code` | UInt8 | ICMPv4 or ICMPv6 type and code |
| `l4_payload_len` | UInt32 | TCP or UDP payload length |
| `trailer_len` | UInt32 | Bytes after the end of the IP datagram, such as Ethernet padding |
| `ip_truncated` | Boolean | The IP length is larger than what was captured |
| `malformed` | Utf8 | Where decoding stopped on a broken header, as `<layer>:<kind>@<offset>` (for example `ipv4:bad_length@14`) |
| `flow_uid` | UInt64 | Identifier of the policy-selected flow that accepted the packet; null for discarded packets |

`flow_uid` is the last default column. It is produced by passing packets through the same `FlowTable` configuration as `flows`, so policy and timeout choices can change it. When `--fields` does not select `flow_uid`, no flow table is created; [Performance](performance.md#cost-of-flow_uid-in-packets) shows what the flow table costs. Under `cicflowmeter`, accepted one-packet flows are omitted from the `flows` output for compatibility; their packet rows can therefore contain a `flow_uid` that has no corresponding flow row.

How lengths and fragments are handled:

- The end of the IP datagram is taken from the IP length field, so Ethernet padding is not counted as payload; it is reported in `trailer_len`.
- For IPv4 and IPv6 fragments, the TCP or UDP header is decoded only in the first fragment. Later fragments have no ports. Fragments are not reassembled.
- Headers quoted inside ICMP error messages and tunnelled packets are not decoded.

The exit status is 1 if the capture cannot be read to the end. Rows read before the error are still written, and the output file is closed properly.

## `flows`

Builds bidirectional flows in capture order and writes CSV or Snappy-compressed Parquet.

```text
Build bidirectional flows and export one row per completed flow

Usage: packet-tools flows [OPTIONS] --output <OUTPUT> <INPUTS>...

Arguments:
  <INPUTS>...  Input captures

Options:
      --policy <POLICY>
          Flow grouping and termination policy [default: corrected] [possible values: corrected, cicflowmeter, idle-only]
      --preset <PRESET>
          Output feature preset [default: cicflowmeter] [possible values: cicflowmeter, minimal]
      --flow-timeout <FLOW_TIMEOUT>
          Maximum flow age in seconds for compatibility policies [default: 120]
      --activity-timeout <ACTIVITY_TIMEOUT>
          Gap in seconds used for Active/Idle feature statistics [default: 5]
      --idle-timeout <IDLE_TIMEOUT>
          IdleOnly expiration in seconds [default: 60]
      --vlan-in-key
          Include the outermost VLAN identifier in IdleOnly flow keys
      --column-names <COLUMN_NAMES>
          Output column naming convention [default: snake] [possible values: snake, original]
      --format <FORMAT>
          Output format; inferred from .parquet or .csv when omitted [possible values: parquet, csv]
      --jobs <JOBS>
          Number of capture files to process concurrently [default: 1]
  -o, --output <OUTPUT>
          Output file, or output directory for multiple inputs
  -h, --help
          Print help
```

```sh
packet-tools flows --policy corrected -o flows.parquet capture.pcapng
packet-tools flows --policy cicflowmeter --column-names original -o official-shape.csv capture.pcap
packet-tools flows --policy idle-only --preset minimal --idle-timeout 30 --vlan-in-key \
    -o minimal.csv capture.pcap
```

`corrected` reproduces GintsEngelen/CICFlowMeter at commit `13a0615` and is the default.
`cicflowmeter` reproduces ahlashkari/CICFlowMeter at commit `9d91f72`, the last version before the
Engelen fork, including its known feature bugs and first-FIN termination. The official CIC-IDS-2017
flow CSVs were produced by an earlier release (CICFlowMeter-V3), so several of their columns differ
from this policy. Their flow timeout defaults to 120 seconds. The 5-second activity timeout
affects Active/Idle features only; it does not close flows. `idle-only` is packet-tools' normalized
5-tuple policy. It closes a flow after 60 seconds without a packet, uses nanosecond timestamps and
optionally includes the outermost VLAN ID in the key.

Snake-case schemas begin with `flow_uid,end_reason`. End reasons are `fin`, `rst`, `flow_timeout`,
`idle_timeout`, `end_of_capture` and `icmp_type_code_change`. `--column-names original` requires the
`cicflowmeter` preset, omits `flow_uid`, `end_reason` and `Label`, and preserves the selected Java
implementation's order and timestamp text: `dd/MM/yyyy hh:mm:ss a` for `cicflowmeter`, and
`yyyy-MM-dd HH:mm:ss[.SSSSSS]` in UTC for `corrected`. The original schemas contain no duplicate
headers; snake_case names are unique as well.

The minimal preset has 21 columns. The compatibility preset has 83 original-policy columns or 88
corrected-policy columns before packet-tools metadata. See [Flow columns](flows-columns.md).

Format inference and read-error handling match `packets`: `.parquet` and `.csv` select the format,
and complete flows available before a capture error are written before exit status 1 is returned.

## `streams`

Reassembles IPv4/IPv6 fragments, decodes completed raw-IP datagrams, and reconstructs each TCP direction.

```text
Reassemble IP fragments and directional TCP byte streams

Usage: packet-tools streams [OPTIONS] --output <OUTPUT> <INPUTS>...

Arguments:
  <INPUTS>...  Input captures

Options:
      --ip-policy <IP_POLICY>
          IP fragment overlap resolution policy [default: bsd] [possible values: first, last, bsd, linux, windows, solaris]
      --tcp-policy <TCP_POLICY>
          TCP segment overlap resolution policy [default: bsd] [possible values: first, vista, last, bsd, windows, macos, hpux10, irix, linux, old-linux, old_linux, solaris, hpux11]
      --delivery <DELIVERY>
          When to deliver reassembled TCP bytes [default: on-ack] [possible values: on-ack, immediate]
      --defrag-timeout <DEFRAG_TIMEOUT>
          IP fragment reassembly timeout in seconds [default: 60]
      --tcp-timeout <TCP_TIMEOUT>
          TCP connection inactivity timeout in seconds [default: 3600]
      --stream-memory <STREAM_MEMORY>
          Maximum retained TCP reassembly memory per direction in bytes [default: 4194304]
      --memory <MEMORY>
          Maximum retained reassembly memory in bytes [default: 1073741824]
      --vlan-in-key
          Include the outermost VLAN identifier in reassembly keys
      --events <EVENTS>
          Event table output file; unavailable with multiple inputs
      --datagrams <DATAGRAMS>
          Datagram table output file; unavailable with multiple inputs
      --dump-dir <DUMP_DIR>
          Directory for delivered TCP bytes; unavailable with multiple inputs
      --format <FORMAT>
          Output format; inferred from .parquet or .csv when omitted [possible values: parquet, csv]
      --jobs <JOBS>
          Number of capture files to process concurrently [default: 1]
  -o, --output <OUTPUT>
          Output file, or output directory for multiple inputs
  -h, --help
          Print help
```

`--defrag-timeout` and `--tcp-timeout` are in seconds, and `--stream-memory` and `--memory` are in bytes. `-o` names the stream table; `--events` and `--datagrams` name the optional event and datagram tables, and `--dump-dir` a directory for the delivered bytes.

```sh
packet-tools streams --tcp-policy linux --events overlap.csv --datagrams datagrams.csv \
    --dump-dir streams -o streams.parquet capture.pcapng
```

IP policies are `first`, `last`, `bsd`, `linux`, `windows`, and `solaris`. `first` always retains existing bytes and `last` always uses new bytes. `bsd` uses a new fragment when it starts before the existing fragment. `linux` also uses it when both start at the same offset. `windows` requires the new fragment to start before and end after the existing fragment; `solaris` accepts an equal end.

TCP policies are `first`, `last`, `bsd`, `linux`, `old-linux`, and `solaris`. Aliases are `vista` for `first`; `windows`, `macos`, `hpux10`, and `irix` for `bsd`; `old_linux` for `old-linux`; and `hpux11` for `solaris`. Names are case-insensitive. Existing bytes are retained by default. A new segment starting before an existing segment wins for `bsd`, `linux`, and `old-linux`; `solaris` also requires it to reach the existing end. At the same start, `linux` replaces only when the new segment extends farther, while `old-linux` and `solaris` also replace equal-length data. Starting inside an existing segment replaces data only under `solaris`, and only when the new segment extends past the existing end. `last` always replaces existing data.

`on-ack` delays delivery until the peer acknowledges the bytes, allowing overlaps received first to be resolved by policy. `immediate` delivers a contiguous prefix as soon as it arrives. Bytes already delivered never change; a later conflicting overlap becomes `tcp_late_overlap_conflict`. A zero- or one-byte segment at exactly one sequence number before the next expected byte, without SYN, FIN or RST, is counted as a keepalive and is neither buffered nor reported as an overlap. FIN completion, accepted RST, timeout, and capture end flush remaining ranges, emitting gaps where bytes are absent.

Fragment and TCP payloads are held as disjoint ranges. `--stream-memory` and `--memory` charge retained payload bytes and logical range metadata rather than sequence-space holes or allocator capacity. Up to the most recent 1 MiB of delivered payload per direction, capped at half of `--stream-memory`, is retained for late-overlap conflict detection and is included in the limits. Reaching a TCP limit advances through the oldest outstanding range, emits a gap where necessary, and records `tcp_memory_limit`. The estimate depends only on the input packet sequence, not allocation addresses or scheduling.

After an accepted RST or a completed two-sided FIN close, the closed connection remains associated with its key for the 60-second closing timeout. Non-SYN packets in that interval are not delivered; packets and payload bytes are counted in `post_close_packets` and `post_close_bytes`, and each packet with payload emits `tcp_data_after_close`. A SYN without ACK starts a new connection immediately. After the closing timeout, any packet may start a new midstream connection.

The stream table has one row per connection and direction: `stream_id`, `flow_uid`, `direction`, client/server addresses and ports, `first_ts_ns`, `last_ts_ns`, `midstream`, `bytes`, `segments`, `gaps`, `gap_bytes`, `overlaps`, `overlap_conflicts`, `retransmitted_bytes`, `post_close_packets`, `post_close_bytes`, `keepalives`, `close_reason`, and `sha256`. The hash concatenates delivered data while omitting gaps. `--dump-dir` writes the same bytes to `<stream_id>.c2s.bin` and `<stream_id>.s2c.bin`.

The event table records `ip_overlap`, `ip_overlap_conflict`, `ip_timeout`, `ip_too_large`, `ip_too_many_fragments`, `ip_memory_limit`, `tcp_overlap_conflict`, `tcp_late_overlap_conflict`, `tcp_data_after_close`, `tcp_memory_limit`, and `tcp_rst_ignored`, together with the applicable key, range and retained side. The datagram table records the completed packet index, IP version, addresses, identification, protocol, fragment count, reassembled length, and payload SHA-256.

## `app`

Reassembles IP fragments and TCP streams, parses application events, and writes one table per selected protocol.

```text
Parse reassembled streams and UDP datagrams into application-layer tables

Usage: packet-tools app [OPTIONS] --output <OUTPUT> <INPUTS>...

Arguments:
  <INPUTS>...  Input captures

Options:
      --ip-policy <IP_POLICY>    IP fragment overlap resolution policy [default: bsd] [possible values: first, last, bsd, linux, windows, solaris]
      --tcp-policy <TCP_POLICY>  TCP segment overlap resolution policy [default: bsd] [possible values: first, vista, last, bsd, windows, macos, hpux10, irix, linux, old-linux, old_linux, solaris, hpux11]
      --delivery <DELIVERY>      When to deliver reassembled TCP bytes [default: on-ack] [possible values: on-ack, immediate]
      --memory <MEMORY>          Maximum retained reassembly memory in bytes [default: 1073741824]
      --app-memory <APP_MEMORY>  Maximum application probe and parser buffer memory in bytes [default: 268435456]
      --protocols <PROTOCOLS>    Comma-separated application protocols to parse [default: dns,http,tls,ftp,ssh,smtp,telnet]
      --format <FORMAT>          Output table format [default: parquet] [possible values: parquet, csv]
      --jobs <JOBS>              Number of capture files to process concurrently [default: 1]
  -o, --output <OUTPUT>          Output directory, or parent output directory for multiple inputs
  -h, --help                     Print help
```

`-o` names the output directory. `--memory` and `--app-memory` are in bytes, and `--protocols` is a comma-separated subset of the default list.

```sh
packet-tools app --format csv --protocols dns,http,tls -o app-tables capture.pcapng
```

Ports only order parser candidates. Each direction is probed independently, including later bytes of a midstream connection, up to 64 KiB per direction. A parser is selected as soon as either direction returns `Certain`, so HTTP, TLS, SSH, FTP, and SMTP can be found on nonstandard ports even when the other direction begins inside a body. Streams with no certain match are recorded as `unknown` in `dispatch` and are not parsed. HTTP and line parsers scan for the next recognizable line after leading damage or a TCP gap; TLS scans for a plausible record boundary. `dispatch.stop_reason` records gaps, failed recovery, and the number of bytes skipped during resynchronization.

`--memory` limits retained TCP reassembly data. `--app-memory` independently limits the deterministic logical size of pending probe data and incomplete parser messages; its default is 256 MiB. The estimate uses retained byte and metadata counts rather than container capacities. If the application limit is exceeded, the oldest undecided stream is abandoned, or a selected parser releases incomplete data and resumes from a recognizable boundary when the protocol permits it. The action is recorded in `dispatch.stop_reason`.

For Parquet output, completed application events are written in bounded batches instead of being retained until the end of the capture. The application-memory limit therefore covers parser state, while completed output remains bounded independently. CSV output preserves capture-order compatibility with earlier releases and is written after analysis.

The directory contains `dns`, `http`, `tls`, `tls_heartbeat`, `ftp`, `ssh`, `smtp`, `telnet`, and `dispatch`, with the selected extension. HTTP/1.x parsing applies to TCP only; UDP HTTP-like protocols such as SSDP are outside this command's HTTP scope. DNS probing also accepts DNS wire messages carried on LLMNR (5355) and mDNS (5353). The event packet `index` and `ts_ns` identify the packet that supplied the final byte, even when `on-ack` releases the bytes later. Fragmented UDP DNS is parsed after IP reassembly. Capture detection, read errors, and exit status match the other commands. See [Application tables](app-tables.md) for the schemas.

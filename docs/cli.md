**English** | [日本語](cli.ja.md)

# CLI

```text
Usage: packet-tools <COMMAND>

Commands:
  validate  Validate capture containers and summarize their records
  packets   Export one row per packet to Parquet or CSV
  help      Print this message or the help of the given subcommand(s)
```

## `validate`

Reads every record of one or more captures and prints a summary per file. It checks that a capture can be read to the end, and it reports what the file contains. It does not dissect packets.

```text
Usage: packet-tools validate [OPTIONS] <FILES>...

Arguments:
  <FILES>...  Capture files to validate

Options:
      --json  Emit one JSON object per line
      --mmap  Memory-map uncompressed regular files instead of reading them through a buffer
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
Usage: packet-tools packets [OPTIONS] --output <OUTPUT> <INPUT>

Arguments:
  <INPUT>  Input capture

Options:
      --fields <FIELDS>  Comma-separated output column names
      --format <FORMAT>  Output format; inferred from .parquet or .csv when omitted [possible values: parquet, csv]
      --limit <LIMIT>    Write at most this many packets
      --depth <DEPTH>    Deepest layer to decode [default: l4] [possible values: l2, l3, l4]
  -o, --output <OUTPUT>  Output file
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

How lengths and fragments are handled:

- The end of the IP datagram is taken from the IP length field, so Ethernet padding is not counted as payload; it is reported in `trailer_len`.
- For IPv4 and IPv6 fragments, the TCP or UDP header is decoded only in the first fragment. Later fragments have no ports. Fragments are not reassembled.
- Headers quoted inside ICMP error messages and tunnelled packets are not decoded.

The exit status is 1 if the capture cannot be read to the end. Rows read before the error are still written, and the output file is closed properly.

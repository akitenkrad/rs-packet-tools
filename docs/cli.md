**English** | [日本語](cli.ja.md)

# CLI

```text
Usage: packet-tools <COMMAND>

Commands:
  validate  Validate capture containers and summarize their records
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

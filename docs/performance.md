**English** | [日本語](performance.ja.md)

# Performance

The measurements below were taken on 2026-10-20 on macOS with 14 cores and 64 GB of memory. Other resident applications kept running during the measurements; the load average before each measurement was 6–9. The benchmark recorder `ptbench` produced every number in the first three sections; see [Recorded benchmark runs](../bench/README.md#recorded-benchmark-runs) for how to reproduce them.

## Parsing speed

`ptbench speedup` runs the same task with three engines: read every packet, decode it, and aggregate IPv4 packets per 5-tuple. Scapy 2.8.0 dissects every layer of each packet; `etherparse` is the minimal Rust baseline in `bench/rsbench`; `packet-tools` is the same program using `packet_tools::capture` and `packet_tools::dissect`. The samples are in the page cache, every engine runs on one thread, and each value is the median of 9 trials. Each trial rotates the order of the three engines. Scapy processes only the first 200,000 packets of the DARPA sample and the first 100,000 packets of the CIC sample.

| Capture | Scapy | etherparse | packet-tools | vs Scapy | vs etherparse |
|---|---:|---:|---:|---:|---:|
| DARPA 1999, first 100 MB (469,340 packets) | 11,538 pkt/s | 22.9 M pkt/s | 24.1 M pkt/s | 2,085× | 1.05× |
| CIC-IDS2017, first 300 MB (234,825 packets) | 14,559 pkt/s | 8.11 M pkt/s | 9.42 M pkt/s | 647× | 1.16× |

## End to end: five days of CIC-IDS2017

`ptbench e2e --jobs 1` processes the five CIC-IDS2017 days from the first byte to the last: 56,370,702 packets in 52.4 GB. The data is on a NAS connected over SMB on 1 GbE and does not fit in the page cache.

| Command | Wall time | CPU time | Read rate | Max RSS |
|---|---:|---:|---:|---:|
| `rsbench` (parse + 5-tuple count) | 463 s | 11.0 s | 113 MB/s | 72 MiB |
| `flows` | 476 s | 39.1 s | 110 MB/s | 2,611 MiB |
| `app` | 481 s | 61.3 s | 109 MB/s | 859 MiB |

At the Scapy rate measured above (14,559 pkt/s), the same packets would take an estimated 3,872 seconds (about 65 minutes), so the end-to-end speed-up is about 8×. All three commands are limited by reading the data: CPU time is at most 13% of wall time. On fast local storage the end-to-end speed-up is expected to approach the parsing speed-up above; this has not been measured.

## File-level parallelism

The 27 DARPA 1999 `inside` captures (53,156,655 packets, 5.4 GB compressed with gzip) were processed from the page cache with `--jobs 1` and `--jobs 8`.

| Command | `--jobs 1` | `--jobs 8` | Speed-up | Max RSS (1 → 8) |
|---|---:|---:|---:|---:|
| `flows` | 54.8 s | 9.4 s | 5.8× | 1,094 → 2,607 MiB |
| `app` | 80.3 s | 15.0 s | 5.3× | 423 → 1,194 MiB |

The output for each input is byte-for-byte identical to a single-input run, whatever the value of `--jobs`; this was checked on these 27 captures. The memory limits apply per job, so total memory grows to about `N` times the per-job use with `--jobs N`. See [Multiple inputs](cli.md#multiple-inputs) for the output layout.

## Cost of `flow_uid` in `packets`

The default `packets` columns include `flow_uid`, which requires running the flow table. On DARPA 1999 week 5 Tuesday (3.4 million packets, gzip), this raises the run time from 4.98 s to 6.39 s (+28%) and the maximum RSS from 66 MiB to 327 MiB. Selecting columns without `flow_uid` with `--fields` skips this work.

## Reading versus dissecting in Scapy

The original comparison in `bench/run.sh` shows where Scapy spends its time. It was measured on an Apple Silicon Mac with the samples in the page cache. Reading the records without dissecting them is fast; full dissection is not. The Rust baseline performs the full 5-tuple aggregation.

| Sample | Scapy, read only | Scapy, full dissection | Rust baseline |
|---|---:|---:|---:|
| DARPA 1999, first 100 MB (classic PCAP, 213 bytes per packet on average) | 1.76 M pkt/s | 10,895 pkt/s | 19.1 M pkt/s |
| CIC-IDS-2017 Wednesday, first 300 MB (pcapng, about 1.3 KB per packet) | 0.63 M pkt/s | 13,385 pkt/s | 5.68 M pkt/s |

See [Packet parsing benchmarks](../bench/README.md) for the procedure.

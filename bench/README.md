# Packet parsing benchmarks

The benchmark compares Scapy with the standalone Rust baseline in `bench/rsbench`. Run all commands from the repository root.

## Prepare input samples

Set `PACKET_TOOLS_DARPA99` to one DARPA-1999 `inside.tcpdump.gz` file and `PACKET_TOOLS_CIC17` to one CIC-IDS-2017 capture file. The samples stay under the ignored `bench/.data/` directory.

```sh
mkdir -p bench/.data
gzip -dc "$PACKET_TOOLS_DARPA99" | head -c 100000000 > bench/.data/darpa99-first-100000000.pcap
head -c 300000000 "$PACKET_TOOLS_CIC17" > bench/.data/cic17-first-300000000.pcap
```

The DARPA sample is decompressed before taking its first 100,000,000 bytes. The CIC sample contains the first 300,000,000 bytes of the source capture.

## Scapy

Create an isolated environment with `uv`, install the pinned Scapy version, and run both the raw-reader and full-dissection measurements. Use 200,000 packets for DARPA and 100,000 for CIC.

```sh
uv venv .venv
uv pip install --python .venv/bin/python scapy==2.8.0
.venv/bin/python -I bench/bench_scapy.py bench/.data/darpa99-first-100000000.pcap 200000
.venv/bin/python -I bench/bench_scapy.py bench/.data/cic17-first-300000000.pcap 100000
```

## Rust baseline

The Rust program reads the complete sample and aggregates IPv4 packets by 5-tuple.

```sh
cargo run --release -p rsbench -- bench/.data/darpa99-first-100000000.pcap
cargo run --release -p rsbench -- bench/.data/cic17-first-300000000.pcap
```

Pass `--json` before the capture path for one-line machine-readable output with unrounded elapsed time and packet rate:

```sh
cargo run -q --release -p rsbench -- --json bench/.data/darpa99-first-100000000.pcap
```

Run `bash bench/run.sh` to prepare both samples, install Scapy, execute all measurements, and print one Markdown results table. The runner reads the Rust rate from this JSON output, rejects missing or non-numeric rates, and includes the integer speed-up over Scapy's full-dissection rate.

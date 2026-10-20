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

## Recorded benchmark runs

`bench/ptbench` is a standalone, unpublished crate with its own lockfile. Build the measured binaries first, then run it from the repository root. Always use `--scratch` for trial runs; they are written below `results/_scratch/bench/` and can be checked with `runvault verify <run-directory>`.

```sh
cargo build --release -p rsbench -p packet-tools
cargo run --manifest-path bench/ptbench/Cargo.toml --release -- \
  --scratch speedup \
  --capture darpa_100m=bench/.data/darpa99-first-100000000.pcap \
  --capture cic_300m=bench/.data/cic17-first-300000000.pcap \
  --scapy-count darpa_100m=200000 --scapy-count cic_300m=100000 \
  --runs 9 --python .venv/bin/python \
  --rsbench target/release/rsbench
```

`speedup` reads every capture once before measurement to warm the page cache. Each trial rotates the order of Scapy, etherparse, and packet-tools. It records medians and speedups in `metrics.csv`, raw observations in `artifacts/speedup_trials.csv`, and start/end load averages in `artifacts/loadavg.csv`.

The end-to-end command measures each requested command in argument order:

```sh
cargo run --manifest-path bench/ptbench/Cargo.toml --release -- \
  --scratch e2e \
  --inputs "$PACKET_TOOLS_DARPA99" "$PACKET_TOOLS_CIC17" \
  --command rsbench --command flows --command app --jobs 2 \
  --packet-tools target/release/packet-tools \
  --rsbench target/release/rsbench \
  --out bench/.work/ptbench \
  --scapy-pkt-per-sec 12000
```

The head-cut captures in `bench/.data/` end in a truncated record, which `flows` and `app` reject, so the example passes complete captures. Each command's CPU time and maximum RSS come from `wait4` on that command's own processes; for `rsbench` the CPU time is summed and the RSS is the largest single run.

`rsbench` runs once per input; `flows` and `app` use one multi-input invocation. `sync` runs immediately before each measured command. No cache-purge or privileged operation is used. The intended 52 GB external-volume run assumes the data does not fit in the page cache. Pass `--sha256sums FILE` to copy existing SHA-256 values into runvault `Dataset` records; ptbench never hashes the 52 GB input set itself. `e2e.<command>.seconds` is the measured target's wall time, distinct from the complete run duration in `status.json`.

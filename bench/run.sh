#!/usr/bin/env bash
set -euo pipefail

scapy_rates() {
    local capture=$1
    local count=$2
    local output
    output=$(.venv/bin/python -I bench/bench_scapy.py "$capture" "$count")
    printf '%s\n' "$output" >&2
    awk '
        /raw read/ { raw = $(NF-1) }
        /full dissect\+5tuple/ { full = $(NF-2) }
        END {
            gsub(/,/, "", raw)
            gsub(/,/, "", full)
            print raw, full
        }
    ' <<< "$output"
}

json_rate() {
    python3 -c '
import json
import math
import sys

try:
    value = json.load(sys.stdin)["pkt_per_sec"]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("pkt_per_sec is not numeric")
    if not math.isfinite(value) or value <= 0:
        raise ValueError("pkt_per_sec is not positive and finite")
except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
    print(f"Invalid rsbench JSON output: {error}", file=sys.stderr)
    raise SystemExit(1)

print(f"{value:.0f}")
'
}

rust_rate() {
    local capture=$1
    local output
    output=$(cargo run --quiet --release -p rsbench -- --json "$capture")
    printf '%s\n' "$output" >&2
    json_rate <<< "$output"
}

validate_rate() {
    local label=$1
    local value=$2
    if ! awk -v value="$value" 'BEGIN {
        exit !(value ~ /^[0-9]+([.][0-9]+)?$/ && value + 0 > 0)
    }'; then
        printf 'Invalid or missing benchmark rate for %s: %s\n' "$label" "${value:-<empty>}" >&2
        return 1
    fi
}

speedup() {
    local rust_rate_value=$1
    local scapy_full_rate=$2
    awk -v rust_rate="$rust_rate_value" -v scapy_rate="$scapy_full_rate" \
        'BEGIN { printf "%.0f\n", rust_rate / scapy_rate }'
}

main() {
    local missing=()
    [[ -n "${PACKET_TOOLS_DARPA99:-}" ]] || missing+=(PACKET_TOOLS_DARPA99)
    [[ -n "${PACKET_TOOLS_CIC17:-}" ]] || missing+=(PACKET_TOOLS_CIC17)
    if (( ${#missing[@]} > 0 )); then
        printf 'Missing required environment variable(s): %s\n' "${missing[*]}" >&2
        return 1
    fi

    local script_dir repo_root data_dir darpa_sample cic_sample
    script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
    repo_root=$(cd -- "$script_dir/.." && pwd)
    cd "$repo_root"

    data_dir=bench/.data
    darpa_sample=$data_dir/darpa99-first-100000000.pcap
    cic_sample=$data_dir/cic17-first-300000000.pcap
    mkdir -p "$data_dir"

    set +o pipefail
    gzip -dc -- "$PACKET_TOOLS_DARPA99" | head -c 100000000 > "$darpa_sample"
    local pipeline_status=("${PIPESTATUS[@]}")
    set -o pipefail
    if (( pipeline_status[1] != 0 )) || (( pipeline_status[0] != 0 && pipeline_status[0] != 141 )); then
        echo 'Failed to extract the DARPA-1999 sample.' >&2
        return 1
    fi
    head -c 300000000 -- "$PACKET_TOOLS_CIC17" > "$cic_sample"

    uv venv .venv >&2
    uv pip install --python .venv/bin/python scapy==2.8.0 >&2

    local darpa_scapy cic_scapy darpa_raw darpa_full cic_raw cic_full
    local darpa_rust cic_rust darpa_speedup cic_speedup
    if ! darpa_scapy=$(scapy_rates "$darpa_sample" 200000); then
        echo 'The DARPA-1999 Scapy benchmark failed.' >&2
        return 1
    fi
    if ! cic_scapy=$(scapy_rates "$cic_sample" 100000); then
        echo 'The CIC-IDS-2017 Scapy benchmark failed.' >&2
        return 1
    fi
    read -r darpa_raw darpa_full <<< "$darpa_scapy"
    read -r cic_raw cic_full <<< "$cic_scapy"
    if ! darpa_rust=$(rust_rate "$darpa_sample"); then
        echo 'The DARPA-1999 Rust benchmark failed.' >&2
        return 1
    fi
    if ! cic_rust=$(rust_rate "$cic_sample"); then
        echo 'The CIC-IDS-2017 Rust benchmark failed.' >&2
        return 1
    fi

    validate_rate 'DARPA-1999 Scapy read-only' "$darpa_raw"
    validate_rate 'DARPA-1999 Scapy full' "$darpa_full"
    validate_rate 'DARPA-1999 Rust' "$darpa_rust"
    validate_rate 'CIC-IDS-2017 Scapy read-only' "$cic_raw"
    validate_rate 'CIC-IDS-2017 Scapy full' "$cic_full"
    validate_rate 'CIC-IDS-2017 Rust' "$cic_rust"

    darpa_speedup=$(speedup "$darpa_rust" "$darpa_full")
    cic_speedup=$(speedup "$cic_rust" "$cic_full")

    printf '| Dataset | Scapy read-only (pkt/s) | Scapy full dissection (pkt/s) | Rust 5-tuple (pkt/s) | Speed-up (Rust / Scapy full) |\n'
    printf '|---|---:|---:|---:|---:|\n'
    printf '| DARPA-1999 | %s | %s | %s | %sx |\n' "$darpa_raw" "$darpa_full" "$darpa_rust" "$darpa_speedup"
    printf '| CIC-IDS-2017 | %s | %s | %s | %sx |\n' "$cic_raw" "$cic_full" "$cic_rust" "$cic_speedup"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi

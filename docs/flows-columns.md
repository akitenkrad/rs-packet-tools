**English** | [日本語](flows-columns.ja.md)

# Flow columns

CSV and Parquet use the same logical types. Counts and byte totals are integers; statistics are
Float64. `--column-names original` removes `flow_uid` and `end_reason`, uses the Original column
below, and also omits CICFlowMeter's `Label`. Original headers are unique, so Parquet needs no
renaming rule.

## Minimal preset

| Column | Type | Meaning |
|---|---|---|
| `flow_uid` | UInt64 | Stable normalized-key and first-time hash |
| `end_reason` | Utf8 | Why the flow was emitted |
| `ip_version` | UInt8 | 4 or 6 |
| `src_ip`, `dst_ip` | Utf8 | Initial endpoints |
| `src_port`, `dst_port` | UInt16 | Transport ports, or zero |
| `protocol` | UInt8 | IP protocol number |
| `first_ts_ns`, `last_ts_ns`, `duration_ns` | Int64 | First, last and elapsed nanoseconds |
| `fwd_packets`, `bwd_packets` | UInt64 | Directional packet counts |
| `fwd_ip_bytes`, `bwd_ip_bytes` | UInt64 | Directional IP bytes |
| `fwd_payload_bytes`, `bwd_payload_bytes` | UInt64 | Directional transport-payload bytes |
| `fwd_tcp_flags`, `bwd_tcp_flags` | UInt16 | Directional bitwise OR of TCP flags |
| `first_index`, `last_index` | UInt64 | First and last `PacketRecord::index` |

## CICFlowMeter preset

The first two rows exist only with snake-case names. `corrected` and `idle-only` have every row;
`cicflowmeter` omits the five rows marked “corrected”.

| snake_case | Original | Type | Meaning |
|---|---|---|---|
| `flow_uid` | — | UInt64 | Stable packet-tools flow identifier |
| `end_reason` | — | Utf8 | Flow termination reason |
| `flow_id` | Flow ID | Utf8 | CICFlowMeter directional five-tuple text |
| `src_ip` | Src IP | Utf8 | Initial source address |
| `src_port` | Src Port | UInt64 | Initial source port |
| `dst_ip` | Dst IP | Utf8 | Initial destination address |
| `dst_port` | Dst Port | UInt64 | Initial destination port |
| `protocol` | Protocol | UInt64 | IP protocol number |
| `timestamp` | Timestamp | Utf8 | UTC first-packet time in policy-specific format |
| `flow_duration` | Flow Duration | Int64 | Last minus first time, microseconds |
| `total_fwd_packets` | Total Fwd Packet | UInt64 | Forward packet count |
| `total_bwd_packets` | Total Bwd packets | UInt64 | Backward packet count |
| `total_fwd_packet_length` | Total Length of Fwd Packet | Float64 | Sum of forward payload lengths |
| `total_bwd_packet_length` | Total Length of Bwd Packet | Float64 | Sum of backward payload lengths |
| `fwd_packet_length_max` | Fwd Packet Length Max | Float64 | Forward payload maximum |
| `fwd_packet_length_min` | Fwd Packet Length Min | Float64 | Forward payload minimum |
| `fwd_packet_length_mean` | Fwd Packet Length Mean | Float64 | Forward payload mean |
| `fwd_packet_length_std` | Fwd Packet Length Std | Float64 | Forward payload sample standard deviation |
| `bwd_packet_length_max` | Bwd Packet Length Max | Float64 | Backward payload maximum |
| `bwd_packet_length_min` | Bwd Packet Length Min | Float64 | Backward payload minimum |
| `bwd_packet_length_mean` | Bwd Packet Length Mean | Float64 | Backward payload mean |
| `bwd_packet_length_std` | Bwd Packet Length Std | Float64 | Backward payload sample standard deviation |
| `flow_bytes_per_second` | Flow Bytes/s | Float64 | Payload bytes per second |
| `flow_packets_per_second` | Flow Packets/s | Float64 | Packets per second |
| `flow_iat_mean` | Flow IAT Mean | Float64 | All-packet inter-arrival mean, microseconds |
| `flow_iat_std` | Flow IAT Std | Float64 | All-packet inter-arrival sample standard deviation |
| `flow_iat_max` | Flow IAT Max | Float64 | Maximum inter-arrival time |
| `flow_iat_min` | Flow IAT Min | Float64 | Minimum inter-arrival time |
| `fwd_iat_total` | Fwd IAT Total | Float64 | Sum of forward inter-arrival times |
| `fwd_iat_mean` | Fwd IAT Mean | Float64 | Forward inter-arrival mean |
| `fwd_iat_std` | Fwd IAT Std | Float64 | Forward inter-arrival sample standard deviation |
| `fwd_iat_max` | Fwd IAT Max | Float64 | Forward inter-arrival maximum |
| `fwd_iat_min` | Fwd IAT Min | Float64 | Forward inter-arrival minimum |
| `bwd_iat_total` | Bwd IAT Total | Float64 | Sum of backward inter-arrival times |
| `bwd_iat_mean` | Bwd IAT Mean | Float64 | Backward inter-arrival mean |
| `bwd_iat_std` | Bwd IAT Std | Float64 | Backward inter-arrival sample standard deviation |
| `bwd_iat_max` | Bwd IAT Max | Float64 | Backward inter-arrival maximum |
| `bwd_iat_min` | Bwd IAT Min | Float64 | Backward inter-arrival minimum |
| `fwd_psh_flags` | Fwd PSH Flags | UInt64 | Directional PSH count |
| `bwd_psh_flags` | Bwd PSH Flags | UInt64 | Directional PSH count |
| `fwd_urg_flags` | Fwd URG Flags | UInt64 | Directional URG count |
| `bwd_urg_flags` | Bwd URG Flags | UInt64 | Directional URG count |
| `fwd_rst_flags` | Fwd RST Flags | UInt64 | Directional RST count (corrected) |
| `bwd_rst_flags` | Bwd RST Flags | UInt64 | Directional RST count (corrected) |
| `fwd_header_length` | Fwd Header Length | UInt64 | Sum of forward transport-header lengths |
| `bwd_header_length` | Bwd Header Length | UInt64 | Sum of backward transport-header lengths |
| `fwd_packets_per_second` | Fwd Packets/s | Float64 | Forward packets per second |
| `bwd_packets_per_second` | Bwd Packets/s | Float64 | Backward packets per second |
| `packet_length_min` | Packet Length Min | Float64 | All-packet payload minimum |
| `packet_length_max` | Packet Length Max | Float64 | All-packet payload maximum |
| `packet_length_mean` | Packet Length Mean | Float64 | All-packet payload mean |
| `packet_length_std` | Packet Length Std | Float64 | All-packet payload sample standard deviation |
| `packet_length_variance` | Packet Length Variance | Float64 | All-packet payload sample variance |
| `fin_flag_count` | FIN Flag Count | UInt64 | TCP FIN count |
| `syn_flag_count` | SYN Flag Count | UInt64 | TCP SYN count |
| `rst_flag_count` | RST Flag Count | UInt64 | TCP RST count |
| `psh_flag_count` | PSH Flag Count | UInt64 | TCP PSH count |
| `ack_flag_count` | ACK Flag Count | UInt64 | TCP ACK count |
| `urg_flag_count` | URG Flag Count | UInt64 | TCP URG count |
| `cwr_flag_count` | CWR Flag Count | UInt64 | TCP CWR count |
| `ece_flag_count` | ECE Flag Count | UInt64 | TCP ECE count |
| `down_up_ratio` | Down/Up Ratio | Float64 | Backward/forward packet ratio |
| `average_packet_size` | Average Packet Size | Float64 | Mean payload length using CICFlowMeter divisor |
| `fwd_segment_size_avg` | Fwd Segment Size Avg | Float64 | Mean forward payload length |
| `bwd_segment_size_avg` | Bwd Segment Size Avg | Float64 | Mean backward payload length |
| `fwd_bytes_per_bulk_avg` | Fwd Bytes/Bulk Avg | UInt64 | Forward bytes per detected bulk |
| `fwd_packets_per_bulk_avg` | Fwd Packet/Bulk Avg | UInt64 | Forward packets per detected bulk |
| `fwd_bulk_rate_avg` | Fwd Bulk Rate Avg | UInt64 | Forward bulk bytes per second |
| `bwd_bytes_per_bulk_avg` | Bwd Bytes/Bulk Avg | UInt64 | Backward bytes per detected bulk |
| `bwd_packets_per_bulk_avg` | Bwd Packet/Bulk Avg | UInt64 | Backward packets per detected bulk |
| `bwd_bulk_rate_avg` | Bwd Bulk Rate Avg | UInt64 | Backward bulk bytes per second |
| `subflow_fwd_packets` | Subflow Fwd Packets | UInt64 | Forward packets divided by subflow count |
| `subflow_fwd_bytes` | Subflow Fwd Bytes | UInt64 | Forward payload bytes divided by subflow count |
| `subflow_bwd_packets` | Subflow Bwd Packets | UInt64 | Backward packets divided by subflow count |
| `subflow_bwd_bytes` | Subflow Bwd Bytes | UInt64 | Backward payload bytes divided by subflow count |
| `fwd_init_win_bytes` | FWD Init Win Bytes | UInt64 | First forward TCP window |
| `bwd_init_win_bytes` | Bwd Init Win Bytes | UInt64 | First backward TCP window |
| `fwd_act_data_packets` | Fwd Act Data Pkts | UInt64 | Forward packets with payload |
| `fwd_segment_size_min` | Fwd Seg Size Min | UInt64 | Minimum forward TCP header length |
| `active_mean` | Active Mean | Float64 | Active-period mean, microseconds |
| `active_std` | Active Std | Float64 | Active-period sample standard deviation |
| `active_max` | Active Max | Float64 | Active-period maximum |
| `active_min` | Active Min | Float64 | Active-period minimum |
| `idle_mean` | Idle Mean | Float64 | Idle-period mean, microseconds |
| `idle_std` | Idle Std | Float64 | Idle-period sample standard deviation |
| `idle_max` | Idle Max | Float64 | Idle-period maximum |
| `idle_min` | Idle Min | Float64 | Idle-period minimum |
| `icmp_code` | ICMP Code | Int64 | Last ICMP code, or -1 (corrected) |
| `icmp_type` | ICMP Type | Int64 | Last ICMP type, or -1 (corrected) |
| `total_tcp_flow_time` | Total TCP Flow Time | Int64 | TCP time carried across corrected splits (corrected) |

## Policy-sensitive values

`cicflowmeter` intentionally retains the original implementation's duplicated first payload in the
all-packet statistics, first-packet-only directional PSH/URG counts, integer `down_up_ratio`,
reference-equality bulk direction, absolute-time Active/Idle bug, subflow expression bug, first-FIN
termination and dropping of one-packet flows. `corrected` uses the Engelen fixes, adds directional
RST and ICMP/TCP-time columns, retains one-packet flows and uses its FIN/RST state machine.
`idle-only` uses the corrected feature accumulator but changes keys, time precision and termination.

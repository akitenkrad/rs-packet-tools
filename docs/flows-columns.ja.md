[English](flows-columns.md) | **日本語**

# フロー列

CSV と Parquet は同じ論理型を使います．件数とバイト数は整数，統計量は Float64 です．`--column-names original` を指定すると `flow_uid` と `end_reason` を除き，下表の «元の列名» を使います．CICFlowMeter の `Label` も出しません．元の列名に重複は無いため，Parquet 用の改名は不要です．

## Minimal プリセット

| 列 | 型 | 意味 |
|---|---|---|
| `flow_uid` | UInt64 | 正規化したキーと最初の時刻から作る安定したハッシュ |
| `end_reason` | Utf8 | フローを出力した理由 |
| `ip_version` | UInt8 | 4 または 6 |
| `src_ip`，`dst_ip` | Utf8 | 最初に決まった端点 |
| `src_port`，`dst_port` | UInt16 | トランスポート層のポート．無ければ 0 |
| `protocol` | UInt8 | IP プロトコル番号 |
| `first_ts_ns`，`last_ts_ns`，`duration_ns` | Int64 | 最初，最後，差分のナノ秒 |
| `fwd_packets`，`bwd_packets` | UInt64 | 方向別のパケット数 |
| `fwd_ip_bytes`，`bwd_ip_bytes` | UInt64 | 方向別の IP バイト数 |
| `fwd_payload_bytes`，`bwd_payload_bytes` | UInt64 | 方向別のトランスポート層ペイロード長 |
| `fwd_tcp_flags`，`bwd_tcp_flags` | UInt16 | 方向別 TCP フラグのビット OR |
| `first_index`，`last_index` | UInt64 | 最初と最後の `PacketRecord::index` |

## CICFlowMeter プリセット

先頭の 2 列は snake_case の出力にだけ付きます．`corrected` と `idle-only` は全列を持ち，`cicflowmeter` は «補正版» と記した 5 列を持ちません．

| snake_case | 元の列名 | 型 | 意味 |
|---|---|---|---|
| `flow_uid` | — | UInt64 | packet-tools の安定したフロー識別子 |
| `end_reason` | — | Utf8 | フローの終了理由 |
| `flow_id` | Flow ID | Utf8 | CICFlowMeter の向き付き 5 タプル文字列 |
| `src_ip`／`dst_ip` | Src IP／Dst IP | Utf8 | 最初に決まった送信元／宛先アドレス |
| `src_port`／`dst_port` | Src Port／Dst Port | UInt64 | 最初に決まった送信元／宛先ポート |
| `protocol` | Protocol | UInt64 | IP プロトコル番号 |
| `timestamp` | Timestamp | Utf8 | 方針ごとの書式による UTC の開始時刻 |
| `flow_duration` | Flow Duration | Int64 | 最後と最初の差，マイクロ秒 |
| `total_fwd_packets`／`total_bwd_packets` | Total Fwd Packet／Total Bwd packets | UInt64 | 方向別パケット数 |
| `total_fwd_packet_length`／`total_bwd_packet_length` | Total Length of Fwd Packet／Total Length of Bwd Packet | Float64 | 方向別ペイロード長の合計 |
| `fwd_packet_length_max`／`min`／`mean`／`std` | Fwd Packet Length Max／Min／Mean／Std | Float64 | 順方向ペイロード長の最大／最小／平均／標本標準偏差 |
| `bwd_packet_length_max`／`min`／`mean`／`std` | Bwd Packet Length Max／Min／Mean／Std | Float64 | 逆方向ペイロード長の最大／最小／平均／標本標準偏差 |
| `flow_bytes_per_second` | Flow Bytes/s | Float64 | 1 秒当たりのペイロードバイト数 |
| `flow_packets_per_second` | Flow Packets/s | Float64 | 1 秒当たりのパケット数 |
| `flow_iat_mean`／`std`／`max`／`min` | Flow IAT Mean／Std／Max／Min | Float64 | 全パケット到着間隔の統計，マイクロ秒 |
| `fwd_iat_total`／`mean`／`std`／`max`／`min` | Fwd IAT Total／Mean／Std／Max／Min | Float64 | 順方向到着間隔の合計と統計 |
| `bwd_iat_total`／`mean`／`std`／`max`／`min` | Bwd IAT Total／Mean／Std／Max／Min | Float64 | 逆方向到着間隔の合計と統計 |
| `fwd_psh_flags`／`bwd_psh_flags` | Fwd PSH Flags／Bwd PSH Flags | UInt64 | 方向別 PSH 数 |
| `fwd_urg_flags`／`bwd_urg_flags` | Fwd URG Flags／Bwd URG Flags | UInt64 | 方向別 URG 数 |
| `fwd_rst_flags`／`bwd_rst_flags` | Fwd RST Flags／Bwd RST Flags | UInt64 | 方向別 RST 数（補正版） |
| `fwd_header_length`／`bwd_header_length` | Fwd Header Length／Bwd Header Length | UInt64 | 方向別トランスポートヘッダ長の合計 |
| `fwd_packets_per_second`／`bwd_packets_per_second` | Fwd Packets/s／Bwd Packets/s | Float64 | 方向別の 1 秒当たりパケット数 |
| `packet_length_min`／`max`／`mean`／`std`／`variance` | Packet Length Min／Max／Mean／Std／Variance | Float64 | 全パケットのペイロード長統計 |
| `fin_flag_count` | FIN Flag Count | UInt64 | TCP FIN 数 |
| `syn_flag_count` | SYN Flag Count | UInt64 | TCP SYN 数 |
| `rst_flag_count` | RST Flag Count | UInt64 | TCP RST 数 |
| `psh_flag_count` | PSH Flag Count | UInt64 | TCP PSH 数 |
| `ack_flag_count` | ACK Flag Count | UInt64 | TCP ACK 数 |
| `urg_flag_count` | URG Flag Count | UInt64 | TCP URG 数 |
| `cwr_flag_count` | CWR Flag Count | UInt64 | TCP CWR 数 |
| `ece_flag_count` | ECE Flag Count | UInt64 | TCP ECE 数 |
| `down_up_ratio` | Down/Up Ratio | Float64 | 逆方向数／順方向数 |
| `average_packet_size` | Average Packet Size | Float64 | CICFlowMeter の除数による平均ペイロード長 |
| `fwd_segment_size_avg`／`bwd_segment_size_avg` | Fwd Segment Size Avg／Bwd Segment Size Avg | Float64 | 方向別の平均ペイロード長 |
| `fwd_bytes_per_bulk_avg`／`bwd_bytes_per_bulk_avg` | Fwd Bytes/Bulk Avg／Bwd Bytes/Bulk Avg | UInt64 | 方向別 bulk 当たりバイト数 |
| `fwd_packets_per_bulk_avg`／`bwd_packets_per_bulk_avg` | Fwd Packet/Bulk Avg／Bwd Packet/Bulk Avg | UInt64 | 方向別 bulk 当たりパケット数 |
| `fwd_bulk_rate_avg`／`bwd_bulk_rate_avg` | Fwd Bulk Rate Avg／Bwd Bulk Rate Avg | UInt64 | 方向別 bulk の 1 秒当たりバイト数 |
| `subflow_fwd_packets`／`subflow_bwd_packets` | Subflow Fwd Packets／Subflow Bwd Packets | UInt64 | 方向別パケット数を subflow 数で割った値 |
| `subflow_fwd_bytes`／`subflow_bwd_bytes` | Subflow Fwd Bytes／Subflow Bwd Bytes | UInt64 | 方向別ペイロード長を subflow 数で割った値 |
| `fwd_init_win_bytes`／`bwd_init_win_bytes` | FWD Init Win Bytes／Bwd Init Win Bytes | UInt64 | 方向ごとの最初の TCP window |
| `fwd_act_data_packets` | Fwd Act Data Pkts | UInt64 | ペイロードを持つ順方向パケット数 |
| `fwd_segment_size_min` | Fwd Seg Size Min | UInt64 | 順方向 TCP ヘッダ長の最小値 |
| `active_mean`／`std`／`max`／`min` | Active Mean／Std／Max／Min | Float64 | 活動期間の統計，マイクロ秒 |
| `idle_mean`／`std`／`max`／`min` | Idle Mean／Std／Max／Min | Float64 | 休止期間の統計，マイクロ秒 |
| `icmp_code` | ICMP Code | Int64 | 最後の ICMP code．無ければ -1（補正版） |
| `icmp_type` | ICMP Type | Int64 | 最後の ICMP type．無ければ -1（補正版） |
| `total_tcp_flow_time` | Total TCP Flow Time | Int64 | 補正版の分割をまたいで引き継ぐ TCP 時間（補正版） |

## 方針によって値が変わる列

`cicflowmeter` は，最初のペイロードを全体統計へ二重に加える処理，最初のパケットだけで決まる方向別 PSH／URG，整数除算の `down_up_ratio`，参照同一性で向きを決める Bulk，絶対時刻が入る Active／Idle，Subflow の式，最初の FIN で閉じる処理，1 パケットのフローを捨てる処理を原典どおり残します．`corrected` は Engelen 版の修正を使い，方向別 RST と ICMP／TCP 時間の列を追加し，1 パケットのフローを残し，FIN／RST の状態遷移に従います．`idle-only` は補正版と同じ特徴量集計器を使い，キー，時刻精度，終了条件だけを変えます．

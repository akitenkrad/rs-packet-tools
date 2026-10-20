[English](flows-columns.md) | **日本語**

# フロー列

CSV と Parquet は同じ論理型を使います．件数とバイト数は整数，統計量は Float64 です．`--column-names original` を指定すると `flow_uid` と `end_reason` を除き，下表の «元の列名» を使います．CICFlowMeter の `Label` も出しません．元の列名に重複は無いため，Parquet 用の改名は不要です．

Parquet の出力を polars で読むには 2.0 以降が必要です．[Parquet の出力を読む](cli.ja.md#parquet-の出力を読む)を参照してください．

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
| `src_ip` | Src IP | Utf8 | 最初に決まった送信元アドレス |
| `src_port` | Src Port | UInt64 | 最初に決まった送信元ポート |
| `dst_ip` | Dst IP | Utf8 | 最初に決まった宛先アドレス |
| `dst_port` | Dst Port | UInt64 | 最初に決まった宛先ポート |
| `protocol` | Protocol | UInt64 | IP プロトコル番号 |
| `timestamp` | Timestamp | Utf8 | 方針ごとの書式による UTC の開始時刻 |
| `flow_duration` | Flow Duration | Int64 | 最後と最初の時刻の差，マイクロ秒 |
| `total_fwd_packets` | Total Fwd Packet | UInt64 | 順方向のパケット数 |
| `total_bwd_packets` | Total Bwd packets | UInt64 | 逆方向のパケット数 |
| `total_fwd_packet_length` | Total Length of Fwd Packet | Float64 | 順方向ペイロード長の合計 |
| `total_bwd_packet_length` | Total Length of Bwd Packet | Float64 | 逆方向ペイロード長の合計 |
| `fwd_packet_length_max` | Fwd Packet Length Max | Float64 | 順方向ペイロード長の最大 |
| `fwd_packet_length_min` | Fwd Packet Length Min | Float64 | 順方向ペイロード長の最小 |
| `fwd_packet_length_mean` | Fwd Packet Length Mean | Float64 | 順方向ペイロード長の平均 |
| `fwd_packet_length_std` | Fwd Packet Length Std | Float64 | 順方向ペイロード長の標本標準偏差 |
| `bwd_packet_length_max` | Bwd Packet Length Max | Float64 | 逆方向ペイロード長の最大 |
| `bwd_packet_length_min` | Bwd Packet Length Min | Float64 | 逆方向ペイロード長の最小 |
| `bwd_packet_length_mean` | Bwd Packet Length Mean | Float64 | 逆方向ペイロード長の平均 |
| `bwd_packet_length_std` | Bwd Packet Length Std | Float64 | 逆方向ペイロード長の標本標準偏差 |
| `flow_bytes_per_second` | Flow Bytes/s | Float64 | 1 秒当たりのペイロードバイト数 |
| `flow_packets_per_second` | Flow Packets/s | Float64 | 1 秒当たりのパケット数 |
| `flow_iat_mean` | Flow IAT Mean | Float64 | 全パケットの到着間隔の平均，マイクロ秒 |
| `flow_iat_std` | Flow IAT Std | Float64 | 全パケットの到着間隔の標本標準偏差 |
| `flow_iat_max` | Flow IAT Max | Float64 | 到着間隔の最大 |
| `flow_iat_min` | Flow IAT Min | Float64 | 到着間隔の最小 |
| `fwd_iat_total` | Fwd IAT Total | Float64 | 順方向の到着間隔の合計 |
| `fwd_iat_mean` | Fwd IAT Mean | Float64 | 順方向の到着間隔の平均 |
| `fwd_iat_std` | Fwd IAT Std | Float64 | 順方向の到着間隔の標本標準偏差 |
| `fwd_iat_max` | Fwd IAT Max | Float64 | 順方向の到着間隔の最大 |
| `fwd_iat_min` | Fwd IAT Min | Float64 | 順方向の到着間隔の最小 |
| `bwd_iat_total` | Bwd IAT Total | Float64 | 逆方向の到着間隔の合計 |
| `bwd_iat_mean` | Bwd IAT Mean | Float64 | 逆方向の到着間隔の平均 |
| `bwd_iat_std` | Bwd IAT Std | Float64 | 逆方向の到着間隔の標本標準偏差 |
| `bwd_iat_max` | Bwd IAT Max | Float64 | 逆方向の到着間隔の最大 |
| `bwd_iat_min` | Bwd IAT Min | Float64 | 逆方向の到着間隔の最小 |
| `fwd_psh_flags` | Fwd PSH Flags | UInt64 | 方向別の PSH 数 |
| `bwd_psh_flags` | Bwd PSH Flags | UInt64 | 方向別の PSH 数 |
| `fwd_urg_flags` | Fwd URG Flags | UInt64 | 方向別の URG 数 |
| `bwd_urg_flags` | Bwd URG Flags | UInt64 | 方向別の URG 数 |
| `fwd_rst_flags` | Fwd RST Flags | UInt64 | 方向別の RST 数（補正版） |
| `bwd_rst_flags` | Bwd RST Flags | UInt64 | 方向別の RST 数（補正版） |
| `fwd_header_length` | Fwd Header Length | UInt64 | 順方向トランスポートヘッダ長の合計 |
| `bwd_header_length` | Bwd Header Length | UInt64 | 逆方向トランスポートヘッダ長の合計 |
| `fwd_packets_per_second` | Fwd Packets/s | Float64 | 順方向の 1 秒当たりパケット数 |
| `bwd_packets_per_second` | Bwd Packets/s | Float64 | 逆方向の 1 秒当たりパケット数 |
| `packet_length_min` | Packet Length Min | Float64 | 全パケットのペイロード長の最小 |
| `packet_length_max` | Packet Length Max | Float64 | 全パケットのペイロード長の最大 |
| `packet_length_mean` | Packet Length Mean | Float64 | 全パケットのペイロード長の平均 |
| `packet_length_std` | Packet Length Std | Float64 | 全パケットのペイロード長の標本標準偏差 |
| `packet_length_variance` | Packet Length Variance | Float64 | 全パケットのペイロード長の標本分散 |
| `fin_flag_count` | FIN Flag Count | UInt64 | TCP FIN 数 |
| `syn_flag_count` | SYN Flag Count | UInt64 | TCP SYN 数 |
| `rst_flag_count` | RST Flag Count | UInt64 | TCP RST 数 |
| `psh_flag_count` | PSH Flag Count | UInt64 | TCP PSH 数 |
| `ack_flag_count` | ACK Flag Count | UInt64 | TCP ACK 数 |
| `urg_flag_count` | URG Flag Count | UInt64 | TCP URG 数 |
| `cwr_flag_count` | CWR Flag Count | UInt64 | TCP CWR 数 |
| `ece_flag_count` | ECE Flag Count | UInt64 | TCP ECE 数 |
| `down_up_ratio` | Down/Up Ratio | Float64 | 逆方向数／順方向数のパケット比 |
| `average_packet_size` | Average Packet Size | Float64 | CICFlowMeter の除数による平均ペイロード長 |
| `fwd_segment_size_avg` | Fwd Segment Size Avg | Float64 | 順方向の平均ペイロード長 |
| `bwd_segment_size_avg` | Bwd Segment Size Avg | Float64 | 逆方向の平均ペイロード長 |
| `fwd_bytes_per_bulk_avg` | Fwd Bytes/Bulk Avg | UInt64 | 順方向の検出した bulk 当たりバイト数 |
| `fwd_packets_per_bulk_avg` | Fwd Packet/Bulk Avg | UInt64 | 順方向の検出した bulk 当たりパケット数 |
| `fwd_bulk_rate_avg` | Fwd Bulk Rate Avg | UInt64 | 順方向 bulk の 1 秒当たりバイト数 |
| `bwd_bytes_per_bulk_avg` | Bwd Bytes/Bulk Avg | UInt64 | 逆方向の検出した bulk 当たりバイト数 |
| `bwd_packets_per_bulk_avg` | Bwd Packet/Bulk Avg | UInt64 | 逆方向の検出した bulk 当たりパケット数 |
| `bwd_bulk_rate_avg` | Bwd Bulk Rate Avg | UInt64 | 逆方向 bulk の 1 秒当たりバイト数 |
| `subflow_fwd_packets` | Subflow Fwd Packets | UInt64 | 順方向パケット数を subflow 数で割った値 |
| `subflow_fwd_bytes` | Subflow Fwd Bytes | UInt64 | 順方向ペイロード長を subflow 数で割った値 |
| `subflow_bwd_packets` | Subflow Bwd Packets | UInt64 | 逆方向パケット数を subflow 数で割った値 |
| `subflow_bwd_bytes` | Subflow Bwd Bytes | UInt64 | 逆方向ペイロード長を subflow 数で割った値 |
| `fwd_init_win_bytes` | FWD Init Win Bytes | UInt64 | 順方向の最初の TCP window |
| `bwd_init_win_bytes` | Bwd Init Win Bytes | UInt64 | 逆方向の最初の TCP window |
| `fwd_act_data_packets` | Fwd Act Data Pkts | UInt64 | ペイロードを持つ順方向パケット数 |
| `fwd_segment_size_min` | Fwd Seg Size Min | UInt64 | 順方向 TCP ヘッダ長の最小値 |
| `active_mean` | Active Mean | Float64 | 活動期間の平均，マイクロ秒 |
| `active_std` | Active Std | Float64 | 活動期間の標本標準偏差 |
| `active_max` | Active Max | Float64 | 活動期間の最大 |
| `active_min` | Active Min | Float64 | 活動期間の最小 |
| `idle_mean` | Idle Mean | Float64 | 休止期間の平均，マイクロ秒 |
| `idle_std` | Idle Std | Float64 | 休止期間の標本標準偏差 |
| `idle_max` | Idle Max | Float64 | 休止期間の最大 |
| `idle_min` | Idle Min | Float64 | 休止期間の最小 |
| `icmp_code` | ICMP Code | Int64 | 最後の ICMP code．無ければ -1（補正版） |
| `icmp_type` | ICMP Type | Int64 | 最後の ICMP type．無ければ -1（補正版） |
| `total_tcp_flow_time` | Total TCP Flow Time | Int64 | 補正版の分割をまたいで引き継ぐ TCP 時間（補正版） |

## 方針によって値が変わる列

`cicflowmeter` は，最初のペイロードを全体統計へ二重に加える処理，最初のパケットだけで決まる方向別 PSH／URG，整数除算の `down_up_ratio`，参照同一性で向きを決める Bulk，絶対時刻が入る Active／Idle，Subflow の式，最初の FIN で閉じる処理，1 パケットのフローを捨てる処理を原典どおり残します．`corrected` は Engelen 版の修正を使い，方向別 RST と ICMP／TCP 時間の列を追加し，1 パケットのフローを残し，FIN／RST の状態遷移に従います．`idle-only` は補正版と同じ特徴量集計器を使い，キー，時刻精度，終了条件だけを変えます．

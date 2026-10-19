[English](cli.md) | **日本語**

# CLI

```text
Usage: packet-tools <COMMAND>

Commands:
  validate  Validate capture containers and summarize their records
  packets   Export one row per packet to Parquet or CSV
  flows     Build bidirectional flows and export one row per completed flow
  streams   Reassemble IP fragments and directional TCP byte streams
  help      Print this message or the help of the given subcommand(s)
```

## `validate`

1 つ以上のキャプチャを最後まで読み，ファイルごとの要約を出します．キャプチャを最後まで読めるかを確かめ，ファイルの中身を報告するためのコマンドです．パケットの解析はしません．

```text
Usage: packet-tools validate [OPTIONS] <FILES>...

Arguments:
  <FILES>...  Capture files to validate

Options:
      --json  Emit one JSON object per line
      --mmap  Memory-map uncompressed regular files instead of reading them through a buffer
```

形式は先頭のバイトで判定するので，`*.pcap` という名前の pcapng ファイルも，gzip で圧縮したキャプチャもそのまま扱えます．対応する入力は，旧形式の PCAP（リトルエンディアンとビッグエンディアン，マイクロ秒とナノ秒），pcapng（セクションとインターフェースの数は問わない），およびそれらを gzip で圧縮したものです．

```sh
$ packet-tools validate tests/fixtures/multi_iface.pcapng tests/fixtures/le_usec.pcap.gz
tests/fixtures/multi_iface.pcapng format=pcapng packets=22 linktypes=1:19,101:3 regressions=1 max_regression=1.000μs truncated_packets=1 truncated tail=false skipped_blocks=- elapsed=0.000076s pkt/s=290909
tests/fixtures/le_usec.pcap.gz format=pcap-le-usec+gzip packets=19 linktypes=1:19 regressions=1 max_regression=1.000μs truncated_packets=1 truncated tail=false skipped_blocks=- elapsed=0.000338s pkt/s=56199
total files=2 packets=41 regressions=2
```

| 項目 | 意味 |
|---|---|
| `format` | コンテナ，バイト順，時刻の分解能．圧縮されていれば `+gzip` が付く |
| `packets` | パケットの件数 |
| `linktypes` | リンク種別ごとのパケット数（`1` は Ethernet，`101` は raw IP） |
| `regressions` | 直前のパケットより時刻が前になっているパケットの数．パケットの並べ替えはしない |
| `max_regression` | その戻り幅のうち最大のもの |
| `truncated_packets` | キャプチャ長が元の長さより短いパケットの数 |
| `truncated tail` | ファイルがレコードの途中で終わっている |
| `skipped_blocks` | パケットを含まない pcapng のブロック（統計，名前解決，カスタムブロック）の，種類ごとの件数 |

`--json` を付けると，ファイルごとにすべての数値（`bytes_captured`，`bytes_original`，`first_ts_ns`，`last_ts_ns`，`min_ts_ns`，`max_ts_ns`，`sections`，`error` を含む）を 1 つの JSON オブジェクトとして出し，最後に `"type": "total"` のオブジェクトを 1 つ出します．

どれかのファイルが読めなかった場合や，レコードの途中で終わっていた場合は終了コード 1，それ以外は 0 です．読めなかったファイルについては，失敗するまでに数えた値を出したうえで，残りのファイルの処理を続けます．

## `packets`

パケットごとに 1 行，L2〜L4 のヘッダの項目を Parquet か CSV に書き出します．

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

Parquet は Snappy で圧縮します．CSV では，値が無いところは空になり，真偽値は `true` / `false` です．`--fields` を指定しなければ全列を書き出します．

| 列 | 型 | 内容 |
|---|---|---|
| `index` | UInt64 | ファイル内のパケットの通し番号（0 始まり） |
| `ts_ns` | Int64 | Unix エポックからのナノ秒 |
| `caplen`，`origlen` | UInt32 | キャプチャ長と元の長さ |
| `linktype`，`interface` | UInt16，UInt32 | リンク種別とインターフェースの番号 |
| `eth_src`，`eth_dst` | Utf8 | MAC アドレス（`aa:bb:cc:dd:ee:ff`） |
| `ethertype` | UInt16 | 最も内側の VLAN タグの後の EtherType（IEEE 802.3 の長さフィールドの場合は null） |
| `vlan_id`，`vlan_depth` | UInt16，UInt8 | 最も外側の VLAN タグの VID と，タグの数 |
| `ip_version` | UInt8 | 4 か 6 |
| `ip_src`，`ip_dst` | Utf8 | アドレス．IPv6 は RFC 5952 の省略表記 |
| `ip_proto` | UInt8 | IPv4 のプロトコル番号，または IPv6 の拡張ヘッダを辿った先の上位プロトコル |
| `ip_ttl` | UInt8 | IPv4 の TTL か IPv6 のホップリミット |
| `ip_len` | UInt32 | IPv4 の全長，または 40 ＋ IPv6 のペイロード長 |
| `ip_id` | UInt32 | IPv4 の識別子，または IPv6 のフラグメントの識別子 |
| `ip_frag_offset` | UInt32 | フラグメントのオフセット（バイト単位） |
| `ip_mf`，`ip_df` | Boolean | More Fragments と Don't Fragment のフラグ（IPv6 の `ip_df` は null） |
| `src_port`，`dst_port` | UInt16 | TCP か UDP のポート |
| `tcp_flags` | UInt16 | NS を含む TCP の 12 ビットのフラグ |
| `tcp_seq`，`tcp_ack`，`tcp_window` | UInt32，UInt32，UInt16 | 生の値（相対値にせず，ウィンドウスケールも掛けない） |
| `udp_length` | UInt16 | UDP の長さフィールド |
| `icmp_type`，`icmp_code` | UInt8 | ICMPv4 か ICMPv6 の type と code |
| `l4_payload_len` | UInt32 | TCP か UDP のペイロード長 |
| `trailer_len` | UInt32 | IP データグラムの終わりより後ろのバイト数（Ethernet のパディングなど） |
| `ip_truncated` | Boolean | IP の長さフィールドが，キャプチャされたバイト数より大きい |
| `malformed` | Utf8 | 壊れたヘッダで解析が止まった位置．`<layer>:<kind>@<offset>` の形（例 `ipv4:bad_length@14`） |

長さとフラグメントの扱い:

- IP データグラムの終わりは IP の長さフィールドから決めます．そのため Ethernet のパディングはペイロードに数えず，`trailer_len` に入ります．
- IPv4 と IPv6 のフラグメントでは，TCP と UDP のヘッダは最初の断片でだけ解析します．2 つ目以降の断片にはポートがありません．フラグメントの再組み立てはしません．
- ICMP のエラーメッセージの中に引用されたヘッダや，トンネルの中のパケットは解析しません．

キャプチャを最後まで読めなかった場合は終了コード 1 です．エラーまでに読んだ行は書き出し，出力ファイルも正しく閉じます．

## `flows`

キャプチャの順に双方向フローを組み立て，CSV または Snappy 圧縮の Parquet に書き出します．

```text
Usage: packet-tools flows [OPTIONS] --output <OUTPUT> <INPUT>

Arguments:
  <INPUT>  Input capture

Options:
      --policy <POLICY>                      [default: corrected] [possible values: corrected, cicflowmeter, idle-only]
      --preset <PRESET>                      [default: cicflowmeter] [possible values: cicflowmeter, minimal]
      --flow-timeout <FLOW_TIMEOUT>          [default: 120]
      --activity-timeout <ACTIVITY_TIMEOUT>  [default: 5]
      --idle-timeout <IDLE_TIMEOUT>          [default: 60]
      --vlan-in-key
      --column-names <COLUMN_NAMES>          [default: snake] [possible values: snake, original]
      --format <FORMAT>                      [possible values: parquet, csv]
  -o, --output <OUTPUT>                      出力ファイル
```

```sh
packet-tools flows --policy corrected -o flows.parquet capture.pcapng
packet-tools flows --policy cicflowmeter --column-names original -o official-shape.csv capture.pcap
packet-tools flows --policy idle-only --preset minimal --idle-timeout 30 --vlan-in-key \
    -o minimal.csv capture.pcap
```

`corrected` は GintsEngelen/CICFlowMeter のコミット `13a0615` の動作を再現する既定の方針です．`cicflowmeter` は，Engelen らが fork する前の最後の版である ahlashkari/CICFlowMeter のコミット `9d91f72` を，既知の特徴量の誤りや最初の FIN で閉じる処理も含めて再現します．CIC-IDS-2017 の公式のフロー CSV はそれより前のリリース（CICFlowMeter-V3）で作られたので，いくつかの列はこの方針と値が違います．全体タイムアウトの既定値は 120 秒です．活動タイムアウトの 5 秒は Active／Idle 特徴量だけに使い，フローを閉じません．`idle-only` は packet-tools 独自の正規化した 5 タプル方針です．既定では最後のパケットから 60 秒で閉じ，ナノ秒時刻を使います．`--vlan-in-key` を指定すると最も外側の VLAN ID もキーに入れます．

snake_case のスキーマは `flow_uid,end_reason` から始まります．終了理由は `fin`，`rst`，`flow_timeout`，`idle_timeout`，`end_of_capture`，`icmp_type_code_change` です．`--column-names original` は `cicflowmeter` プリセットでだけ使えます．この場合は `flow_uid`，`end_reason`，`Label` を出さず，選んだ Java 実装と同じ順と UTC の時刻表記を使います．`cicflowmeter` は `dd/MM/yyyy hh:mm:ss a`，`corrected` は `yyyy-MM-dd HH:mm:ss[.SSSSSS]` です．元のスキーマにも snake_case 側にも，重複した列名はありません．

minimal プリセットは 21 列です．互換プリセットは packet-tools の 2 列を加える前に，原典方針で 83 列，補正版方針で 88 列です．詳しくは[フロー列](flows-columns.ja.md)を参照してください．

形式の推定と読み込みエラーの扱いは `packets` と同じです．`.parquet` と `.csv` から形式を決め，キャプチャのエラーより前に完成したフローを書き出してから終了コード 1 を返します．

## `streams`

IPv4／IPv6 フラグメントを再び組み立て，完成した raw IP を解析してから，TCP の各方向を再構成します．

```text
Usage: packet-tools streams [OPTIONS] --output <OUTPUT> <INPUT>

Options:
      --ip-policy <IP_POLICY>          [default: bsd]
      --tcp-policy <TCP_POLICY>        [default: bsd]
      --delivery <DELIVERY>            [default: on-ack] [possible values: on-ack, immediate]
      --defrag-timeout <SECONDS>       [default: 60]
      --tcp-timeout <SECONDS>          [default: 3600]
      --stream-memory <BYTES>          [default: 4194304]
      --memory <BYTES>                 [default: 1073741824]
      --vlan-in-key
      --events <FILE>
      --datagrams <FILE>
      --dump-dir <DIRECTORY>
      --format <FORMAT>                [possible values: parquet, csv]
  -o, --output <OUTPUT>
```

```sh
packet-tools streams --tcp-policy linux --events overlap.csv --datagrams datagrams.csv \
    --dump-dir streams -o streams.parquet capture.pcapng
```

IP 方針は `first`，`last`，`bsd`，`linux`，`windows`，`solaris` です．`first` は常に既存を残し，`last` は常に新しい断片を使います．`bsd` は新しい断片が既存より前から始まるときに新しい側を使い，`linux` は同じ位置から始まる場合も新しい側を使います．`windows` は新しい断片が既存より前から始まり，かつ既存の終端より先まで続く場合に使います．`solaris` は終端が同じ場合も新しい側を使います．

TCP 方針は `first`，`last`，`bsd`，`linux`，`old-linux`，`solaris` です．別名は，`vista` が `first`，`windows`，`macos`，`hpux10`，`irix` が `bsd`，`hpux11` が `solaris` です．既定では既存を残し，`last` だけは常に新しい側を使います．新しいセグメントが既存より前から始まる場合，`bsd`，`linux`，`old-linux` は新しい側を使い，`solaris` はさらに既存の終端以上まで続く場合に使います．開始位置が同じ場合，`linux` は既存より先まで続く場合，`old-linux` と `solaris` は終端が同じ場合も新しい側を使います．既存の途中から始まる場合は，`solaris` だけが，既存の終端より先まで続く新しい側を使います．

`on-ack` は相手が ACK した位置まで配送を待つため，配送前に届いた重なりへ方針を適用できます．`immediate` は連続した prefix がそろった時点で配送します．配送済みのバイトは変更せず，あとから内容の異なる重なりが来た場合は `tcp_late_overlap_conflict` を記録します．SYN，FIN，RST がなく，payload が 0 または 1 バイトで，sequence number が次に期待するバイトの 1 つ前にある segment は keepalive として数え，buffer へ入れず，重なりとしても扱いません．FIN の完了，受理した RST，timeout，capture の終端では残りを配送し，届いていない範囲を gap として渡します．

IP 断片と TCP payload は，重ならない区間として保持します．`--stream-memory` と `--memory` は，sequence space の欠けた範囲ではなく，payload の capacity と区間の管理領域を算入します．遅れて届いた重なりの食い違いを検出するため，各方向で配送済み payload の直近 1 MiB までを残しますが，`--stream-memory` の半分を上限とし，この履歴も上限に算入します．TCP の上限に達した場合は，届いている最古の区間まで進み，必要な gap と `tcp_memory_limit` を出します．

受理した RST または双方の FIN が完了した後も，閉じた接続を 60 秒の closing timeout が過ぎるまで key に対応づけて残します．その間の SYN（ACK なし）以外の packet は配送せず，packet 数と payload bytes を `post_close_packets` と `post_close_bytes` に数えます．payload がある packet ごとに `tcp_data_after_close` を記録します．SYN（ACK なし）は直ちに新しい接続を開始し，closing timeout 後は任意の packet が新しい midstream 接続を開始できます．

ストリーム表は接続・方向ごとに 1 行です．列は `stream_id`，`flow_uid`，`direction`，client/server のアドレスとポート，`first_ts_ns`，`last_ts_ns`，`midstream`，`bytes`，`segments`，`gaps`，`gap_bytes`，`overlaps`，`overlap_conflicts`，`retransmitted_bytes`，`post_close_packets`，`post_close_bytes`，`keepalives`，`close_reason`，`sha256` です．hash は gap を除いて配送済みデータを連結した値です．`--dump-dir` は同じバイト列を `<stream_id>.c2s.bin` と `<stream_id>.s2c.bin` に保存します．

事象表には `ip_overlap`，`ip_overlap_conflict`，`ip_timeout`，`ip_too_large`，`ip_too_many_fragments`，`ip_memory_limit`，`tcp_overlap_conflict`，`tcp_late_overlap_conflict`，`tcp_data_after_close`，`tcp_memory_limit`，`tcp_rst_ignored` と，該当するキー，範囲，残した側を記録します．データグラム表には，完成時の packet index，IP 版，アドレス，識別子，protocol，断片数，再構成後の長さ，payload の SHA-256 を記録します．

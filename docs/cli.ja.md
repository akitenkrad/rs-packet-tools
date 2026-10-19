[English](cli.md) | **日本語**

# CLI

```text
Usage: packet-tools <COMMAND>

Commands:
  validate  Validate capture containers and summarize their records
  packets   Export one row per packet to Parquet or CSV
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

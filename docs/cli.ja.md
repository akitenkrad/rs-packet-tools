[English](cli.md) | **日本語**

# CLI

```text
High-performance packet analysis tools

Usage: packet-tools <COMMAND>

Commands:
  validate  Validate capture containers and summarize their records
  packets   Export one row per packet to Parquet or CSV
  flows     Build bidirectional flows and export one row per completed flow
  streams   Reassemble IP fragments and directional TCP byte streams
  app       Parse reassembled streams and UDP datagrams into application-layer tables
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

## 複数入力

すべてのサブコマンドが `--jobs N`（既定 1）を受け取ります．ワーカーは次の未処理入力を順次取得し，1 個のキャプチャの中は 1 スレッドで処理します．`validate` は結果を保持し，入力順に出力します．ほかのコマンドでは，入力が 1 個なら従来のファイルまたはディレクトリ出力を保ちます．

入力が 2 個以上なら，`-o` は出力ディレクトリです．存在しなければ作り，存在する場合は空でなければなりません．`--format` を省略したときは Parquet を使います．各キャプチャのディレクトリ名には，入力どうしの最長共通親ディレクトリより下のパス全体を使います．入力のファイル名もディレクトリ名に含むため，同じ basename は衝突しません．たとえば `a/week5/tuesday/inside.tcpdump.gz` は `OUT/week5/tuesday/inside.tcpdump.gz/` になります．

各ディレクトリには，`packets.<ext>`，`flows.<ext>`，`streams.<ext>` と `events.<ext>` と `datagrams.<ext>` の 3 表，または通常の `app` 表一式を書きます．複数入力の `streams` では `--events`，`--datagrams`，`--dump-dir` を指定できません．同じ入力の重複もエラーです．`OUT/inputs.csv` は `input_id,input,output_dir,packets,status,error` を引数の順に記録します．1 入力が失敗しても残りを処理し，すべてのワーカーが終わった後で失敗一覧を標準エラーへ出し，終了コード 1 を返します．

`--memory`，`--app-memory`，`--stream-memory` はジョブごとの上限です．したがって `--jobs N` の全体では，選んだジョブ単位の上限のおよそ N 倍まで使うことがあります．計測した短縮率とメモリ使用量は[性能](performance.ja.md#ファイル単位の並列)にあります．

## `validate`

1 つ以上のキャプチャを最後まで読み，ファイルごとの要約を出します．キャプチャを最後まで読めるかを確かめ，ファイルの中身を報告するためのコマンドです．パケットの解析はしません．

```text
Validate capture containers and summarize their records

Usage: packet-tools validate [OPTIONS] <FILES>...

Arguments:
  <FILES>...  Capture files to validate

Options:
      --json         Emit one JSON object per line
      --mmap         Memory-map uncompressed regular files instead of reading them through a buffer
      --jobs <JOBS>  Number of capture files to process concurrently [default: 1]
  -h, --help         Print help
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
Export one row per packet to Parquet or CSV

Usage: packet-tools packets [OPTIONS] --output <OUTPUT> <INPUTS>...

Arguments:
  <INPUTS>...  Input captures

Options:
      --fields <FIELDS>              Comma-separated output column names
      --format <FORMAT>              Output format; inferred from .parquet or .csv when omitted [possible values: parquet, csv]
      --limit <LIMIT>                Write at most this many packets
      --depth <DEPTH>                Deepest layer to decode [default: l4] [possible values: l2, l3, l4]
      --policy <POLICY>              Flow grouping and termination policy used by flow_uid [default: corrected] [possible values: corrected, cicflowmeter, idle-only]
      --flow-timeout <FLOW_TIMEOUT>  Maximum flow age in seconds for compatibility policies [default: 120]
      --idle-timeout <IDLE_TIMEOUT>  IdleOnly expiration in seconds [default: 60]
      --vlan-in-key                  Include the outermost VLAN identifier in IdleOnly flow keys
      --jobs <JOBS>                  Number of capture files to process concurrently [default: 1]
  -o, --output <OUTPUT>              Output file, or output directory for multiple inputs
  -h, --help                         Print help
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
| `flow_uid` | UInt64 | 選んだ方針でパケットを受け入れたフローの識別子．数えないパケットは null |

`flow_uid` は既定列の最後です．`flows` と同じ設定の `FlowTable` にパケットを通して作るため，方針とタイムアウトによって値が変わります．`--fields` で `flow_uid` を選ばなければ，フロー表を作りません．フロー表にかかる費用は[性能](performance.ja.md#packets-の-flow_uid-にかかる費用)を参照してください．`cicflowmeter` は互換性のため，受理した 1 パケットだけのフローを `flows` に出しません．そのため，対応するフロー行がない `flow_uid` を packets 行が持つことがあります．

長さとフラグメントの扱い:

- IP データグラムの終わりは IP の長さフィールドから決めます．そのため Ethernet のパディングはペイロードに数えず，`trailer_len` に入ります．
- IPv4 と IPv6 のフラグメントでは，TCP と UDP のヘッダは最初の断片でだけ解析します．2 つ目以降の断片にはポートがありません．フラグメントの再組み立てはしません．
- ICMP のエラーメッセージの中に引用されたヘッダや，トンネルの中のパケットは解析しません．

キャプチャを最後まで読めなかった場合は終了コード 1 です．エラーまでに読んだ行は書き出し，出力ファイルも正しく閉じます．

## `flows`

キャプチャの順に双方向フローを組み立て，CSV または Snappy 圧縮の Parquet に書き出します．

```text
Build bidirectional flows and export one row per completed flow

Usage: packet-tools flows [OPTIONS] --output <OUTPUT> <INPUTS>...

Arguments:
  <INPUTS>...  Input captures

Options:
      --policy <POLICY>
          Flow grouping and termination policy [default: corrected] [possible values: corrected, cicflowmeter, idle-only]
      --preset <PRESET>
          Output feature preset [default: cicflowmeter] [possible values: cicflowmeter, minimal]
      --flow-timeout <FLOW_TIMEOUT>
          Maximum flow age in seconds for compatibility policies [default: 120]
      --activity-timeout <ACTIVITY_TIMEOUT>
          Gap in seconds used for Active/Idle feature statistics [default: 5]
      --idle-timeout <IDLE_TIMEOUT>
          IdleOnly expiration in seconds [default: 60]
      --vlan-in-key
          Include the outermost VLAN identifier in IdleOnly flow keys
      --column-names <COLUMN_NAMES>
          Output column naming convention [default: snake] [possible values: snake, original]
      --format <FORMAT>
          Output format; inferred from .parquet or .csv when omitted [possible values: parquet, csv]
      --jobs <JOBS>
          Number of capture files to process concurrently [default: 1]
  -o, --output <OUTPUT>
          Output file, or output directory for multiple inputs
  -h, --help
          Print help
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
Reassemble IP fragments and directional TCP byte streams

Usage: packet-tools streams [OPTIONS] --output <OUTPUT> <INPUTS>...

Arguments:
  <INPUTS>...  Input captures

Options:
      --ip-policy <IP_POLICY>
          IP fragment overlap resolution policy [default: bsd] [possible values: first, last, bsd, linux, windows, solaris]
      --tcp-policy <TCP_POLICY>
          TCP segment overlap resolution policy [default: bsd] [possible values: first, vista, last, bsd, windows, macos, hpux10, irix, linux, old-linux, old_linux, solaris, hpux11]
      --delivery <DELIVERY>
          When to deliver reassembled TCP bytes [default: on-ack] [possible values: on-ack, immediate]
      --defrag-timeout <DEFRAG_TIMEOUT>
          IP fragment reassembly timeout in seconds [default: 60]
      --tcp-timeout <TCP_TIMEOUT>
          TCP connection inactivity timeout in seconds [default: 3600]
      --stream-memory <STREAM_MEMORY>
          Maximum retained TCP reassembly memory per direction in bytes [default: 4194304]
      --memory <MEMORY>
          Maximum retained reassembly memory in bytes [default: 1073741824]
      --vlan-in-key
          Include the outermost VLAN identifier in reassembly keys
      --events <EVENTS>
          Event table output file; unavailable with multiple inputs
      --datagrams <DATAGRAMS>
          Datagram table output file; unavailable with multiple inputs
      --dump-dir <DUMP_DIR>
          Directory for delivered TCP bytes; unavailable with multiple inputs
      --format <FORMAT>
          Output format; inferred from .parquet or .csv when omitted [possible values: parquet, csv]
      --jobs <JOBS>
          Number of capture files to process concurrently [default: 1]
  -o, --output <OUTPUT>
          Output file, or output directory for multiple inputs
  -h, --help
          Print help
```

`--defrag-timeout` と `--tcp-timeout` は秒，`--stream-memory` と `--memory` はバイト単位です．`-o` はストリーム表の出力先です．`--events` と `--datagrams` は省略可能な事象表とデータグラム表の出力先，`--dump-dir` は配送したバイト列を保存するディレクトリです．

```sh
packet-tools streams --tcp-policy linux --events overlap.csv --datagrams datagrams.csv \
    --dump-dir streams -o streams.parquet capture.pcapng
```

IP 方針は `first`，`last`，`bsd`，`linux`，`windows`，`solaris` です．`first` は常に既存を残し，`last` は常に新しい断片を使います．`bsd` は新しい断片が既存より前から始まるときに新しい側を使い，`linux` は同じ位置から始まる場合も新しい側を使います．`windows` は新しい断片が既存より前から始まり，かつ既存の終端より先まで続く場合に使います．`solaris` は終端が同じ場合も新しい側を使います．

TCP 方針は `first`，`last`，`bsd`，`linux`，`old-linux`，`solaris` です．別名は，`vista` が `first`，`windows`，`macos`，`hpux10`，`irix` が `bsd`，`old_linux` が `old-linux`，`hpux11` が `solaris` です．名前の大文字と小文字は区別しません．既定では既存を残し，`last` だけは常に新しい側を使います．新しいセグメントが既存より前から始まる場合，`bsd`，`linux`，`old-linux` は新しい側を使い，`solaris` はさらに既存の終端以上まで続く場合に使います．開始位置が同じ場合，`linux` は既存より先まで続く場合，`old-linux` と `solaris` は終端が同じ場合も新しい側を使います．既存の途中から始まる場合は，`solaris` だけが，既存の終端より先まで続く新しい側を使います．

`on-ack` は相手が ACK した位置まで配送を待つため，配送前に届いた重なりへ方針を適用できます．`immediate` は連続した prefix がそろった時点で配送します．配送済みのバイトは変更せず，あとから内容の異なる重なりが来た場合は `tcp_late_overlap_conflict` を記録します．SYN，FIN，RST がなく，payload が 0 または 1 バイトで，sequence number が次に期待するバイトの 1 つ前にある segment は keepalive として数え，buffer へ入れず，重なりとしても扱いません．FIN の完了，受理した RST，timeout，capture の終端では残りを配送し，届いていない範囲を gap として渡します．

IP 断片と TCP payload は，重ならない区間として保持します．`--stream-memory` と `--memory` は，sequence space の欠けた範囲や allocator の capacity ではなく，保持中の payload byte 数と論理的な区間 metadata を算入します．遅れて届いた重なりの食い違いを検出するため，各方向で配送済み payload の直近 1 MiB までを残しますが，`--stream-memory` の半分を上限とし，この履歴も上限に算入します．TCP の上限に達した場合は，届いている最古の区間まで進み，必要な gap と `tcp_memory_limit` を出します．見積りは allocation address や scheduling ではなく，入力 packet 列だけで決まります．

受理した RST または双方の FIN が完了した後も，閉じた接続を 60 秒の closing timeout が過ぎるまで key に対応づけて残します．その間の SYN（ACK なし）以外の packet は配送せず，packet 数と payload bytes を `post_close_packets` と `post_close_bytes` に数えます．payload がある packet ごとに `tcp_data_after_close` を記録します．SYN（ACK なし）は直ちに新しい接続を開始し，closing timeout 後は任意の packet が新しい midstream 接続を開始できます．

ストリーム表は接続・方向ごとに 1 行です．列は `stream_id`，`flow_uid`，`direction`，client/server のアドレスとポート，`first_ts_ns`，`last_ts_ns`，`midstream`，`bytes`，`segments`，`gaps`，`gap_bytes`，`overlaps`，`overlap_conflicts`，`retransmitted_bytes`，`post_close_packets`，`post_close_bytes`，`keepalives`，`close_reason`，`sha256` です．hash は gap を除いて配送済みデータを連結した値です．`--dump-dir` は同じバイト列を `<stream_id>.c2s.bin` と `<stream_id>.s2c.bin` に保存します．

事象表には `ip_overlap`，`ip_overlap_conflict`，`ip_timeout`，`ip_too_large`，`ip_too_many_fragments`，`ip_memory_limit`，`tcp_overlap_conflict`，`tcp_late_overlap_conflict`，`tcp_data_after_close`，`tcp_memory_limit`，`tcp_rst_ignored` と，該当するキー，範囲，残した側を記録します．データグラム表には，完成時の packet index，IP 版，アドレス，識別子，protocol，断片数，再構成後の長さ，payload の SHA-256 を記録します．

## `app`

IP フラグメントと TCP ストリームを再構成し，アプリ層の事象を解析して，選んだプロトコルごとの表へ書き出します．

```text
Parse reassembled streams and UDP datagrams into application-layer tables

Usage: packet-tools app [OPTIONS] --output <OUTPUT> <INPUTS>...

Arguments:
  <INPUTS>...  Input captures

Options:
      --ip-policy <IP_POLICY>    IP fragment overlap resolution policy [default: bsd] [possible values: first, last, bsd, linux, windows, solaris]
      --tcp-policy <TCP_POLICY>  TCP segment overlap resolution policy [default: bsd] [possible values: first, vista, last, bsd, windows, macos, hpux10, irix, linux, old-linux, old_linux, solaris, hpux11]
      --delivery <DELIVERY>      When to deliver reassembled TCP bytes [default: on-ack] [possible values: on-ack, immediate]
      --memory <MEMORY>          Maximum retained reassembly memory in bytes [default: 1073741824]
      --app-memory <APP_MEMORY>  Maximum application probe and parser buffer memory in bytes [default: 268435456]
      --protocols <PROTOCOLS>    Comma-separated application protocols to parse [default: dns,http,tls,ftp,ssh,smtp,telnet]
      --format <FORMAT>          Output table format [default: parquet] [possible values: parquet, csv]
      --jobs <JOBS>              Number of capture files to process concurrently [default: 1]
  -o, --output <OUTPUT>          Output directory, or parent output directory for multiple inputs
  -h, --help                     Print help
```

`-o` は出力ディレクトリです．`--memory` と `--app-memory` はバイト単位，`--protocols` は既定の一覧から選んだプロトコルをカンマ区切りで並べます．

```sh
packet-tools app --format csv --protocols dns,http,tls -o app-tables capture.pcapng
```

ポート番号は解析器の候補を並べるためだけに使います．midstream 接続では後から届くバイト列も含め，各方向を独立に 64 KiB まで調べます．どちらか一方の `probe` が `Certain` を返した時点で解析器を決めるため，反対方向が本文の途中から始まっていても，標準外のポートにある HTTP，TLS，SSH，FTP，SMTP を検出できます．確実に判定できなかったストリームは `dispatch` に `unknown` として残し，解析しません．先頭の壊れたバイト列や TCP の gap がある場合，HTTP と行指向の解析器は次の識別可能な行から再開し，TLS は妥当なレコード境界を探します．gap，再開できない理由，再同期で読み飛ばしたバイト数は `dispatch.stop_reason` に残ります．

`--memory` は TCP 再構成が保持するデータを制限します．`--app-memory` は probe 待ちのデータと解析途中のメッセージについて，保持中の byte 数と metadata 数から決まる論理サイズの合計を別に制限し，既定値は 256 MiB です．コンテナの capacity は使いません．上限を超えると，未判定のストリームは古いものから判定を中止します．解析器を選択済みの場合は，そのプロトコルで可能なら未完成のデータを解放し，識別できる次の境界から再開します．実施内容は `dispatch.stop_reason` に残ります．

Parquet では，完成したアプリ層事象を有界なバッチで逐次書き出し，capture の終端まで保持しません．このため，アプリ層の上限は解析器の状態を制御し，完成済みの出力も別に有界になります．CSV は従来版との capture 順の互換性を保つため，解析の終了後に書き出します．

出力ディレクトリには，選んだ形式の `dns`，`http`，`tls`，`tls_heartbeat`，`ftp`，`ssh`，`smtp`，`telnet`，`dispatch` を作ります．HTTP/1.x の対象は TCP だけであり，SSDP のような UDP 上の HTTP 形式は対象外です．DNS の wire 形式として判定できる LLMNR（5355）と mDNS（5353）は DNS 表に含めます．事象の `index` と `ts_ns` は，最後のバイトを運んだ packet を指します．`on-ack` であとから配送された場合も ACK packet にはなりません．フラグメント化された UDP DNS は IP 再構成の後に解析します．入力形式の判定，読み込みエラー，終了コードはほかのコマンドと同じです．スキーマは[アプリ層の表](app-tables.ja.md)を参照してください．

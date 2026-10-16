[English](cli.md) | **日本語**

# CLI

```text
Usage: packet-tools <COMMAND>

Commands:
  validate  Validate capture containers and summarize their records
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

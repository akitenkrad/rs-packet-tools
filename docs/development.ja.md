[English](development.md) | **日本語**

# 開発

## 検査

CI は push とプルリクエストのたびに次を実行します．変更を送る前に手元でも実行してください．

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI はさらに合成キャプチャを作り直し，1 バイトでも変わったら失敗します（下記）．

## 合成キャプチャ

公開されている侵入検知データセットは再配布できないので，試験には `tests/fixtures/` の小さな合成キャプチャを使います．合成キャプチャは `packet-tools-fixtures` で生成し，リポジトリにコミットしています．

```sh
cargo run -p packet-tools-fixtures -- --out tests/fixtures
```

生成は決定的です．もう一度実行しても，すべてのファイルがバイト単位で同じになる必要があります．

| ファイル | 形式 |
|---|---|
| `le_usec.pcap` | 旧形式の PCAP，リトルエンディアン，マイクロ秒 |
| `be_usec.pcap` | 旧形式の PCAP，ビッグエンディアン，マイクロ秒 |
| `le_nsec.pcap` | 旧形式の PCAP，リトルエンディアン，ナノ秒 |
| `be_nsec.pcap` | 旧形式の PCAP，ビッグエンディアン，ナノ秒 |
| `le_usec.pcap.gz` | `le_usec.pcap` を gzip で圧縮したもの |
| `multi_iface.pcapng` | 2 つのインターフェースを持つ pcapng（マイクロ秒の Ethernet と，ナノ秒の raw IP） |

旧形式の 4 ファイルと gzip のファイルは，同じ 19 個の Ethernet フレームを持ちます．内訳は次のとおりです．

- TCP の 3-way handshake
- HTTP/1.1 のリクエストとレスポンス
- 双方の FIN による接続の終了
- DNS の問い合わせと応答
- IPv6 の UDP パケット
- ARP 要求
- 802.1Q のタグ付きフレーム
- 2 つに分割された IPv4 フラグメント
- スナップ長で切られたフレーム
- Ethernet のパディングが付いたフレーム
- 直前より時刻が 1 μs 戻るフレーム

pcapng のほうは，2 つ目のインターフェースに raw IP のパケットを 3 つ加えています（計 22 パケット）．

`tests/fixtures/manifest.json` がこれらのファイルの正解表です．パケットごとに，ナノ秒の時刻，キャプチャ長と元の長さ，リンク種別，インターフェースを記録しています．試験では，2 つの独立した読み込み実装（`pcap-file` と `pcap-parser`）でファイルを読み直し，正解表と照合します．Wireshark の `tshark` でも，6 ファイルすべてがエラーなしで解読されることを確かめています．

後段の試験用に，さらに 3 つのディレクトリにシナリオのキャプチャがあります．それぞれの README に，何を網羅しているかを書いています．

| ディレクトリ | 中身 |
|---|---|
| `tests/fixtures/flows/` | `scenarios.pcap` と，2 つの CICFlowMeter の参照実装がそこから作ったフロー CSV（`scenarios.cicflowmeter-9d91f72.csv`，`scenarios.corrected-13a0615.csv`）．CSV は外部の参照出力なので，生成プログラムが書き換えてはいけない |
| `tests/fixtures/reassembly/` | `scenarios.pcap` と，Sturges & Novak の重なり試験の入力と期待値を収めた `sturges_novak_ip.json`，`sturges_novak_tcp.json` |
| `tests/fixtures/app/` | DNS，HTTP，TLS，FTP，SSH，SMTP，Telnet を含む `scenarios.pcap`．`tshark` で確かめてある |

実データを使う試験は，パスを環境変数で受け取ります．変数が無ければ，その試験は飛ばします．`PACKET_TOOLS_CFM_REF` には，`in/` にキャプチャ，`orig/`（ahlashkari 版）と `engelen/`（GintsEngelen 版）に対応する CICFlowMeter の出力を置いたディレクトリを指定します．試験は両方の方針の結果をそれらの CSV と比べます．`PACKET_TOOLS_CFM_DAY` には 1 日分のキャプチャを 1 つ指定し，フロー表のメモリ使用量を確かめます．

## ベンチマーク

`bench/` では，Scapy と最小限の Rust の比較対象（`bench/rsbench`．`pcap-file` と `etherparse` で作った試作）を同じ処理で比べます．処理は，全パケットを読み，IPv4 のバイト数を 5 タプルごとに足し合わせるものです．`rsbench --engine packet-tools` は同じ処理を `packet_tools::capture` と `packet_tools::dissect` で行います．既定は `--engine etherparse` です．詳しい手順は [`bench/README.ja.md`](../bench/README.ja.md) にあります．要点は次のとおりです．

```sh
export PACKET_TOOLS_DARPA99=/path/to/inside.tcpdump.gz
export PACKET_TOOLS_CIC17=/path/to/Wednesday-workingHours.pcap
bash bench/run.sh
```

このスクリプトは，それぞれのキャプチャの先頭を切り出し，`uv` で作った仮想環境に Scapy 2.8.0 を入れ，両方を実行して結果を Markdown の表で出力します．独立 crate の `bench/ptbench` は，解析部分の速度と端から端までの計測を runvault の run として記録します．[runvault に記録する計測](../bench/README.ja.md#runvault-に記録する計測)を参照してください．

切り出したファイルでの 1 回の実行は数十ミリ秒と短いので，ほかに負荷の無い状態で測り，中央値で比べてください．計測結果は[性能](performance.ja.md)にあります．

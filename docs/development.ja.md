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

実データを使う試験は，データセットのパスを環境変数で受け取ります．変数が無ければ，その試験は飛ばします．

## ベンチマーク

`bench/` では，Scapy と最小限の Rust の比較対象（`bench/rsbench`．`pcap-file` と `etherparse` で作った試作）を同じ処理で比べます．処理は，全パケットを読み，IPv4 のバイト数を 5 タプルごとに足し合わせるものです．詳しい手順は [`bench/README.md`](../bench/README.md)（英語）にあります．要点は次のとおりです．

```sh
export PACKET_TOOLS_DARPA99=/path/to/inside.tcpdump.gz
export PACKET_TOOLS_CIC17=/path/to/Wednesday-workingHours.pcap
bash bench/run.sh
```

このスクリプトは，それぞれのキャプチャの先頭を切り出し，`uv` で作った仮想環境に Scapy 2.8.0 を入れ，両方を実行して結果を Markdown の表で出力します．

Apple Silicon の Mac で，切り出したファイルがページキャッシュに載った状態での結果です．

| 切り出したデータ | Scapy（読むだけ） | Scapy（全層を解析） | Rust の比較対象 |
|---|---:|---:|---:|
| DARPA 1999 の先頭 100 MB（旧形式 PCAP，平均 213 バイト/パケット） | 176 万 pkt/s | 10,895 pkt/s | 1,910 万 pkt/s |
| CIC-IDS-2017 水曜の先頭 300 MB（pcapng，約 1.3 KB/パケット） | 63 万 pkt/s | 13,385 pkt/s | 568 万 pkt/s |

CIC-IDS-2017 の 1 日分をまるごと外付けディスクから読む場合は，Rust の比較対象は CPU ではなくディスクの速度（私たちの環境では約 110 MB/s）で頭打ちになります．

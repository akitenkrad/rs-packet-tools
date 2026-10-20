[English](README.md) | **日本語**

# パケット解析のベンチマーク

このベンチマークは，Scapy と `bench/rsbench` にある単独の Rust の比較対象を比べます．コマンドはすべてリポジトリの最上位で実行してください．

## 入力の切り出し

`PACKET_TOOLS_DARPA99` に DARPA-1999 の `inside.tcpdump.gz` を 1 つ，`PACKET_TOOLS_CIC17` に CIC-IDS-2017 のキャプチャを 1 つ指定します．切り出したファイルは，git が無視する `bench/.data/` に置きます．

```sh
mkdir -p bench/.data
gzip -dc "$PACKET_TOOLS_DARPA99" | head -c 100000000 > bench/.data/darpa99-first-100000000.pcap
head -c 300000000 "$PACKET_TOOLS_CIC17" > bench/.data/cic17-first-300000000.pcap
```

DARPA のファイルは展開してから先頭の 100,000,000 バイトを取ります．CIC のファイルは，元のキャプチャの先頭 300,000,000 バイトです．

## Scapy

`uv` で独立した環境を作り，版を固定した Scapy を入れて，読むだけの計測と全層を解析する計測の両方を実行します．DARPA では 200,000 パケット，CIC では 100,000 パケットを使います．

```sh
uv venv .venv
uv pip install --python .venv/bin/python scapy==2.8.0
.venv/bin/python -I bench/bench_scapy.py bench/.data/darpa99-first-100000000.pcap 200000
.venv/bin/python -I bench/bench_scapy.py bench/.data/cic17-first-300000000.pcap 100000
```

## Rust の比較対象

Rust のプログラムは切り出したファイルを最後まで読み，IPv4 のパケットを 5 タプルごとに集計します．既定では `etherparse` で解析します．`--engine packet-tools` を渡すと，代わりに `packet_tools::capture` と `packet_tools::dissect` で解析します．

```sh
cargo run --release -p rsbench -- bench/.data/darpa99-first-100000000.pcap
cargo run --release -p rsbench -- bench/.data/cic17-first-300000000.pcap
```

キャプチャのパスの前に `--json` を付けると，丸めていない経過時間とパケット速度を 1 行の機械可読な形式で出します．

```sh
cargo run -q --release -p rsbench -- --json bench/.data/darpa99-first-100000000.pcap
```

`bash bench/run.sh` は，2 つの切り出し，Scapy の導入，すべての計測を行い，結果を 1 つの Markdown の表で出力します．Rust の速度はこの JSON 出力から読み，値が無いものや数値でないものは受け付けません．表には，Scapy の全層解析の速度に対する整数の倍率も入ります．

## runvault に記録する計測

`bench/ptbench` は，独自の lockfile を持つ非公開の独立 crate です．先に計測対象のバイナリをビルドしてから，リポジトリの最上位で実行します．試行用の run には必ず `--scratch` を付けます．run は `results/_scratch/bench/` の下に作られ，`runvault verify <run-directory>` で検査できます．

```sh
cargo build --release -p rsbench -p packet-tools
cargo run --manifest-path bench/ptbench/Cargo.toml --release -- \
  --scratch speedup \
  --capture darpa_100m=bench/.data/darpa99-first-100000000.pcap \
  --capture cic_300m=bench/.data/cic17-first-300000000.pcap \
  --scapy-count darpa_100m=200000 --scapy-count cic_300m=100000 \
  --runs 9 --python .venv/bin/python \
  --rsbench target/release/rsbench
```

`speedup` は計測の前に各ファイルを 1 回読み，ページキャッシュへ載せます．試行ごとに Scapy，etherparse，packet-tools の順を回し，中央値と倍率を `metrics.csv`，各試行の観測値を `artifacts/speedup_trials.csv`，開始時と終了時の負荷平均を `artifacts/loadavg.csv` に記録します．

端から端までの計測は，指定したコマンドを引数の順に 1 つずつ測ります．

```sh
cargo run --manifest-path bench/ptbench/Cargo.toml --release -- \
  --scratch e2e \
  --inputs "$PACKET_TOOLS_DARPA99" "$PACKET_TOOLS_CIC17" \
  --command rsbench --command flows --command app --jobs 2 \
  --packet-tools target/release/packet-tools \
  --rsbench target/release/rsbench \
  --out bench/.work/ptbench \
  --scapy-pkt-per-sec 12000
```

`bench/.data/` の切り出しは末尾のレコードが途中で切れており，`flows` と `app` はこれを受け付けないので，例では完全なキャプチャを渡します．各コマンドの CPU 時間と最大 RSS は，そのコマンド自身のプロセスを `wait4` で回収したときの値です．`rsbench` は CPU 時間を合計し，RSS は 1 回の実行の最大を取ります．

`rsbench` は入力ごとに 1 回ずつ実行し，`flows` と `app` は複数入力を 1 回で処理します．計測する各コマンドの直前に `sync` を呼びます．ページキャッシュを捨てる操作や，管理者権限が必要な操作は行いません．想定している 52 GB の外部ボリュームでの計測は，データがページキャッシュに収まらない前提です．既存の SHA-256 を runvault の `Dataset` に写す場合は `--sha256sums FILE` を渡します．ptbench 自体は 52 GB の入力のハッシュを計算しません．`e2e.<command>.seconds` は計測対象の壁時計時間であり，run 全体の時間（`status.json` の `duration_sec`）とは別です．

これらの計測の結果は[性能](../docs/performance.ja.md)にまとめています．

[English](README.md) | **日本語**

# パケット解析のベンチマーク

`bench/rsbench` は，Scapy と比較する単独の Rust 実装です．入力の切り出し，Scapy 環境の作成，従来の `bench/run.sh` の使い方は英語版と同じです．作業用のキャプチャは，git が無視する `bench/.data/` に置きます．

```sh
mkdir -p bench/.data
gzip -dc "$PACKET_TOOLS_DARPA99" | head -c 100000000 > bench/.data/darpa99-first-100000000.pcap
head -c 300000000 "$PACKET_TOOLS_CIC17" > bench/.data/cic17-first-300000000.pcap
uv venv .venv
uv pip install --python .venv/bin/python scapy==2.8.0
cargo build --release -p rsbench -p packet-tools
```

## runvault に記録する計測

`bench/ptbench` は，独自の lockfile を持つ非公開の独立 crate です．試行用の run には必ず `--scratch` を付けます．run は `results/_scratch/bench/` の下に作られ，`runvault verify <run-directory>` で検査できます．

```sh
cargo run --manifest-path bench/ptbench/Cargo.toml --release -- \
  --scratch speedup \
  --capture darpa_100m=bench/.data/darpa99-first-100000000.pcap \
  --capture cic_300m=bench/.data/cic17-first-300000000.pcap \
  --scapy-count darpa_100m=200000 --scapy-count cic_300m=100000 \
  --runs 9 --python .venv/bin/python \
  --rsbench target/release/rsbench
```

`speedup` は最初に各ファイルを 1 回読み，ページキャッシュへ載せます．試行ごとに Scapy，etherparse，packet-tools の順を回し，中央値と倍率を `metrics.csv`，各試行を `artifacts/speedup_trials.csv`，開始時と終了時の負荷平均を `artifacts/loadavg.csv` に記録します．

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

`bench/.data/` の切り出しは末尾のレコードが途中で切れており，`flows` と `app` はこれを受け付けないので，例では完全なキャプチャを渡します．各コマンドの CPU 時間と最大 RSS は，そのコマンドのプロセスを `wait4` で回収したときの値です．`rsbench` は CPU 時間を合計し，RSS は 1 回の実行の最大を取ります．

`rsbench` は入力ごとに 1 回ずつ実行し，`flows` と `app` は複数入力を 1 回で処理します．各コマンドの直前に `sync` を呼びますが，ページキャッシュを捨てる操作や管理者権限が必要な操作は行いません．外付けボリュームの 52 GB はページキャッシュに収まりきらない前提です．既存の SHA-256 を runvault の `Dataset` に記録する場合は `--sha256sums FILE` を渡します．ptbench 自体は 52 GB のハッシュを計算しません．`e2e.<command>.seconds` は計測対象の処理時間であり，run 全体の時間の正本は `status.json` の `duration_sec` です．

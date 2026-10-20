<p align="center"><img src="docs/assets/hero.svg" width="100%"></p>

[English](README.md) | **日本語**

# packet-tools

`packet-tools` は，PCAP と pcapng のキャプチャをオフラインで高速に解析する Rust のライブラリと CLI です．侵入検知データセットのような研究用途で，Scapy の代わりに使える速さを目指しています．パケット単位の項目の取り出し，終了条件を選べる双方向フローとフロー特徴量の計算，IP フラグメントと TCP ストリームの再構成，アプリ層のプロトコル（DNS，HTTP/1.x，TLS，FTP，SSH，SMTP，Telnet）の解析を行い，結果を Parquet か CSV に書き出します．

> **状況: 開発の初期段階（M6）．** キャプチャの読み込み，L2〜L4 のパケット表，双方向フロー表，CICFlowMeter 互換のフロー特徴量，IP／TCP 再構成，アプリ層の解析，ファイル単位の並列処理を実装済みです．計画は[アーキテクチャ](docs/architecture.ja.md)を見てください．

## インストール

crates.io にはまだ公開していません．Rust の安定版ツールチェーン（1.94 以降）でソースからビルドしてください．

```sh
git clone https://github.com/akitenkrad/rs-packet-tools.git
cd rs-packet-tools
cargo build --release
cargo run -p packet-tools -- --version
```

## ドキュメント

- [CLI](docs/cli.ja.md): `packet-tools` コマンド
- [ライブラリ](docs/library.ja.md): Rust からキャプチャを読み，解析する
- [フロー列](docs/flows-columns.ja.md): フロー表のスキーマと CICFlowMeter の列名との対応
- [アプリ層の表](docs/app-tables.ja.md): アプリ層の出力スキーマ
- [アーキテクチャ](docs/architecture.ja.md): crate の構成，設計の方針，マイルストーン
- [開発](docs/development.ja.md): 試験，合成キャプチャ，CI，ベンチマーク

## M6 の変更

5 つの CLI サブコマンドは，1 個以上のキャプチャと `--jobs N` を受け取ります．入力が 1 個なら，出力先と動作は従来どおりです．複数入力では，`packets`，`flows`，`streams`，`app` が入力どうしの最長共通親ディレクトリより下のパスを `-o` の下に保ち，入力順の結果を `inputs.csv` に記録します．

既定の `packets` スキーマの最後に `flow_uid` を追加しました．値は `flows` と同じ，方針に依存する `FlowTable` の状態機械が割り当てます．`--fields` で `flow_uid` を選ばなければ，この処理は行いません．配置と失敗時の動作は [CLI リファレンス](docs/cli.ja.md#複数入力)を参照してください．

## ライセンス

[Apache License, Version 2.0](LICENSE-APACHE) と [MIT license](LICENSE-MIT) のどちらかを選んで利用できます．CICFlowMeter 由来の動作については[第三者ライセンス表示](THIRD_PARTY_NOTICES.md)も参照してください．

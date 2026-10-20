[English](architecture.md) | **日本語**

# アーキテクチャ

## なぜ新しいパケットライブラリを作るのか

Scapy は便利ですが，パケットを読んだ時点で全層を Python のオブジェクトにします．手元の計測では，Scapy でキャプチャを読むだけなら毎秒 60 万〜180 万パケット出ますが，全層を解析すると毎秒約 1.1 万〜1.3 万パケットまで落ちます．遅いのは解析で，ファイルの読み込みではありません．同じ 5 タプル集計を Rust の試作で行うと，同じデータで毎秒 570 万〜1,900 万パケットでした．これらと，その後に packet-tools 自体を測った結果は[性能](performance.ja.md)に，再現方法は[開発](development.ja.md#ベンチマーク)にあります．

## 設計の方針

| Scapy | packet-tools |
|---|---|
| 層ごとにオブジェクトと値の辞書を作る | 元のバイト列を借りて，アクセスしたときに値を読むビュー型 |
| 全層を先に解析する | 指定した深さ（`L2`，`L3`，`L4`）までしか解析しない．再構成とアプリ層の解析は，求めたときだけ動く別の段 |
| 次の層を `bind_layers` の表から選ぶ（ポート番号だけで判断する） | L2〜L4 は EtherType と IP のプロトコル番号で `match` する．アプリ層はポート番号で候補を絞り，中身で確かめる |
| 時刻を浮動小数点で持つ | 時刻をナノ秒の整数（`i64`）で持つ |
| 失敗したら `Raw` に落とす | `Raw` に落としたうえで，どの層のどの位置で何が起きたかを記録する |

そのほかの決めごと:

- ファイル形式はマジックナンバーで判定し，拡張子は見ません．公開データセットには，中身が pcapng なのに `*.pcap` という名前のファイルがあります．
- パケットはファイル内の順序を保ちます．時刻の逆行は数えますが，並べ替えはしません．
- フローの終了条件は «方針» として選べます．`corrected`（既定）は，双方の FIN か RST で TCP のフローを閉じます．`cicflowmeter` は CICFlowMeter の挙動（最初の FIN でフローを閉じる）まで再現します．公開されている CSV と結果を比べるためです．
- TCP セグメントや IP フラグメントが重なったときの解釈も方針として選べます（IP は `first`，`last`，`bsd`，`linux`，`windows`，`solaris`，TCP は `first`，`last`，`bsd`，`linux`，`old-linux`，`solaris`）．監視装置と終端ホストが，同じ重なりを別々に解釈しうるためです．規則は [`streams`](cli.ja.md#streams) を参照してください．

## crate の構成

| crate | 役割 |
|---|---|
| `packet-tools` | 下の crate を再エクスポートする窓口のライブラリと，`packet-tools` CLI |
| `packet-tools-capture` | PCAP，pcapng，gzip 圧縮されたキャプチャの読み込みと形式の判定 |
| `packet-tools-dissect` | L2〜L4 のゼロコピーなビュー型と，必要になってから作る層の索引 |
| `packet-tools-flow` | 双方向フロー表，終了方針，流しながら更新するフロー特徴量 |
| `packet-tools-reassembly` | IPv4/IPv6 のフラグメントの再組み立てと，TCP ストリームの再構成 |
| `packet-tools-app` | アプリ層の解析器と，その登録の仕組み |
| `packet-tools-export` | Parquet と CSV への書き出し |

このほか，公開しない workspace のメンバーが 2 つあります．`packet-tools-fixtures` は試験用の合成キャプチャを作り，`bench/rsbench` はベンチマークで使う Rust の比較対象です．workspace から除外した独立 crate `bench/ptbench` は，ベンチマーク専用の依存を workspace の CI に加えず，runvault に計測 run を記録します．

データは次の順に crate を通ります．

```text
capture -> dissect -> flow ----------------------> export
                   \-> reassembly -> app --------> export
           dissect (per-packet fields) ----------> export
```

## 出力

| 表 | 1 行の単位 | 主な列 |
|---|---|---|
| `packets` | パケット | ファイル内の通し番号，時刻，キャプチャ長と元の長さ，選んだ L2〜L4 の項目，`flow_uid` |
| `flows` | フロー | `flow_uid`，キー，開始時刻と終了時刻，終了理由，フロー特徴量 |
| `streams` | 接続の片方向 | `flow_uid`，終端点，渡したバイト数，欠落，重なり，終了理由，ペイロードのハッシュ |
| `events`，`datagrams` | 再構成の事象，再構成した IP データグラム | パケットの通し番号，キー，範囲，残した側．断片数，長さ，ペイロードのハッシュ |
| `dns`，`http`，`tls` など | アプリ層の事象 | `flow_uid`，パケットの通し番号，プロトコルごとの項目 |
| `dispatch` | アプリ層の解析器に渡した TCP ストリームか UDP フロー | `flow_uid`，選んだプロトコル，probe の方向とバイト数，停止理由 |
| `inputs.csv` | 複数入力の実行での各入力 | 入力のパス，出力ディレクトリ，パケット数，状態，エラー |

表どうしは `flow_uid` でつなぎます．ファイルごとのキャプチャの統計（パケット数，形式，リンク種別，時刻の逆行，切り詰められたパケット）は表にしません．`validate` がテキストか JSON の行として出します．

## マイルストーン

最初のリリースのマイルストーンはすべて完了しています．

| | 範囲 | 状態 |
|---|---|---|
| M0 | workspace，合成キャプチャ，CI，ベンチマーク | 完了 |
| M1 | `packet-tools-capture`: PCAP，pcapng，gzip の読み込み | 完了 |
| M2 | `packet-tools-dissect` と `packets` 表 | 完了 |
| M3 | `packet-tools-flow` と `flows` 表 | 完了 |
| M4 | `packet-tools-reassembly` | 完了 |
| M5 | `packet-tools-app` | 完了 |
| M6 | ファイル単位の並列化，packets の `flow_uid`，ベンチマークの記録 | 完了 |

パケットの生成とライブキャプチャは対象外です．キャプチャはファイルから読むか，`Capture::from_reader` で任意の `Read`（パイプラインの標準入力など）から読みます．

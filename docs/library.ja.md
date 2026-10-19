[English](library.md) | **日本語**

# ライブラリ

窓口の crate `packet-tools` に依存すると，ほかの crate をモジュール（`packet_tools::capture`，`packet_tools::dissect` など）として使えます．`packet-tools-capture` のように個々の crate に依存してもかまいません．crates.io にはまだ公開していないので，git で依存してください．

```toml
[dependencies]
packet-tools = { git = "https://github.com/akitenkrad/rs-packet-tools" }
```

## キャプチャを読む（`packet_tools::capture`）

```rust
use packet_tools::capture::{Capture, CaptureError};

fn main() -> Result<(), CaptureError> {
    let path = std::env::args().nth(1).expect("usage: docex <capture>");
    let mut capture = Capture::open(&path)?; // format is detected from the leading bytes
    let mut bytes = 0u64;
    while let Some(record) = capture.next_record() {
        let record = record?; // borrows from `capture` until the next call
        bytes += record.data.len() as u64;
        if let Some(ts_ns) = record.ts_ns {
            let _ = (record.index, ts_ns, record.linktype, record.interface);
        }
    }
    let stats = capture.stats();
    println!("{:?}: {} packets, {} bytes, {} backward timestamps",
        capture.format(), stats.packets, bytes, stats.timestamp_regressions);
    Ok(())
}
```

- `Capture::open` は内部のバッファを通してファイルを読みます．`Capture::open_with(path, OpenOptions { mmap: true })` を使うと，非圧縮のファイルをメモリマップで読みます．既定がバッファ読み込みなのは，計測でそちらが速かったためです．レコードを 1 つずつ貸し出す方式なので，メモリマップにしてもコピーは減りません．
- `Capture::from_reader` は標準入力などの任意の `Read` を受け付けます．gzip の判定もここで行います．
- `next_record` が返す `PacketRecord` は，次に呼び出すまでの間だけ借りられます．保持したい場合は `record.data` をコピーしてください．

### `PacketRecord`

| 項目 | 意味 |
|---|---|
| `index` | ファイル内のパケットの通し番号（0 始まり） |
| `ts_ns` | Unix エポックからのナノ秒（整数）．時刻を持たない pcapng の Simple Packet Block の場合だけ `None` |
| `caplen`，`origlen` | キャプチャ長と，回線上の元の長さ |
| `linktype` | インターフェースのリンク種別（`LinkType(1)` は Ethernet） |
| `interface` | `Capture::interfaces()` の添字．pcapng のすべてのセクションを通した番号（旧形式の PCAP では常に 0） |
| `data` | キャプチャされたバイト列（`caplen` バイト） |

レコードはファイルの順に返し，並べ替えはしません．`CaptureStats` は，直前のパケットより時刻が前になっているパケットを数えます．

### エラー

エラーは 1 回だけ返し，その後の `next_record` は `None` を返します．ファイルがレコードの途中で終わっている場合は，完全なレコードをすべて返したあとに `CaptureError::TruncatedRecord` を返し，`stats().truncated_tail` が `true` になります．壊れた pcapng のブロックには，バイト位置と理由を添えた `CaptureError::Corrupt` を返します．キャプチャ長が 64 MiB を超えるものは，メモリを確保せずに壊れたデータとして扱います．

## L2〜L4 を解析する（`packet_tools::dissect`）

```rust
use packet_tools::capture::Capture;
use packet_tools::dissect::{decode, DecodeDepth, Ipv4View, TcpView, UdpView};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).expect("usage: docex <capture>");
    let mut capture = Capture::open(&path)?;
    while let Some(record) = capture.next_record() {
        let record = record?;
        let packet = decode(record.data, record.linktype, DecodeDepth::L4);
        let Some(ip) = packet.layer::<Ipv4View>() else { continue };
        if let Some(tcp) = packet.layer::<TcpView>() {
            println!("{} {}:{} -> {}:{} flags={:#05x} payload={}B",
                record.index, ip.src(), tcp.src_port(), ip.dst(), tcp.dst_port(),
                tcp.flags(), packet.payload().len());
        } else if let Some(udp) = packet.layer::<UdpView>() {
            println!("{} {}:{} -> {}:{} udp", record.index, ip.src(), udp.src_port(), ip.dst(), udp.dst_port());
        }
        if let Some(m) = packet.malformed() {
            eprintln!("packet {}: {:?}", record.index, m);
        }
    }
    Ok(())
}
```

`decode(data, linktype, depth)` は，`depth`（`L2`，`L3`，`L4`）までの層の位置を見つけ，小さな `Packet` 値を返します．メモリの確保はしません．ヘッダの値は，ビューのアクセサを呼んだときに元のバイト列から読みます．

| メソッド | 返すもの |
|---|---|
| `layer::<T>()` | ビュー型 `T` の最初の層．無ければ `None` |
| `layers_of::<T>()` | 型 `T` のすべての層（積み重なった VLAN タグなど） |
| `layers()` | 解析した各層の `LayerKind`（外側から順に） |
| `payload()` | 最も深く解析した層より後ろのバイト列（パディングを除く） |
| `trailer()` | IP データグラムの終わりより後ろのバイト列（Ethernet のパディングなど） |
| `malformed()` | 壊れたヘッダで解析が止まった位置（`layer`，`offset`，`kind`） |
| `ip_truncated()` | IP の長さが，キャプチャされたバイト数を超えているか |

対応するリンク種別は，Ethernet（1），raw IP（101，12，14），Linux cooked capture の v1 と v2（113，276），BSD のループバック（0，108）です．ビューは `EthernetView`，`VlanView`，`LinuxSllView`，`LinuxSll2View`，`NullView`，`ArpView`，`Ipv4View`，`Ipv6View`，`Icmpv4View`，`Icmpv6View`，`TcpView`，`UdpView` があります．IPv6 の拡張ヘッダは辿って上位プロトコルを求めます（`Ipv6View::upper_protocol`）．チェックサムは解析の途中では検査しません．必要なときに `Ipv4View`，`TcpView`，`UdpView` の `verify_checksum` を呼んでください．

長さとフラグメントの扱いは，[CLI](cli.ja.md#packets) の文書にある `packets` 表の規則と同じです．

## フローを組み立てる（`packet_tools::flow`）

`FlowTable` に，解析済みのパケットをキャプチャの順で渡します．選んだ方針で閉じたフローは，`push` の返り値から受け取れます．キャプチャの末尾で `finish()` を 1 回呼び，残ったフローを取り出します．

```rust
use packet_tools::capture::Capture;
use packet_tools::dissect::{decode, DecodeDepth};
use packet_tools::flow::{FlowConfig, FlowTable, Policy};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = Capture::open("capture.pcap")?;
    let mut table = FlowTable::new(FlowConfig {
        policy: Policy::Corrected,
        ..FlowConfig::default()
    });
    while let Some(record) = capture.next_record() {
        let record = record?;
        let packet = decode(record.data, record.linktype, DecodeDepth::L4);
        for flow in table.push(&record, &packet) {
            println!("{} {}", flow.flow_uid, flow.end_reason.as_str());
        }
    }
    for flow in table.finish() {
        println!("{} {}", flow.flow_uid, flow.end_reason.as_str());
    }
    Ok(())
}
```

既定値は，`Corrected`，`CicFlowMeter` プリセット，全体タイムアウト 120 秒，活動タイムアウト 5 秒，IdleOnly タイムアウト 60 秒です．`CicFlowMeter` は，既知の特徴量の誤りや最初の FIN で閉じる動作も含め，ahlashkari 版を再現します．`Corrected` は，双方の FIN と最後の ACK を扱う状態遷移や，1 パケットのフローを残す処理を含め，Engelen 版を再現します．両方の互換方針は，時刻をマイクロ秒へ切り捨て，キャプチャの順を変えません．`IdleOnly` は正規化したキーとナノ秒時刻を使い，それまでに見た最大の時刻を基準に期限切れを判定します．`vlan_in_key` を指定すると，最も外側の VLAN ID をキーに加えます．ICMP echo のキーには type と identifier が入ります．

`EndReason` の値は `fin`，`rst`，`flow_timeout`，`idle_timeout`，`end_of_capture`，`icmp_type_code_change` です．各方針では，その状態遷移で起こりうる値だけを出します．

### 安定したフロー識別子

`flow_uid` は 64 ビット FNV-1a（初期値 `0xcbf29ce484222325`，素数 `0x100000001b3`）です．ハッシュへ渡すバイト列は，IP 版，プロトコル，VLAN の有無と VLAN ID のビッグエンディアン表現，正規化後の第 1 アドレスとポート，第 2 アドレスとポート，ICMP type の有無と値，ICMP identifier の有無とビッグエンディアン表現，最初の時刻を符号付き 64 ビットのビッグエンディアンで表したナノ秒，の順です．IPv4 アドレスは 4 バイト，IPv6 アドレスは 16 バイトです．packets 表や今後のアプリ層の表から同じ値を計算できるように，この形式を固定します．

スキーマと，方針によって値が変わる特徴量は[フロー列](flows-columns.ja.md)にまとめています．

## 再構成（`packet_tools::reassembly`）

`Defragmenter::push(&PacketRecord, &Packet)` は解析済み packet を受け取り，完成した `ReassembledDatagram` と型付きの `IpEvent` を返します．完成したデータグラムは `decode(bytes, LinkType(101), DecodeDepth::L4)` に渡せる raw IP のバイト列を所有します．IPv4 では全長，fragment field，checksum を直します．IPv6 では Fragment header より前の extension header を保ち，Fragment header を除き，next-header chain と payload length を直します．`DefragConfig` で方針，VLAN key，timeout，断片数，データグラム長，memory の上限を設定できます．断片の payload は開始位置順の重ならない区間として保持するため，大きな offset に孤立した断片があっても，欠けた prefix の領域は確保しません．`Defragmenter::estimated_memory_bytes` は，上限に算入する payload の capacity と区間の管理領域を返します．

`TcpReassembler::push` には通常の解析済み TCP packet と，再び解析した完成データグラムのどちらも渡せます．出力の `TcpItem` は `Start`，`Data`，`Gap`，`PostClose`，`End` です．`StreamChunk` は接続 ID，方向，0 始まりの stream position，`Arc<[u8]>` に加え，元 packet の index と時刻を持つ source range を含みます．`source_at` で各バイトの元 packet を調べられます．既定は `DeliveryMode::OnAck` で，`Immediate` は連続した prefix をすぐに返します．TCP の payload は順序付きの範囲 map に保持します．分割した範囲は共有した segment allocation の部分範囲を参照するため，overlap の挿入では範囲列を作り直さず，影響しない payload もコピーしません．配送済みの payload は原則として捨てますが，遅れて届いた食い違う重なりを検出するため，各方向で直近 1 MiB まで（かつ `stream_memory` の半分以下）を残します．この履歴，共有 payload allocation，区間の管理領域は両方の memory 上限に算入し，現在値は `TcpReassembler::estimated_memory_bytes` で取得できます．`PostClose` は統計だけの通知です．受理した RST または双方の FIN が完了した後は，`TcpConfig::closing_timeout` の間，接続を墓石として残します．その間の SYN（ACK なし）以外の packet は数えますが，`Data` としては返しません．SYN（ACK なし）は墓石を置き換え，timeout 後の packet は新しい midstream 接続を開始できます．`next_expected - 1` にある 0 または 1 バイトの keepalive は `DirectionSummary::keepalives` に数え，buffer と重なり判定を通しません．capture の終端で `finish()` を呼びます．

`FragmentBuffer` と `TcpSegmentBuffer` は，protocol 適合試験から方針適用後の buffer を直接調べるための API です．`interval_count` と `allocated_bytes` で区間数と heap の推定確保量も調べられます．`packet_tools::flow` の `FlowIdentityKey::normalized` と `flow_uid` を再構成側も共有するので，`IdleOnly` flow と TCP 接続は，同じ最初の packet 時刻から同じ識別子を作ります．

## アプリ層の解析（`packet_tools::app`）

`AppParser` は `probe`，`feed`，`gap`，`finish` を提供します．`AppChunk` は所有する再構成 chunk とは別の借用 adapter であり，同じ解析器へ UDP データグラムも渡せます．`AppAnalyzer` は `TcpItem` を受け取り，各方向を独立に調べます．有効にした解析器のどれかが `Confidence::Certain` を返すまで方向ごとに最大 64 KiB を保持し，型付きの `AppEvent` と，stream ごとの `DispatchRow` を返します．このため，片方向が応答本文の途中から始まる midstream 接続でも，後から届いた反対方向のリクエストで判定できます．

`AppAnalyzer::new` は，probe 待ちのデータと解析途中のメッセージに 256 MiB の全体上限を適用します．別の上限は `AppAnalyzer::with_memory_limit(protocols, bytes)` で指定し，算入中の capacity は `estimated_buffer_memory_bytes` で取得できます．上限を超えると，未判定のストリームは古いものから判定を中止します．後続の境界を探せる解析器は未完成のデータを解放して再同期します．どちらの処置も `DispatchRow::stop_reason` に残します．

`packet_tools_export::app::AppWriter` は，完成した事象を複数のバッチに分けて受け取り，長い capture の Parquet 出力を有界に保ちます．`write_app` は一括書き出し用の簡便 API として残しています．

```rust
use packet_tools::app::{AppAnalyzer, Protocol};
use packet_tools::reassembly::{TcpConfig, TcpReassembler};

let mut tcp = TcpReassembler::new(TcpConfig::default());
let mut app = AppAnalyzer::new(Protocol::ALL.to_vec());

// capture loop では先に packet を decode する．
for item in tcp.push(&record, &packet).items {
    app.consume(item);
}
for item in tcp.finish().items {
    app.consume(item);
}
let output = app.finish();
for event in output.events {
    println!("{event:?}");
}
```

フラグメント化された通信は，再構成の例と同様に各 packet を `Defragmenter` へ渡し，完成したデータグラムを raw IP として decode してから `TcpReassembler` へ渡します．UDP DNS は `DnsParser::new(context, false)` を作り，データグラムを 1 つの `AppChunk` として渡せます．CLI は両方の経路を実装しています．事象の項目は[アプリ層の表](app-tables.ja.md)を参照してください．

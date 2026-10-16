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

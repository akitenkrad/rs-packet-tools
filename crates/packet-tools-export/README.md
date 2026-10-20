# packet-tools-export

`packet-tools-export` provides streaming Parquet and CSV writers for packet, flow, reassembly, and application-layer tables produced by the packet-tools crates.

```rust
use packet_tools_export::packets::{Format, PacketsWriter, parse_fields};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fields = parse_fields("index,ts_ns")?;
    let writer = PacketsWriter::new(Vec::<u8>::new(), Format::Csv, &fields)?;
    writer.finish()?;
    Ok(())
}
```

Parquet files declare the IEEE 754 total order for floating-point columns; read them with polars 2.0 or later (polars 1.x cannot parse them), pandas, pyarrow or DuckDB.

Most users should depend on the `packet-tools` facade crate and use `packet_tools::export`. See the [repository](https://github.com/akitenkrad/rs-packet-tools) and the [API documentation](https://docs.rs/packet-tools-export).

Licensed under either of Apache-2.0 or MIT at your option.

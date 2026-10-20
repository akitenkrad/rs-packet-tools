//! Parquet and CSV output for packet analysis tables.
//!
//! [`packets::PacketsWriter`] and [`flows::FlowsWriter`] stream packet and flow rows, while
//! [`streams`] and [`app::AppWriter`] export reassembly and application-layer results. Output can
//! use [`packets::Format::Parquet`] or [`packets::Format::Csv`].
//!
//! # Example
//!
//! ```
//! use packet_tools_export::packets::{Format, PacketsWriter, parse_fields};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let fields = parse_fields("index,ts_ns")?;
//!     let writer = PacketsWriter::new(Vec::<u8>::new(), Format::Csv, &fields)?;
//!     writer.finish()?;
//!     Ok(())
//! }
//! ```
//!
//! Most applications can access this crate through `packet_tools::export` in the `packet-tools`
//! facade crate.

pub mod app;
pub mod flows;
pub mod packets;
pub mod streams;

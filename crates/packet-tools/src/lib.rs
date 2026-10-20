//! Unified facade for packet capture analysis.
//!
//! The facade re-exports capture reading as [`capture`], L2-L4 decoding as [`dissect`],
//! bidirectional features as [`flow`], IP and TCP reconstruction as [`reassembly`],
//! application-layer parsing as [`app`], and Parquet/CSV output as [`export`]. The package also
//! provides the `packet-tools` command-line program for validation and for packet, flow, stream,
//! and application-table exports.
//!
//! # Example
//!
//! ```no_run
//! use packet_tools::capture::{Capture, CaptureError};
//! use packet_tools::dissect::{decode, DecodeDepth};
//!
//! fn main() -> Result<(), CaptureError> {
//!     let mut capture = Capture::open("capture.pcap")?;
//!     while let Some(record) = capture.next_record() {
//!         let record = record?;
//!         let packet = decode(record.data, record.linktype, DecodeDepth::L4);
//!         println!("{}: {:?}", record.index, packet.layers().collect::<Vec<_>>());
//!     }
//!     Ok(())
//! }
//! ```

pub use packet_tools_app as app;
pub use packet_tools_capture as capture;
pub use packet_tools_dissect as dissect;
pub use packet_tools_export as export;
pub use packet_tools_flow as flow;
pub use packet_tools_reassembly as reassembly;

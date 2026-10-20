//! Stateful application-layer parsers and stream dispatch.
//!
//! [`AppAnalyzer`] consumes reconstructed TCP items, selects one of the enabled [`Protocol`]
//! parsers, and returns typed [`AppEvent`] values plus dispatch records. Individual parsers such
//! as [`DnsParser`], [`HttpParser`], and [`TlsParser`] can also consume application chunks
//! directly.
//!
//! # Example
//!
//! ```
//! use packet_tools_app::{AppAnalyzer, Protocol};
//!
//! let analyzer = AppAnalyzer::new(Protocol::ALL.to_vec());
//! let output = analyzer.finish();
//! assert!(output.events.is_empty());
//! ```
//!
//! Most applications can access this crate through `packet_tools::app` in the `packet-tools`
//! facade crate.

mod dispatch;
mod dns;
mod http;
mod line;
mod model;
mod ssh;
mod tls;

pub use dispatch::*;
pub use dns::DnsParser;
pub use http::HttpParser;
pub use line::{FtpParser, SmtpParser, TelnetParser};
pub use model::*;
pub use ssh::SshParser;
pub use tls::TlsParser;

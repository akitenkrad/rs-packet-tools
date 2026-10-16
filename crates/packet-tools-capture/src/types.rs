use std::{collections::BTreeMap, io};

use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TsResolution {
    Pow10(u8),
    Pow2(u8),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Container {
    Pcap {
        endian: Endian,
        ts_resolution: TsResolution,
    },
    PcapNg,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Compression {
    None,
    Gzip,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureFormat {
    pub container: Container,
    pub compression: Compression,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct LinkType(pub u16);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceInfo {
    pub linktype: LinkType,
    pub snaplen: u32,
    pub ts_resolution: TsResolution,
    pub ts_offset_secs: i64,
    pub section: u32,
    pub name: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CaptureStats {
    pub packets: u64,
    pub bytes_captured: u64,
    pub bytes_original: u64,
    pub truncated_packets: u64,
    pub packets_without_timestamp: u64,
    pub timestamp_regressions: u64,
    pub max_regression_ns: i64,
    pub first_ts_ns: Option<i64>,
    pub last_ts_ns: Option<i64>,
    pub min_ts_ns: Option<i64>,
    pub max_ts_ns: Option<i64>,
    pub linktypes: BTreeMap<u16, u64>,
    pub sections: u32,
    pub skipped_blocks: BTreeMap<u32, u64>,
    pub truncated_tail: bool,
}

/// Options for [`Capture::open_with`](crate::Capture::open_with).
#[derive(Clone, Debug, Default)]
pub struct OpenOptions {
    /// Memory-map uncompressed regular files instead of reading them through a buffer.
    ///
    /// Off by default: with the lending `next_record` API the mapping saves no copies, and
    /// buffered reading measured 20-40% faster on page-cached captures.
    pub mmap: bool,
}

#[derive(Debug)]
pub struct PacketRecord<'capture> {
    pub index: u64,
    pub ts_ns: Option<i64>,
    pub caplen: u32,
    pub origlen: u32,
    pub linktype: LinkType,
    pub interface: u32,
    pub data: &'capture [u8],
}

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("unknown capture format (magic {magic:02x?})")]
    UnknownFormat { magic: [u8; 4] },
    #[error("nested gzip streams are not supported")]
    NestedGzip,
    #[error("corrupt capture at byte {offset}: {reason}")]
    Corrupt { offset: u64, reason: String },
    #[error("packet record {index} is truncated at byte {offset}")]
    TruncatedRecord { index: u64, offset: u64 },
    #[error("packet record {index} refers to undefined interface {interface} in section {section}")]
    UnknownInterface {
        index: u64,
        interface: u32,
        section: u32,
        offset: u64,
    },
    #[error("timestamp for packet record {index} does not fit in i64 nanoseconds")]
    TimestampOverflow { index: u64 },
}

pub(crate) fn corrupt(offset: u64, reason: impl Into<String>) -> CaptureError {
    CaptureError::Corrupt {
        offset,
        reason: reason.into(),
    }
}

pub(crate) fn read_u16(bytes: &[u8], endian: Endian) -> u16 {
    let bytes = [bytes[0], bytes[1]];
    match endian {
        Endian::Little => u16::from_le_bytes(bytes),
        Endian::Big => u16::from_be_bytes(bytes),
    }
}

pub(crate) fn read_u32(bytes: &[u8], endian: Endian) -> u32 {
    let bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
    match endian {
        Endian::Little => u32::from_le_bytes(bytes),
        Endian::Big => u32::from_be_bytes(bytes),
    }
}

pub(crate) fn read_i64(bytes: &[u8], endian: Endian) -> i64 {
    let bytes: [u8; 8] = bytes.try_into().expect("caller checked option length");
    match endian {
        Endian::Little => i64::from_le_bytes(bytes),
        Endian::Big => i64::from_be_bytes(bytes),
    }
}

pub(crate) fn timestamp_ns(raw: u64, resolution: TsResolution, offset_secs: i64) -> Option<i64> {
    let numerator = i128::from(raw) * 1_000_000_000;
    let scaled = match resolution {
        TsResolution::Pow10(power) if power <= 28 => numerator / 10i128.pow(u32::from(power)),
        TsResolution::Pow10(_) => 0,
        TsResolution::Pow2(power) if power < 127 => numerator / (1i128 << power),
        TsResolution::Pow2(_) => 0,
    };
    let offset = i128::from(offset_secs).checked_mul(1_000_000_000)?;
    i64::try_from(scaled.checked_add(offset)?).ok()
}

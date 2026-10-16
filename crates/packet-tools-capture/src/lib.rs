//! PCAP, pcapng, and gzip input with magic-number format detection independent of file names.

mod input;
mod types;

pub use types::{
    CaptureError, CaptureFormat, CaptureStats, Compression, Container, Endian, InterfaceInfo,
    LinkType, OpenOptions, PacketRecord, TsResolution,
};

use std::{
    fs::File,
    io::{Cursor, Read},
    path::Path,
};

use flate2::read::MultiGzDecoder;
use input::Input;
use types::{corrupt, read_i64, read_u16, read_u32, timestamp_ns};

const MAX_RECORD_SIZE: usize = 64 * 1024 * 1024;
const SHB_TYPE_BYTES: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

/// A lending capture reader.
pub struct Capture {
    input: Input,
    format: CaptureFormat,
    parser: Parser,
    interfaces: Vec<InterfaceInfo>,
    stats: CaptureStats,
    next_index: u64,
    previous_timestamp: Option<i64>,
    done: bool,
}

impl Capture {
    /// Opens a file. Its format is detected from the leading bytes, never its extension.
    ///
    /// The file is read through an internal buffer; gzip input is decompressed as a stream.
    /// Use [`Capture::open_with`] to memory-map uncompressed files instead.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CaptureError> {
        Self::open_with(path, OpenOptions::default())
    }

    /// Opens a file with explicit memory-mapping options.
    ///
    /// When `options.mmap` is enabled, the caller must ensure the file is not modified while
    /// this value exists; modifying a mapped file can cause undefined behavior on access.
    pub fn open_with(path: impl AsRef<Path>, options: OpenOptions) -> Result<Self, CaptureError> {
        let path = path.as_ref();
        let mut file = File::open(path)?;
        let prefix = read_prefix(&mut file)?;
        let compression = detect_outer(&prefix)?;
        let metadata = file.metadata()?;
        if compression == Compression::None
            && options.mmap
            && metadata.is_file()
            && metadata.len() > 0
        {
            return Self::from_input(Input::mmap(&file)?, Compression::None);
        }
        Self::from_prefetched_reader(Box::new(file), prefix, compression)
    }

    /// Reads from any byte stream without memory mapping. Gzip is detected from its bytes.
    pub fn from_reader<R: Read + Send + 'static>(reader: R) -> Result<Self, CaptureError> {
        Self::from_boxed_reader(Box::new(reader))
    }

    fn from_boxed_reader(mut reader: Box<dyn Read + Send>) -> Result<Self, CaptureError> {
        let prefix = read_prefix(&mut reader)?;
        let compression = detect_outer(&prefix)?;
        Self::from_prefetched_reader(reader, prefix, compression)
    }

    fn from_prefetched_reader(
        reader: Box<dyn Read + Send>,
        prefix: Vec<u8>,
        compression: Compression,
    ) -> Result<Self, CaptureError> {
        if compression == Compression::Gzip {
            let chained = Cursor::new(prefix).chain(reader);
            let mut decoder: Box<dyn Read + Send> = Box::new(MultiGzDecoder::new(chained));
            let inner_prefix = read_prefix(&mut decoder)?;
            if inner_prefix.starts_with(&[0x1f, 0x8b]) {
                return Err(CaptureError::NestedGzip);
            }
            detect_container(&inner_prefix)?;
            Self::from_input(Input::stream(decoder, inner_prefix), Compression::Gzip)
        } else {
            Self::from_input(Input::stream(reader, prefix), Compression::None)
        }
    }

    fn from_input(mut input: Input, compression: Compression) -> Result<Self, CaptureError> {
        if !input.ensure(4)? {
            return Err(unknown_format(input.available_bytes()));
        }
        let container = detect_container(&input.peek_array::<4>())?;
        let parser = match container {
            Container::Pcap {
                endian,
                ts_resolution,
            } => Parser::Pcap(PcapState {
                endian,
                ts_resolution,
                snaplen: 0,
                linktype: LinkType(0),
            }),
            Container::PcapNg => Parser::PcapNg(PcapNgState::default()),
        };
        let mut capture = Self {
            input,
            format: CaptureFormat {
                container,
                compression,
            },
            parser,
            interfaces: Vec::new(),
            stats: CaptureStats::default(),
            next_index: 0,
            previous_timestamp: None,
            done: false,
        };
        if matches!(capture.parser, Parser::Pcap(_)) {
            capture.read_pcap_header()?;
        }
        Ok(capture)
    }

    fn read_pcap_header(&mut self) -> Result<(), CaptureError> {
        if !self.input.ensure(24)? {
            return Err(self.truncated(self.input.offset()));
        }
        let header = self.input.peek_array::<24>();
        let Parser::Pcap(state) = &mut self.parser else {
            unreachable!();
        };
        state.snaplen = read_u32(&header[16..20], state.endian);
        state.linktype = LinkType(read_u32(&header[20..24], state.endian) as u16);
        self.interfaces.push(InterfaceInfo {
            linktype: state.linktype,
            snaplen: state.snaplen,
            ts_resolution: state.ts_resolution,
            ts_offset_secs: 0,
            section: 0,
            name: None,
        });
        self.stats.sections = 1;
        self.input.advance(24);
        Ok(())
    }

    /// Returns the next record, whose packet data borrows from this capture.
    pub fn next_record(&mut self) -> Option<Result<PacketRecord<'_>, CaptureError>> {
        if self.done {
            return None;
        }
        let result = match self.parser {
            Parser::Pcap(_) => self.next_pcap_meta(),
            Parser::PcapNg(_) => self.next_pcapng_meta(),
        };
        match result {
            Ok(Some(meta)) => {
                self.observe(&meta);
                let data = self.input.slice(meta.data_start, meta.data_end);
                Some(Ok(PacketRecord {
                    index: meta.index,
                    ts_ns: meta.ts_ns,
                    caplen: meta.caplen,
                    origlen: meta.origlen,
                    linktype: meta.linktype,
                    interface: meta.interface,
                    data,
                }))
            }
            Ok(None) => {
                self.done = true;
                None
            }
            Err(error) => {
                if matches!(error, CaptureError::TruncatedRecord { .. }) {
                    self.stats.truncated_tail = true;
                }
                self.done = true;
                Some(Err(error))
            }
        }
    }

    pub fn format(&self) -> CaptureFormat {
        self.format
    }

    pub fn interfaces(&self) -> &[InterfaceInfo] {
        &self.interfaces
    }

    pub fn stats(&self) -> &CaptureStats {
        &self.stats
    }

    fn next_pcap_meta(&mut self) -> Result<Option<RecordMeta>, CaptureError> {
        if !self.input.ensure(1)? {
            return Ok(None);
        }
        let offset = self.input.offset();
        if !self.input.ensure(16)? {
            return Err(self.truncated(offset));
        }
        let header = self.input.peek_array::<16>();
        let Parser::Pcap(state) = self.parser else {
            unreachable!();
        };
        let seconds = read_u32(&header[0..4], state.endian);
        let fraction = read_u32(&header[4..8], state.endian);
        let caplen = read_u32(&header[8..12], state.endian);
        let origlen = read_u32(&header[12..16], state.endian);
        if caplen as usize > MAX_RECORD_SIZE {
            return Err(corrupt(offset, "captured length exceeds 64 MiB"));
        }
        let total = 16 + caplen as usize;
        if !self.input.ensure(total)? {
            return Err(self.truncated(offset));
        }
        let scale = match state.ts_resolution {
            TsResolution::Pow10(6) => 1_000i128,
            TsResolution::Pow10(9) => 1i128,
            _ => unreachable!(),
        };
        let timestamp = i128::from(seconds) * 1_000_000_000 + i128::from(fraction) * scale;
        let ts_ns = i64::try_from(timestamp).map_err(|_| CaptureError::TimestampOverflow {
            index: self.next_index,
        })?;
        let data_start = self.input.cursor() + 16;
        let data_end = data_start + caplen as usize;
        self.input.advance(total);
        Ok(Some(RecordMeta {
            index: self.take_index(),
            ts_ns: Some(ts_ns),
            caplen,
            origlen,
            linktype: state.linktype,
            interface: 0,
            data_start,
            data_end,
        }))
    }

    fn next_pcapng_meta(&mut self) -> Result<Option<RecordMeta>, CaptureError> {
        loop {
            if !self.input.ensure(1)? {
                return Ok(None);
            }
            let offset = self.input.offset();
            if !self.input.ensure(12)? {
                return Err(self.truncated(offset));
            }
            let header = self.input.peek_array::<12>();
            if header[0..4] == SHB_TYPE_BYTES {
                self.read_section_header(offset, &header)?;
                continue;
            }
            let endian = self
                .pcapng_state()
                .endian
                .ok_or_else(|| corrupt(offset, "block appears before a section header"))?;
            let kind = read_u32(&header[0..4], endian);
            let total = read_u32(&header[4..8], endian) as usize;
            self.validate_block(offset, total)?;
            if !self.input.ensure(total)? {
                return Err(self.truncated(offset));
            }
            self.validate_trailer(offset, total, endian)?;
            match kind {
                1 => self.read_interface(offset, total, endian)?,
                2 => return self.read_packet_block(offset, total, endian).map(Some),
                3 => return self.read_simple_packet(offset, total, endian).map(Some),
                6 => return self.read_enhanced_packet(offset, total, endian).map(Some),
                _ => {
                    *self.stats.skipped_blocks.entry(kind).or_default() += 1;
                    self.input.advance(total);
                }
            }
        }
    }

    fn read_section_header(&mut self, offset: u64, header: &[u8; 12]) -> Result<(), CaptureError> {
        let endian = match &header[8..12] {
            [0x4d, 0x3c, 0x2b, 0x1a] => Endian::Little,
            [0x1a, 0x2b, 0x3c, 0x4d] => Endian::Big,
            _ => return Err(corrupt(offset, "invalid pcapng byte-order magic")),
        };
        let total = read_u32(&header[4..8], endian) as usize;
        self.validate_block(offset, total)?;
        if total < 28 {
            return Err(corrupt(offset, "section header is shorter than 28 bytes"));
        }
        if !self.input.ensure(total)? {
            return Err(self.truncated(offset));
        }
        self.validate_trailer(offset, total, endian)?;
        let section = self.stats.sections;
        self.stats.sections = self.stats.sections.saturating_add(1);
        let state = self.pcapng_state_mut();
        state.endian = Some(endian);
        state.section = section;
        state.local_interfaces.clear();
        self.input.advance(total);
        Ok(())
    }

    fn read_interface(
        &mut self,
        offset: u64,
        total: usize,
        endian: Endian,
    ) -> Result<(), CaptureError> {
        if total < 20 {
            return Err(corrupt(
                offset,
                "interface description is shorter than 20 bytes",
            ));
        }
        let start = self.input.cursor();
        let block = self.input.slice(start, start + total);
        let linktype = LinkType(read_u16(&block[8..10], endian));
        let snaplen = read_u32(&block[12..16], endian);
        let mut resolution = TsResolution::Pow10(6);
        let mut ts_offset_secs = 0;
        let mut name = None;
        let mut cursor = 16usize;
        let options_end = total - 4;
        while cursor < options_end {
            if options_end - cursor < 4 {
                return Err(corrupt(offset + cursor as u64, "truncated option header"));
            }
            let code = read_u16(&block[cursor..cursor + 2], endian);
            let length = read_u16(&block[cursor + 2..cursor + 4], endian) as usize;
            cursor += 4;
            if code == 0 {
                break;
            }
            let padded = length
                .checked_add(3)
                .map(|value| value & !3)
                .ok_or_else(|| corrupt(offset, "option length overflow"))?;
            if cursor + padded > options_end || cursor + length > options_end {
                return Err(corrupt(offset + cursor as u64, "option exceeds block"));
            }
            let value = &block[cursor..cursor + length];
            match code {
                2 => name = Some(String::from_utf8_lossy(value).into_owned()),
                9 if length == 1 => {
                    resolution = if value[0] & 0x80 == 0 {
                        TsResolution::Pow10(value[0])
                    } else {
                        TsResolution::Pow2(value[0] & 0x7f)
                    };
                }
                14 if length == 8 => ts_offset_secs = read_i64(value, endian),
                _ => {}
            }
            cursor += padded;
        }
        let section = self.pcapng_state().section;
        let global = self.interfaces.len() as u32;
        self.interfaces.push(InterfaceInfo {
            linktype,
            snaplen,
            ts_resolution: resolution,
            ts_offset_secs,
            section,
            name,
        });
        self.pcapng_state_mut().local_interfaces.push(global);
        self.input.advance(total);
        Ok(())
    }

    fn read_enhanced_packet(
        &mut self,
        offset: u64,
        total: usize,
        endian: Endian,
    ) -> Result<RecordMeta, CaptureError> {
        if total < 32 {
            return Err(corrupt(
                offset,
                "enhanced packet block is shorter than 32 bytes",
            ));
        }
        let fixed = self.input.peek_array::<28>();
        let local = read_u32(&fixed[8..12], endian);
        let raw = (u64::from(read_u32(&fixed[12..16], endian)) << 32)
            | u64::from(read_u32(&fixed[16..20], endian));
        let caplen = read_u32(&fixed[20..24], endian);
        let origlen = read_u32(&fixed[24..28], endian);
        self.packet_meta(offset, total, local, raw, caplen, origlen, 28)
    }

    fn read_packet_block(
        &mut self,
        offset: u64,
        total: usize,
        endian: Endian,
    ) -> Result<RecordMeta, CaptureError> {
        if total < 32 {
            return Err(corrupt(offset, "packet block is shorter than 32 bytes"));
        }
        let fixed = self.input.peek_array::<28>();
        let local = u32::from(read_u16(&fixed[8..10], endian));
        let raw = (u64::from(read_u32(&fixed[12..16], endian)) << 32)
            | u64::from(read_u32(&fixed[16..20], endian));
        let caplen = read_u32(&fixed[20..24], endian);
        let origlen = read_u32(&fixed[24..28], endian);
        self.packet_meta(offset, total, local, raw, caplen, origlen, 28)
    }

    fn read_simple_packet(
        &mut self,
        offset: u64,
        total: usize,
        endian: Endian,
    ) -> Result<RecordMeta, CaptureError> {
        if total < 16 {
            return Err(corrupt(
                offset,
                "simple packet block is shorter than 16 bytes",
            ));
        }
        let global = self.global_interface(0, offset)?;
        let interface = &self.interfaces[global as usize];
        let fixed = self.input.peek_array::<12>();
        let origlen = read_u32(&fixed[8..12], endian);
        let body_remaining = total - 16;
        let snap_limit = if interface.snaplen == 0 {
            usize::MAX
        } else {
            interface.snaplen as usize
        };
        let caplen_usize = (origlen as usize).min(snap_limit).min(body_remaining);
        if caplen_usize > MAX_RECORD_SIZE {
            return Err(corrupt(offset, "captured length exceeds 64 MiB"));
        }
        let linktype = interface.linktype;
        let data_start = self.input.cursor() + 12;
        let data_end = data_start + caplen_usize;
        self.input.advance(total);
        Ok(RecordMeta {
            index: self.take_index(),
            ts_ns: None,
            caplen: caplen_usize as u32,
            origlen,
            linktype,
            interface: global,
            data_start,
            data_end,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn packet_meta(
        &mut self,
        offset: u64,
        total: usize,
        local_interface: u32,
        raw_timestamp: u64,
        caplen: u32,
        origlen: u32,
        data_offset: usize,
    ) -> Result<RecordMeta, CaptureError> {
        if caplen as usize > MAX_RECORD_SIZE {
            return Err(corrupt(offset, "captured length exceeds 64 MiB"));
        }
        let caplen_end = data_offset
            .checked_add(caplen as usize)
            .ok_or_else(|| corrupt(offset, "captured length overflow"))?;
        if caplen_end > total - 4 {
            return Err(corrupt(offset, "captured data exceeds packet block"));
        }
        let global = self.global_interface(local_interface, offset)?;
        let interface = &self.interfaces[global as usize];
        let ts_ns = timestamp_ns(
            raw_timestamp,
            interface.ts_resolution,
            interface.ts_offset_secs,
        )
        .ok_or(CaptureError::TimestampOverflow {
            index: self.next_index,
        })?;
        let linktype = interface.linktype;
        let data_start = self.input.cursor() + data_offset;
        let data_end = data_start + caplen as usize;
        self.input.advance(total);
        Ok(RecordMeta {
            index: self.take_index(),
            ts_ns: Some(ts_ns),
            caplen,
            origlen,
            linktype,
            interface: global,
            data_start,
            data_end,
        })
    }

    fn global_interface(&self, local: u32, offset: u64) -> Result<u32, CaptureError> {
        self.pcapng_state()
            .local_interfaces
            .get(local as usize)
            .copied()
            .ok_or(CaptureError::UnknownInterface {
                index: self.next_index,
                interface: local,
                section: self.pcapng_state().section,
                offset,
            })
    }

    fn validate_block(&self, offset: u64, total: usize) -> Result<(), CaptureError> {
        if total < 12 {
            return Err(corrupt(offset, "block total length is less than 12"));
        }
        if !total.is_multiple_of(4) {
            return Err(corrupt(
                offset,
                "block total length is not a multiple of four",
            ));
        }
        if total > MAX_RECORD_SIZE + 32 {
            return Err(corrupt(offset, "block total length exceeds safety limit"));
        }
        Ok(())
    }

    fn validate_trailer(
        &self,
        offset: u64,
        total: usize,
        endian: Endian,
    ) -> Result<(), CaptureError> {
        let start = self.input.cursor();
        let trailing =
            read_u32(self.input.slice(start + total - 4, start + total), endian) as usize;
        if trailing != total {
            return Err(corrupt(offset, "leading and trailing block lengths differ"));
        }
        Ok(())
    }

    fn truncated(&self, offset: u64) -> CaptureError {
        CaptureError::TruncatedRecord {
            index: self.next_index,
            offset,
        }
    }

    fn take_index(&mut self) -> u64 {
        let index = self.next_index;
        self.next_index = self.next_index.saturating_add(1);
        index
    }

    fn observe(&mut self, record: &RecordMeta) {
        self.stats.packets = self.stats.packets.saturating_add(1);
        self.stats.bytes_captured = self
            .stats
            .bytes_captured
            .saturating_add(u64::from(record.caplen));
        self.stats.bytes_original = self
            .stats
            .bytes_original
            .saturating_add(u64::from(record.origlen));
        if record.caplen < record.origlen {
            self.stats.truncated_packets = self.stats.truncated_packets.saturating_add(1);
        }
        if let Some(timestamp) = record.ts_ns {
            if self.stats.first_ts_ns.is_none() {
                self.stats.first_ts_ns = Some(timestamp);
            }
            if let Some(previous) = self.previous_timestamp
                && timestamp < previous
            {
                self.stats.timestamp_regressions =
                    self.stats.timestamp_regressions.saturating_add(1);
                self.stats.max_regression_ns = self
                    .stats
                    .max_regression_ns
                    .max(previous.saturating_sub(timestamp));
            }
            self.previous_timestamp = Some(timestamp);
            self.stats.last_ts_ns = Some(timestamp);
            self.stats.min_ts_ns = Some(
                self.stats
                    .min_ts_ns
                    .map_or(timestamp, |value| value.min(timestamp)),
            );
            self.stats.max_ts_ns = Some(
                self.stats
                    .max_ts_ns
                    .map_or(timestamp, |value| value.max(timestamp)),
            );
        } else {
            self.stats.packets_without_timestamp =
                self.stats.packets_without_timestamp.saturating_add(1);
        }
        *self.stats.linktypes.entry(record.linktype.0).or_default() += 1;
    }

    fn pcapng_state(&self) -> &PcapNgState {
        let Parser::PcapNg(state) = &self.parser else {
            unreachable!();
        };
        state
    }

    fn pcapng_state_mut(&mut self) -> &mut PcapNgState {
        let Parser::PcapNg(state) = &mut self.parser else {
            unreachable!();
        };
        state
    }
}

#[derive(Clone, Copy)]
struct PcapState {
    endian: Endian,
    ts_resolution: TsResolution,
    snaplen: u32,
    linktype: LinkType,
}

#[derive(Default)]
struct PcapNgState {
    endian: Option<Endian>,
    section: u32,
    local_interfaces: Vec<u32>,
}

enum Parser {
    Pcap(PcapState),
    PcapNg(PcapNgState),
}

struct RecordMeta {
    index: u64,
    ts_ns: Option<i64>,
    caplen: u32,
    origlen: u32,
    linktype: LinkType,
    interface: u32,
    data_start: usize,
    data_end: usize,
}

fn detect_outer(prefix: &[u8]) -> Result<Compression, CaptureError> {
    if prefix.starts_with(&[0x1f, 0x8b]) {
        Ok(Compression::Gzip)
    } else {
        detect_container(prefix)?;
        Ok(Compression::None)
    }
}

fn detect_container(prefix: &[u8]) -> Result<Container, CaptureError> {
    let magic: [u8; 4] = prefix
        .get(..4)
        .ok_or_else(|| unknown_format(prefix))?
        .try_into()
        .expect("slice length checked");
    match magic {
        [0x0a, 0x0d, 0x0d, 0x0a] => Ok(Container::PcapNg),
        [0xd4, 0xc3, 0xb2, 0xa1] => Ok(Container::Pcap {
            endian: Endian::Little,
            ts_resolution: TsResolution::Pow10(6),
        }),
        [0xa1, 0xb2, 0xc3, 0xd4] => Ok(Container::Pcap {
            endian: Endian::Big,
            ts_resolution: TsResolution::Pow10(6),
        }),
        [0x4d, 0x3c, 0xb2, 0xa1] => Ok(Container::Pcap {
            endian: Endian::Little,
            ts_resolution: TsResolution::Pow10(9),
        }),
        [0xa1, 0xb2, 0x3c, 0x4d] => Ok(Container::Pcap {
            endian: Endian::Big,
            ts_resolution: TsResolution::Pow10(9),
        }),
        _ => Err(CaptureError::UnknownFormat { magic }),
    }
}

fn read_prefix(reader: &mut dyn Read) -> std::io::Result<Vec<u8>> {
    let mut prefix = Vec::with_capacity(4);
    while prefix.len() < 4 {
        let mut buffer = [0u8; 4];
        let read = reader.read(&mut buffer[..4 - prefix.len()])?;
        if read == 0 {
            break;
        }
        prefix.extend_from_slice(&buffer[..read]);
    }
    Ok(prefix)
}

fn unknown_format(bytes: &[u8]) -> CaptureError {
    let mut magic = [0u8; 4];
    let count = bytes.len().min(4);
    magic[..count].copy_from_slice(&bytes[..count]);
    CaptureError::UnknownFormat { magic }
}

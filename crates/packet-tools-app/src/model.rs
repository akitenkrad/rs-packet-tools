use std::net::IpAddr;

pub use packet_tools_reassembly::Direction;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Confidence {
    No,
    Possible,
    Certain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowCtx {
    pub flow_uid: u64,
    pub stream_id: Option<u64>,
    pub client_ip: IpAddr,
    pub server_ip: IpAddr,
    pub client_port: u16,
    pub server_port: u16,
    pub transport: Transport,
    pub midstream: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ByteSource {
    pub offset: usize,
    pub len: usize,
    pub index: u64,
    pub ts_ns: i64,
}

#[derive(Clone, Copy, Debug)]
pub struct AppChunk<'a> {
    pub position: u64,
    pub bytes: &'a [u8],
    pub sources: &'a [ByteSource],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Common {
    pub flow_uid: u64,
    pub stream_id: Option<u64>,
    pub index: u64,
    pub ts_ns: i64,
    pub direction: Direction,
    pub client_ip: IpAddr,
    pub server_ip: IpAddr,
    pub client_port: u16,
    pub server_port: u16,
    pub transport: Transport,
}

impl FlowCtx {
    pub fn common(&self, direction: Direction, source: Option<ByteSource>) -> Common {
        let source = source.unwrap_or(ByteSource {
            offset: 0,
            len: 0,
            index: 0,
            ts_ns: 0,
        });
        Common {
            flow_uid: self.flow_uid,
            stream_id: self.stream_id,
            index: source.index,
            ts_ns: source.ts_ns,
            direction,
            client_ip: self.client_ip,
            server_ip: self.server_ip,
            client_port: self.client_port,
            server_port: self.server_port,
            transport: self.transport,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRow {
    pub common: Common,
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub rcode: u8,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub qname: Option<String>,
    pub qtype: Option<u16>,
    pub qclass: Option<u16>,
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
    pub answers: Vec<String>,
    pub malformed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpRow {
    pub common: Common,
    pub transaction: u64,
    pub kind: String,
    pub method: Option<String>,
    pub uri: Option<String>,
    pub version: Option<String>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub referer: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<u64>,
    pub transfer_encoding: Option<String>,
    pub status: Option<u16>,
    pub reason: Option<String>,
    pub body_len: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsRow {
    pub common: Common,
    pub kind: String,
    pub record_version: Option<u16>,
    pub client_version: Option<u16>,
    pub selected_version: Option<u16>,
    pub supported_versions: Vec<u16>,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub cipher_suites: Vec<u16>,
    pub selected_cipher: Option<u16>,
    pub extensions: Vec<u16>,
    pub ja3: Option<String>,
    pub ja3_md5: Option<String>,
    pub ja4: Option<String>,
    pub ja3s: Option<String>,
    pub ja3s_md5: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsHeartbeatRow {
    pub common: Common,
    pub record_version: u16,
    pub record_length: u16,
    pub encrypted: bool,
    pub heartbeat_type: Option<String>,
    pub declared_payload_length: Option<u16>,
    pub length_mismatch: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FtpRow {
    pub common: Common,
    pub kind: String,
    pub command: Option<String>,
    pub argument: Option<String>,
    pub code: Option<u16>,
    pub text: Option<String>,
    pub login: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshRow {
    pub common: Common,
    pub kind: String,
    pub proto_version: Option<String>,
    pub software: Option<String>,
    pub comments: Option<String>,
    pub kex_algorithms: Vec<String>,
    pub host_key_algorithms: Vec<String>,
    pub encryption_c2s: Vec<String>,
    pub encryption_s2c: Vec<String>,
    pub mac_c2s: Vec<String>,
    pub mac_s2c: Vec<String>,
    pub compression_c2s: Vec<String>,
    pub compression_s2c: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmtpRow {
    pub common: Common,
    pub kind: String,
    pub command: Option<String>,
    pub argument: Option<String>,
    pub code: Option<u16>,
    pub text: Option<String>,
    pub body_len: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelnetRow {
    pub common: Common,
    pub kind: String,
    pub negotiation: Option<String>,
    pub line: Option<String>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AppEvent {
    Dns(DnsRow),
    Http(HttpRow),
    Tls(TlsRow),
    TlsHeartbeat(TlsHeartbeatRow),
    Ftp(FtpRow),
    Ssh(SshRow),
    Smtp(SmtpRow),
    Telnet(TelnetRow),
    Stopped {
        common: Common,
        protocol: String,
        reason: String,
    },
}

pub trait AppParser: Send {
    fn name(&self) -> &'static str;
    fn probe(&self, ctx: &FlowCtx, dir: Direction, head: &[u8]) -> Confidence;
    fn feed(&mut self, dir: Direction, chunk: AppChunk<'_>, out: &mut Vec<AppEvent>);
    fn gap(&mut self, _dir: Direction, _len: u64, _out: &mut Vec<AppEvent>) {}
    fn finish(&mut self, _out: &mut Vec<AppEvent>) {}
    /// Capacity-independent size estimate for retained incomplete messages.
    fn allocated_bytes(&self) -> usize {
        0
    }
    /// Releases incomplete messages after global memory pressure.
    ///
    /// Returns whether parsing can continue by searching for a new boundary.
    fn release_buffered(&mut self) -> bool {
        false
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct Buffer {
    pub bytes: Vec<u8>,
    pub sources: Vec<ByteSource>,
    pub cursor: usize,
}

impl Buffer {
    pub fn push(&mut self, chunk: AppChunk<'_>) {
        let base = self.bytes.len();
        self.bytes.extend_from_slice(chunk.bytes);
        self.sources
            .extend(chunk.sources.iter().map(|source| ByteSource {
                offset: base + source.offset,
                ..*source
            }));
    }
    pub fn available(&self) -> &[u8] {
        &self.bytes[self.cursor..]
    }
    pub fn source_at_absolute(&self, offset: usize) -> Option<ByteSource> {
        self.sources
            .iter()
            .find(|source| {
                offset >= source.offset && offset < source.offset.saturating_add(source.len)
            })
            .copied()
    }
    pub fn source_at_end(&self, end: usize) -> Option<ByteSource> {
        end.checked_sub(1)
            .and_then(|offset| self.source_at_absolute(offset))
    }
    pub fn consume(&mut self, len: usize) {
        self.cursor = self.cursor.saturating_add(len).min(self.bytes.len());
        self.compact();
    }
    pub fn clear_for_gap(&mut self) {
        *self = Self::default();
    }
    pub fn allocated_bytes(&self) -> usize {
        self.bytes.len().saturating_add(
            self.sources
                .len()
                .saturating_mul(std::mem::size_of::<ByteSource>()),
        )
    }
    fn compact(&mut self) {
        if self.cursor < 65_536 || self.cursor * 2 < self.bytes.len() {
            return;
        }
        let removed = self.cursor;
        self.bytes.drain(..removed);
        self.sources = self
            .sources
            .iter()
            .filter_map(|source| {
                let end = source.offset.saturating_add(source.len);
                if end <= removed {
                    return None;
                }
                let start = source.offset.max(removed);
                Some(ByteSource {
                    offset: start - removed,
                    len: end - start,
                    index: source.index,
                    ts_ns: source.ts_ns,
                })
            })
            .collect();
        self.cursor = 0;
    }
}

pub(crate) fn dir_index(dir: Direction) -> usize {
    match dir {
        Direction::ClientToServer => 0,
        Direction::ServerToClient => 1,
    }
}
pub(crate) fn utf8_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod memory_tests {
    use super::{AppChunk, Buffer, ByteSource};

    #[test]
    fn buffer_memory_estimate_ignores_spare_capacity() {
        let source = ByteSource {
            offset: 0,
            len: 7,
            index: 1,
            ts_ns: 2,
        };
        let chunk = AppChunk {
            position: 0,
            bytes: b"payload",
            sources: &[source],
        };
        let mut compact = Buffer::default();
        compact.push(chunk);
        let mut reserved = Buffer {
            bytes: Vec::with_capacity(4_096),
            sources: Vec::with_capacity(64),
            cursor: 0,
        };
        reserved.push(chunk);

        assert_eq!(compact.allocated_bytes(), reserved.allocated_bytes());
    }
}

use md5::{Digest as Md5Digest, Md5};
use sha2::Sha256;

use crate::{
    AppChunk, AppEvent, AppParser, Buffer, ByteSource, Confidence, Direction, FlowCtx,
    TlsHeartbeatRow, TlsRow, dir_index, utf8_lossy,
};

#[derive(Default)]
struct HandshakeBuffer {
    bytes: Vec<u8>,
    sources: Vec<(usize, usize, ByteSource)>,
    cursor: usize,
}
impl HandshakeBuffer {
    fn push(&mut self, bytes: &[u8], source: Option<ByteSource>) {
        let start = self.bytes.len();
        self.bytes.extend_from_slice(bytes);
        if let Some(source) = source {
            self.sources.push((start, self.bytes.len(), source));
        }
    }
    fn source_at_end(&self, end: usize) -> Option<ByteSource> {
        end.checked_sub(1).and_then(|at| {
            self.sources
                .iter()
                .find(|(a, b, _)| at >= *a && at < *b)
                .map(|v| v.2)
        })
    }
    fn allocated_bytes(&self) -> usize {
        self.bytes
            .len()
            .saturating_add(self.sources.len().saturating_mul(std::mem::size_of::<(
                usize,
                usize,
                ByteSource,
            )>()))
    }
}

pub struct TlsParser {
    ctx: FlowCtx,
    records: [Buffer; 2],
    handshakes: [HandshakeBuffer; 2],
    encrypted: [bool; 2],
    tls13: bool,
    resync: [bool; 2],
}
impl TlsParser {
    pub fn new(ctx: FlowCtx) -> Self {
        Self {
            ctx,
            records: Default::default(),
            handshakes: Default::default(),
            encrypted: [false; 2],
            tls13: false,
            resync: [false; 2],
        }
    }
    fn parse_records(&mut self, dir: Direction, out: &mut Vec<AppEvent>) {
        let index = dir_index(dir);
        loop {
            if self.resync[index] {
                let skip = self.records[index]
                    .available()
                    .windows(5)
                    .position(plausible_header);
                match skip {
                    Some(skip) => {
                        self.records[index].consume(skip);
                        self.resync[index] = false;
                    }
                    None if self.records[index].available().len() > 65_540 => {
                        out.push(AppEvent::Stopped {
                            common: self.ctx.common(dir, None),
                            protocol: "tls".into(),
                            reason: "record boundary not found after gap".into(),
                        });
                        self.records[index].clear_for_gap();
                        return;
                    }
                    None => return,
                }
            }
            let data = self.records[index].available();
            if data.len() < 5 {
                break;
            }
            if !plausible_header(&data[..5]) {
                self.resync[index] = true;
                continue;
            }
            let kind = data[0];
            let version = u16::from_be_bytes([data[1], data[2]]);
            let length = usize::from(u16::from_be_bytes([data[3], data[4]]));
            if data.len() < 5 + length {
                break;
            }
            let consumed = 5 + length;
            let absolute_end = self.records[index].cursor + consumed;
            let source = self.records[index].source_at_end(absolute_end);
            let payload = data[5..consumed].to_vec();
            let encrypted = self.encrypted[index] || self.tls13;
            if kind == 24 {
                let heartbeat_type = (!encrypted)
                    .then(|| match payload.first() {
                        Some(1) => Some("request".into()),
                        Some(2) => Some("response".into()),
                        _ => None,
                    })
                    .flatten();
                let declared = (!encrypted && payload.len() >= 3)
                    .then(|| u16::from_be_bytes([payload[1], payload[2]]));
                let available = length.saturating_sub(3 + 16);
                let mismatch = declared.is_some_and(|value| usize::from(value) > available);
                out.push(AppEvent::TlsHeartbeat(TlsHeartbeatRow {
                    common: self.ctx.common(dir, source),
                    record_version: version,
                    record_length: length as u16,
                    encrypted,
                    heartbeat_type,
                    declared_payload_length: declared,
                    length_mismatch: mismatch,
                }));
            }
            if kind == 22 && !encrypted {
                self.handshakes[index].push(&payload, source);
                self.parse_handshakes(dir, version, out);
            }
            if kind == 20 {
                self.encrypted[index] = true;
            }
            self.records[index].consume(consumed);
        }
    }
    fn parse_handshakes(&mut self, dir: Direction, record_version: u16, out: &mut Vec<AppEvent>) {
        let index = dir_index(dir);
        loop {
            let hs = &self.handshakes[index];
            let data = &hs.bytes[hs.cursor..];
            if data.len() < 4 {
                break;
            }
            let length =
                (usize::from(data[1]) << 16) | (usize::from(data[2]) << 8) | usize::from(data[3]);
            if data.len() < 4 + length {
                break;
            }
            let end = hs.cursor + 4 + length;
            let source = hs.source_at_end(end);
            let kind = data[0];
            let body = data[4..4 + length].to_vec();
            let parsed = match kind {
                1 => parse_client_hello(&self.ctx, dir, source, record_version, &body),
                2 => parse_server_hello(&self.ctx, dir, source, record_version, &body),
                11 => Some(simple_row(
                    &self.ctx,
                    dir,
                    source,
                    "certificate",
                    record_version,
                )),
                12 => Some(simple_row(
                    &self.ctx,
                    dir,
                    source,
                    "server_key_exchange",
                    record_version,
                )),
                14 => Some(simple_row(
                    &self.ctx,
                    dir,
                    source,
                    "server_hello_done",
                    record_version,
                )),
                16 => Some(simple_row(
                    &self.ctx,
                    dir,
                    source,
                    "client_key_exchange",
                    record_version,
                )),
                _ => None,
            };
            let parsed = if parsed.is_none() && matches!(kind, 1 | 2) {
                Some(simple_row(
                    &self.ctx,
                    dir,
                    source,
                    "malformed",
                    record_version,
                ))
            } else {
                parsed
            };
            if let Some(row) = parsed {
                if kind == 2 && row.selected_version == Some(0x0304) {
                    self.tls13 = true;
                }
                out.push(AppEvent::Tls(row));
            }
            self.handshakes[index].cursor = end;
        }
    }
}
impl AppParser for TlsParser {
    fn name(&self) -> &'static str {
        "tls"
    }
    fn probe(&self, _ctx: &FlowCtx, _dir: Direction, head: &[u8]) -> Confidence {
        if head.len() < 5 {
            return Confidence::Possible;
        }
        if plausible_header(&head[..5]) && matches!(head[0], 20..=24) {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }
    fn feed(&mut self, dir: Direction, chunk: AppChunk<'_>, out: &mut Vec<AppEvent>) {
        self.records[dir_index(dir)].push(chunk);
        self.parse_records(dir, out);
    }
    fn gap(&mut self, dir: Direction, _len: u64, _out: &mut Vec<AppEvent>) {
        let index = dir_index(dir);
        self.records[index].clear_for_gap();
        self.handshakes[index] = HandshakeBuffer::default();
        self.resync[index] = true;
    }
    fn allocated_bytes(&self) -> usize {
        self.records
            .iter()
            .map(Buffer::allocated_bytes)
            .sum::<usize>()
            .saturating_add(
                self.handshakes
                    .iter()
                    .map(HandshakeBuffer::allocated_bytes)
                    .sum(),
            )
    }
    fn release_buffered(&mut self) -> bool {
        self.records = Default::default();
        self.handshakes = Default::default();
        self.resync = [true; 2];
        true
    }
}

fn plausible_header(header: &[u8]) -> bool {
    header.len() >= 5
        && matches!(header[0], 20..=24)
        && header[1] == 3
        && header[2] <= 4
        && u16::from_be_bytes([header[3], header[4]]) <= 18_432
}
fn blank(
    ctx: &FlowCtx,
    dir: Direction,
    source: Option<ByteSource>,
    kind: &str,
    record_version: u16,
) -> TlsRow {
    TlsRow {
        common: ctx.common(dir, source),
        kind: kind.into(),
        record_version: Some(record_version),
        client_version: None,
        selected_version: None,
        supported_versions: vec![],
        sni: None,
        alpn: vec![],
        cipher_suites: vec![],
        selected_cipher: None,
        extensions: vec![],
        ja3: None,
        ja3_md5: None,
        ja4: None,
        ja3s: None,
        ja3s_md5: None,
    }
}
fn simple_row(
    ctx: &FlowCtx,
    dir: Direction,
    source: Option<ByteSource>,
    kind: &str,
    record_version: u16,
) -> TlsRow {
    blank(ctx, dir, source, kind, record_version)
}

#[derive(Default)]
struct Extensions {
    kinds: Vec<u16>,
    supported: Vec<u16>,
    sni: Option<String>,
    alpn: Vec<String>,
    groups: Vec<u16>,
    points: Vec<u8>,
    signatures: Vec<u16>,
}
fn parse_extensions(data: &[u8]) -> Option<Extensions> {
    let mut at = 0;
    let mut result = Extensions {
        kinds: vec![],
        supported: vec![],
        sni: None,
        alpn: vec![],
        groups: vec![],
        points: vec![],
        signatures: vec![],
    };
    while at < data.len() {
        let header = data.get(at..at + 4)?;
        let kind = u16::from_be_bytes([header[0], header[1]]);
        let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        at += 4;
        let value = data.get(at..at + len)?;
        at += len;
        result.kinds.push(kind);
        match kind {
            0 if value.len() >= 5 => {
                let name_len = usize::from(u16::from_be_bytes([value[3], value[4]]));
                result.sni = value.get(5..5 + name_len).map(utf8_lossy);
            }
            10 if value.len() >= 2 => {
                let len =
                    usize::from(u16::from_be_bytes([value[0], value[1]])).min(value.len() - 2);
                result.groups = value[2..2 + len]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|v| u16::from_be_bytes([v[0], v[1]]))
                    .collect();
            }
            11 if !value.is_empty() => {
                let len = usize::from(value[0]).min(value.len() - 1);
                result.points = value[1..1 + len].to_vec();
            }
            13 if value.len() >= 2 => {
                let len =
                    usize::from(u16::from_be_bytes([value[0], value[1]])).min(value.len() - 2);
                result.signatures = value[2..2 + len]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|v| u16::from_be_bytes([v[0], v[1]]))
                    .collect();
            }
            16 if value.len() >= 2 => {
                let mut p = 2;
                while p < value.len() {
                    let len = usize::from(*value.get(p)?);
                    p += 1;
                    result.alpn.push(utf8_lossy(value.get(p..p + len)?));
                    p += len;
                }
            }
            43 if !value.is_empty() => {
                if value.len() == 2 {
                    result
                        .supported
                        .push(u16::from_be_bytes([value[0], value[1]]));
                } else {
                    let len = usize::from(value[0]).min(value.len() - 1);
                    result.supported = value[1..1 + len]
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|v| u16::from_be_bytes([v[0], v[1]]))
                        .collect();
                }
            }
            _ => {}
        }
    }
    Some(result)
}

fn parse_client_hello(
    ctx: &FlowCtx,
    dir: Direction,
    source: Option<ByteSource>,
    record_version: u16,
    body: &[u8],
) -> Option<TlsRow> {
    let version = read16(body, 0)?;
    let mut at = 34;
    let session = usize::from(*body.get(at)?);
    at += 1 + session;
    let cipher_len = usize::from(read16(body, at)?);
    at += 2;
    let ciphers = body
        .get(at..at + cipher_len)?
        .as_chunks::<2>()
        .0
        .iter()
        .map(|v| u16::from_be_bytes([v[0], v[1]]))
        .collect::<Vec<_>>();
    at += cipher_len;
    let compression = usize::from(*body.get(at)?);
    at += 1 + compression;
    let ext = if at == body.len() {
        Extensions::default()
    } else {
        let ext_len = usize::from(read16(body, at)?);
        at += 2;
        parse_extensions(body.get(at..at + ext_len)?)?
    };
    let filtered_ciphers = ciphers
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect::<Vec<_>>();
    let filtered_ext = ext
        .kinds
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect::<Vec<_>>();
    let filtered_groups = ext
        .groups
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect::<Vec<_>>();
    let ja3 = format!(
        "{},{},{},{},{}",
        version,
        join_dec(&filtered_ciphers),
        join_dec(&filtered_ext),
        join_dec(&filtered_groups),
        ext.points
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join("-")
    );
    let mut row = blank(ctx, dir, source, "client_hello", record_version);
    row.client_version = Some(version);
    row.supported_versions = ext.supported.clone();
    row.sni = ext.sni.clone();
    row.alpn = ext.alpn.clone();
    row.cipher_suites = ciphers;
    row.extensions = ext.kinds.clone();
    row.ja3_md5 = Some(md5_hex(&ja3));
    row.ja3 = Some(ja3);
    row.ja4 = Some(ja4(version, &filtered_ciphers, &ext));
    Some(row)
}
fn parse_server_hello(
    ctx: &FlowCtx,
    dir: Direction,
    source: Option<ByteSource>,
    record_version: u16,
    body: &[u8],
) -> Option<TlsRow> {
    let version = read16(body, 0)?;
    let mut at = 34;
    let session = usize::from(*body.get(at)?);
    at += 1 + session;
    let cipher = read16(body, at)?;
    at += 3;
    let ext = if at == body.len() {
        Extensions::default()
    } else {
        let ext_len = usize::from(read16(body, at)?);
        at += 2;
        parse_extensions(body.get(at..at + ext_len)?)?
    };
    let selected = ext.supported.first().copied().unwrap_or(version);
    let kinds = ext
        .kinds
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect::<Vec<_>>();
    let ja3s = format!("{selected},{cipher},{}", join_dec(&kinds));
    let mut row = blank(ctx, dir, source, "server_hello", record_version);
    row.selected_version = Some(selected);
    row.selected_cipher = Some(cipher);
    row.extensions = ext.kinds;
    row.ja3s_md5 = Some(md5_hex(&ja3s));
    row.ja3s = Some(ja3s);
    Some(row)
}
fn read16(data: &[u8], at: usize) -> Option<u16> {
    let v = data.get(at..at + 2)?;
    Some(u16::from_be_bytes([v[0], v[1]]))
}
fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && (value >> 8) == (value & 0xff)
}
fn join_dec(values: &[u16]) -> String {
    values
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join("-")
}
fn md5_hex(value: &str) -> String {
    format!("{:x}", Md5::digest(value.as_bytes()))
}
fn sha12(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().take(6).map(|v| format!("{v:02x}")).collect()
}
fn ja4(legacy: u16, ciphers: &[u16], ext: &Extensions) -> String {
    let version = ext
        .supported
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .max()
        .unwrap_or(legacy);
    let ver = match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    };
    let sni = if ext.sni.is_some() { 'd' } else { 'i' };
    let alpn = ext
        .alpn
        .first()
        .map(|v| alpn_code(v.as_bytes()))
        .unwrap_or_else(|| "00".into());
    let mut cipher_hex = ciphers
        .iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>();
    cipher_hex.sort();
    let filtered_ext = ext
        .kinds
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect::<Vec<_>>();
    let mut extension_hex = filtered_ext
        .iter()
        .copied()
        .filter(|v| !matches!(v, 0 | 16))
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>();
    extension_hex.sort();
    let mut ext_input = extension_hex.join(",");
    if !ext.signatures.is_empty() {
        ext_input.push('_');
        ext_input.push_str(
            &ext.signatures
                .iter()
                .copied()
                .filter(|v| !is_grease(*v))
                .map(|v| format!("{v:04x}"))
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    let cipher_hash = if cipher_hex.is_empty() {
        "000000000000".into()
    } else {
        sha12(&cipher_hex.join(","))
    };
    let ext_hash = if extension_hex.is_empty() {
        "000000000000".into()
    } else {
        sha12(&ext_input)
    };
    format!(
        "t{ver}{sni}{:02}{:02}{alpn}_{cipher_hash}_{ext_hash}",
        ciphers.len().min(99),
        filtered_ext.len().min(99)
    )
}
fn alpn_code(value: &[u8]) -> String {
    if value.is_empty() {
        return "00".into();
    }
    let first = value[0];
    let last = *value.last().unwrap_or(&first);
    if first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric() {
        format!("{}{}", char::from(first), char::from(last))
    } else {
        let hex = value.iter().map(|v| format!("{v:02x}")).collect::<String>();
        format!("{}{}", &hex[..1], &hex[hex.len() - 1..])
    }
}

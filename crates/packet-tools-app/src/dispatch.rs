use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use packet_tools_reassembly::{Direction, StreamChunk, TcpItem};

use crate::{
    AppChunk, AppEvent, AppParser, ByteSource, Confidence, DnsParser, FlowCtx, FtpParser,
    HttpParser, SmtpParser, SshParser, TelnetParser, TlsParser, Transport,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    Dns,
    Http,
    Tls,
    Ftp,
    Ssh,
    Smtp,
    Telnet,
}
impl Protocol {
    pub const ALL: [Self; 7] = [
        Self::Dns,
        Self::Http,
        Self::Tls,
        Self::Ftp,
        Self::Ssh,
        Self::Smtp,
        Self::Telnet,
    ];
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Http => "http",
            Self::Tls => "tls",
            Self::Ftp => "ftp",
            Self::Ssh => "ssh",
            Self::Smtp => "smtp",
            Self::Telnet => "telnet",
        }
    }
}
impl FromStr for Protocol {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "dns" => Ok(Self::Dns),
            "http" => Ok(Self::Http),
            "tls" => Ok(Self::Tls),
            "ftp" => Ok(Self::Ftp),
            "ssh" => Ok(Self::Ssh),
            "smtp" => Ok(Self::Smtp),
            "telnet" => Ok(Self::Telnet),
            _ => Err(format!("unknown application protocol `{value}`")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchRow {
    pub stream_id: Option<u64>,
    pub flow_uid: u64,
    pub client_ip: String,
    pub server_ip: String,
    pub client_port: u16,
    pub server_port: u16,
    pub protocol: String,
    pub probe_direction: Option<String>,
    pub probe_bytes: u64,
    pub stop_reason: Option<String>,
}
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AppOutput {
    pub events: Vec<AppEvent>,
    pub dispatch: Vec<DispatchRow>,
}

#[derive(Clone)]
struct Pending {
    direction: Direction,
    position: u64,
    bytes: Vec<u8>,
    sources: Vec<ByteSource>,
}
struct StreamState {
    ctx: FlowCtx,
    pending: Vec<Pending>,
    heads: [Vec<u8>; 2],
    parser: Option<Box<dyn AppParser>>,
    protocol: Option<Protocol>,
    probe_direction: Option<Direction>,
    probe_bytes: usize,
    stop_reason: Option<String>,
    flip: bool,
    memory_bytes: usize,
    activity_epoch: u64,
}

pub const DEFAULT_APP_MEMORY_LIMIT: usize = 256 * 1024 * 1024;

pub struct AppAnalyzer {
    protocols: Vec<Protocol>,
    streams: BTreeMap<u64, StreamState>,
    output: AppOutput,
    memory_limit: usize,
    buffered_memory: usize,
    activity: BTreeSet<(u64, u64)>,
    next_activity_epoch: u64,
}
impl AppAnalyzer {
    pub fn new(protocols: Vec<Protocol>) -> Self {
        Self::with_memory_limit(protocols, DEFAULT_APP_MEMORY_LIMIT)
    }
    pub fn with_memory_limit(protocols: Vec<Protocol>, memory_limit: usize) -> Self {
        Self {
            protocols,
            streams: BTreeMap::new(),
            output: AppOutput::default(),
            memory_limit,
            buffered_memory: 0,
            activity: BTreeSet::new(),
            next_activity_epoch: 0,
        }
    }
    pub fn consume(&mut self, item: TcpItem) {
        match item {
            TcpItem::Start(start) => {
                self.streams.insert(
                    start.stream_id,
                    StreamState {
                        ctx: FlowCtx {
                            flow_uid: start.flow_uid,
                            stream_id: Some(start.stream_id),
                            client_ip: start.client_ip,
                            server_ip: start.server_ip,
                            client_port: start.client_port,
                            server_port: start.server_port,
                            transport: Transport::Tcp,
                            midstream: start.midstream,
                        },
                        pending: vec![],
                        heads: Default::default(),
                        parser: None,
                        protocol: None,
                        probe_direction: None,
                        probe_bytes: 0,
                        stop_reason: None,
                        flip: false,
                        memory_bytes: 0,
                        activity_epoch: 0,
                    },
                );
            }
            TcpItem::Data(chunk) => self.data(chunk),
            TcpItem::Gap(gap) => {
                if let Some(state) = self.streams.get_mut(&gap.stream_id) {
                    if let Some(parser) = state.parser.as_mut() {
                        let before = self.output.events.len();
                        parser.gap(
                            mapped_direction(gap.direction, state.flip),
                            gap.len,
                            &mut self.output.events,
                        );
                        update_stop(state, &self.output.events[before..]);
                    } else {
                        state.pending = Vec::new();
                        state.heads = Default::default();
                        state.stop_reason = Some("gap before dispatch".into());
                    }
                }
                self.refresh_memory(gap.stream_id);
                self.enforce_memory_limit();
            }
            TcpItem::End(end) => self.close(end.stream_id),
            TcpItem::PostClose(_) => {}
        }
    }
    fn data(&mut self, chunk: StreamChunk) {
        let stream_id = chunk.stream_id;
        let Some(state) = self.streams.get_mut(&chunk.stream_id) else {
            return;
        };
        if state.parser.is_none() && state.stop_reason.is_some() {
            return;
        }
        let sources = chunk
            .sources
            .iter()
            .map(|s| ByteSource {
                offset: s.offset,
                len: s.len,
                index: s.index,
                ts_ns: s.ts_ns,
            })
            .collect::<Vec<_>>();
        if let Some(parser) = state.parser.as_mut() {
            let before = self.output.events.len();
            parser.feed(
                mapped_direction(chunk.direction, state.flip),
                AppChunk {
                    position: chunk.position,
                    bytes: &chunk.bytes,
                    sources: &sources,
                },
                &mut self.output.events,
            );
            update_stop(state, &self.output.events[before..]);
        } else {
            let head = &mut state.heads[dir_index(chunk.direction)];
            let room = 65_536usize.saturating_sub(head.len());
            let retained = chunk.bytes.len().min(room);
            head.extend_from_slice(&chunk.bytes[..retained]);
            if retained == 0 {
                return;
            }
            state.pending.push(Pending {
                direction: chunk.direction,
                position: chunk.position,
                bytes: chunk.bytes[..retained].to_vec(),
                sources: sources
                    .into_iter()
                    .filter_map(|source| {
                        let start = source.offset.min(retained);
                        let end = source.offset.saturating_add(source.len).min(retained);
                        (start < end).then_some(ByteSource {
                            offset: start,
                            len: end - start,
                            ..source
                        })
                    })
                    .collect(),
            });
            let probe_index = dir_index(chunk.direction);
            if let Some((protocol, direction, bytes, flip)) = select(
                &self.protocols,
                &state.ctx,
                chunk.direction,
                &state.heads[probe_index],
                state.heads[probe_index].len(),
            ) {
                if flip {
                    std::mem::swap(&mut state.ctx.client_ip, &mut state.ctx.server_ip);
                    std::mem::swap(&mut state.ctx.client_port, &mut state.ctx.server_port);
                }
                state.flip = flip;
                state.protocol = Some(protocol);
                state.probe_direction = Some(mapped_direction(direction, flip));
                state.probe_bytes = bytes;
                let mut parser = make_parser(protocol, state.ctx.clone());
                let before = self.output.events.len();
                for pending in &state.pending {
                    parser.feed(
                        mapped_direction(pending.direction, flip),
                        AppChunk {
                            position: pending.position,
                            bytes: &pending.bytes,
                            sources: &pending.sources,
                        },
                        &mut self.output.events,
                    );
                }
                update_stop(state, &self.output.events[before..]);
                state.pending = Vec::new();
                state.heads = Default::default();
                state.parser = Some(parser);
            }
            if state.parser.is_none() && state.heads.iter().all(|head| head.len() == 65_536) {
                state.pending = Vec::new();
                state.heads = Default::default();
                state.stop_reason = Some("probe limit reached".into());
            }
        }
        self.refresh_memory(stream_id);
        self.enforce_memory_limit();
    }
    fn close(&mut self, stream_id: u64) {
        if let Some(mut state) = self.streams.remove(&stream_id) {
            self.buffered_memory = self.buffered_memory.saturating_sub(state.memory_bytes);
            self.activity.remove(&(state.activity_epoch, stream_id));
            if let Some(parser) = state.parser.as_mut() {
                let before = self.output.events.len();
                parser.finish(&mut self.output.events);
                update_stop(&mut state, &self.output.events[before..]);
            }
            self.output.dispatch.push(dispatch_row(&state));
        }
    }
    pub fn estimated_buffer_memory_bytes(&self) -> usize {
        self.buffered_memory
    }
    pub fn event_count(&self) -> usize {
        self.output.events.len()
    }
    pub fn drain_events(&mut self) -> Vec<AppEvent> {
        std::mem::take(&mut self.output.events)
    }
    pub fn finish(mut self) -> AppOutput {
        let ids = self.streams.keys().copied().collect::<Vec<_>>();
        for id in ids {
            self.close(id);
        }
        self.output.dispatch.sort_by_key(|row| row.stream_id);
        self.output
    }

    fn refresh_memory(&mut self, stream_id: u64) {
        let Some(state) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let previous = state.memory_bytes;
        if previous > 0 {
            self.activity.remove(&(state.activity_epoch, stream_id));
        }
        state.memory_bytes = stream_memory_bytes(state);
        self.buffered_memory = self
            .buffered_memory
            .saturating_sub(previous)
            .saturating_add(state.memory_bytes);
        if state.memory_bytes > 0 {
            state.activity_epoch = self.next_activity_epoch;
            self.next_activity_epoch = self.next_activity_epoch.wrapping_add(1);
            self.activity.insert((state.activity_epoch, stream_id));
        }
    }

    fn enforce_memory_limit(&mut self) {
        while self.buffered_memory > self.memory_limit {
            let Some((epoch, stream_id)) = self.activity.pop_first() else {
                break;
            };
            let Some(state) = self.streams.get_mut(&stream_id) else {
                continue;
            };
            if state.activity_epoch != epoch || state.memory_bytes == 0 {
                continue;
            }
            let previous = state.memory_bytes;
            if let Some(parser) = state.parser.as_mut() {
                let can_resume = parser.release_buffered();
                state.stop_reason = Some(if can_resume {
                    "app memory limit exceeded; parser buffers discarded; resynchronizing".into()
                } else {
                    "app memory limit exceeded; parser stopped".into()
                });
                if !can_resume {
                    state.parser = None;
                }
            } else {
                state.pending = Vec::new();
                state.heads = Default::default();
                state.stop_reason = Some("app memory limit exceeded before dispatch".into());
            }
            state.memory_bytes = stream_memory_bytes(state);
            self.buffered_memory = self
                .buffered_memory
                .saturating_sub(previous)
                .saturating_add(state.memory_bytes);
        }
    }
}

fn stream_memory_bytes(state: &StreamState) -> usize {
    let heads = state.heads.iter().map(Vec::len).sum::<usize>();
    let pending = state
        .pending
        .len()
        .saturating_mul(std::mem::size_of::<Pending>())
        .saturating_add(
            state
                .pending
                .iter()
                .map(|pending| {
                    pending.bytes.len().saturating_add(
                        pending
                            .sources
                            .len()
                            .saturating_mul(std::mem::size_of::<ByteSource>()),
                    )
                })
                .sum(),
        );
    heads.saturating_add(pending).saturating_add(
        state
            .parser
            .as_ref()
            .map_or(0, |parser| parser.allocated_bytes()),
    )
}

fn update_stop(state: &mut StreamState, events: &[AppEvent]) {
    if let Some(reason) = events.iter().rev().find_map(|event| match event {
        AppEvent::Stopped { reason, .. } => Some(reason.clone()),
        _ => None,
    }) {
        state.stop_reason = Some(reason);
    }
}
fn dispatch_row(state: &StreamState) -> DispatchRow {
    DispatchRow {
        stream_id: state.ctx.stream_id,
        flow_uid: state.ctx.flow_uid,
        client_ip: state.ctx.client_ip.to_string(),
        server_ip: state.ctx.server_ip.to_string(),
        client_port: state.ctx.client_port,
        server_port: state.ctx.server_port,
        protocol: state.protocol.map_or("unknown", Protocol::as_str).into(),
        probe_direction: state.probe_direction.map(|d| d.as_str().into()),
        probe_bytes: state.probe_bytes as u64,
        stop_reason: state.stop_reason.clone(),
    }
}
fn dir_index(dir: Direction) -> usize {
    match dir {
        Direction::ClientToServer => 0,
        Direction::ServerToClient => 1,
    }
}
fn select(
    protocols: &[Protocol],
    ctx: &FlowCtx,
    direction: Direction,
    head: &[u8],
    observed: usize,
) -> Option<(Protocol, Direction, usize, bool)> {
    let mut ordered = protocols.to_vec();
    ordered.sort_by_key(|p| {
        if port_hint(*p, ctx.client_port) || port_hint(*p, ctx.server_port) {
            0
        } else {
            1
        }
    });
    for protocol in ordered {
        let parser = make_parser(protocol, ctx.clone());
        if !head.is_empty() && parser.probe(ctx, direction, head) == Confidence::Certain {
            let flip = match sender_role(protocol, head) {
                SenderRole::Client => direction == Direction::ServerToClient,
                SenderRole::Server => direction == Direction::ClientToServer,
                SenderRole::Unknown => false,
            };
            return Some((protocol, direction, observed, flip));
        }
    }
    None
}

#[derive(Clone, Copy)]
enum SenderRole {
    Client,
    Server,
    Unknown,
}

fn sender_role(protocol: Protocol, head: &[u8]) -> SenderRole {
    match protocol {
        Protocol::Http => {
            if head
                .split(|byte| *byte == b'\n')
                .any(|line| line.starts_with(b"HTTP/1."))
            {
                SenderRole::Server
            } else {
                SenderRole::Client
            }
        }
        Protocol::Ftp | Protocol::Smtp => {
            if head.len() >= 4 && head[..3].iter().all(u8::is_ascii_digit) {
                SenderRole::Server
            } else {
                SenderRole::Client
            }
        }
        Protocol::Tls if head.len() >= 6 && head[0] == 22 => match head[5] {
            1 => SenderRole::Client,
            2 => SenderRole::Server,
            _ => SenderRole::Unknown,
        },
        Protocol::Dns if head.len() >= 6 => {
            if head[4] & 0x80 != 0 {
                SenderRole::Server
            } else {
                SenderRole::Client
            }
        }
        _ => SenderRole::Unknown,
    }
}

fn mapped_direction(direction: Direction, flip: bool) -> Direction {
    if !flip {
        return direction;
    }
    match direction {
        Direction::ClientToServer => Direction::ServerToClient,
        Direction::ServerToClient => Direction::ClientToServer,
    }
}
fn port_hint(protocol: Protocol, port: u16) -> bool {
    match protocol {
        Protocol::Dns => port == 53,
        Protocol::Http => matches!(port, 80 | 8000 | 8080),
        Protocol::Tls => port == 443,
        Protocol::Ftp => port == 21,
        Protocol::Ssh => port == 22,
        Protocol::Smtp => matches!(port, 25 | 465 | 587),
        Protocol::Telnet => port == 23,
    }
}
fn make_parser(protocol: Protocol, ctx: FlowCtx) -> Box<dyn AppParser> {
    match protocol {
        Protocol::Dns => Box::new(DnsParser::new(ctx, true)),
        Protocol::Http => Box::new(HttpParser::new(ctx)),
        Protocol::Tls => Box::new(TlsParser::new(ctx)),
        Protocol::Ftp => Box::new(FtpParser::new(ctx)),
        Protocol::Ssh => Box::new(SshParser::new(ctx)),
        Protocol::Smtp => Box::new(SmtpParser::new(ctx)),
        Protocol::Telnet => Box::new(TelnetParser::new(ctx)),
    }
}

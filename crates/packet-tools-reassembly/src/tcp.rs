use std::{cmp::Reverse, collections::BinaryHeap, net::IpAddr, sync::Arc, time::Duration};

use ahash::AHashMap;
use packet_tools_capture::PacketRecord;
use packet_tools_dissect::{Ipv4View, Ipv6View, Packet, TcpOption, TcpView, VlanView};
use packet_tools_flow::{FlowIdentityKey, flow_uid};

use crate::{RetainedSide, TcpPolicy, TcpSegmentBuffer};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DeliveryMode {
    #[default]
    OnAck,
    Immediate,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

impl Direction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientToServer => "client_to_server",
            Self::ServerToClient => "server_to_client",
        }
    }

    const fn opposite(self) -> Self {
        match self {
            Self::ClientToServer => Self::ServerToClient,
            Self::ServerToClient => Self::ClientToServer,
        }
    }

    const fn index(self) -> usize {
        match self {
            Self::ClientToServer => 0,
            Self::ServerToClient => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CloseReason {
    Fin,
    Rst,
    Timeout,
    EndOfCapture,
}

impl CloseReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fin => "fin",
            Self::Rst => "rst",
            Self::Timeout => "timeout",
            Self::EndOfCapture => "end_of_capture",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpEventKind {
    OverlapConflict,
    LateOverlapConflict,
    DataAfterClose,
    MemoryLimit,
    RstIgnored,
}

impl TcpEventKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OverlapConflict => "tcp_overlap_conflict",
            Self::LateOverlapConflict => "tcp_late_overlap_conflict",
            Self::DataAfterClose => "tcp_data_after_close",
            Self::MemoryLimit => "tcp_memory_limit",
            Self::RstIgnored => "tcp_rst_ignored",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpEvent {
    pub index: u64,
    pub ts_ns: i64,
    pub kind: TcpEventKind,
    pub stream_id: u64,
    pub direction: Direction,
    pub position: u64,
    pub len: usize,
    pub retained: Option<RetainedSide>,
    pub previous_index: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionStart {
    pub stream_id: u64,
    pub flow_uid: u64,
    pub client_ip: IpAddr,
    pub server_ip: IpAddr,
    pub client_port: u16,
    pub server_port: u16,
    pub first_ts_ns: i64,
    pub midstream: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamChunk {
    pub stream_id: u64,
    pub direction: Direction,
    pub position: u64,
    pub bytes: Arc<[u8]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamGap {
    pub stream_id: u64,
    pub direction: Direction,
    pub position: u64,
    pub len: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PostClosePacket {
    pub stream_id: u64,
    pub direction: Direction,
    pub ts_ns: i64,
    pub payload_len: usize,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DirectionSummary {
    pub segments: u64,
    pub gaps: u64,
    pub gap_bytes: u64,
    pub overlaps: u64,
    pub overlap_conflicts: u64,
    pub retransmitted_bytes: u64,
    pub post_close_packets: u64,
    pub post_close_bytes: u64,
    pub keepalives: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionEnd {
    pub stream_id: u64,
    pub reason: CloseReason,
    pub last_ts_ns: i64,
    pub directions: [DirectionSummary; 2],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TcpItem {
    Start(ConnectionStart),
    Data(StreamChunk),
    Gap(StreamGap),
    PostClose(PostClosePacket),
    End(ConnectionEnd),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TcpOutput {
    pub items: Vec<TcpItem>,
    pub events: Vec<TcpEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpConfig {
    pub policy: TcpPolicy,
    pub delivery: DeliveryMode,
    pub established_timeout: Duration,
    pub closing_timeout: Duration,
    pub stream_memory: usize,
    pub memory_limit: usize,
    pub vlan_in_key: bool,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            policy: TcpPolicy::Bsd,
            delivery: DeliveryMode::OnAck,
            established_timeout: Duration::from_secs(3_600),
            closing_timeout: Duration::from_secs(60),
            stream_memory: 4 * 1024 * 1024,
            memory_limit: 1024 * 1024 * 1024,
            vlan_in_key: false,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct ConnectionKey {
    first_ip: IpAddr,
    second_ip: IpAddr,
    first_port: u16,
    second_port: u16,
    vlan: Option<u16>,
}

impl ConnectionKey {
    fn new(src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16, vlan: Option<u16>) -> Self {
        let left = (ip_bytes(src), src_port);
        let right = (ip_bytes(dst), dst_port);
        if left <= right {
            Self {
                first_ip: src,
                second_ip: dst,
                first_port: src_port,
                second_port: dst_port,
                vlan,
            }
        } else {
            Self {
                first_ip: dst,
                second_ip: src,
                first_port: dst_port,
                second_port: src_port,
                vlan,
            }
        }
    }
}

#[derive(Clone, Debug)]
struct ReceiveDirection {
    buffer: TcpSegmentBuffer,
    delivered: usize,
    ack_limit: usize,
    receive_window: u32,
    window_scale: u8,
    fin_end: Option<u32>,
    fin_acked: bool,
    summary: DirectionSummary,
}

impl ReceiveDirection {
    fn new(policy: TcpPolicy, origin: u32, window_scale: u8, stream_memory: usize) -> Self {
        Self {
            buffer: TcpSegmentBuffer::with_history_bytes(
                policy,
                origin,
                (stream_memory / 2).min(1024 * 1024),
            ),
            delivered: 0,
            ack_limit: 0,
            receive_window: u32::from(u16::MAX),
            window_scale,
            fin_end: None,
            fin_acked: false,
            summary: DirectionSummary::default(),
        }
    }
}

#[derive(Clone, Debug)]
struct Connection {
    start: ConnectionStart,
    client: (IpAddr, u16),
    directions: [Option<ReceiveDirection>; 2],
    last_ts_ns: i64,
    activity_ts_ns: i64,
    closed_at_ts_ns: Option<i64>,
    expiry_epoch: u64,
    scheduled_expiry_ts_ns: i64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Expiry {
    ts_ns: i64,
    epoch: u64,
    key: ConnectionKey,
}

pub struct TcpReassembler {
    config: TcpConfig,
    connections: AHashMap<ConnectionKey, Connection>,
    next_stream_id: u64,
    max_seen_ts_ns: Option<i64>,
    last_index: u64,
    expirations: BinaryHeap<Reverse<Expiry>>,
    next_expiry_epoch: u64,
    allocated_bytes: usize,
}

impl TcpReassembler {
    pub fn new(config: TcpConfig) -> Self {
        Self {
            config,
            connections: AHashMap::new(),
            next_stream_id: 0,
            max_seen_ts_ns: None,
            last_index: 0,
            expirations: BinaryHeap::new(),
            next_expiry_epoch: 0,
            allocated_bytes: 0,
        }
    }

    pub fn push(&mut self, record: &PacketRecord<'_>, packet: &Packet<'_>) -> TcpOutput {
        self.last_index = record.index;
        let raw_ts = record.ts_ns.unwrap_or(self.max_seen_ts_ns.unwrap_or(0));
        let now = self.max_seen_ts_ns.map_or(raw_ts, |old| old.max(raw_ts));
        self.max_seen_ts_ns = Some(now);
        let mut output = TcpOutput::default();
        self.expire(now, &mut output);
        let Some(input) = tcp_input(packet, self.config.vlan_in_key) else {
            return output;
        };
        let key = ConnectionKey::new(
            input.src,
            input.dst,
            input.src_port,
            input.dst_port,
            input.vlan,
        );
        let existing = self.remove_connection(&key);
        let mut connection = match existing {
            Some(connection)
                if connection.closed_at_ts_ns.is_some() && input.syn && !input.ack_flag =>
            {
                self.new_connection(input, raw_ts, now, &mut output)
            }
            Some(mut connection) if connection.closed_at_ts_ns.is_some() => {
                let direction = if (input.src, input.src_port) == connection.client {
                    Direction::ClientToServer
                } else {
                    Direction::ServerToClient
                };
                let position = connection.directions[direction.index()]
                    .as_ref()
                    .and_then(|state| state.buffer.position(input.seq))
                    .unwrap_or(0) as u64;
                connection.last_ts_ns = raw_ts;
                if let Some(state) = connection.directions[direction.index()].as_mut() {
                    state.summary.post_close_packets += 1;
                    state.summary.post_close_bytes += input.payload.len() as u64;
                }
                output.items.push(TcpItem::PostClose(PostClosePacket {
                    stream_id: connection.start.stream_id,
                    direction,
                    ts_ns: raw_ts,
                    payload_len: input.payload.len(),
                }));
                if !input.payload.is_empty() {
                    output.events.push(TcpEvent {
                        index: record.index,
                        ts_ns: raw_ts,
                        kind: TcpEventKind::DataAfterClose,
                        stream_id: connection.start.stream_id,
                        direction,
                        position,
                        len: input.payload.len(),
                        retained: None,
                        previous_index: None,
                    });
                }
                self.store_connection(key, connection);
                return output;
            }
            Some(connection) => connection,
            None => self.new_connection(input, raw_ts, now, &mut output),
        };
        connection.last_ts_ns = raw_ts;
        connection.activity_ts_ns = now;
        let direction = if (input.src, input.src_port) == connection.client {
            Direction::ClientToServer
        } else {
            Direction::ServerToClient
        };
        let idx = direction.index();
        let peer_idx = direction.opposite().index();

        if connection.directions[idx].is_none() {
            let origin = if input.syn {
                input.seq
            } else {
                input.seq.wrapping_sub(1)
            };
            connection.directions[idx] = Some(ReceiveDirection::new(
                self.config.policy,
                origin,
                input.window_scale,
                self.config.stream_memory,
            ));
        }
        let scale = connection.directions[idx]
            .as_ref()
            .map_or(0, |current| current.window_scale);
        if let Some(peer) = connection.directions[peer_idx].as_mut() {
            peer.receive_window = u32::from(input.window)
                .checked_shl(u32::from(scale))
                .unwrap_or(u32::MAX);
        }

        if input.ack_flag
            && let Some(peer) = connection.directions[peer_idx].as_mut()
        {
            let relative = input.ack.wrapping_sub(peer.buffer.isn).wrapping_sub(1);
            if relative <= i32::MAX as u32 {
                peer.ack_limit = peer.ack_limit.max(relative as usize);
            }
            if let Some(fin_end) = peer.fin_end
                && sequence_at_or_after(input.ack, fin_end)
            {
                peer.fin_acked = true;
            }
            if self.config.delivery == DeliveryMode::OnAck {
                deliver_available(
                    &connection.start,
                    direction.opposite(),
                    peer,
                    Some(peer.ack_limit),
                    false,
                    &mut output.items,
                );
            }
        }

        let current = connection.directions[idx]
            .as_mut()
            .expect("direction initialized");
        let expected = current
            .buffer
            .isn
            .wrapping_add(1)
            .wrapping_add(current.buffer.contiguous_len() as u32);
        if input.payload.len() <= 1
            && input.seq == expected.wrapping_sub(1)
            && !input.syn
            && !input.fin
            && !input.rst
        {
            current.summary.keepalives += 1;
            self.store_connection(key, connection);
            return output;
        }
        if input.rst {
            let delta = input.seq.wrapping_sub(expected);
            if delta > current.receive_window {
                output.events.push(TcpEvent {
                    index: record.index,
                    ts_ns: raw_ts,
                    kind: TcpEventKind::RstIgnored,
                    stream_id: connection.start.stream_id,
                    direction,
                    position: current.delivered as u64,
                    len: 0,
                    retained: None,
                    previous_index: None,
                });
                self.store_connection(key, connection);
                return output;
            }
            mark_closed(&mut connection, CloseReason::Rst, now, &mut output.items);
            self.store_connection(key, connection);
            return output;
        }

        if !input.payload.is_empty() {
            current.summary.segments += 1;
            let payload_seq = input.seq.wrapping_add(u32::from(input.syn));
            let overlaps = current
                .buffer
                .insert(payload_seq, input.payload, record.index);
            for overlap in overlaps {
                current.summary.overlaps += 1;
                current.summary.retransmitted_bytes += overlap.len as u64;
                if overlap.conflict {
                    current.summary.overlap_conflicts += 1;
                    output.events.push(TcpEvent {
                        index: record.index,
                        ts_ns: raw_ts,
                        kind: if overlap.offset < current.delivered {
                            TcpEventKind::LateOverlapConflict
                        } else {
                            TcpEventKind::OverlapConflict
                        },
                        stream_id: connection.start.stream_id,
                        direction,
                        position: overlap.offset as u64,
                        len: overlap.len,
                        retained: Some(overlap.retained),
                        previous_index: Some(overlap.previous_index),
                    });
                }
            }
            if self.config.delivery == DeliveryMode::Immediate {
                deliver_available(
                    &connection.start,
                    direction,
                    current,
                    None,
                    false,
                    &mut output.items,
                );
            }
        }
        if input.fin {
            current.fin_end = Some(
                input
                    .seq
                    .wrapping_add(u32::from(input.syn))
                    .wrapping_add(input.payload.len() as u32)
                    .wrapping_add(1),
            );
        }

        enforce_direction_memory(
            &connection.start,
            direction,
            current,
            self.config.stream_memory,
            record,
            &mut output,
        );
        if connection.directions.iter().all(|state| {
            state
                .as_ref()
                .is_some_and(|state| state.fin_end.is_some() && state.fin_acked)
        }) {
            mark_closed(&mut connection, CloseReason::Fin, now, &mut output.items);
            self.store_connection(key, connection);
            return output;
        }
        self.store_connection(key, connection);
        self.enforce_global_memory(record, raw_ts, &mut output);
        output
    }

    pub fn finish(&mut self) -> TcpOutput {
        let mut output = TcpOutput::default();
        // Emit in stream order so the output does not depend on hash-map iteration order.
        let mut connections: Vec<_> = self.connections.drain().map(|(_, c)| c).collect();
        connections.sort_unstable_by_key(|connection| connection.start.stream_id);
        for mut connection in connections {
            if connection.closed_at_ts_ns.is_none() {
                mark_closed(
                    &mut connection,
                    CloseReason::EndOfCapture,
                    self.max_seen_ts_ns.unwrap_or(0),
                    &mut output.items,
                );
            }
        }
        self.allocated_bytes = 0;
        output
    }

    pub fn active_len(&self) -> usize {
        self.connections.len()
    }

    /// Estimated heap allocation used by retained TCP payload and interval metadata.
    pub fn estimated_memory_bytes(&self) -> usize {
        self.allocated_bytes
    }

    fn expire(&mut self, now: i64, output: &mut TcpOutput) {
        while self
            .expirations
            .peek()
            .is_some_and(|entry| entry.0.ts_ns < now)
        {
            let Reverse(expiry) = self.expirations.pop().expect("peeked expiration");
            let Some(connection) = self.connections.get(&expiry.key) else {
                continue;
            };
            if connection.expiry_epoch != expiry.epoch
                || connection.scheduled_expiry_ts_ns != expiry.ts_ns
            {
                continue;
            }
            let actual = connection_expiry(&self.config, connection);
            if actual > expiry.ts_ns {
                let mut connection = self
                    .remove_connection(&expiry.key)
                    .expect("checked connection");
                connection.scheduled_expiry_ts_ns = actual;
                self.expirations.push(Reverse(Expiry {
                    ts_ns: actual,
                    epoch: expiry.epoch,
                    key: expiry.key.clone(),
                }));
                self.store_connection(expiry.key, connection);
                continue;
            }
            if let Some(mut connection) = self.remove_connection(&expiry.key)
                && connection.closed_at_ts_ns.is_none()
            {
                mark_closed(
                    &mut connection,
                    CloseReason::Timeout,
                    now,
                    &mut output.items,
                );
            }
        }
    }

    fn store_connection(&mut self, key: ConnectionKey, mut connection: Connection) {
        let expiry = connection_expiry(&self.config, &connection);
        if expiry < connection.scheduled_expiry_ts_ns {
            connection.scheduled_expiry_ts_ns = expiry;
            self.expirations.push(Reverse(Expiry {
                ts_ns: expiry,
                epoch: connection.expiry_epoch,
                key: key.clone(),
            }));
        }
        self.allocated_bytes = self
            .allocated_bytes
            .saturating_add(connection_allocated_bytes(&connection));
        self.connections.insert(key, connection);
    }

    fn remove_connection(&mut self, key: &ConnectionKey) -> Option<Connection> {
        let connection = self.connections.remove(key)?;
        self.allocated_bytes = self
            .allocated_bytes
            .saturating_sub(connection_allocated_bytes(&connection));
        Some(connection)
    }

    fn new_connection(
        &mut self,
        input: TcpInput<'_>,
        raw_ts: i64,
        now: i64,
        output: &mut TcpOutput,
    ) -> Connection {
        let client = (input.src, input.src_port);
        let midstream = !(input.syn && !input.ack_flag);
        let identity = FlowIdentityKey::normalized(
            input.src,
            input.dst,
            input.src_port,
            input.dst_port,
            6,
            input.vlan,
        );
        let start = ConnectionStart {
            stream_id: self.next_stream_id,
            flow_uid: flow_uid(&identity, raw_ts),
            client_ip: client.0,
            server_ip: input.dst,
            client_port: client.1,
            server_port: input.dst_port,
            first_ts_ns: raw_ts,
            midstream,
        };
        self.next_stream_id += 1;
        output.items.push(TcpItem::Start(start.clone()));
        let expiry_epoch = self.next_expiry_epoch;
        self.next_expiry_epoch += 1;
        Connection {
            start,
            client,
            directions: [None, None],
            last_ts_ns: raw_ts,
            activity_ts_ns: now,
            closed_at_ts_ns: None,
            expiry_epoch,
            scheduled_expiry_ts_ns: i64::MAX,
        }
    }

    fn enforce_global_memory(
        &mut self,
        record: &PacketRecord<'_>,
        ts_ns: i64,
        output: &mut TcpOutput,
    ) {
        if self.allocated_bytes > self.config.memory_limit {
            for connection in self.connections.values_mut() {
                for state in connection.directions.iter_mut().flatten() {
                    state.buffer.drop_delivered_history();
                }
            }
            self.allocated_bytes = self
                .connections
                .values()
                .map(connection_allocated_bytes)
                .sum();
        }
        while self.allocated_bytes > self.config.memory_limit {
            let Some(key) = self
                .connections
                .iter()
                .filter(|(_, connection)| {
                    connection
                        .directions
                        .iter()
                        .filter_map(Option::as_ref)
                        .any(|state| state.buffer.allocated_bytes() > 0)
                })
                .min_by_key(|(_, connection)| {
                    (connection.activity_ts_ns, connection.start.stream_id)
                })
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            let Some(mut connection) = self.remove_connection(&key) else {
                break;
            };
            for direction in [Direction::ClientToServer, Direction::ServerToClient] {
                if let Some(state) = connection.directions[direction.index()].as_mut() {
                    let target = state.buffer.len();
                    force_deliver(
                        &connection.start,
                        direction,
                        state,
                        target,
                        &mut output.items,
                    );
                    state.buffer.drop_delivered_history();
                    output.events.push(TcpEvent {
                        index: record.index,
                        ts_ns,
                        kind: TcpEventKind::MemoryLimit,
                        stream_id: connection.start.stream_id,
                        direction,
                        position: state.delivered as u64,
                        len: 0,
                        retained: None,
                        previous_index: None,
                    });
                }
            }
            self.store_connection(key, connection);
        }
    }
}

fn connection_expiry(config: &TcpConfig, connection: &Connection) -> i64 {
    let closing = connection.closed_at_ts_ns.is_some()
        || connection.directions.iter().any(|direction| {
            direction
                .as_ref()
                .is_some_and(|direction| direction.fin_end.is_some())
        });
    let timeout = if closing {
        config.closing_timeout
    } else {
        config.established_timeout
    };
    let timeout = i64::try_from(timeout.as_nanos()).unwrap_or(i64::MAX);
    connection
        .closed_at_ts_ns
        .unwrap_or(connection.activity_ts_ns)
        .saturating_add(timeout)
}

#[derive(Clone, Copy)]
struct TcpInput<'a> {
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    window: u16,
    syn: bool,
    fin: bool,
    rst: bool,
    ack_flag: bool,
    payload: &'a [u8],
    vlan: Option<u16>,
    window_scale: u8,
}

fn tcp_input<'a>(packet: &'a Packet<'a>, vlan_in_key: bool) -> Option<TcpInput<'a>> {
    let tcp = packet.layer::<TcpView>()?;
    let (src, dst) = if let Some(ip) = packet.layer::<Ipv4View>() {
        (IpAddr::V4(ip.src()), IpAddr::V4(ip.dst()))
    } else {
        let ip = packet.layer::<Ipv6View>()?;
        (IpAddr::V6(ip.src()), IpAddr::V6(ip.dst()))
    };
    Some(TcpInput {
        src,
        dst,
        src_port: tcp.src_port(),
        dst_port: tcp.dst_port(),
        seq: tcp.seq(),
        ack: tcp.ack(),
        window: tcp.window(),
        syn: tcp.syn(),
        fin: tcp.fin(),
        rst: tcp.rst(),
        ack_flag: tcp.ack_flag(),
        payload: packet.payload(),
        vlan: vlan_in_key
            .then(|| packet.layer::<VlanView>().map(|vlan| vlan.vid()))
            .flatten(),
        window_scale: tcp
            .options()
            .find_map(|option| match option {
                TcpOption::WindowScale(scale) => Some(scale.min(14)),
                _ => None,
            })
            .unwrap_or(0),
    })
}

fn deliver_available(
    start: &ConnectionStart,
    direction: Direction,
    state: &mut ReceiveDirection,
    limit: Option<usize>,
    allow_gaps: bool,
    items: &mut Vec<TcpItem>,
) {
    let end = limit
        .unwrap_or_else(|| state.buffer.len())
        .min(state.buffer.len());
    let mut cursor = state.delivered;
    while cursor < end {
        if let Some((next, bytes)) = state.buffer.data_at(cursor, end) {
            items.push(TcpItem::Data(StreamChunk {
                stream_id: start.stream_id,
                direction,
                position: cursor as u64,
                bytes: Arc::from(bytes),
            }));
            cursor = next;
        } else if allow_gaps {
            let begin = cursor;
            cursor = state.buffer.next_present(cursor, end).unwrap_or(end);
            state.summary.gaps += 1;
            state.summary.gap_bytes += (cursor - begin) as u64;
            items.push(TcpItem::Gap(StreamGap {
                stream_id: start.stream_id,
                direction,
                position: begin as u64,
                len: (cursor - begin) as u64,
            }));
        } else {
            break;
        }
    }
    state.delivered = cursor;
    state.buffer.set_immutable_prefix(cursor);
}

fn force_deliver(
    start: &ConnectionStart,
    direction: Direction,
    state: &mut ReceiveDirection,
    end: usize,
    items: &mut Vec<TcpItem>,
) {
    deliver_available(start, direction, state, Some(end), true, items);
}

fn mark_closed(
    connection: &mut Connection,
    reason: CloseReason,
    now: i64,
    items: &mut Vec<TcpItem>,
) {
    if connection.closed_at_ts_ns.is_some() {
        return;
    }
    for direction in [Direction::ClientToServer, Direction::ServerToClient] {
        if let Some(state) = connection.directions[direction.index()].as_mut() {
            let end = state.buffer.len();
            force_deliver(&connection.start, direction, state, end, items);
        }
    }
    let summaries = connection.directions.each_ref().map(|state| {
        state
            .as_ref()
            .map_or_else(DirectionSummary::default, |state| state.summary.clone())
    });
    items.push(TcpItem::End(ConnectionEnd {
        stream_id: connection.start.stream_id,
        reason,
        last_ts_ns: connection.last_ts_ns,
        directions: summaries,
    }));
    for state in connection.directions.iter_mut().flatten() {
        state.buffer.release_storage();
    }
    connection.closed_at_ts_ns = Some(now);
}

fn enforce_direction_memory(
    start: &ConnectionStart,
    direction: Direction,
    state: &mut ReceiveDirection,
    limit: usize,
    record: &PacketRecord<'_>,
    output: &mut TcpOutput,
) {
    if state.buffer.allocated_bytes() <= limit {
        return;
    }
    state.buffer.drop_delivered_history();
    if state.buffer.allocated_bytes() <= limit {
        return;
    }
    let before = state.delivered;
    while state.buffer.allocated_bytes() > limit {
        let Some(target) = state.buffer.oldest_pending_end(state.delivered) else {
            break;
        };
        force_deliver(start, direction, state, target, &mut output.items);
        state.buffer.drop_delivered_history();
    }
    output.events.push(TcpEvent {
        index: record.index,
        ts_ns: record.ts_ns.unwrap_or(0),
        kind: TcpEventKind::MemoryLimit,
        stream_id: start.stream_id,
        direction,
        position: before as u64,
        len: state.delivered.saturating_sub(before),
        retained: None,
        previous_index: None,
    });
}

fn connection_allocated_bytes(connection: &Connection) -> usize {
    connection
        .directions
        .iter()
        .filter_map(Option::as_ref)
        .map(|state| state.buffer.allocated_bytes())
        .sum()
}

fn sequence_at_or_after(value: u32, target: u32) -> bool {
    value.wrapping_sub(target) <= i32::MAX as u32
}

fn ip_bytes(ip: IpAddr) -> [u8; 17] {
    let mut bytes = [0; 17];
    match ip {
        IpAddr::V4(ip) => {
            bytes[0] = 4;
            bytes[1..5].copy_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            bytes[0] = 6;
            bytes[1..].copy_from_slice(&ip.octets());
        }
    }
    bytes
}

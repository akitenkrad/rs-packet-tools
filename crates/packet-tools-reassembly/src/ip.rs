use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use ahash::AHashMap;
use packet_tools_capture::PacketRecord;
use packet_tools_dissect::{Ipv4View, Ipv6View, Packet};

use crate::{FragmentBuffer, IpPolicy, RetainedSide};

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IpFragmentKey {
    pub version: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub identification: u32,
    pub protocol: u8,
    pub vlan: Option<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpEventKind {
    Overlap,
    OverlapConflict,
    Timeout,
    TooLarge,
    TooManyFragments,
    MemoryLimit,
}

impl IpEventKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Overlap => "ip_overlap",
            Self::OverlapConflict => "ip_overlap_conflict",
            Self::Timeout => "ip_timeout",
            Self::TooLarge => "ip_too_large",
            Self::TooManyFragments => "ip_too_many_fragments",
            Self::MemoryLimit => "ip_memory_limit",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpEvent {
    pub index: u64,
    pub ts_ns: i64,
    pub kind: IpEventKind,
    pub key: IpFragmentKey,
    pub offset: Option<usize>,
    pub len: Option<usize>,
    pub retained: Option<RetainedSide>,
    pub previous_index: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReassembledDatagram {
    pub key: IpFragmentKey,
    pub bytes: Vec<u8>,
    pub payload_offset: usize,
    pub fragment_count: usize,
    pub first_index: u64,
    pub last_index: u64,
    pub first_ts_ns: i64,
    pub last_ts_ns: i64,
}

impl ReassembledDatagram {
    pub fn payload(&self) -> &[u8] {
        &self.bytes[self.payload_offset..]
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DefragOutput {
    pub datagrams: Vec<ReassembledDatagram>,
    pub events: Vec<IpEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefragConfig {
    pub policy: IpPolicy,
    pub timeout: Duration,
    pub max_fragments: usize,
    pub max_datagram_bytes: usize,
    pub memory_limit: usize,
    pub vlan_in_key: bool,
}

impl Default for DefragConfig {
    fn default() -> Self {
        Self {
            policy: IpPolicy::Bsd,
            timeout: Duration::from_secs(60),
            max_fragments: 1_024,
            max_datagram_bytes: 65_535,
            memory_limit: 64 * 1024 * 1024,
            vlan_in_key: false,
        }
    }
}

#[derive(Clone, Debug)]
struct FragmentInput<'a> {
    key: IpFragmentKey,
    offset: usize,
    more: bool,
    payload: &'a [u8],
    header: Option<HeaderTemplate>,
}

#[derive(Clone, Debug)]
enum HeaderTemplate {
    V4(Vec<u8>),
    V6 {
        bytes: Vec<u8>,
        next_header_field: usize,
        upper_protocol: u8,
    },
}

#[derive(Clone, Debug)]
struct DatagramState {
    buffer: FragmentBuffer,
    header: Option<HeaderTemplate>,
    fragments: usize,
    first_index: u64,
    last_index: u64,
    first_ts_ns: i64,
    last_ts_ns: i64,
    activity_ts_ns: i64,
    expiry_epoch: u64,
    scheduled_expiry_ts_ns: i64,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Expiry {
    ts_ns: i64,
    epoch: u64,
    key: IpFragmentKey,
}

pub struct Defragmenter {
    config: DefragConfig,
    datagrams: AHashMap<IpFragmentKey, DatagramState>,
    max_seen_ts_ns: Option<i64>,
    expirations: BinaryHeap<Reverse<Expiry>>,
    next_expiry_epoch: u64,
    allocated_bytes: usize,
}

impl Defragmenter {
    pub fn new(config: DefragConfig) -> Self {
        Self {
            config,
            datagrams: AHashMap::new(),
            max_seen_ts_ns: None,
            expirations: BinaryHeap::new(),
            next_expiry_epoch: 0,
            allocated_bytes: 0,
        }
    }

    pub fn push(&mut self, record: &PacketRecord<'_>, packet: &Packet<'_>) -> DefragOutput {
        let raw_ts = record.ts_ns.unwrap_or(self.max_seen_ts_ns.unwrap_or(0));
        let policy_ts = self.max_seen_ts_ns.map_or(raw_ts, |old| old.max(raw_ts));
        self.max_seen_ts_ns = Some(policy_ts);
        let mut output = DefragOutput::default();
        self.expire(policy_ts, record.index, &mut output.events);
        let fragmented = packet
            .layer::<Ipv4View>()
            .is_some_and(|ip| ip.more_fragments() || ip.fragment_offset() != 0)
            || packet
                .layer::<Ipv6View>()
                .is_some_and(|ip| ip.fragment().is_some());
        if !fragmented {
            return output;
        }
        let Some(input) = parse_fragment(record, self.config.vlan_in_key) else {
            return output;
        };
        let header_len = input.header.as_ref().map_or_else(
            || if input.key.version == 4 { 20 } else { 40 },
            |header| match header {
                HeaderTemplate::V4(bytes) => bytes.len(),
                HeaderTemplate::V6 { bytes, .. } => bytes.len(),
            },
        );
        let end = input.offset.saturating_add(input.payload.len());
        if end.saturating_add(header_len) > self.config.max_datagram_bytes {
            self.remove_datagram(&input.key);
            output
                .events
                .push(event(record, policy_ts, input.key, IpEventKind::TooLarge));
            return output;
        }

        let key = input.key.clone();
        let mut state = self.remove_datagram(&key).unwrap_or_else(|| {
            let expiry_epoch = self.next_expiry_epoch;
            self.next_expiry_epoch += 1;
            DatagramState {
                buffer: FragmentBuffer::new(self.config.policy),
                header: None,
                fragments: 0,
                first_index: record.index,
                last_index: record.index,
                first_ts_ns: raw_ts,
                last_ts_ns: raw_ts,
                activity_ts_ns: policy_ts,
                expiry_epoch,
                scheduled_expiry_ts_ns: i64::MAX,
            }
        });
        if state.fragments == self.config.max_fragments {
            output
                .events
                .push(event(record, policy_ts, key, IpEventKind::TooManyFragments));
            return output;
        }
        state.fragments += 1;
        state.last_index = record.index;
        state.last_ts_ns = raw_ts;
        state.activity_ts_ns = policy_ts;
        if input.offset == 0 && input.header.is_some() {
            state.header = input.header;
        }
        let inserted = state
            .buffer
            .insert(input.offset, input.more, input.payload, record.index);
        for overlap in inserted.events {
            let mut base = event(record, policy_ts, key.clone(), IpEventKind::Overlap);
            base.offset = Some(overlap.offset);
            base.len = Some(overlap.len);
            base.retained = Some(overlap.retained);
            base.previous_index = Some(overlap.previous_index);
            output.events.push(base.clone());
            if overlap.conflict {
                base.kind = IpEventKind::OverlapConflict;
                output.events.push(base);
            }
        }
        match inserted.complete {
            Some(payload) => {
                if let Some(header) = state.header.clone() {
                    output
                        .datagrams
                        .push(build_datagram(key, header, payload, state));
                }
            }
            None => self.store_datagram(key, state),
        }
        self.enforce_memory(record, policy_ts, &mut output.events);
        output
    }

    pub fn active_len(&self) -> usize {
        self.datagrams.len()
    }

    /// Estimated heap allocation used by retained fragment payload and interval metadata.
    pub fn estimated_memory_bytes(&self) -> usize {
        self.allocated_bytes
    }

    fn expire(&mut self, now: i64, index: u64, events: &mut Vec<IpEvent>) {
        while self
            .expirations
            .peek()
            .is_some_and(|entry| entry.0.ts_ns < now)
        {
            let Reverse(expiry) = self.expirations.pop().expect("peeked expiration");
            let Some(state) = self.datagrams.get(&expiry.key) else {
                continue;
            };
            if state.expiry_epoch != expiry.epoch || state.scheduled_expiry_ts_ns != expiry.ts_ns {
                continue;
            }
            let actual = self.expiry_for(state);
            if actual > expiry.ts_ns {
                let mut state = self.remove_datagram(&expiry.key).expect("checked datagram");
                state.scheduled_expiry_ts_ns = actual;
                self.allocated_bytes = self
                    .allocated_bytes
                    .saturating_add(state.buffer.allocated_bytes());
                self.expirations.push(Reverse(Expiry {
                    ts_ns: actual,
                    epoch: expiry.epoch,
                    key: expiry.key.clone(),
                }));
                self.datagrams.insert(expiry.key, state);
                continue;
            }
            self.remove_datagram(&expiry.key);
            events.push(IpEvent {
                index,
                ts_ns: now,
                kind: IpEventKind::Timeout,
                key: expiry.key,
                offset: None,
                len: None,
                retained: None,
                previous_index: None,
            });
        }
    }

    fn enforce_memory(&mut self, record: &PacketRecord<'_>, now: i64, events: &mut Vec<IpEvent>) {
        while self.allocated_bytes > self.config.memory_limit {
            let Some(key) = self
                .datagrams
                .iter()
                .min_by_key(|(_, state)| (state.activity_ts_ns, state.first_index))
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.remove_datagram(&key);
            events.push(event(record, now, key, IpEventKind::MemoryLimit));
        }
    }

    fn store_datagram(&mut self, key: IpFragmentKey, mut state: DatagramState) {
        let expiry = self.expiry_for(&state);
        if expiry < state.scheduled_expiry_ts_ns {
            state.scheduled_expiry_ts_ns = expiry;
            self.expirations.push(Reverse(Expiry {
                ts_ns: expiry,
                epoch: state.expiry_epoch,
                key: key.clone(),
            }));
        }
        self.allocated_bytes = self
            .allocated_bytes
            .saturating_add(state.buffer.allocated_bytes());
        self.datagrams.insert(key, state);
    }

    fn remove_datagram(&mut self, key: &IpFragmentKey) -> Option<DatagramState> {
        let state = self.datagrams.remove(key)?;
        self.allocated_bytes = self
            .allocated_bytes
            .saturating_sub(state.buffer.allocated_bytes());
        Some(state)
    }

    fn expiry_for(&self, state: &DatagramState) -> i64 {
        let timeout = i64::try_from(self.config.timeout.as_nanos()).unwrap_or(i64::MAX);
        state.activity_ts_ns.saturating_add(timeout)
    }
}

fn event(record: &PacketRecord<'_>, ts_ns: i64, key: IpFragmentKey, kind: IpEventKind) -> IpEvent {
    IpEvent {
        index: record.index,
        ts_ns,
        kind,
        key,
        offset: None,
        len: None,
        retained: None,
        previous_index: None,
    }
}

fn build_datagram(
    key: IpFragmentKey,
    header: HeaderTemplate,
    payload: Vec<u8>,
    state: DatagramState,
) -> ReassembledDatagram {
    let (mut bytes, payload_offset) = match header {
        HeaderTemplate::V4(mut header) => {
            let total = header.len() + payload.len();
            header[2..4].copy_from_slice(&(total as u16).to_be_bytes());
            let flags = u16::from_be_bytes([header[6], header[7]]) & 0x4000;
            header[6..8].copy_from_slice(&flags.to_be_bytes());
            header[10..12].fill(0);
            let checksum = ipv4_checksum(&header);
            header[10..12].copy_from_slice(&checksum.to_be_bytes());
            let offset = header.len();
            (header, offset)
        }
        HeaderTemplate::V6 {
            mut bytes,
            next_header_field,
            upper_protocol,
        } => {
            bytes[next_header_field] = upper_protocol;
            let payload_len = bytes.len() - 40 + payload.len();
            bytes[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
            (bytes, 40)
        }
    };
    bytes.extend_from_slice(&payload);
    ReassembledDatagram {
        key,
        bytes,
        payload_offset,
        fragment_count: state.fragments,
        first_index: state.first_index,
        last_index: state.last_index,
        first_ts_ns: state.first_ts_ns,
        last_ts_ns: state.last_ts_ns,
    }
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = header.as_chunks::<2>().0.iter().fold(0u32, |sum, pair| {
        sum + u32::from(u16::from_be_bytes([pair[0], pair[1]]))
    });
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn parse_fragment<'a>(
    record: &'a PacketRecord<'_>,
    vlan_in_key: bool,
) -> Option<FragmentInput<'a>> {
    let (offset, vlan) = network_offset(record)?;
    let data = record.data.get(offset..)?;
    match data.first()? >> 4 {
        4 => parse_ipv4(data, vlan_in_key.then_some(vlan).flatten()),
        6 => parse_ipv6(data, vlan_in_key.then_some(vlan).flatten()),
        _ => None,
    }
}

fn parse_ipv4(data: &[u8], vlan: Option<u16>) -> Option<FragmentInput<'_>> {
    let header_len = usize::from(*data.first()? & 0x0f) * 4;
    if header_len < 20 || data.len() < header_len {
        return None;
    }
    let total = usize::from(u16::from_be_bytes([data[2], data[3]])).min(data.len());
    if total < header_len {
        return None;
    }
    let field = u16::from_be_bytes([data[6], data[7]]);
    let offset = usize::from(field & 0x1fff) * 8;
    let more = field & 0x2000 != 0;
    if offset == 0 && !more {
        return None;
    }
    let src = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    Some(FragmentInput {
        key: IpFragmentKey {
            version: 4,
            src: IpAddr::V4(src),
            dst: IpAddr::V4(dst),
            identification: u32::from(u16::from_be_bytes([data[4], data[5]])),
            protocol: data[9],
            vlan,
        },
        offset,
        more,
        payload: &data[header_len..total],
        header: (offset == 0).then(|| HeaderTemplate::V4(data[..header_len].to_vec())),
    })
}

fn parse_ipv6(data: &[u8], vlan: Option<u16>) -> Option<FragmentInput<'_>> {
    if data.len() < 48 {
        return None;
    }
    let declared = 40usize.saturating_add(usize::from(u16::from_be_bytes([data[4], data[5]])));
    let end = declared.min(data.len());
    let mut next = data[6];
    let mut cursor = 40usize;
    let mut next_field = 6usize;
    for _ in 0..8 {
        if next == 44 {
            if cursor + 8 > end {
                return None;
            }
            let upper = data[cursor];
            let field = u16::from_be_bytes([data[cursor + 2], data[cursor + 3]]);
            let offset = usize::from(field & 0xfff8);
            let more = field & 1 != 0;
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?);
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).ok()?);
            return Some(FragmentInput {
                key: IpFragmentKey {
                    version: 6,
                    src: IpAddr::V6(src),
                    dst: IpAddr::V6(dst),
                    identification: u32::from_be_bytes(
                        data[cursor + 4..cursor + 8].try_into().ok()?,
                    ),
                    protocol: upper,
                    vlan,
                },
                offset,
                more,
                payload: &data[cursor + 8..end],
                header: (offset == 0).then(|| HeaderTemplate::V6 {
                    bytes: data[..cursor].to_vec(),
                    next_header_field: next_field,
                    upper_protocol: upper,
                }),
            });
        }
        if !matches!(next, 0 | 43 | 51 | 60 | 135) || cursor + 2 > end {
            return None;
        }
        let length = if next == 51 {
            (usize::from(data[cursor + 1]) + 2) * 4
        } else {
            (usize::from(data[cursor + 1]) + 1) * 8
        };
        if cursor + length > end {
            return None;
        }
        next_field = cursor;
        next = data[cursor];
        cursor += length;
    }
    None
}

fn network_offset(record: &PacketRecord<'_>) -> Option<(usize, Option<u16>)> {
    match record.linktype.0 {
        101 | 228 | 229 => Some((0, None)),
        113 => Some((16, None)),
        276 => Some((20, None)),
        0 | 108 => Some((4, None)),
        1 => {
            if record.data.len() < 14 {
                return None;
            }
            let mut offset = 14;
            let mut ethertype = u16::from_be_bytes([record.data[12], record.data[13]]);
            let mut vlan = None;
            while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
                if record.data.len() < offset + 4 {
                    return None;
                }
                vlan.get_or_insert(
                    u16::from_be_bytes([record.data[offset], record.data[offset + 1]]) & 0x0fff,
                );
                ethertype = u16::from_be_bytes([record.data[offset + 2], record.data[offset + 3]]);
                offset += 4;
            }
            matches!(ethertype, 0x0800 | 0x86dd).then_some((offset, vlan))
        }
        _ => None,
    }
}

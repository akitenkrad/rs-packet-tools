//! Zero-copy L2-L4 packet views backed by a fixed-size layer index.

mod views;

use packet_tools_capture::LinkType;
pub use views::*;

const MAX_LAYERS: usize = 8;
const LAYER_INDEX_BITS: usize = 4;
const LAYER_KIND_MASK: u32 = 0x0f;
const NO_LAYER: u8 = u8::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DecodeDepth {
    L2,
    L3,
    L4,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LayerKind {
    Ethernet,
    Vlan,
    LinuxSll,
    LinuxSll2,
    Null,
    Arp,
    Ipv4,
    Ipv6,
    Icmpv4,
    Icmpv6,
    Tcp,
    Udp,
}

impl LayerKind {
    fn from_code(code: u8) -> Self {
        match code {
            0 => Self::Ethernet,
            1 => Self::Vlan,
            2 => Self::LinuxSll,
            3 => Self::LinuxSll2,
            4 => Self::Null,
            5 => Self::Arp,
            6 => Self::Ipv4,
            7 => Self::Ipv6,
            8 => Self::Icmpv4,
            9 => Self::Icmpv6,
            10 => Self::Tcp,
            11 => Self::Udp,
            _ => unreachable!("layer kind is stored in four bits"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ethernet => "ethernet",
            Self::Vlan => "vlan",
            Self::LinuxSll => "linux_sll",
            Self::LinuxSll2 => "linux_sll2",
            Self::Null => "null",
            Self::Arp => "arp",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Icmpv4 => "icmpv4",
            Self::Icmpv6 => "icmpv6",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Malformed {
    pub layer: LayerKind,
    pub offset: usize,
    pub kind: MalformedKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MalformedKind {
    Truncated,
    BadLength,
    BadVersion,
    BadHeaderLength,
    TooManyLayers,
}

impl MalformedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Truncated => "truncated",
            Self::BadLength => "bad_length",
            Self::BadVersion => "bad_version",
            Self::BadHeaderLength => "bad_header_length",
            Self::TooManyLayers => "too_many_layers",
        }
    }
}

pub struct Packet<'a> {
    pub(crate) data: &'a [u8],
    offsets: [u16; MAX_LAYERS],
    kinds: u32,
    entry_count: u8,
    network_layer: u8,
    transport_layer: u8,
    payload_start: u16,
    payload_end: usize,
    trailer_start: usize,
    malformed_offset: u16,
    malformed_layer: LayerKind,
    malformed_kind: Option<MalformedKind>,
    null_network_order: bool,
    ip_truncated: bool,
}

impl<'a> Packet<'a> {
    pub fn layers(&self) -> impl Iterator<Item = LayerKind> + '_ {
        (0..usize::from(self.entry_count)).map(|index| self.kind_at(index))
    }

    #[inline(always)]
    pub fn layer<L: Layer<'a>>(&self) -> Option<L> {
        let count = usize::from(self.entry_count);
        let index = match L::KIND {
            LayerKind::Ethernet | LayerKind::LinuxSll | LayerKind::LinuxSll2 | LayerKind::Null => {
                (count > 0 && self.kind_at(0) == L::KIND).then_some(0)
            }
            LayerKind::Vlan => (0..count).find(|&index| self.kind_at(index) == L::KIND),
            LayerKind::Arp | LayerKind::Ipv4 | LayerKind::Ipv6 => (self.network_layer != NO_LAYER
                && self.kind_at(usize::from(self.network_layer)) == L::KIND)
                .then_some(usize::from(self.network_layer)),
            LayerKind::Icmpv4 | LayerKind::Icmpv6 | LayerKind::Tcp | LayerKind::Udp => {
                (self.transport_layer != NO_LAYER
                    && self.kind_at(usize::from(self.transport_layer)) == L::KIND)
                    .then_some(usize::from(self.transport_layer))
            }
        }?;
        let offset = usize::from(self.offsets[index]);
        Some(L::from_packet(
            self,
            offset,
            self.layer_end(L::KIND, offset),
        ))
    }

    /// Returns all indexed layers of a given view type in outer-to-inner order.
    pub fn layers_of<L: Layer<'a>>(&self) -> impl Iterator<Item = L> + '_ {
        (0..usize::from(self.entry_count))
            .filter(|&index| self.kind_at(index) == L::KIND)
            .map(|index| {
                let offset = usize::from(self.offsets[index]);
                L::from_packet(self, offset, self.layer_end(L::KIND, offset))
            })
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.data[usize::from(self.payload_start)..self.payload_end]
    }

    pub fn trailer(&self) -> &'a [u8] {
        &self.data[self.trailer_start..]
    }

    pub fn malformed(&self) -> Option<Malformed> {
        self.malformed_kind.map(|kind| Malformed {
            layer: self.malformed_layer,
            offset: usize::from(self.malformed_offset),
            kind,
        })
    }

    pub fn ip_truncated(&self) -> bool {
        self.ip_truncated
    }

    fn new(data: &'a [u8], linktype: LinkType) -> Self {
        Self {
            data,
            offsets: [0; MAX_LAYERS],
            kinds: 0,
            entry_count: 0,
            network_layer: NO_LAYER,
            transport_layer: NO_LAYER,
            payload_start: 0,
            payload_end: data.len(),
            trailer_start: data.len(),
            malformed_offset: 0,
            malformed_layer: LayerKind::Ethernet,
            malformed_kind: None,
            null_network_order: linktype.0 == 108,
            ip_truncated: false,
        }
    }

    fn add(&mut self, kind: LayerKind, offset: usize) -> bool {
        if usize::from(self.entry_count) == MAX_LAYERS {
            self.fail(kind, offset, MalformedKind::TooManyLayers);
            return false;
        }
        let index = self.entry_count;
        debug_assert!(u16::try_from(offset).is_ok());
        self.offsets[usize::from(index)] = offset as u16;
        self.kinds |= u32::from(kind as u8) << (usize::from(index) * LAYER_INDEX_BITS);
        match kind {
            LayerKind::Arp | LayerKind::Ipv4 | LayerKind::Ipv6 => self.network_layer = index,
            LayerKind::Icmpv4 | LayerKind::Icmpv6 | LayerKind::Tcp | LayerKind::Udp => {
                self.transport_layer = index;
            }
            _ => {}
        }
        self.entry_count += 1;
        true
    }

    #[inline]
    fn kind_at(&self, index: usize) -> LayerKind {
        let code = ((self.kinds >> (index * LAYER_INDEX_BITS)) & LAYER_KIND_MASK) as u8;
        LayerKind::from_code(code)
    }

    #[inline]
    fn layer_end(&self, kind: LayerKind, offset: usize) -> usize {
        match kind {
            LayerKind::Ethernet => offset + 14,
            LayerKind::Vlan => offset + 4,
            LayerKind::LinuxSll => offset + 16,
            LayerKind::LinuxSll2 => offset + 20,
            LayerKind::Null => offset + 4,
            LayerKind::Arp => {
                offset
                    + 8
                    + 2 * usize::from(self.data[offset + 4])
                    + 2 * usize::from(self.data[offset + 5])
            }
            LayerKind::Ipv4
            | LayerKind::Ipv6
            | LayerKind::Icmpv4
            | LayerKind::Icmpv6
            | LayerKind::Tcp => self.trailer_start,
            LayerKind::Udp => self.payload_end,
        }
    }

    fn fail(&mut self, layer: LayerKind, offset: usize, kind: MalformedKind) {
        if self.malformed_kind.is_none() {
            debug_assert!(u16::try_from(offset).is_ok());
            self.malformed_offset = offset as u16;
            self.malformed_layer = layer;
            self.malformed_kind = Some(kind);
        }
    }

    #[inline]
    fn set_payload_start(&mut self, offset: usize) {
        debug_assert!(u16::try_from(offset).is_ok());
        self.payload_start = offset as u16;
    }
}

#[inline(always)]
pub fn decode<'a>(data: &'a [u8], linktype: LinkType, depth: DecodeDepth) -> Packet<'a> {
    let mut packet = Packet::new(data, linktype);
    let Some((mut offset, mut protocol)) = decode_link(&mut packet, linktype) else {
        return packet;
    };
    while is_vlan(protocol) {
        if data.len().saturating_sub(offset) < 4 {
            packet.fail(LayerKind::Vlan, offset, MalformedKind::Truncated);
            packet.set_payload_start(offset);
            return packet;
        }
        if !packet.add(LayerKind::Vlan, offset) {
            packet.set_payload_start(offset);
            return packet;
        }
        protocol = be_u16(data, offset + 2);
        offset += 4;
        packet.set_payload_start(offset);
    }
    if depth == DecodeDepth::L2 || protocol < 0x0600 {
        return packet;
    }
    match protocol {
        0x0800 => decode_ipv4(&mut packet, offset, depth),
        0x86dd => decode_ipv6(&mut packet, offset, depth),
        0x0806 => decode_arp(&mut packet, offset),
        _ => {}
    }
    packet
}

#[inline(always)]
fn decode_link(packet: &mut Packet<'_>, linktype: LinkType) -> Option<(usize, u16)> {
    let data = packet.data;
    let (kind, length, protocol_offset) = match linktype.0 {
        1 => (LayerKind::Ethernet, 14, 12),
        113 => (LayerKind::LinuxSll, 16, 14),
        276 => (LayerKind::LinuxSll2, 20, 0),
        0 | 108 => {
            if data.len() < 4 {
                packet.fail(LayerKind::Null, 0, MalformedKind::Truncated);
                return None;
            }
            packet.add(LayerKind::Null, 0);
            packet.set_payload_start(4);
            let bytes: [u8; 4] = data[..4].try_into().expect("length checked");
            let family = if linktype.0 == 0 {
                u32::from_ne_bytes(bytes)
            } else {
                u32::from_be_bytes(bytes)
            };
            return match family {
                2 => Some((4, 0x0800)),
                24 | 28 | 30 => Some((4, 0x86dd)),
                _ => None,
            };
        }
        12 | 14 | 101 => {
            return match data.first().map(|byte| byte >> 4) {
                Some(4) => Some((0, 0x0800)),
                Some(6) => Some((0, 0x86dd)),
                _ => None,
            };
        }
        _ => return None,
    };
    if data.len() < length {
        packet.fail(kind, 0, MalformedKind::Truncated);
        return None;
    }
    packet.add(kind, 0);
    packet.set_payload_start(length);
    Some((length, be_u16(data, protocol_offset)))
}

fn decode_arp(packet: &mut Packet<'_>, offset: usize) {
    let data = packet.data;
    if data.len().saturating_sub(offset) < 8 {
        packet.fail(LayerKind::Arp, offset, MalformedKind::Truncated);
        packet.set_payload_start(offset);
        return;
    }
    let hlen = usize::from(data[offset + 4]);
    let plen = usize::from(data[offset + 5]);
    let header_len = 8 + 2 * hlen + 2 * plen;
    if data.len().saturating_sub(offset) < header_len {
        packet.fail(LayerKind::Arp, offset, MalformedKind::Truncated);
        packet.set_payload_start(offset);
        return;
    }
    if packet.add(LayerKind::Arp, offset) {
        packet.set_payload_start(offset + header_len);
    }
}

#[inline(always)]
fn decode_ipv4(packet: &mut Packet<'_>, offset: usize, depth: DecodeDepth) {
    let data = packet.data;
    if data.len().saturating_sub(offset) < 20 {
        packet.fail(LayerKind::Ipv4, offset, MalformedKind::Truncated);
        packet.set_payload_start(offset);
        return;
    }
    if data[offset] >> 4 != 4 {
        packet.fail(LayerKind::Ipv4, offset, MalformedKind::BadVersion);
        packet.set_payload_start(offset);
        return;
    }
    let ihl = usize::from(data[offset] & 0x0f);
    if ihl < 5 {
        packet.fail(LayerKind::Ipv4, offset, MalformedKind::BadHeaderLength);
        packet.set_payload_start(offset);
        return;
    }
    let header_len = ihl * 4;
    if data.len().saturating_sub(offset) < header_len {
        packet.fail(LayerKind::Ipv4, offset, MalformedKind::Truncated);
        packet.set_payload_start(offset);
        return;
    }
    let total_len = usize::from(be_u16(data, offset + 2));
    if total_len < header_len {
        packet.fail(LayerKind::Ipv4, offset, MalformedKind::BadLength);
        packet.set_payload_start(offset);
        return;
    }
    let available = data.len() - offset;
    let ip_end = offset + total_len.min(available);
    packet.ip_truncated = total_len > available;
    packet.payload_end = ip_end;
    packet.trailer_start = ip_end;
    if !packet.add(LayerKind::Ipv4, offset) {
        packet.set_payload_start(offset);
        return;
    }
    packet.set_payload_start(offset + header_len);
    if depth == DecodeDepth::L4 && be_u16(data, offset + 6) & 0x1fff == 0 {
        decode_transport(packet, offset + header_len, ip_end, data[offset + 9], false);
    }
}

fn decode_ipv6(packet: &mut Packet<'_>, offset: usize, depth: DecodeDepth) {
    let data = packet.data;
    if data.len().saturating_sub(offset) < 40 {
        packet.fail(LayerKind::Ipv6, offset, MalformedKind::Truncated);
        packet.set_payload_start(offset);
        return;
    }
    if data[offset] >> 4 != 6 {
        packet.fail(LayerKind::Ipv6, offset, MalformedKind::BadVersion);
        packet.set_payload_start(offset);
        return;
    }
    let payload_len = usize::from(be_u16(data, offset + 4));
    let available = data.len() - offset;
    let declared_len = if payload_len == 0 {
        available
    } else {
        40 + payload_len
    };
    let ip_end = offset + declared_len.min(available);
    packet.ip_truncated = payload_len != 0 && declared_len > available;
    packet.payload_end = ip_end;
    packet.trailer_start = ip_end;
    if !packet.add(LayerKind::Ipv6, offset) {
        packet.set_payload_start(offset);
        return;
    }
    let mut failure = None;
    let walked = walk_ipv6_extensions(
        data,
        offset + 40,
        ip_end,
        data[offset + 6],
        |bad_offset, kind| failure = Some((bad_offset, kind)),
    );
    if let Some((bad_offset, kind)) = failure {
        packet.fail(LayerKind::Ipv6, bad_offset, kind);
        packet.set_payload_start(bad_offset);
        return;
    }
    let Some((upper_offset, upper_protocol, fragment_offset)) = walked else {
        return;
    };
    packet.set_payload_start(upper_offset);
    if depth == DecodeDepth::L4 && fragment_offset.unwrap_or(0) == 0 {
        decode_transport(packet, upper_offset, ip_end, upper_protocol, true);
    }
}

pub(crate) fn walk_ipv6_extensions(
    data: &[u8],
    mut offset: usize,
    end: usize,
    mut next: u8,
    mut fail: impl FnMut(usize, MalformedKind),
) -> Option<(usize, u8, Option<u32>)> {
    let mut count = 0;
    let mut fragment_offset = None;
    while matches!(next, 0 | 43 | 44 | 51 | 60 | 135) {
        if count == 8 {
            fail(offset, MalformedKind::TooManyLayers);
            return None;
        }
        count += 1;
        let minimum = if next == 44 { 8 } else { 2 };
        if end.saturating_sub(offset) < minimum {
            fail(offset, MalformedKind::Truncated);
            return None;
        }
        let following = data[offset];
        let length = match next {
            44 => 8,
            51 => (usize::from(data[offset + 1]) + 2) * 4,
            _ => (usize::from(data[offset + 1]) + 1) * 8,
        };
        if end.saturating_sub(offset) < length {
            fail(offset, MalformedKind::Truncated);
            return None;
        }
        if next == 44 {
            fragment_offset = Some(u32::from(be_u16(data, offset + 2) & 0xfff8));
        }
        offset += length;
        next = following;
    }
    Some((offset, next, fragment_offset))
}

#[inline(always)]
fn decode_transport(packet: &mut Packet<'_>, offset: usize, ip_end: usize, protocol: u8, v6: bool) {
    let (kind, minimum) = match protocol {
        6 => (LayerKind::Tcp, 20),
        17 => (LayerKind::Udp, 8),
        1 if !v6 => (LayerKind::Icmpv4, 4),
        58 if v6 => (LayerKind::Icmpv6, 4),
        _ => return,
    };
    if ip_end.saturating_sub(offset) < minimum {
        packet.fail(kind, offset, MalformedKind::Truncated);
        return;
    }
    match kind {
        LayerKind::Tcp => {
            let header_len = usize::from(packet.data[offset + 12] >> 4) * 4;
            if header_len < 20 {
                packet.fail(kind, offset, MalformedKind::BadHeaderLength);
            } else if ip_end.saturating_sub(offset) < header_len {
                packet.fail(kind, offset, MalformedKind::Truncated);
            } else if packet.add(kind, offset) {
                packet.set_payload_start(offset + header_len);
            }
        }
        LayerKind::Udp => {
            let length = usize::from(be_u16(packet.data, offset + 4));
            if length < 8 {
                packet.fail(kind, offset, MalformedKind::BadLength);
            } else {
                let udp_end = offset + length.min(ip_end - offset);
                if packet.add(kind, offset) {
                    packet.set_payload_start(offset + 8);
                    packet.payload_end = udp_end;
                }
            }
        }
        LayerKind::Icmpv4 | LayerKind::Icmpv6 => {
            if packet.add(kind, offset) {
                packet.set_payload_start(offset + 4);
            }
        }
        _ => unreachable!(),
    }
}

fn is_vlan(protocol: u16) -> bool {
    matches!(protocol, 0x8100 | 0x88a8 | 0x9100)
}

pub(crate) fn be_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([data[offset], data[offset + 1]])
}

pub(crate) fn be_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

#[cfg(test)]
mod representation_tests {
    use super::Packet;

    #[test]
    fn packet_index_stays_compact() {
        assert!(std::mem::size_of::<Packet<'_>>() <= 72);
    }
}

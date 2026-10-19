use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{LayerKind, Packet, be_u16, be_u32};

mod sealed {
    pub trait Sealed {}
}

pub trait Layer<'a>: sealed::Sealed + Sized {
    const KIND: LayerKind;

    #[doc(hidden)]
    fn from_packet(packet: &Packet<'a>, offset: usize, end: usize) -> Self;
}

macro_rules! simple_view {
    ($name:ident, $kind:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name<'a> {
            data: &'a [u8],
        }

        impl sealed::Sealed for $name<'_> {}

        impl<'a> Layer<'a> for $name<'a> {
            const KIND: LayerKind = $kind;

            #[inline(always)]
            fn from_packet(packet: &Packet<'a>, offset: usize, end: usize) -> Self {
                Self {
                    data: &packet.data[offset..end],
                }
            }
        }
    };
}

simple_view!(EthernetView, LayerKind::Ethernet);
simple_view!(VlanView, LayerKind::Vlan);
simple_view!(LinuxSllView, LayerKind::LinuxSll);
simple_view!(LinuxSll2View, LayerKind::LinuxSll2);
simple_view!(ArpView, LayerKind::Arp);
simple_view!(Ipv4View, LayerKind::Ipv4);
simple_view!(Ipv6View, LayerKind::Ipv6);
simple_view!(Icmpv4View, LayerKind::Icmpv4);
simple_view!(Icmpv6View, LayerKind::Icmpv6);
simple_view!(TcpView, LayerKind::Tcp);
simple_view!(UdpView, LayerKind::Udp);

#[derive(Clone, Copy, Debug)]
pub struct NullView<'a> {
    data: &'a [u8],
    network_order: bool,
}

impl sealed::Sealed for NullView<'_> {}

impl<'a> Layer<'a> for NullView<'a> {
    const KIND: LayerKind = LayerKind::Null;

    #[inline(always)]
    fn from_packet(packet: &Packet<'a>, offset: usize, end: usize) -> Self {
        Self {
            data: &packet.data[offset..end],
            network_order: packet.null_network_order,
        }
    }
}

impl EthernetView<'_> {
    pub fn dst(&self) -> [u8; 6] {
        self.data[..6]
            .try_into()
            .expect("validated Ethernet header")
    }

    pub fn src(&self) -> [u8; 6] {
        self.data[6..12]
            .try_into()
            .expect("validated Ethernet header")
    }

    pub fn ethertype(&self) -> u16 {
        be_u16(self.data, 12)
    }
}

impl VlanView<'_> {
    pub fn pcp(&self) -> u8 {
        self.data[0] >> 5
    }

    pub fn dei(&self) -> bool {
        self.data[0] & 0x10 != 0
    }

    pub fn vid(&self) -> u16 {
        be_u16(self.data, 0) & 0x0fff
    }

    pub fn ethertype(&self) -> u16 {
        be_u16(self.data, 2)
    }
}

impl LinuxSllView<'_> {
    pub fn packet_type(&self) -> u16 {
        be_u16(self.data, 0)
    }

    pub fn address_type(&self) -> u16 {
        be_u16(self.data, 2)
    }

    pub fn address(&self) -> &[u8] {
        let length = usize::from(be_u16(self.data, 4)).min(8);
        &self.data[6..6 + length]
    }

    pub fn protocol(&self) -> u16 {
        be_u16(self.data, 14)
    }
}

impl LinuxSll2View<'_> {
    pub fn protocol(&self) -> u16 {
        be_u16(self.data, 0)
    }

    pub fn interface_index(&self) -> u32 {
        be_u32(self.data, 4)
    }

    pub fn address_type(&self) -> u16 {
        be_u16(self.data, 8)
    }

    pub fn packet_type(&self) -> u8 {
        self.data[10]
    }

    pub fn address(&self) -> &[u8] {
        let length = usize::from(self.data[11]).min(8);
        &self.data[12..12 + length]
    }
}

impl NullView<'_> {
    pub fn family(&self) -> u32 {
        let bytes: [u8; 4] = self.data.try_into().expect("validated null header");
        if self.network_order {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_ne_bytes(bytes)
        }
    }
}

impl ArpView<'_> {
    pub fn operation(&self) -> u16 {
        be_u16(self.data, 6)
    }

    pub fn sender_mac(&self) -> Option<[u8; 6]> {
        self.ethernet_ipv4().then(|| {
            self.data[8..14]
                .try_into()
                .expect("validated Ethernet/IPv4 ARP")
        })
    }

    pub fn sender_ipv4(&self) -> Option<Ipv4Addr> {
        self.ethernet_ipv4()
            .then(|| Ipv4Addr::new(self.data[14], self.data[15], self.data[16], self.data[17]))
    }

    pub fn target_mac(&self) -> Option<[u8; 6]> {
        self.ethernet_ipv4().then(|| {
            self.data[18..24]
                .try_into()
                .expect("validated Ethernet/IPv4 ARP")
        })
    }

    pub fn target_ipv4(&self) -> Option<Ipv4Addr> {
        self.ethernet_ipv4()
            .then(|| Ipv4Addr::new(self.data[24], self.data[25], self.data[26], self.data[27]))
    }

    fn ethernet_ipv4(&self) -> bool {
        self.data.len() >= 28
            && be_u16(self.data, 0) == 1
            && be_u16(self.data, 2) == 0x0800
            && self.data[4] == 6
            && self.data[5] == 4
    }
}

impl Ipv4View<'_> {
    pub fn ihl(&self) -> u8 {
        self.data[0] & 0x0f
    }

    pub fn header_len(&self) -> usize {
        usize::from(self.ihl()) * 4
    }

    pub fn dscp(&self) -> u8 {
        self.data[1] >> 2
    }

    pub fn ecn(&self) -> u8 {
        self.data[1] & 3
    }

    pub fn total_len(&self) -> u16 {
        be_u16(self.data, 2)
    }

    pub fn id(&self) -> u16 {
        be_u16(self.data, 4)
    }

    pub fn dont_fragment(&self) -> bool {
        be_u16(self.data, 6) & 0x4000 != 0
    }

    pub fn more_fragments(&self) -> bool {
        be_u16(self.data, 6) & 0x2000 != 0
    }

    pub fn fragment_offset(&self) -> u32 {
        u32::from(be_u16(self.data, 6) & 0x1fff) * 8
    }

    pub fn ttl(&self) -> u8 {
        self.data[8]
    }

    pub fn protocol(&self) -> u8 {
        self.data[9]
    }

    pub fn checksum(&self) -> u16 {
        be_u16(self.data, 10)
    }

    pub fn src(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.data[12], self.data[13], self.data[14], self.data[15])
    }

    pub fn dst(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.data[16], self.data[17], self.data[18], self.data[19])
    }

    pub fn options(&self) -> &[u8] {
        &self.data[20..self.header_len()]
    }

    pub fn verify_checksum(&self) -> bool {
        checksum_sum(&self.data[..self.header_len()]) == 0xffff
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv6Fragment {
    pub offset_bytes: u32,
    pub more: bool,
    pub id: u32,
}

impl Ipv6View<'_> {
    pub fn traffic_class(&self) -> u8 {
        (self.data[0] << 4) | (self.data[1] >> 4)
    }

    pub fn flow_label(&self) -> u32 {
        be_u32(self.data, 0) & 0x000f_ffff
    }

    pub fn payload_len(&self) -> u16 {
        be_u16(self.data, 4)
    }

    pub fn next_header(&self) -> u8 {
        self.data[6]
    }

    pub fn upper_protocol(&self) -> u8 {
        self.walk().0
    }

    pub fn hop_limit(&self) -> u8 {
        self.data[7]
    }

    pub fn src(&self) -> Ipv6Addr {
        Ipv6Addr::from(<[u8; 16]>::try_from(&self.data[8..24]).expect("validated IPv6 header"))
    }

    pub fn dst(&self) -> Ipv6Addr {
        Ipv6Addr::from(<[u8; 16]>::try_from(&self.data[24..40]).expect("validated IPv6 header"))
    }

    pub fn fragment(&self) -> Option<Ipv6Fragment> {
        self.walk().1
    }

    fn walk(&self) -> (u8, Option<Ipv6Fragment>) {
        let mut offset = 40;
        let mut next = self.data[6];
        let mut fragment = None;
        for _ in 0..8 {
            if !matches!(next, 0 | 43 | 44 | 51 | 60 | 135)
                || self.data.len().saturating_sub(offset) < 2
            {
                break;
            }
            let following = self.data[offset];
            let length = match next {
                44 => 8,
                51 => (usize::from(self.data[offset + 1]) + 2) * 4,
                _ => (usize::from(self.data[offset + 1]) + 1) * 8,
            };
            if self.data.len().saturating_sub(offset) < length {
                break;
            }
            if next == 44 {
                let field = be_u16(self.data, offset + 2);
                fragment = Some(Ipv6Fragment {
                    offset_bytes: u32::from(field & 0xfff8),
                    more: field & 1 != 0,
                    id: be_u32(self.data, offset + 4),
                });
            }
            offset += length;
            next = following;
        }
        (next, fragment)
    }
}

macro_rules! icmp_accessors {
    ($name:ident) => {
        impl $name<'_> {
            pub fn icmp_type(&self) -> u8 {
                self.data[0]
            }
            pub fn code(&self) -> u8 {
                self.data[1]
            }
            pub fn checksum(&self) -> u16 {
                be_u16(self.data, 2)
            }
        }
    };
}

icmp_accessors!(Icmpv4View);
icmp_accessors!(Icmpv6View);

impl TcpView<'_> {
    pub fn src_port(&self) -> u16 {
        be_u16(self.data, 0)
    }
    pub fn dst_port(&self) -> u16 {
        be_u16(self.data, 2)
    }
    pub fn seq(&self) -> u32 {
        be_u32(self.data, 4)
    }
    pub fn ack(&self) -> u32 {
        be_u32(self.data, 8)
    }
    pub fn header_len(&self) -> usize {
        usize::from(self.data[12] >> 4) * 4
    }
    pub fn flags(&self) -> u16 {
        (u16::from(self.data[12] & 0x0f) << 8) | u16::from(self.data[13])
    }
    pub fn fin(&self) -> bool {
        self.flags() & 0x001 != 0
    }
    pub fn syn(&self) -> bool {
        self.flags() & 0x002 != 0
    }
    pub fn rst(&self) -> bool {
        self.flags() & 0x004 != 0
    }
    pub fn psh(&self) -> bool {
        self.flags() & 0x008 != 0
    }
    pub fn ack_flag(&self) -> bool {
        self.flags() & 0x010 != 0
    }
    pub fn urg(&self) -> bool {
        self.flags() & 0x020 != 0
    }
    pub fn ece(&self) -> bool {
        self.flags() & 0x040 != 0
    }
    pub fn cwr(&self) -> bool {
        self.flags() & 0x080 != 0
    }
    pub fn ns(&self) -> bool {
        self.flags() & 0x100 != 0
    }
    pub fn window(&self) -> u16 {
        be_u16(self.data, 14)
    }
    pub fn checksum(&self) -> u16 {
        be_u16(self.data, 16)
    }
    pub fn urgent(&self) -> u16 {
        be_u16(self.data, 18)
    }
    pub fn options(&self) -> TcpOptions<'_> {
        TcpOptions {
            data: &self.data[20..self.header_len()],
            offset: 0,
            done: false,
        }
    }
    pub fn verify_checksum<I: IpView>(&self, ip: &I) -> bool {
        ip.verify_transport_checksum(6, self.data)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpOption<'a> {
    End,
    Noop,
    MaximumSegmentSize(u16),
    WindowScale(u8),
    SackPermitted,
    Sack(&'a [u8]),
    Timestamp { value: u32, echo_reply: u32 },
    Other { kind: u8, data: &'a [u8] },
}

pub struct TcpOptions<'a> {
    data: &'a [u8],
    offset: usize,
    done: bool,
}

impl<'a> Iterator for TcpOptions<'a> {
    type Item = TcpOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.offset >= self.data.len() {
            return None;
        }
        let kind = self.data[self.offset];
        if kind == 0 {
            self.done = true;
            return Some(TcpOption::End);
        }
        if kind == 1 {
            self.offset += 1;
            return Some(TcpOption::Noop);
        }
        if self.data.len().saturating_sub(self.offset) < 2 {
            self.done = true;
            return Some(TcpOption::Other { kind, data: &[] });
        }
        let length = usize::from(self.data[self.offset + 1]);
        if length < 2 || self.data.len().saturating_sub(self.offset) < length {
            let data = &self.data[self.offset + 2..];
            self.done = true;
            return Some(TcpOption::Other { kind, data });
        }
        let data = &self.data[self.offset + 2..self.offset + length];
        self.offset += length;
        Some(match (kind, data) {
            (2, [high, low]) => TcpOption::MaximumSegmentSize(u16::from_be_bytes([*high, *low])),
            (3, [scale]) => TcpOption::WindowScale(*scale),
            (4, []) => TcpOption::SackPermitted,
            (5, blocks) if blocks.len() % 8 == 0 => TcpOption::Sack(blocks),
            (8, [a, b, c, d, e, f, g, h]) => TcpOption::Timestamp {
                value: u32::from_be_bytes([*a, *b, *c, *d]),
                echo_reply: u32::from_be_bytes([*e, *f, *g, *h]),
            },
            _ => TcpOption::Other { kind, data },
        })
    }
}

impl UdpView<'_> {
    pub fn src_port(&self) -> u16 {
        be_u16(self.data, 0)
    }
    pub fn dst_port(&self) -> u16 {
        be_u16(self.data, 2)
    }
    pub fn length(&self) -> u16 {
        be_u16(self.data, 4)
    }
    pub fn checksum(&self) -> u16 {
        be_u16(self.data, 6)
    }
    pub fn verify_checksum<I: IpView>(&self, ip: &I) -> bool {
        let length = usize::from(self.length());
        if length > self.data.len() {
            return false;
        }
        if self.checksum() == 0 && ip.version() == 4 {
            return true;
        }
        ip.verify_transport_checksum(17, &self.data[..length])
    }
}

mod ip_sealed {
    pub trait Sealed {}
}

pub trait IpView: ip_sealed::Sealed {
    #[doc(hidden)]
    fn version(&self) -> u8;
    #[doc(hidden)]
    fn endpoints(&self) -> (IpAddr, IpAddr);
    #[doc(hidden)]
    fn verify_transport_checksum(&self, protocol: u8, segment: &[u8]) -> bool {
        let (source, destination) = self.endpoints();
        let mut sum = 0;
        match (source, destination) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                sum = add_checksum(sum, &source.octets());
                sum = add_checksum(sum, &destination.octets());
                sum += u32::from(protocol) + segment.len() as u32;
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                sum = add_checksum(sum, &source.octets());
                sum = add_checksum(sum, &destination.octets());
                let length = segment.len() as u32;
                sum += (length >> 16) + (length & 0xffff) + u32::from(protocol);
            }
            _ => return false,
        }
        fold_checksum(add_checksum(sum, segment)) == 0xffff
    }
}

impl ip_sealed::Sealed for Ipv4View<'_> {}
impl ip_sealed::Sealed for Ipv6View<'_> {}

impl IpView for Ipv4View<'_> {
    fn version(&self) -> u8 {
        4
    }
    fn endpoints(&self) -> (IpAddr, IpAddr) {
        (self.src().into(), self.dst().into())
    }
}

impl IpView for Ipv6View<'_> {
    fn version(&self) -> u8 {
        6
    }
    fn endpoints(&self) -> (IpAddr, IpAddr) {
        (self.src().into(), self.dst().into())
    }
}

fn checksum_sum(data: &[u8]) -> u16 {
    fold_checksum(add_checksum(0, data))
}

fn add_checksum(mut sum: u32, data: &[u8]) -> u32 {
    for chunk in data.chunks(2) {
        sum += if let [high, low] = chunk {
            u32::from(u16::from_be_bytes([*high, *low]))
        } else {
            u32::from(chunk[0]) << 8
        };
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum
}

fn fold_checksum(mut sum: u32) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

//! Bidirectional flow tables and streaming flow features.
//!
//! [`FlowTable`] accepts decoded packets in capture order. The compatibility policies use
//! microsecond timestamps, as CICFlowMeter does; [`Policy::IdleOnly`] retains nanoseconds.

use std::{
    collections::{BTreeSet, HashMap},
    net::IpAddr,
    time::Duration,
};

use packet_tools_capture::PacketRecord;
use packet_tools_dissect::{
    Icmpv4View, Icmpv6View, Ipv4View, Ipv6View, Packet, TcpView, UdpView, VlanView,
};

/// A direction-independent key used by the stable packet-tools flow identifier.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FlowIdentityKey {
    pub first_ip: IpAddr,
    pub second_ip: IpAddr,
    pub first_port: u16,
    pub second_port: u16,
    pub protocol: u8,
    pub vlan: Option<u16>,
    pub icmp_type: Option<u8>,
    pub icmp_id: Option<u16>,
}

impl FlowIdentityKey {
    /// Builds a key with endpoints sorted by address bytes and then port.
    pub fn normalized(
        src: IpAddr,
        dst: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
        vlan: Option<u16>,
    ) -> Self {
        let left = (ip_sort_bytes(src), src_port);
        let right = (ip_sort_bytes(dst), dst_port);
        let (first_ip, second_ip, first_port, second_port) = if left <= right {
            (src, dst, src_port, dst_port)
        } else {
            (dst, src, dst_port, src_port)
        };
        Self {
            first_ip,
            second_ip,
            first_port,
            second_port,
            protocol,
            vlan,
            icmp_type: None,
            icmp_id: None,
        }
    }
}

mod columns;
pub use columns::{Column, ColumnType, cicflowmeter_columns};

/// A typed CICFlowMeter feature value.
#[derive(Clone, Debug, PartialEq)]
pub enum FeatureValue {
    /// UTF-8 text.
    Utf8(String),
    /// Unsigned integer.
    UInt64(u64),
    /// Signed integer.
    Int64(i64),
    /// IEEE 754 double-precision value.
    Float64(f64),
}

impl FeatureValue {
    /// Formats a value the same way Java's CSV concatenation formats the corresponding type.
    pub fn java_string(&self) -> String {
        match self {
            Self::Utf8(value) => value.clone(),
            Self::UInt64(value) => value.to_string(),
            Self::Int64(value) => value.to_string(),
            Self::Float64(value) if value.is_infinite() && value.is_sign_positive() => {
                "Infinity".to_owned()
            }
            Self::Float64(value) if value.is_infinite() => "-Infinity".to_owned(),
            Self::Float64(value) => value.to_string(),
        }
    }
}

/// Rules used to group and terminate flows.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Policy {
    /// Reproduce ahlashkari/CICFlowMeter, including closing a TCP flow at its first FIN.
    CicFlowMeter,
    /// Reproduce GintsEngelen/CICFlowMeter's corrected flow state machine.
    #[default]
    Corrected,
    /// Use a normalized key and close flows only after an idle timeout.
    IdleOnly,
}

/// Output feature set.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Preset {
    /// CICFlowMeter-compatible columns for the selected policy.
    #[default]
    CicFlowMeter,
    /// Twenty-one stable packet and byte counters plus flow identity.
    Minimal,
}

/// Why a flow was emitted.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EndReason {
    /// The selected FIN handshake rule completed.
    Fin,
    /// A TCP reset was observed.
    Rst,
    /// The duration from the first packet exceeded `flow_timeout`.
    FlowTimeout,
    /// No packet arrived before `idle_timeout` under [`Policy::IdleOnly`].
    IdleTimeout,
    /// The capture ended while the flow was still resident.
    EndOfCapture,
    /// Engelen's ICMP code-and-type change rule split the flow.
    IcmpTypeCodeChange,
}

impl EndReason {
    /// Stable value used by CSV and Parquet output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fin => "fin",
            Self::Rst => "rst",
            Self::FlowTimeout => "flow_timeout",
            Self::IdleTimeout => "idle_timeout",
            Self::EndOfCapture => "end_of_capture",
            Self::IcmpTypeCodeChange => "icmp_type_code_change",
        }
    }
}

/// Flow-table configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowConfig {
    /// Grouping and termination policy.
    pub policy: Policy,
    /// Feature set retained on emitted flows.
    pub preset: Preset,
    /// Maximum age of a CICFlowMeter-compatible flow.
    pub flow_timeout: Duration,
    /// Gap used only for Active/Idle feature statistics.
    pub activity_timeout: Duration,
    /// Idle timeout used only by [`Policy::IdleOnly`].
    pub idle_timeout: Duration,
    /// Include the outermost VLAN identifier in an IdleOnly key.
    pub vlan_in_key: bool,
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            policy: Policy::Corrected,
            preset: Preset::CicFlowMeter,
            flow_timeout: Duration::from_secs(120),
            activity_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(60),
            vlan_in_key: false,
        }
    }
}

/// A completed bidirectional flow.
#[derive(Clone, Debug, PartialEq)]
pub struct Flow {
    /// Stable FNV-1a identifier derived from the normalized key and first timestamp.
    pub flow_uid: u64,
    /// Event that caused this row to be emitted.
    pub end_reason: EndReason,
    /// Internet Protocol version, 4 or 6.
    pub ip_version: u8,
    /// Source address selected by the first packet (normalized for IdleOnly).
    pub src_ip: IpAddr,
    /// Destination address selected by the first packet (normalized for IdleOnly).
    pub dst_ip: IpAddr,
    /// Source transport port, or zero when the protocol has no port.
    pub src_port: u16,
    /// Destination transport port, or zero when the protocol has no port.
    pub dst_port: u16,
    /// IP protocol number.
    pub protocol: u8,
    /// First packet timestamp in nanoseconds since the Unix epoch.
    pub first_ts_ns: i64,
    /// Last packet timestamp in nanoseconds since the Unix epoch.
    pub last_ts_ns: i64,
    /// `last_ts_ns - first_ts_ns`; it may be negative for regressing captures.
    pub duration_ns: i64,
    /// Packets in the initial direction.
    pub fwd_packets: u64,
    /// Packets in the reverse direction.
    pub bwd_packets: u64,
    /// IPv4 total lengths or IPv6 packet lengths in the initial direction.
    pub fwd_ip_bytes: u64,
    /// IP bytes in the reverse direction.
    pub bwd_ip_bytes: u64,
    /// Transport payload bytes in the initial direction.
    pub fwd_payload_bytes: u64,
    /// Transport payload bytes in the reverse direction.
    pub bwd_payload_bytes: u64,
    /// Bitwise OR of TCP flags in the initial direction.
    pub fwd_tcp_flags: u16,
    /// Bitwise OR of TCP flags in the reverse direction.
    pub bwd_tcp_flags: u16,
    /// Capture index of the first packet.
    pub first_index: u64,
    /// Capture index of the last packet added to the flow.
    pub last_index: u64,
    compatibility_values: Vec<FeatureValue>,
}

impl Flow {
    /// Values for [`cicflowmeter_columns`] in the same order, excluding Label.
    pub fn compatibility_values(&self) -> &[FeatureValue] {
        &self.compatibility_values
    }

    /// Looks up one compatibility value by its stable snake_case name.
    pub fn compatibility_value(&self, policy: Policy, name: &str) -> Option<&FeatureValue> {
        cicflowmeter_columns(policy)
            .iter()
            .position(|column| column.snake == name)
            .and_then(|index| self.compatibility_values.get(index))
    }
}

#[derive(Clone, Debug)]
struct SummaryStats {
    n: u64,
    sum: f64,
    min: f64,
    max: f64,
    m1: f64,
    m2: f64,
}

impl Default for SummaryStats {
    fn default() -> Self {
        Self {
            n: 0,
            sum: 0.0,
            min: f64::NAN,
            max: f64::NAN,
            m1: f64::NAN,
            m2: f64::NAN,
        }
    }
}

impl SummaryStats {
    fn add(&mut self, value: f64) {
        if self.n == 0 {
            self.m1 = 0.0;
            self.m2 = 0.0;
        }
        self.n += 1;
        let dev = value - self.m1;
        let n_dev = dev / self.n as f64;
        self.m1 += n_dev;
        self.m2 += (self.n - 1) as f64 * dev * n_dev;
        self.sum += value;
        if value < self.min || self.min.is_nan() || self.n == 1 {
            self.min = value;
        }
        if value > self.max || self.max.is_nan() || self.n == 1 {
            self.max = value;
        }
    }

    fn mean(&self) -> f64 {
        if self.n == 0 { f64::NAN } else { self.m1 }
    }

    fn variance(&self) -> f64 {
        match self.n {
            0 => f64::NAN,
            1 => 0.0,
            _ => self.m2 / (self.n - 1) as f64,
        }
    }

    fn stddev(&self) -> f64 {
        self.variance().sqrt()
    }
}

#[derive(Clone, Debug, Default)]
struct Bulk {
    duration: i64,
    packets: u64,
    bytes: u64,
    states: u64,
    helper_packets: u64,
    helper_start: i64,
    helper_bytes: u64,
    last_ts: i64,
}

impl Bulk {
    fn add(&mut self, packet_ts: i64, size: u64, other_last_ts: i64) {
        if other_last_ts > self.helper_start {
            self.helper_start = 0;
        }
        if size == 0 {
            return;
        }
        if self.helper_start == 0 {
            self.helper_start = packet_ts;
            self.helper_packets = 1;
            self.helper_bytes = size;
            self.last_ts = packet_ts;
        } else if (packet_ts - self.last_ts) as f64 / 1_000_000.0 > 1.0 {
            self.helper_start = packet_ts;
            self.last_ts = packet_ts;
            self.helper_packets = 1;
            self.helper_bytes = size;
        } else {
            self.helper_packets += 1;
            self.helper_bytes += size;
            if self.helper_packets == 4 {
                self.states += 1;
                self.packets += self.helper_packets;
                self.bytes += self.helper_bytes;
                self.duration += packet_ts - self.helper_start;
            } else if self.helper_packets > 4 {
                self.packets += 1;
                self.bytes += size;
                self.duration += packet_ts - self.last_ts;
            }
            self.last_ts = packet_ts;
        }
    }

    fn avg_bytes(&self) -> u64 {
        self.bytes.checked_div(self.states).unwrap_or(0)
    }

    fn avg_packets(&self) -> u64 {
        self.packets.checked_div(self.states).unwrap_or(0)
    }

    fn avg_rate(&self) -> u64 {
        if self.duration == 0 {
            0
        } else {
            (self.bytes as f64 / (self.duration as f64 / 1_000_000.0)) as u64
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct DirectionalKey {
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    vlan: Option<u16>,
    icmp_type: Option<u8>,
    icmp_id: Option<u16>,
}

impl DirectionalKey {
    fn reverse(&self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
            vlan: self.vlan,
            icmp_type: self.icmp_type,
            icmp_id: self.icmp_id,
        }
    }

    fn normalized(&self) -> Self {
        let left = (ip_sort_bytes(self.src), self.src_port);
        let right = (ip_sort_bytes(self.dst), self.dst_port);
        if left <= right {
            self.clone()
        } else {
            self.reverse()
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TcpState {
    FirstFin,
    SecondFin,
    ReadyFin,
    ReadyRst,
}

#[derive(Clone, Debug)]
struct PacketInfo {
    key: DirectionalKey,
    raw_ts_ns: i64,
    ts_ns: i64,
    ts_us: i64,
    index: u64,
    ip_bytes: u64,
    payload_bytes: u64,
    header_bytes: u64,
    tcp_window: u64,
    tcp_flags: u16,
    fin: bool,
    syn: bool,
    ack: bool,
    rst: bool,
    psh: bool,
    urg: bool,
    cwr: bool,
    ece: bool,
    icmp_code: i64,
    icmp_type: i64,
}

#[derive(Clone, Debug)]
struct FlowState {
    initial_key: DirectionalKey,
    first_ts_ns: i64,
    last_ts_ns: i64,
    first_raw_ts_ns: i64,
    last_raw_ts_ns: i64,
    first_policy_ts: i64,
    last_policy_ts: i64,
    first_index: u64,
    last_index: u64,
    fwd_packets: u64,
    bwd_packets: u64,
    fwd_ip_bytes: u64,
    bwd_ip_bytes: u64,
    fwd_payload_bytes: u64,
    bwd_payload_bytes: u64,
    fwd_tcp_flags: u16,
    bwd_tcp_flags: u16,
    tcp_state: Option<TcpState>,
    policy: Policy,
    flow_id: String,
    fwd_stats: SummaryStats,
    bwd_stats: SummaryStats,
    length_stats: SummaryStats,
    flow_iat: SummaryStats,
    fwd_iat: SummaryStats,
    bwd_iat: SummaryStats,
    active: SummaryStats,
    idle: SummaryStats,
    fwd_last_us: i64,
    bwd_last_us: i64,
    start_active_us: i64,
    end_active_us: i64,
    activity_timeout_us: i64,
    fwd_header_bytes: u64,
    bwd_header_bytes: u64,
    fwd_psh: u64,
    bwd_psh: u64,
    fwd_urg: u64,
    bwd_urg: u64,
    fwd_rst: u64,
    bwd_rst: u64,
    fwd_fin: u64,
    bwd_fin: u64,
    flag_counts: [u64; 8],
    active_data_fwd: u64,
    min_seg_fwd: u64,
    init_win_fwd: u64,
    init_win_bwd: u64,
    sf_last_us: i64,
    sf_count: u64,
    sf_active_helper_us: i64,
    fwd_bulk: Bulk,
    bwd_bulk: Bulk,
    cumulative_tcp_us: i64,
    icmp_code: i64,
    icmp_type: i64,
}

impl FlowState {
    fn flow_uid(&self) -> u64 {
        flow_uid_for_directional(&self.initial_key.normalized(), self.first_raw_ts_ns)
    }

    fn new(
        packet: &PacketInfo,
        initial_key: DirectionalKey,
        policy_ts: i64,
        policy: Policy,
        activity_timeout_us: i64,
        inherit_after_first: bool,
    ) -> Self {
        let processing_key = if inherit_after_first {
            packet.key.clone()
        } else {
            initial_key.clone()
        };
        let mut state = Self {
            initial_key: processing_key,
            first_ts_ns: packet.ts_ns,
            last_ts_ns: packet.ts_ns,
            first_raw_ts_ns: packet.raw_ts_ns,
            last_raw_ts_ns: packet.raw_ts_ns,
            first_policy_ts: policy_ts,
            last_policy_ts: policy_ts,
            first_index: packet.index,
            last_index: packet.index,
            fwd_packets: 0,
            bwd_packets: 0,
            fwd_ip_bytes: 0,
            bwd_ip_bytes: 0,
            fwd_payload_bytes: 0,
            bwd_payload_bytes: 0,
            fwd_tcp_flags: 0,
            bwd_tcp_flags: 0,
            tcp_state: None,
            policy,
            flow_id: directional_flow_id(&initial_key),
            fwd_stats: SummaryStats::default(),
            bwd_stats: SummaryStats::default(),
            length_stats: SummaryStats::default(),
            flow_iat: SummaryStats::default(),
            fwd_iat: SummaryStats::default(),
            bwd_iat: SummaryStats::default(),
            active: SummaryStats::default(),
            idle: SummaryStats::default(),
            fwd_last_us: 0,
            bwd_last_us: 0,
            start_active_us: 0,
            end_active_us: 0,
            activity_timeout_us,
            fwd_header_bytes: 0,
            bwd_header_bytes: 0,
            fwd_psh: 0,
            bwd_psh: 0,
            fwd_urg: 0,
            bwd_urg: 0,
            fwd_rst: 0,
            bwd_rst: 0,
            fwd_fin: 0,
            bwd_fin: 0,
            flag_counts: [0; 8],
            active_data_fwd: 0,
            min_seg_fwd: 0,
            init_win_fwd: 0,
            init_win_bwd: 0,
            sf_last_us: -1,
            sf_count: 0,
            sf_active_helper_us: -1,
            fwd_bulk: Bulk::default(),
            bwd_bulk: Bulk::default(),
            cumulative_tcp_us: 0,
            icmp_code: packet.icmp_code,
            icmp_type: packet.icmp_type,
        };
        state.add_first(packet, policy_ts);
        state.initial_key = initial_key;
        state
    }

    fn add_first(&mut self, packet: &PacketInfo, policy_ts: i64) {
        if self.policy == Policy::Corrected || self.policy == Policy::IdleOnly {
            self.end_active_us = packet.ts_us;
            self.start_active_us = packet.ts_us;
        }
        self.update_bulk(packet);
        self.check_flags(packet);
        self.detect_subflow(packet.ts_us);
        self.length_stats.add(packet.payload_bytes as f64);
        if self.policy == Policy::CicFlowMeter {
            self.length_stats.add(packet.payload_bytes as f64);
            self.start_active_us = packet.ts_us;
            self.end_active_us = packet.ts_us;
        }
        self.add_direction(packet, true);
        self.last_ts_ns = packet.ts_ns;
        self.last_raw_ts_ns = packet.raw_ts_ns;
        self.last_policy_ts = policy_ts;
    }

    fn add(&mut self, packet: &PacketInfo, policy_ts: i64) {
        self.update_bulk(packet);
        self.detect_subflow(packet.ts_us);
        self.check_flags(packet);
        self.length_stats.add(packet.payload_bytes as f64);
        self.add_direction(packet, false);
        self.flow_iat
            .add((packet.ts_us - self.last_ts_ns / 1_000) as f64);
        self.last_ts_ns = packet.ts_ns;
        self.last_raw_ts_ns = packet.raw_ts_ns;
        self.last_policy_ts = policy_ts;
        self.last_index = packet.index;
    }

    fn add_direction(&mut self, packet: &PacketInfo, first: bool) {
        let forward = packet.key.src == self.initial_key.src;
        if forward {
            self.fwd_packets += 1;
            self.fwd_ip_bytes += packet.ip_bytes;
            self.fwd_payload_bytes += packet.payload_bytes;
            self.fwd_tcp_flags |= packet.tcp_flags;
            self.fwd_stats.add(packet.payload_bytes as f64);
            self.fwd_header_bytes += packet.header_bytes;
            if !first && self.fwd_packets > 1 {
                self.fwd_iat.add((packet.ts_us - self.fwd_last_us) as f64);
            }
            self.fwd_last_us = packet.ts_us;
            if first {
                self.min_seg_fwd = packet.header_bytes;
                self.init_win_fwd = packet.tcp_window;
            } else {
                if packet.payload_bytes >= 1 {
                    self.active_data_fwd += 1;
                }
                self.min_seg_fwd = self.min_seg_fwd.min(packet.header_bytes);
            }
            if first || self.policy != Policy::CicFlowMeter {
                self.fwd_psh += u64::from(packet.psh);
                self.fwd_urg += u64::from(packet.urg);
            }
            if !first && self.policy != Policy::CicFlowMeter {
                self.fwd_rst += u64::from(packet.rst);
                self.fwd_fin += u64::from(packet.fin);
            }
        } else {
            self.bwd_packets += 1;
            self.bwd_ip_bytes += packet.ip_bytes;
            self.bwd_payload_bytes += packet.payload_bytes;
            self.bwd_tcp_flags |= packet.tcp_flags;
            self.bwd_stats.add(packet.payload_bytes as f64);
            self.bwd_header_bytes += packet.header_bytes;
            if !first && self.bwd_packets > 1 {
                self.bwd_iat.add((packet.ts_us - self.bwd_last_us) as f64);
            }
            self.bwd_last_us = packet.ts_us;
            self.init_win_bwd = packet.tcp_window;
            if first || self.policy != Policy::CicFlowMeter {
                self.bwd_psh += u64::from(packet.psh);
                self.bwd_urg += u64::from(packet.urg);
            }
            if !first && self.policy != Policy::CicFlowMeter {
                self.bwd_rst += u64::from(packet.rst);
                self.bwd_fin += u64::from(packet.fin);
            }
        }
    }

    fn check_flags(&mut self, packet: &PacketInfo) {
        for (slot, present) in [
            packet.fin, packet.syn, packet.rst, packet.psh, packet.ack, packet.urg, packet.cwr,
            packet.ece,
        ]
        .into_iter()
        .enumerate()
        {
            self.flag_counts[slot] += u64::from(present);
        }
    }

    fn update_bulk(&mut self, packet: &PacketInfo) {
        let forward = self.policy != Policy::CicFlowMeter && packet.key.src == self.initial_key.src;
        if forward {
            let other = self.bwd_bulk.last_ts;
            self.fwd_bulk.add(packet.ts_us, packet.payload_bytes, other);
        } else {
            let other = self.fwd_bulk.last_ts;
            self.bwd_bulk.add(packet.ts_us, packet.payload_bytes, other);
        }
    }

    fn detect_subflow(&mut self, current_us: i64) {
        if self.sf_last_us == -1 {
            self.sf_last_us = current_us;
            self.sf_active_helper_us = current_us;
        }
        if current_us as f64 - self.sf_last_us as f64 / 1_000_000.0 > 1.0 {
            self.sf_count += 1;
            self.update_active_idle(current_us);
            self.sf_active_helper_us = current_us;
        }
        self.sf_last_us = current_us;
    }

    fn update_active_idle(&mut self, current_us: i64) {
        if current_us - self.end_active_us > self.activity_timeout_us {
            if self.end_active_us - self.start_active_us > 0 {
                self.active
                    .add((self.end_active_us - self.start_active_us) as f64);
            }
            self.idle.add((current_us - self.end_active_us) as f64);
            self.start_active_us = current_us;
            self.end_active_us = current_us;
        } else {
            self.end_active_us = current_us;
        }
    }

    fn packet_count(&self) -> u64 {
        self.fwd_packets + self.bwd_packets
    }

    fn complete(self, end_reason: EndReason) -> Flow {
        let flow_uid = self.flow_uid();
        let compatibility_values = self.build_compatibility_values();
        Flow {
            flow_uid,
            end_reason,
            ip_version: match self.initial_key.src {
                IpAddr::V4(_) => 4,
                IpAddr::V6(_) => 6,
            },
            src_ip: self.initial_key.src,
            dst_ip: self.initial_key.dst,
            src_port: self.initial_key.src_port,
            dst_port: self.initial_key.dst_port,
            protocol: self.initial_key.protocol,
            first_ts_ns: self.first_raw_ts_ns,
            last_ts_ns: self.last_raw_ts_ns,
            duration_ns: self.last_raw_ts_ns - self.first_raw_ts_ns,
            fwd_packets: self.fwd_packets,
            bwd_packets: self.bwd_packets,
            fwd_ip_bytes: self.fwd_ip_bytes,
            bwd_ip_bytes: self.bwd_ip_bytes,
            fwd_payload_bytes: self.fwd_payload_bytes,
            bwd_payload_bytes: self.bwd_payload_bytes,
            fwd_tcp_flags: self.fwd_tcp_flags,
            bwd_tcp_flags: self.bwd_tcp_flags,
            first_index: self.first_index,
            last_index: self.last_index,
            compatibility_values,
        }
    }

    fn build_compatibility_values(&self) -> Vec<FeatureValue> {
        use FeatureValue::{Float64 as f, Int64 as i, UInt64 as u, Utf8 as s};

        let duration_us = self.last_ts_ns / 1_000 - self.first_ts_ns / 1_000;
        let seconds = duration_us as f64 / 1_000_000.0;
        let mut values = vec![
            s(self.flow_id.clone()),
            s(self.initial_key.src.to_string()),
            u(u64::from(self.initial_key.src_port)),
            s(self.initial_key.dst.to_string()),
            u(u64::from(self.initial_key.dst_port)),
            u(u64::from(self.initial_key.protocol)),
            s(format_timestamp(self.first_ts_ns / 1_000, self.policy)),
            i(duration_us),
            u(self.fwd_packets),
            u(self.bwd_packets),
            f(self.fwd_stats.sum),
            f(self.bwd_stats.sum),
        ];
        append_packet_stats(&mut values, &self.fwd_stats);
        append_packet_stats(&mut values, &self.bwd_stats);
        values.extend([
            f((self.fwd_payload_bytes + self.bwd_payload_bytes) as f64 / seconds),
            f(self.packet_count() as f64 / seconds),
            f(self.flow_iat.mean()),
            f(self.flow_iat.stddev()),
            f(self.flow_iat.max),
            f(self.flow_iat.min),
        ]);
        append_iat(&mut values, &self.fwd_iat, self.fwd_packets);
        append_iat(&mut values, &self.bwd_iat, self.bwd_packets);
        values.extend([
            u(self.fwd_psh),
            u(self.bwd_psh),
            u(self.fwd_urg),
            u(self.bwd_urg),
        ]);
        if self.policy != Policy::CicFlowMeter {
            values.extend([u(self.fwd_rst), u(self.bwd_rst)]);
        }
        values.extend([
            u(self.fwd_header_bytes),
            u(self.bwd_header_bytes),
            f(if duration_us > 0 {
                self.fwd_packets as f64 / seconds
            } else {
                0.0
            }),
            f(if duration_us > 0 {
                self.bwd_packets as f64 / seconds
            } else {
                0.0
            }),
            f(self.length_stats.min),
            f(self.length_stats.max),
            f(self.length_stats.mean()),
            f(self.length_stats.stddev()),
            f(self.length_stats.variance()),
        ]);
        values.extend(self.flag_counts.into_iter().map(u));
        let ratio = if self.fwd_packets == 0 {
            0.0
        } else if self.policy == Policy::CicFlowMeter {
            (self.bwd_packets / self.fwd_packets) as f64
        } else {
            self.bwd_packets as f64 / self.fwd_packets as f64
        };
        let avg_packet = if self.packet_count() == 0 {
            0.0
        } else {
            self.length_stats.sum / self.packet_count() as f64
        };
        values.extend([
            f(ratio),
            f(avg_packet),
            f(if self.fwd_packets == 0 {
                0.0
            } else {
                self.fwd_stats.sum / self.fwd_packets as f64
            }),
            f(if self.bwd_packets == 0 {
                0.0
            } else {
                self.bwd_stats.sum / self.bwd_packets as f64
            }),
            u(self.fwd_bulk.avg_bytes()),
            u(self.fwd_bulk.avg_packets()),
            u(self.fwd_bulk.avg_rate()),
            u(self.bwd_bulk.avg_bytes()),
            u(self.bwd_bulk.avg_packets()),
            u(self.bwd_bulk.avg_rate()),
            u(self.fwd_packets.checked_div(self.sf_count).unwrap_or(0)),
            u(self
                .fwd_payload_bytes
                .checked_div(self.sf_count)
                .unwrap_or(0)),
            u(self.bwd_packets.checked_div(self.sf_count).unwrap_or(0)),
            u(self
                .bwd_payload_bytes
                .checked_div(self.sf_count)
                .unwrap_or(0)),
            u(self.init_win_fwd),
            u(self.init_win_bwd),
            u(self.active_data_fwd),
            u(self.min_seg_fwd),
        ]);
        append_optional_stats(&mut values, &self.active);
        append_optional_stats(&mut values, &self.idle);
        if self.policy != Policy::CicFlowMeter {
            values.extend([
                i(self.icmp_code),
                i(self.icmp_type),
                i(if self.initial_key.protocol == 6 {
                    self.cumulative_tcp_us + duration_us
                } else {
                    0
                }),
            ]);
        }
        values
    }
}

/// Result of adding one packet to a [`FlowTable`].
#[derive(Clone, Debug, PartialEq)]
pub struct PushResult {
    /// Identifier of the flow which accepted this packet, or `None` when it was discarded.
    pub flow_uid: Option<u64>,
    /// Flows closed as a consequence of adding this packet.
    pub closed: Vec<Flow>,
}

fn append_packet_stats(values: &mut Vec<FeatureValue>, stats: &SummaryStats) {
    if stats.n == 0 {
        values.extend((0..4).map(|_| FeatureValue::UInt64(0)));
    } else {
        values.extend([
            FeatureValue::Float64(stats.max),
            FeatureValue::Float64(stats.min),
            FeatureValue::Float64(stats.mean()),
            FeatureValue::Float64(stats.stddev()),
        ]);
    }
}

fn append_iat(values: &mut Vec<FeatureValue>, stats: &SummaryStats, packets: u64) {
    if packets <= 1 {
        values.extend((0..5).map(|_| FeatureValue::UInt64(0)));
    } else {
        values.extend([
            FeatureValue::Float64(stats.sum),
            FeatureValue::Float64(stats.mean()),
            FeatureValue::Float64(stats.stddev()),
            FeatureValue::Float64(stats.max),
            FeatureValue::Float64(stats.min),
        ]);
    }
}

fn append_optional_stats(values: &mut Vec<FeatureValue>, stats: &SummaryStats) {
    if stats.n == 0 {
        values.extend((0..4).map(|_| FeatureValue::UInt64(0)));
    } else {
        values.extend([
            FeatureValue::Float64(stats.mean()),
            FeatureValue::Float64(stats.stddev()),
            FeatureValue::Float64(stats.max),
            FeatureValue::Float64(stats.min),
        ]);
    }
}

/// Streaming bidirectional flow table.
#[derive(Default)]
pub struct FlowTable {
    config: FlowConfig,
    flows: HashMap<DirectionalKey, FlowState>,
    max_seen_ts_ns: Option<i64>,
    idle_deadlines: BTreeSet<(i64, DirectionalKey)>,
    accepted_packets: u64,
    discarded_packets: u64,
    max_active_len: usize,
}

impl FlowTable {
    /// Creates an empty flow table.
    pub fn new(config: FlowConfig) -> Self {
        Self {
            config,
            flows: HashMap::new(),
            max_seen_ts_ns: None,
            idle_deadlines: BTreeSet::new(),
            accepted_packets: 0,
            discarded_packets: 0,
            max_active_len: 0,
        }
    }

    /// Adds one decoded packet and returns any flows closed by that packet.
    pub fn push(&mut self, record: &PacketRecord<'_>, packet: &Packet<'_>) -> Vec<Flow> {
        self.push_with_uid(record, packet).closed
    }

    /// Adds one decoded packet and also returns the identifier of the flow which accepted it.
    pub fn push_with_uid(&mut self, record: &PacketRecord<'_>, packet: &Packet<'_>) -> PushResult {
        let Some(info) = packet_info(record, packet, &self.config) else {
            self.discarded_packets += 1;
            return PushResult {
                flow_uid: None,
                closed: Vec::new(),
            };
        };
        self.accepted_packets += 1;
        let lookup_key = if self.config.policy == Policy::IdleOnly {
            info.key.normalized()
        } else {
            info.key.clone()
        };
        let closed = match self.config.policy {
            Policy::IdleOnly => self.push_idle(info),
            Policy::CicFlowMeter | Policy::Corrected => self.push_compat(info),
        };
        self.max_active_len = self.max_active_len.max(self.flows.len());
        let reverse = lookup_key.reverse();
        let flow_uid = self
            .flows
            .get(&lookup_key)
            .or_else(|| self.flows.get(&reverse))
            .map(FlowState::flow_uid)
            .or_else(|| closed.last().map(|flow| flow.flow_uid));
        PushResult { flow_uid, closed }
    }

    /// Emits all flows remaining at end of capture.
    pub fn finish(mut self) -> Vec<Flow> {
        let mut flows = self
            .flows
            .drain()
            .filter_map(|(_, state)| {
                if self.config.policy == Policy::CicFlowMeter && state.packet_count() <= 1 {
                    return None;
                }
                let reason = match state.tcp_state {
                    Some(TcpState::ReadyRst) => EndReason::Rst,
                    Some(TcpState::ReadyFin | TcpState::SecondFin) => EndReason::Fin,
                    _ => EndReason::EndOfCapture,
                };
                Some(state.complete(reason))
            })
            .collect::<Vec<_>>();
        flows.sort_by_key(|flow| (flow.first_index, flow.last_index, flow.flow_uid));
        flows
    }

    /// Number of currently resident flows.
    pub fn active_len(&self) -> usize {
        self.flows.len()
    }

    /// Largest number of simultaneously resident flow states observed so far.
    pub fn max_active_len(&self) -> usize {
        self.max_active_len
    }

    /// Number of packets accepted by the selected policy.
    pub fn accepted_packets(&self) -> u64 {
        self.accepted_packets
    }

    /// Number of packets that could not be represented as a flow packet.
    pub fn discarded_packets(&self) -> u64 {
        self.discarded_packets
    }

    fn push_compat(&mut self, info: PacketInfo) -> Vec<Flow> {
        let policy_ts = info.ts_ns / 1_000;
        let reverse = info.key.reverse();
        let stored_key = if self.flows.contains_key(&info.key) {
            Some(info.key.clone())
        } else if self.flows.contains_key(&reverse) {
            Some(reverse)
        } else {
            None
        };
        let Some(stored_key) = stored_key else {
            let key = info.key.clone();
            self.flows.insert(
                key.clone(),
                FlowState::new(
                    &info,
                    key,
                    policy_ts,
                    self.config.policy,
                    duration_micros_i64(self.config.activity_timeout),
                    false,
                ),
            );
            return Vec::new();
        };

        let timeout_us = duration_micros_i64(self.config.flow_timeout);
        let timed_out = policy_ts - self.flows[&stored_key].first_policy_ts > timeout_us;
        let ready_and_syn = self.config.policy == Policy::Corrected
            && matches!(
                self.flows[&stored_key].tcp_state,
                Some(TcpState::ReadyFin | TcpState::ReadyRst)
            )
            && info.syn;
        if timed_out || ready_and_syn {
            let old = self
                .flows
                .remove(&stored_key)
                .expect("flow key was checked");
            let should_emit = self.config.policy == Policy::Corrected || old.packet_count() > 1;
            let reason = if timed_out {
                EndReason::FlowTimeout
            } else {
                match old.tcp_state {
                    Some(TcpState::ReadyRst) => EndReason::Rst,
                    _ => EndReason::Fin,
                }
            };
            let starts_new_direction = self.config.policy == Policy::Corrected
                && ((ready_and_syn && !info.ack) || info.key.protocol != 6);
            let inherited = if starts_new_direction {
                info.key.clone()
            } else {
                old.initial_key.clone()
            };
            let carry_tcp = self.config.policy == Policy::Corrected && !starts_new_direction;
            let cumulative_tcp_us = if carry_tcp {
                old.cumulative_tcp_us + policy_ts - old.first_policy_ts
            } else {
                0
            };
            let mut new_state = FlowState::new(
                &info,
                inherited,
                policy_ts,
                self.config.policy,
                duration_micros_i64(self.config.activity_timeout),
                self.config.policy == Policy::CicFlowMeter && timed_out,
            );
            new_state.cumulative_tcp_us = cumulative_tcp_us;
            new_state.flow_id = directional_flow_id(&stored_key);
            self.flows.insert(stored_key, new_state);
            return should_emit
                .then(|| old.complete(reason))
                .into_iter()
                .collect();
        }

        if self.config.policy == Policy::CicFlowMeter && info.fin {
            let mut state = self
                .flows
                .remove(&stored_key)
                .expect("flow key was checked");
            state.add(&info, policy_ts);
            return vec![state.complete(EndReason::Fin)];
        }

        if self.config.policy == Policy::Corrected
            && info.key.protocol == 1
            && self.flows[&stored_key].icmp_code != info.icmp_code
            && self.flows[&stored_key].icmp_type != info.icmp_type
        {
            let old = self
                .flows
                .remove(&stored_key)
                .expect("flow key was checked");
            let mut new_state = FlowState::new(
                &info,
                info.key.clone(),
                policy_ts,
                self.config.policy,
                duration_micros_i64(self.config.activity_timeout),
                false,
            );
            new_state.flow_id = directional_flow_id(&stored_key);
            self.flows.insert(stored_key, new_state);
            return vec![old.complete(EndReason::IcmpTypeCodeChange)];
        }

        let state = self
            .flows
            .get_mut(&stored_key)
            .expect("flow key was checked");
        state.add(&info, policy_ts);
        if self.config.policy == Policy::Corrected {
            if info.fin {
                state.tcp_state = match state.tcp_state {
                    None => Some(TcpState::FirstFin),
                    Some(TcpState::FirstFin) if state.fwd_fin > 0 && state.bwd_fin > 0 => {
                        Some(TcpState::SecondFin)
                    }
                    other => other,
                };
            } else if info.rst {
                state.tcp_state = Some(TcpState::ReadyRst);
            } else if info.ack && state.tcp_state == Some(TcpState::SecondFin) {
                state.tcp_state = Some(TcpState::ReadyFin);
            }
        }
        Vec::new()
    }

    fn push_idle(&mut self, info: PacketInfo) -> Vec<Flow> {
        let now = self
            .max_seen_ts_ns
            .map_or(info.ts_ns, |seen| seen.max(info.ts_ns));
        self.max_seen_ts_ns = Some(now);
        let timeout = duration_nanos_i64(self.config.idle_timeout);
        let mut closed = Vec::new();
        while self
            .idle_deadlines
            .first()
            .is_some_and(|(deadline, _)| *deadline < now)
        {
            let (_, key) = self
                .idle_deadlines
                .pop_first()
                .expect("the first deadline was checked");
            if let Some(flow) = self.flows.remove(&key) {
                closed.push(flow.complete(EndReason::IdleTimeout));
            }
        }

        let key = info.key.normalized();
        if let Some(flow) = self.flows.get_mut(&key) {
            self.idle_deadlines
                .remove(&(flow.last_policy_ts.saturating_add(timeout), key.clone()));
            flow.add(&info, info.ts_ns);
            self.idle_deadlines
                .insert((flow.last_policy_ts.saturating_add(timeout), key));
        } else {
            self.flows.insert(
                key.clone(),
                FlowState::new(
                    &info,
                    info.key.clone(),
                    info.ts_ns,
                    self.config.policy,
                    duration_micros_i64(self.config.activity_timeout),
                    false,
                ),
            );
            self.idle_deadlines
                .insert((info.ts_ns.saturating_add(timeout), key));
        }
        closed
    }
}

fn packet_info(
    record: &PacketRecord<'_>,
    packet: &Packet<'_>,
    config: &FlowConfig,
) -> Option<PacketInfo> {
    let raw_ts_ns = record.ts_ns?;

    // jNetPcap 1.4.1's scanner reports both an IPv4 header and an ICMP header for this
    // malformed interpretation of the DARPA capture's ARP request.  Engelen's PacketReader
    // tries ICMP first and rejects the resulting packet, while the original reader reaches
    // its IPv4 fallback.  Retain the scanner-specific distinction needed for byte-for-byte
    // compatibility with the two published data sets.
    if config.policy == Policy::Corrected
        && record.data.len() >= 22
        && record.data[..12]
            == [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x08, 0x00, 0x20, 0x83, 0x4a, 0x82,
            ]
        && record.data[12..14] == [0x08, 0x06]
        && record.data[20..22] == [0x00, 0x01]
    {
        return None;
    }

    let ts_ns = if config.policy == Policy::IdleOnly {
        raw_ts_ns
    } else {
        raw_ts_ns / 1_000 * 1_000
    };
    if packet.layer::<Ipv4View>().is_none()
        && let Some(info) = corrected_tso_info(record, config, raw_ts_ns, ts_ns)
    {
        return Some(info);
    }
    let (src, dst, ip_bytes, ip_protocol) = if let Some(ip) = packet.layer::<Ipv4View>() {
        (
            IpAddr::V4(ip.src()),
            IpAddr::V4(ip.dst()),
            u64::from(ip.total_len()),
            ip.protocol(),
        )
    } else if config.policy != Policy::IdleOnly
        && record.data.len() >= 20
        && record.data[12..14] == [0x08, 0x06]
        && record.data[0] != 0
    {
        // jnetpcap 1.4.1 registers an Ip4 header at offset zero for ARP Ethernet frames whose
        // destination MAC starts with a nonzero octet. PacketReader then reads these byte ranges
        // as IPv4 addresses. Compatibility policies intentionally retain that scanner bug.
        (
            IpAddr::V4(std::net::Ipv4Addr::new(
                record.data[12],
                record.data[13],
                record.data[14],
                record.data[15],
            )),
            IpAddr::V4(std::net::Ipv4Addr::new(
                record.data[16],
                record.data[17],
                record.data[18],
                record.data[19],
            )),
            u64::from(u16::from_be_bytes([record.data[2], record.data[3]])),
            record.data[9],
        )
    } else if config.policy == Policy::IdleOnly {
        let ip = packet.layer::<Ipv6View>()?;
        (
            IpAddr::V6(ip.src()),
            IpAddr::V6(ip.dst()),
            u64::from(ip.payload_len()) + 40,
            ip.upper_protocol(),
        )
    } else {
        return None;
    };

    let tcp = packet.layer::<TcpView>();
    let udp = packet.layer::<UdpView>();
    let icmp4 = packet.layer::<Icmpv4View>();
    let icmp6 = packet.layer::<Icmpv6View>();
    let corrected_icmp =
        config.policy != Policy::CicFlowMeter && (icmp4.is_some() || icmp6.is_some());
    let embedded = (config.policy == Policy::CicFlowMeter && icmp4.is_some())
        .then(|| embedded_transport(packet.payload()))
        .flatten();
    let (src_port, dst_port, protocol, payload_bytes, header_bytes, tcp_window, tcp_flags) =
        if corrected_icmp {
            (0, 0, ip_protocol, 0, 0, 0, 0)
        } else if let Some(tcp) = tcp {
            (
                tcp.src_port(),
                tcp.dst_port(),
                6,
                packet.payload().len() as u64,
                tcp.header_len() as u64,
                u64::from(tcp.window()),
                tcp.flags(),
            )
        } else if let Some(udp) = udp {
            (
                udp.src_port(),
                udp.dst_port(),
                17,
                packet.payload().len() as u64,
                8,
                0,
                0,
            )
        } else if let Some(embedded) = embedded {
            (
                embedded.src_port,
                embedded.dst_port,
                embedded.protocol,
                embedded.payload_bytes,
                embedded.header_bytes,
                embedded.tcp_window,
                embedded.tcp_flags,
            )
        } else if config.policy == Policy::IdleOnly {
            (0, 0, ip_protocol, 0, 0, 0, 0)
        } else {
            (0, 0, 0, 0, 0, 0, 0)
        };
    let vlan = config
        .vlan_in_key
        .then(|| packet.layers_of::<VlanView>().next().map(|vlan| vlan.vid()))
        .flatten();
    let icmp_type = icmp4
        .map(|icmp| icmp.icmp_type())
        .or_else(|| icmp6.map(|icmp| icmp.icmp_type()));
    let icmp_code = icmp4
        .map(|icmp| icmp.code())
        .or_else(|| icmp6.map(|icmp| icmp.code()));
    let icmp_id = icmp_type
        .filter(|icmp_type| matches!(icmp_type, 0 | 8 | 128 | 129))
        .and_then(|_| packet.payload().get(..2))
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]));
    Some(PacketInfo {
        key: DirectionalKey {
            src,
            dst,
            src_port,
            dst_port,
            protocol,
            vlan,
            icmp_type: (config.policy == Policy::IdleOnly)
                .then_some(icmp_type)
                .flatten(),
            icmp_id: (config.policy == Policy::IdleOnly)
                .then_some(icmp_id)
                .flatten(),
        },
        raw_ts_ns,
        ts_ns,
        ts_us: ts_ns / 1_000,
        index: record.index,
        ip_bytes,
        payload_bytes,
        header_bytes,
        tcp_window,
        tcp_flags,
        fin: tcp_flags & 0x01 != 0,
        syn: tcp_flags & 0x02 != 0,
        rst: tcp_flags & 0x04 != 0,
        psh: tcp_flags & 0x08 != 0,
        ack: tcp_flags & 0x10 != 0,
        urg: tcp_flags & 0x20 != 0,
        ece: tcp_flags & 0x40 != 0,
        cwr: tcp_flags & 0x80 != 0,
        icmp_code: icmp_code.map_or(-1, i64::from),
        icmp_type: icmp_type.map_or(-1, i64::from),
    })
}

fn corrected_tso_info(
    record: &PacketRecord<'_>,
    config: &FlowConfig,
    raw_ts_ns: i64,
    ts_ns: i64,
) -> Option<PacketInfo> {
    if config.policy != Policy::Corrected || record.linktype.0 != 1 || record.data.len() < 34 {
        return None;
    }
    let data = record.data;
    let mut ip_offset = 14usize;
    let mut ether_type = u16::from_be_bytes([data[12], data[13]]);
    while matches!(ether_type, 0x8100 | 0x88a8 | 0x9100) {
        let tag = data.get(ip_offset..ip_offset + 4)?;
        ether_type = u16::from_be_bytes([tag[2], tag[3]]);
        ip_offset += 4;
    }
    if ether_type != 0x0800 || data.get(ip_offset)? >> 4 != 4 {
        return None;
    }
    let header_bytes = usize::from(data[ip_offset] & 0x0f) * 4;
    if header_bytes < 20 || data.len() < ip_offset + header_bytes {
        return None;
    }
    if data[ip_offset + 2..ip_offset + 4] != [0, 0] {
        return None;
    }
    let src = IpAddr::V4(std::net::Ipv4Addr::new(
        data[ip_offset + 12],
        data[ip_offset + 13],
        data[ip_offset + 14],
        data[ip_offset + 15],
    ));
    let dst = IpAddr::V4(std::net::Ipv4Addr::new(
        data[ip_offset + 16],
        data[ip_offset + 17],
        data[ip_offset + 18],
        data[ip_offset + 19],
    ));
    let protocol = data[ip_offset + 9];
    let transport_offset = ip_offset + header_bytes;
    let transport = data.get(transport_offset..)?;
    let (src_port, dst_port, payload_bytes, l4_header_bytes, tcp_window, tcp_flags) = match protocol
    {
        6 if transport.len() >= 20 => {
            let tcp_header = usize::from(transport[12] >> 4) * 4;
            if tcp_header < 20 || transport.len() < tcp_header {
                return None;
            }
            (
                u16::from_be_bytes([transport[0], transport[1]]),
                u16::from_be_bytes([transport[2], transport[3]]),
                (transport.len() - tcp_header) as u64,
                tcp_header as u64,
                u64::from(u16::from_be_bytes([transport[14], transport[15]])),
                u16::from(transport[13]) | (u16::from(transport[12] & 1) << 8),
            )
        }
        17 if transport.len() >= 8 => (
            u16::from_be_bytes([transport[0], transport[1]]),
            u16::from_be_bytes([transport[2], transport[3]]),
            (transport.len() - 8) as u64,
            8,
            0,
            0,
        ),
        _ => (0, 0, 0, 0, 0, 0),
    };
    let flags = tcp_flags as u8;
    Some(PacketInfo {
        key: DirectionalKey {
            src,
            dst,
            src_port,
            dst_port,
            protocol,
            vlan: None,
            icmp_type: None,
            icmp_id: None,
        },
        raw_ts_ns,
        ts_ns,
        ts_us: ts_ns / 1_000,
        index: record.index,
        ip_bytes: (data.len() - ip_offset) as u64,
        payload_bytes,
        header_bytes: l4_header_bytes,
        tcp_window,
        tcp_flags,
        fin: flags & 0x01 != 0,
        syn: flags & 0x02 != 0,
        rst: flags & 0x04 != 0,
        psh: flags & 0x08 != 0,
        ack: flags & 0x10 != 0,
        urg: flags & 0x20 != 0,
        ece: flags & 0x40 != 0,
        cwr: flags & 0x80 != 0,
        icmp_code: -1,
        icmp_type: -1,
    })
}

#[derive(Clone, Copy, Debug)]
struct EmbeddedTransport {
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    payload_bytes: u64,
    header_bytes: u64,
    tcp_window: u64,
    tcp_flags: u16,
}

fn embedded_transport(payload: &[u8]) -> Option<EmbeddedTransport> {
    parse_embedded_transport(payload)
        .or_else(|| payload.get(4..).and_then(parse_embedded_transport))
}

fn parse_embedded_transport(payload: &[u8]) -> Option<EmbeddedTransport> {
    if payload.len() < 20 || payload[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(payload[0] & 0x0f) * 4;
    if header_len < 20 || payload.len() < header_len + 4 {
        return None;
    }
    let protocol = payload[9];
    if protocol != 6 && protocol != 17 {
        return None;
    }
    let transport = &payload[header_len..];
    let transport_header_len = if protocol == 6 {
        let tcp_header_len = usize::from(transport.get(12)? >> 4) * 4;
        if tcp_header_len < 20 || transport.len() < tcp_header_len {
            return None;
        }
        tcp_header_len
    } else {
        if transport.len() < 8 {
            return None;
        }
        8
    };
    Some(EmbeddedTransport {
        protocol,
        src_port: u16::from_be_bytes([transport[0], transport[1]]),
        dst_port: u16::from_be_bytes([transport[2], transport[3]]),
        payload_bytes: (transport.len() - transport_header_len) as u64,
        header_bytes: transport_header_len as u64,
        tcp_window: if protocol == 6 {
            u64::from(u16::from_be_bytes([transport[14], transport[15]]))
        } else {
            0
        },
        tcp_flags: if protocol == 6 {
            u16::from(transport[13]) | (u16::from(transport[12] & 1) << 8)
        } else {
            0
        },
    })
}

fn duration_micros_i64(duration: Duration) -> i64 {
    i64::try_from(duration.as_micros()).unwrap_or(i64::MAX)
}

fn duration_nanos_i64(duration: Duration) -> i64 {
    i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX)
}

fn ip_sort_bytes(ip: IpAddr) -> [u8; 17] {
    let mut bytes = [0u8; 17];
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

/// Computes the stable 64-bit flow identifier used by packet-tools.
///
/// Bytes are fed to FNV-1a in this order: IP version, protocol, VLAN presence/value, first
/// endpoint address and port, second endpoint address and port, ICMP type/identifier presence and
/// value, then the first timestamp as a signed big-endian nanosecond value. Endpoints are sorted by
/// address bytes followed by port before hashing.
fn flow_uid_for_directional(key: &DirectionalKey, first_ts_ns: i64) -> u64 {
    flow_uid(
        &FlowIdentityKey {
            first_ip: key.src,
            second_ip: key.dst,
            first_port: key.src_port,
            second_port: key.dst_port,
            protocol: key.protocol,
            vlan: key.vlan,
            icmp_type: key.icmp_type,
            icmp_id: key.icmp_id,
        },
        first_ts_ns,
    )
}

/// Computes the stable FNV-1a identifier shared by flow and reassembly crates.
pub fn flow_uid(key: &FlowIdentityKey, first_ts_ns: i64) -> u64 {
    let mut bytes = Vec::with_capacity(64);
    bytes.push(match key.first_ip {
        IpAddr::V4(_) => 4,
        IpAddr::V6(_) => 6,
    });
    bytes.push(key.protocol);
    match key.vlan {
        Some(vlan) => {
            bytes.push(1);
            bytes.extend_from_slice(&vlan.to_be_bytes());
        }
        None => bytes.push(0),
    }
    append_ip(&mut bytes, key.first_ip);
    bytes.extend_from_slice(&key.first_port.to_be_bytes());
    append_ip(&mut bytes, key.second_ip);
    bytes.extend_from_slice(&key.second_port.to_be_bytes());
    match key.icmp_type {
        Some(value) => {
            bytes.push(1);
            bytes.push(value);
        }
        None => bytes.push(0),
    }
    match key.icmp_id {
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        None => bytes.push(0),
    }
    bytes.extend_from_slice(&first_ts_ns.to_be_bytes());
    bytes.into_iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

fn append_ip(out: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(ip) => out.extend_from_slice(&ip.octets()),
        IpAddr::V6(ip) => out.extend_from_slice(&ip.octets()),
    }
}

fn directional_flow_id(key: &DirectionalKey) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        key.src, key.dst, key.src_port, key.dst_port, key.protocol
    )
}

fn format_timestamp(timestamp_us: i64, policy: Policy) -> String {
    let seconds = timestamp_us.div_euclid(1_000_000);
    let micros = timestamp_us.rem_euclid(1_000_000);
    let days = seconds.div_euclid(86_400);
    let second_of_day = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = second_of_day / 3_600;
    let minute = second_of_day % 3_600 / 60;
    let second = second_of_day % 60;
    if policy == Policy::CicFlowMeter {
        let suffix = if hour < 12 { "AM" } else { "PM" };
        let hour12 = match hour % 12 {
            0 => 12,
            value => value,
        };
        format!("{day:02}/{month:02}/{year:04} {hour12:02}:{minute:02}:{second:02} {suffix}")
    } else {
        let base = format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02}");
        if micros == 0 {
            base
        } else if micros % 1_000 == 0 {
            format!("{base}.{:03}", micros / 1_000)
        } else {
            format!("{base}.{micros:06}")
        }
    }
}

fn civil_from_days(days_since_epoch: i64) -> (i64, i64, i64) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

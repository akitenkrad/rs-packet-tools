use std::{fs::File, io::Write, sync::Arc};

use arrow::{
    array::{
        ArrayRef, BooleanArray, Int64Array, StringArray, UInt8Array, UInt16Array, UInt32Array,
        UInt64Array,
    },
    csv,
    datatypes::{DataType, Field as ArrowField, Schema, SchemaRef},
    error::ArrowError,
    record_batch::RecordBatch,
};
use packet_tools_capture::PacketRecord;
use packet_tools_dissect::{
    EthernetView, Icmpv4View, Icmpv6View, Ipv4View, Ipv6View, Packet, TcpView, UdpView, VlanView,
};
use parquet::{
    arrow::ArrowWriter, basic::Compression, errors::ParquetError,
    file::properties::WriterProperties,
};
use thiserror::Error;

const BATCH_SIZE: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Parquet,
    Csv,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Index,
    TsNs,
    Caplen,
    Origlen,
    Linktype,
    Interface,
    EthSrc,
    EthDst,
    Ethertype,
    VlanId,
    VlanDepth,
    IpVersion,
    IpSrc,
    IpDst,
    IpProto,
    IpTtl,
    IpLen,
    IpId,
    IpFragOffset,
    IpMf,
    IpDf,
    SrcPort,
    DstPort,
    TcpFlags,
    TcpSeq,
    TcpAck,
    TcpWindow,
    UdpLength,
    IcmpType,
    IcmpCode,
    L4PayloadLen,
    TrailerLen,
    IpTruncated,
    Malformed,
}

impl Field {
    pub const ALL: &'static [Self] = &[
        Self::Index,
        Self::TsNs,
        Self::Caplen,
        Self::Origlen,
        Self::Linktype,
        Self::Interface,
        Self::EthSrc,
        Self::EthDst,
        Self::Ethertype,
        Self::VlanId,
        Self::VlanDepth,
        Self::IpVersion,
        Self::IpSrc,
        Self::IpDst,
        Self::IpProto,
        Self::IpTtl,
        Self::IpLen,
        Self::IpId,
        Self::IpFragOffset,
        Self::IpMf,
        Self::IpDf,
        Self::SrcPort,
        Self::DstPort,
        Self::TcpFlags,
        Self::TcpSeq,
        Self::TcpAck,
        Self::TcpWindow,
        Self::UdpLength,
        Self::IcmpType,
        Self::IcmpCode,
        Self::L4PayloadLen,
        Self::TrailerLen,
        Self::IpTruncated,
        Self::Malformed,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Self::Index => "index",
            Self::TsNs => "ts_ns",
            Self::Caplen => "caplen",
            Self::Origlen => "origlen",
            Self::Linktype => "linktype",
            Self::Interface => "interface",
            Self::EthSrc => "eth_src",
            Self::EthDst => "eth_dst",
            Self::Ethertype => "ethertype",
            Self::VlanId => "vlan_id",
            Self::VlanDepth => "vlan_depth",
            Self::IpVersion => "ip_version",
            Self::IpSrc => "ip_src",
            Self::IpDst => "ip_dst",
            Self::IpProto => "ip_proto",
            Self::IpTtl => "ip_ttl",
            Self::IpLen => "ip_len",
            Self::IpId => "ip_id",
            Self::IpFragOffset => "ip_frag_offset",
            Self::IpMf => "ip_mf",
            Self::IpDf => "ip_df",
            Self::SrcPort => "src_port",
            Self::DstPort => "dst_port",
            Self::TcpFlags => "tcp_flags",
            Self::TcpSeq => "tcp_seq",
            Self::TcpAck => "tcp_ack",
            Self::TcpWindow => "tcp_window",
            Self::UdpLength => "udp_length",
            Self::IcmpType => "icmp_type",
            Self::IcmpCode => "icmp_code",
            Self::L4PayloadLen => "l4_payload_len",
            Self::TrailerLen => "trailer_len",
            Self::IpTruncated => "ip_truncated",
            Self::Malformed => "malformed",
        }
    }

    fn data_type(self) -> DataType {
        match self {
            Self::Index => DataType::UInt64,
            Self::TsNs => DataType::Int64,
            Self::Caplen
            | Self::Origlen
            | Self::Interface
            | Self::IpLen
            | Self::IpId
            | Self::IpFragOffset
            | Self::TcpSeq
            | Self::TcpAck
            | Self::L4PayloadLen
            | Self::TrailerLen => DataType::UInt32,
            Self::Linktype
            | Self::Ethertype
            | Self::VlanId
            | Self::SrcPort
            | Self::DstPort
            | Self::TcpFlags
            | Self::TcpWindow
            | Self::UdpLength => DataType::UInt16,
            Self::VlanDepth
            | Self::IpVersion
            | Self::IpProto
            | Self::IpTtl
            | Self::IcmpType
            | Self::IcmpCode => DataType::UInt8,
            Self::IpMf | Self::IpDf | Self::IpTruncated => DataType::Boolean,
            Self::EthSrc | Self::EthDst | Self::IpSrc | Self::IpDst | Self::Malformed => {
                DataType::Utf8
            }
        }
    }

    fn nullable(self) -> bool {
        !matches!(
            self,
            Self::Index
                | Self::Caplen
                | Self::Origlen
                | Self::Linktype
                | Self::Interface
                | Self::VlanDepth
                | Self::TrailerLen
                | Self::IpTruncated
        )
    }
}

#[derive(Debug, Error)]
#[error("unknown field `{name}`; available fields: {available}")]
pub struct UnknownField {
    name: String,
    available: String,
}

pub fn parse_fields(list: &str) -> Result<Vec<Field>, UnknownField> {
    let available = Field::ALL
        .iter()
        .map(|field| field.name())
        .collect::<Vec<_>>()
        .join(", ");
    list.split(',')
        .map(|name| {
            let name = name.trim();
            Field::ALL
                .iter()
                .copied()
                .find(|field| field.name() == name)
                .ok_or_else(|| UnknownField {
                    name: name.to_owned(),
                    available: available.clone(),
                })
        })
        .collect()
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Arrow(#[from] ArrowError),
    #[error(transparent)]
    Parquet(#[from] ParquetError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

enum Output<W: Write + Send> {
    Parquet(ArrowWriter<W>),
    Csv(csv::Writer<W>),
}

pub struct PacketsWriter<W: Write + Send> {
    fields: Vec<Field>,
    schema: SchemaRef,
    rows: Vec<Row>,
    output: Output<W>,
    wrote_batch: bool,
}

impl<W: Write + Send> PacketsWriter<W> {
    pub fn new(writer: W, format: Format, fields: &[Field]) -> Result<Self, Error> {
        let fields = fields.to_vec();
        let schema = Arc::new(Schema::new(
            fields
                .iter()
                .map(|field| ArrowField::new(field.name(), field.data_type(), field.nullable()))
                .collect::<Vec<_>>(),
        ));
        let output = match format {
            Format::Parquet => {
                let properties = WriterProperties::builder()
                    .set_compression(Compression::SNAPPY)
                    .build();
                Output::Parquet(ArrowWriter::try_new(
                    writer,
                    Arc::clone(&schema),
                    Some(properties),
                )?)
            }
            Format::Csv => Output::Csv(csv::WriterBuilder::new().with_header(true).build(writer)),
        };
        Ok(Self {
            fields,
            schema,
            rows: Vec::with_capacity(BATCH_SIZE),
            output,
            wrote_batch: false,
        })
    }

    pub fn push(&mut self, record: &PacketRecord<'_>, packet: &Packet<'_>) -> Result<(), Error> {
        self.rows.push(Row::new(record, packet));
        if self.rows.len() == BATCH_SIZE {
            self.flush()?;
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), Error> {
        if self.rows.is_empty() && !self.wrote_batch {
            self.write_batch()?;
        } else {
            self.flush()?;
        }
        match self.output {
            Output::Parquet(writer) => {
                writer.close()?;
            }
            Output::Csv(writer) => writer.into_inner().flush()?,
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), Error> {
        if self.rows.is_empty() {
            return Ok(());
        }
        self.write_batch()?;
        self.rows.clear();
        Ok(())
    }

    fn write_batch(&mut self) -> Result<(), Error> {
        let columns = self
            .fields
            .iter()
            .map(|field| column(*field, &self.rows))
            .collect::<Vec<_>>();
        let batch = RecordBatch::try_new(Arc::clone(&self.schema), columns)?;
        match &mut self.output {
            Output::Parquet(writer) => writer.write(&batch)?,
            Output::Csv(writer) => writer.write(&batch)?,
        }
        self.wrote_batch = true;
        Ok(())
    }
}

impl PacketsWriter<File> {
    pub fn create(
        path: impl AsRef<std::path::Path>,
        format: Format,
        fields: &[Field],
    ) -> Result<Self, Error> {
        Self::new(File::create(path)?, format, fields)
    }
}

#[derive(Default)]
struct Row {
    index: u64,
    ts_ns: Option<i64>,
    caplen: u32,
    origlen: u32,
    linktype: u16,
    interface: u32,
    eth_src: Option<String>,
    eth_dst: Option<String>,
    ethertype: Option<u16>,
    vlan_id: Option<u16>,
    vlan_depth: u8,
    ip_version: Option<u8>,
    ip_src: Option<String>,
    ip_dst: Option<String>,
    ip_proto: Option<u8>,
    ip_ttl: Option<u8>,
    ip_len: Option<u32>,
    ip_id: Option<u32>,
    ip_frag_offset: Option<u32>,
    ip_mf: Option<bool>,
    ip_df: Option<bool>,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    tcp_flags: Option<u16>,
    tcp_seq: Option<u32>,
    tcp_ack: Option<u32>,
    tcp_window: Option<u16>,
    udp_length: Option<u16>,
    icmp_type: Option<u8>,
    icmp_code: Option<u8>,
    l4_payload_len: Option<u32>,
    trailer_len: u32,
    ip_truncated: bool,
    malformed: Option<String>,
}

impl Row {
    fn new(record: &PacketRecord<'_>, packet: &Packet<'_>) -> Self {
        let mut row = Self {
            index: record.index,
            ts_ns: record.ts_ns,
            caplen: record.caplen,
            origlen: record.origlen,
            linktype: record.linktype.0,
            interface: record.interface,
            trailer_len: packet.trailer().len() as u32,
            ip_truncated: packet.ip_truncated(),
            malformed: packet.malformed().map(|malformed| {
                format!(
                    "{}:{}@{}",
                    malformed.layer.as_str(),
                    malformed.kind.as_str(),
                    malformed.offset
                )
            }),
            ..Self::default()
        };
        if let Some(ethernet) = packet.layer::<EthernetView>() {
            row.eth_src = Some(mac(ethernet.src()));
            row.eth_dst = Some(mac(ethernet.dst()));
            row.ethertype = ethertype_value(ethernet.ethertype());
        }
        let vlans = packet.layers_of::<VlanView>().collect::<Vec<_>>();
        row.vlan_depth = vlans.len() as u8;
        row.vlan_id = vlans.first().map(VlanView::vid);
        if let Some(inner) = vlans.last() {
            row.ethertype = ethertype_value(inner.ethertype());
        }
        if let Some(sll) = packet.layer::<packet_tools_dissect::LinuxSllView>() {
            row.ethertype = Some(sll.protocol());
        }
        if let Some(sll) = packet.layer::<packet_tools_dissect::LinuxSll2View>() {
            row.ethertype = Some(sll.protocol());
        }
        if let Some(ip) = packet.layer::<Ipv4View>() {
            row.ip_version = Some(4);
            row.ip_src = Some(ip.src().to_string());
            row.ip_dst = Some(ip.dst().to_string());
            row.ip_proto = Some(ip.protocol());
            row.ip_ttl = Some(ip.ttl());
            row.ip_len = Some(u32::from(ip.total_len()));
            row.ip_id = Some(u32::from(ip.id()));
            row.ip_frag_offset = Some(ip.fragment_offset());
            row.ip_mf = Some(ip.more_fragments());
            row.ip_df = Some(ip.dont_fragment());
        } else if let Some(ip) = packet.layer::<Ipv6View>() {
            row.ip_version = Some(6);
            row.ip_src = Some(ip.src().to_string());
            row.ip_dst = Some(ip.dst().to_string());
            row.ip_proto = Some(ip.upper_protocol());
            row.ip_ttl = Some(ip.hop_limit());
            row.ip_len = Some(40 + u32::from(ip.payload_len()));
            if let Some(fragment) = ip.fragment() {
                row.ip_id = Some(fragment.id);
                row.ip_frag_offset = Some(fragment.offset_bytes);
                row.ip_mf = Some(fragment.more);
            }
        }
        if let Some(tcp) = packet.layer::<TcpView>() {
            row.src_port = Some(tcp.src_port());
            row.dst_port = Some(tcp.dst_port());
            row.tcp_flags = Some(tcp.flags());
            row.tcp_seq = Some(tcp.seq());
            row.tcp_ack = Some(tcp.ack());
            row.tcp_window = Some(tcp.window());
            row.l4_payload_len = Some(packet.payload().len() as u32);
        } else if let Some(udp) = packet.layer::<UdpView>() {
            row.src_port = Some(udp.src_port());
            row.dst_port = Some(udp.dst_port());
            row.udp_length = Some(udp.length());
            row.l4_payload_len = Some(packet.payload().len() as u32);
        } else if let Some(icmp) = packet.layer::<Icmpv4View>() {
            row.icmp_type = Some(icmp.icmp_type());
            row.icmp_code = Some(icmp.code());
        } else if let Some(icmp) = packet.layer::<Icmpv6View>() {
            row.icmp_type = Some(icmp.icmp_type());
            row.icmp_code = Some(icmp.code());
        }
        row
    }
}

fn mac(bytes: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

macro_rules! primitive_column {
    ($rows:expr, $array:ty, $member:ident) => {
        Arc::new(<$array>::from(
            $rows.iter().map(|row| row.$member).collect::<Vec<_>>(),
        )) as ArrayRef
    };
}

fn column(field: Field, rows: &[Row]) -> ArrayRef {
    match field {
        Field::Index => Arc::new(UInt64Array::from_iter_values(
            rows.iter().map(|row| row.index),
        )),
        Field::TsNs => primitive_column!(rows, Int64Array, ts_ns),
        Field::Caplen => Arc::new(UInt32Array::from_iter_values(
            rows.iter().map(|row| row.caplen),
        )),
        Field::Origlen => Arc::new(UInt32Array::from_iter_values(
            rows.iter().map(|row| row.origlen),
        )),
        Field::Linktype => Arc::new(UInt16Array::from_iter_values(
            rows.iter().map(|row| row.linktype),
        )),
        Field::Interface => Arc::new(UInt32Array::from_iter_values(
            rows.iter().map(|row| row.interface),
        )),
        Field::EthSrc => string_column(rows.iter().map(|row| row.eth_src.as_deref())),
        Field::EthDst => string_column(rows.iter().map(|row| row.eth_dst.as_deref())),
        Field::Ethertype => primitive_column!(rows, UInt16Array, ethertype),
        Field::VlanId => primitive_column!(rows, UInt16Array, vlan_id),
        Field::VlanDepth => Arc::new(UInt8Array::from_iter_values(
            rows.iter().map(|row| row.vlan_depth),
        )),
        Field::IpVersion => primitive_column!(rows, UInt8Array, ip_version),
        Field::IpSrc => string_column(rows.iter().map(|row| row.ip_src.as_deref())),
        Field::IpDst => string_column(rows.iter().map(|row| row.ip_dst.as_deref())),
        Field::IpProto => primitive_column!(rows, UInt8Array, ip_proto),
        Field::IpTtl => primitive_column!(rows, UInt8Array, ip_ttl),
        Field::IpLen => primitive_column!(rows, UInt32Array, ip_len),
        Field::IpId => primitive_column!(rows, UInt32Array, ip_id),
        Field::IpFragOffset => primitive_column!(rows, UInt32Array, ip_frag_offset),
        Field::IpMf => primitive_column!(rows, BooleanArray, ip_mf),
        Field::IpDf => primitive_column!(rows, BooleanArray, ip_df),
        Field::SrcPort => primitive_column!(rows, UInt16Array, src_port),
        Field::DstPort => primitive_column!(rows, UInt16Array, dst_port),
        Field::TcpFlags => primitive_column!(rows, UInt16Array, tcp_flags),
        Field::TcpSeq => primitive_column!(rows, UInt32Array, tcp_seq),
        Field::TcpAck => primitive_column!(rows, UInt32Array, tcp_ack),
        Field::TcpWindow => primitive_column!(rows, UInt16Array, tcp_window),
        Field::UdpLength => primitive_column!(rows, UInt16Array, udp_length),
        Field::IcmpType => primitive_column!(rows, UInt8Array, icmp_type),
        Field::IcmpCode => primitive_column!(rows, UInt8Array, icmp_code),
        Field::L4PayloadLen => primitive_column!(rows, UInt32Array, l4_payload_len),
        Field::TrailerLen => Arc::new(UInt32Array::from_iter_values(
            rows.iter().map(|row| row.trailer_len),
        )),
        Field::IpTruncated => Arc::new(BooleanArray::from(
            rows.iter().map(|row| row.ip_truncated).collect::<Vec<_>>(),
        )),
        Field::Malformed => string_column(rows.iter().map(|row| row.malformed.as_deref())),
    }
}

fn string_column<'a>(values: impl Iterator<Item = Option<&'a str>>) -> ArrayRef {
    Arc::new(StringArray::from_iter(values))
}

/// Values below 0x0600 are IEEE 802.3 frame lengths, not EtherTypes.
fn ethertype_value(field: u16) -> Option<u16> {
    (field >= 0x0600).then_some(field)
}

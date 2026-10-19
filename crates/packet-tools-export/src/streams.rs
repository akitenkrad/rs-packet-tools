//! CSV and Parquet tables produced by `packet-tools streams`.

use std::{fs::File, path::Path, sync::Arc};

use arrow::{
    array::{
        ArrayRef, BooleanArray, Int64Array, StringArray, UInt8Array, UInt16Array, UInt32Array,
        UInt64Array,
    },
    csv,
    datatypes::{DataType, Field, Schema},
    error::ArrowError,
    record_batch::RecordBatch,
};
use parquet::{
    arrow::ArrowWriter, basic::Compression, errors::ParquetError,
    file::properties::WriterProperties,
};
use thiserror::Error;

use crate::packets::Format;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamRow {
    pub stream_id: u64,
    pub flow_uid: u64,
    pub direction: String,
    pub client_ip: String,
    pub server_ip: String,
    pub client_port: u16,
    pub server_port: u16,
    pub first_ts_ns: i64,
    pub last_ts_ns: i64,
    pub midstream: bool,
    pub bytes: u64,
    pub segments: u64,
    pub gaps: u64,
    pub gap_bytes: u64,
    pub overlaps: u64,
    pub overlap_conflicts: u64,
    pub retransmitted_bytes: u64,
    pub post_close_packets: u64,
    pub post_close_bytes: u64,
    pub keepalives: u64,
    pub close_reason: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EventRow {
    pub index: u64,
    pub ts_ns: i64,
    pub kind: String,
    pub stream_id: Option<u64>,
    pub direction: Option<String>,
    pub ip_version: Option<u8>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub identification: Option<u32>,
    pub protocol: Option<u8>,
    pub vlan: Option<u16>,
    pub position: Option<u64>,
    pub length: Option<u64>,
    pub retained: Option<String>,
    pub previous_index: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatagramRow {
    pub index: u64,
    pub ip_version: u8,
    pub src_ip: String,
    pub dst_ip: String,
    pub identification: u32,
    pub protocol: u8,
    pub fragments: u64,
    pub reassembled_len: u64,
    pub payload_sha256: String,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Arrow(#[from] ArrowError),
    #[error(transparent)]
    Parquet(#[from] ParquetError),
}

pub fn write_streams(
    path: impl AsRef<Path>,
    format: Format,
    rows: &[StreamRow],
) -> Result<(), Error> {
    let fields = vec![
        field("stream_id", DataType::UInt64, false),
        field("flow_uid", DataType::UInt64, false),
        field("direction", DataType::Utf8, false),
        field("client_ip", DataType::Utf8, false),
        field("server_ip", DataType::Utf8, false),
        field("client_port", DataType::UInt16, false),
        field("server_port", DataType::UInt16, false),
        field("first_ts_ns", DataType::Int64, false),
        field("last_ts_ns", DataType::Int64, false),
        field("midstream", DataType::Boolean, false),
        field("bytes", DataType::UInt64, false),
        field("segments", DataType::UInt64, false),
        field("gaps", DataType::UInt64, false),
        field("gap_bytes", DataType::UInt64, false),
        field("overlaps", DataType::UInt64, false),
        field("overlap_conflicts", DataType::UInt64, false),
        field("retransmitted_bytes", DataType::UInt64, false),
        field("post_close_packets", DataType::UInt64, false),
        field("post_close_bytes", DataType::UInt64, false),
        field("keepalives", DataType::UInt64, false),
        field("close_reason", DataType::Utf8, false),
        field("sha256", DataType::Utf8, false),
    ];
    let arrays: Vec<ArrayRef> = vec![
        Arc::new(UInt64Array::from_iter_values(
            rows.iter().map(|r| r.stream_id),
        )),
        Arc::new(UInt64Array::from_iter_values(
            rows.iter().map(|r| r.flow_uid),
        )),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|r| r.direction.as_str()),
        )),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|r| r.client_ip.as_str()),
        )),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|r| r.server_ip.as_str()),
        )),
        Arc::new(UInt16Array::from_iter_values(
            rows.iter().map(|r| r.client_port),
        )),
        Arc::new(UInt16Array::from_iter_values(
            rows.iter().map(|r| r.server_port),
        )),
        Arc::new(Int64Array::from_iter_values(
            rows.iter().map(|r| r.first_ts_ns),
        )),
        Arc::new(Int64Array::from_iter_values(
            rows.iter().map(|r| r.last_ts_ns),
        )),
        Arc::new(BooleanArray::from(
            rows.iter().map(|r| r.midstream).collect::<Vec<_>>(),
        )),
        Arc::new(UInt64Array::from_iter_values(rows.iter().map(|r| r.bytes))),
        Arc::new(UInt64Array::from_iter_values(
            rows.iter().map(|r| r.segments),
        )),
        Arc::new(UInt64Array::from_iter_values(rows.iter().map(|r| r.gaps))),
        Arc::new(UInt64Array::from_iter_values(
            rows.iter().map(|r| r.gap_bytes),
        )),
        Arc::new(UInt64Array::from_iter_values(
            rows.iter().map(|r| r.overlaps),
        )),
        Arc::new(UInt64Array::from_iter_values(
            rows.iter().map(|r| r.overlap_conflicts),
        )),
        Arc::new(UInt64Array::from_iter_values(
            rows.iter().map(|r| r.retransmitted_bytes),
        )),
        Arc::new(UInt64Array::from_iter_values(
            rows.iter().map(|r| r.post_close_packets),
        )),
        Arc::new(UInt64Array::from_iter_values(
            rows.iter().map(|r| r.post_close_bytes),
        )),
        Arc::new(UInt64Array::from_iter_values(
            rows.iter().map(|r| r.keepalives),
        )),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|r| r.close_reason.as_str()),
        )),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|r| r.sha256.as_str()),
        )),
    ];
    write(path.as_ref(), format, fields, arrays)
}

pub fn write_events(
    path: impl AsRef<Path>,
    format: Format,
    rows: &[EventRow],
) -> Result<(), Error> {
    let fields = vec![
        field("index", DataType::UInt64, false),
        field("ts_ns", DataType::Int64, false),
        field("kind", DataType::Utf8, false),
        field("stream_id", DataType::UInt64, true),
        field("direction", DataType::Utf8, true),
        field("ip_version", DataType::UInt8, true),
        field("src_ip", DataType::Utf8, true),
        field("dst_ip", DataType::Utf8, true),
        field("identification", DataType::UInt32, true),
        field("protocol", DataType::UInt8, true),
        field("vlan", DataType::UInt16, true),
        field("position", DataType::UInt64, true),
        field("length", DataType::UInt64, true),
        field("retained", DataType::Utf8, true),
        field("previous_index", DataType::UInt64, true),
    ];
    let arrays: Vec<ArrayRef> = vec![
        Arc::new(UInt64Array::from_iter_values(rows.iter().map(|r| r.index))),
        Arc::new(Int64Array::from_iter_values(rows.iter().map(|r| r.ts_ns))),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|r| r.kind.as_str()),
        )),
        Arc::new(UInt64Array::from_iter(rows.iter().map(|r| r.stream_id))),
        Arc::new(StringArray::from_iter(
            rows.iter().map(|r| r.direction.as_deref()),
        )),
        Arc::new(UInt8Array::from_iter(rows.iter().map(|r| r.ip_version))),
        Arc::new(StringArray::from_iter(
            rows.iter().map(|r| r.src_ip.as_deref()),
        )),
        Arc::new(StringArray::from_iter(
            rows.iter().map(|r| r.dst_ip.as_deref()),
        )),
        Arc::new(UInt32Array::from_iter(
            rows.iter().map(|r| r.identification),
        )),
        Arc::new(UInt8Array::from_iter(rows.iter().map(|r| r.protocol))),
        Arc::new(UInt16Array::from_iter(rows.iter().map(|r| r.vlan))),
        Arc::new(UInt64Array::from_iter(rows.iter().map(|r| r.position))),
        Arc::new(UInt64Array::from_iter(rows.iter().map(|r| r.length))),
        Arc::new(StringArray::from_iter(
            rows.iter().map(|r| r.retained.as_deref()),
        )),
        Arc::new(UInt64Array::from_iter(
            rows.iter().map(|r| r.previous_index),
        )),
    ];
    write(path.as_ref(), format, fields, arrays)
}

pub fn write_datagrams(
    path: impl AsRef<Path>,
    format: Format,
    rows: &[DatagramRow],
) -> Result<(), Error> {
    let fields = vec![
        field("index", DataType::UInt64, false),
        field("ip_version", DataType::UInt8, false),
        field("src_ip", DataType::Utf8, false),
        field("dst_ip", DataType::Utf8, false),
        field("identification", DataType::UInt32, false),
        field("protocol", DataType::UInt8, false),
        field("fragments", DataType::UInt64, false),
        field("reassembled_len", DataType::UInt64, false),
        field("payload_sha256", DataType::Utf8, false),
    ];
    let arrays: Vec<ArrayRef> = vec![
        Arc::new(UInt64Array::from_iter_values(rows.iter().map(|r| r.index))),
        Arc::new(UInt8Array::from_iter_values(
            rows.iter().map(|r| r.ip_version),
        )),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|r| r.src_ip.as_str()),
        )),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|r| r.dst_ip.as_str()),
        )),
        Arc::new(UInt32Array::from_iter_values(
            rows.iter().map(|r| r.identification),
        )),
        Arc::new(UInt8Array::from_iter_values(
            rows.iter().map(|r| r.protocol),
        )),
        Arc::new(UInt64Array::from_iter_values(
            rows.iter().map(|r| r.fragments),
        )),
        Arc::new(UInt64Array::from_iter_values(
            rows.iter().map(|r| r.reassembled_len),
        )),
        Arc::new(StringArray::from_iter_values(
            rows.iter().map(|r| r.payload_sha256.as_str()),
        )),
    ];
    write(path.as_ref(), format, fields, arrays)
}

fn field(name: &'static str, data_type: DataType, nullable: bool) -> Field {
    Field::new(name, data_type, nullable)
}

fn write(
    path: &Path,
    format: Format,
    fields: Vec<Field>,
    arrays: Vec<ArrayRef>,
) -> Result<(), Error> {
    let schema = Arc::new(Schema::new(fields));
    let batch = RecordBatch::try_new(Arc::clone(&schema), arrays)?;
    let file = File::create(path)?;
    match format {
        Format::Csv => {
            let mut writer = csv::WriterBuilder::new().with_header(true).build(file);
            writer.write(&batch)?;
            writer.into_inner().sync_all()?;
        }
        Format::Parquet => {
            let properties = WriterProperties::builder()
                .set_compression(Compression::SNAPPY)
                .build();
            let mut writer = ArrowWriter::try_new(file, schema, Some(properties))?;
            writer.write(&batch)?;
            writer.close()?;
        }
    }
    Ok(())
}

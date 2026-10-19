//! CSV and Parquet writers for completed flow rows.

use std::{fs::File, io::Write, sync::Arc};

use arrow::{
    array::{
        ArrayRef, Float64Array, Int64Array, StringArray, UInt8Array, UInt16Array, UInt64Array,
    },
    csv,
    datatypes::{DataType, Field as ArrowField, Schema, SchemaRef},
    error::ArrowError,
    record_batch::RecordBatch,
};
use packet_tools_flow::{ColumnType, FeatureValue, Flow, Policy, Preset, cicflowmeter_columns};
use parquet::{
    arrow::ArrowWriter, basic::Compression, errors::ParquetError,
    file::properties::WriterProperties,
};
use thiserror::Error;

use crate::packets::Format;

const BATCH_SIZE: usize = 16_384;

/// Naming convention for a flows table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ColumnNames {
    /// Stable snake_case names, including `flow_uid` and `end_reason`.
    Snake,
    /// CICFlowMeter's names and order, excluding `Label` and packet-tools metadata.
    Original,
}

/// Errors returned while creating or writing a flows table.
#[derive(Debug, Error)]
pub enum Error {
    #[error("original column names require the cicflowmeter preset")]
    OriginalMinimal,
    #[error(transparent)]
    Arrow(#[from] ArrowError),
    #[error(transparent)]
    Parquet(#[from] ParquetError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Copy)]
enum Source {
    FlowUid,
    EndReason,
    Minimal(usize),
    Compatibility(usize),
}

#[derive(Clone)]
struct OutputColumn {
    name: &'static str,
    data_type: DataType,
    source: Source,
}

enum Output<W: Write + Send> {
    Parquet(ArrowWriter<W>),
    Csv(csv::Writer<W>),
}

/// Streaming writer for completed flows.
pub struct FlowsWriter<W: Write + Send> {
    columns: Vec<OutputColumn>,
    schema: SchemaRef,
    rows: Vec<Flow>,
    output: Output<W>,
    wrote_batch: bool,
}

impl<W: Write + Send> std::fmt::Debug for FlowsWriter<W> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FlowsWriter")
            .field("columns", &self.columns.len())
            .field("buffered_rows", &self.rows.len())
            .finish_non_exhaustive()
    }
}

impl<W: Write + Send> FlowsWriter<W> {
    /// Creates a writer with a fixed schema.
    pub fn new(
        writer: W,
        format: Format,
        policy: Policy,
        preset: Preset,
        names: ColumnNames,
    ) -> Result<Self, Error> {
        if names == ColumnNames::Original && preset == Preset::Minimal {
            return Err(Error::OriginalMinimal);
        }
        let columns = output_columns(policy, preset, names);
        let schema = Arc::new(Schema::new(
            columns
                .iter()
                .map(|column| ArrowField::new(column.name, column.data_type.clone(), false))
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
            columns,
            schema,
            rows: Vec::with_capacity(BATCH_SIZE),
            output,
            wrote_batch: false,
        })
    }

    /// Buffers one completed flow and flushes a full batch.
    pub fn push(&mut self, flow: &Flow) -> Result<(), Error> {
        self.rows.push(flow.clone());
        if self.rows.len() == BATCH_SIZE {
            self.flush()?;
        }
        Ok(())
    }

    /// Flushes buffered flows and closes the underlying writer.
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
        let arrays = self
            .columns
            .iter()
            .map(|column| build_array(column, &self.rows))
            .collect::<Vec<_>>();
        let batch = RecordBatch::try_new(Arc::clone(&self.schema), arrays)?;
        match &mut self.output {
            Output::Parquet(writer) => writer.write(&batch)?,
            Output::Csv(writer) => writer.write(&batch)?,
        }
        self.wrote_batch = true;
        Ok(())
    }
}

impl FlowsWriter<File> {
    /// Creates a flows table at `path`.
    pub fn create(
        path: impl AsRef<std::path::Path>,
        format: Format,
        policy: Policy,
        preset: Preset,
        names: ColumnNames,
    ) -> Result<Self, Error> {
        Self::new(File::create(path)?, format, policy, preset, names)
    }
}

fn output_columns(policy: Policy, preset: Preset, names: ColumnNames) -> Vec<OutputColumn> {
    if preset == Preset::Minimal {
        return MINIMAL_COLUMNS
            .iter()
            .enumerate()
            .map(|(index, (name, data_type))| OutputColumn {
                name,
                data_type: data_type.clone(),
                source: Source::Minimal(index),
            })
            .collect();
    }

    let mut columns = Vec::new();
    if names == ColumnNames::Snake {
        columns.push(OutputColumn {
            name: "flow_uid",
            data_type: DataType::UInt64,
            source: Source::FlowUid,
        });
        columns.push(OutputColumn {
            name: "end_reason",
            data_type: DataType::Utf8,
            source: Source::EndReason,
        });
    }
    columns.extend(
        cicflowmeter_columns(policy)
            .iter()
            .enumerate()
            .map(|(index, column)| OutputColumn {
                name: if names == ColumnNames::Snake {
                    column.snake
                } else {
                    column.original
                },
                data_type: compatibility_data_type(column.data_type),
                source: Source::Compatibility(index),
            }),
    );
    columns
}

const MINIMAL_COLUMNS: &[(&str, DataType)] = &[
    ("flow_uid", DataType::UInt64),
    ("end_reason", DataType::Utf8),
    ("ip_version", DataType::UInt8),
    ("src_ip", DataType::Utf8),
    ("dst_ip", DataType::Utf8),
    ("src_port", DataType::UInt16),
    ("dst_port", DataType::UInt16),
    ("protocol", DataType::UInt8),
    ("first_ts_ns", DataType::Int64),
    ("last_ts_ns", DataType::Int64),
    ("duration_ns", DataType::Int64),
    ("fwd_packets", DataType::UInt64),
    ("bwd_packets", DataType::UInt64),
    ("fwd_ip_bytes", DataType::UInt64),
    ("bwd_ip_bytes", DataType::UInt64),
    ("fwd_payload_bytes", DataType::UInt64),
    ("bwd_payload_bytes", DataType::UInt64),
    ("fwd_tcp_flags", DataType::UInt16),
    ("bwd_tcp_flags", DataType::UInt16),
    ("first_index", DataType::UInt64),
    ("last_index", DataType::UInt64),
];

fn compatibility_data_type(data_type: ColumnType) -> DataType {
    match data_type {
        ColumnType::Utf8 => DataType::Utf8,
        ColumnType::UInt64 => DataType::UInt64,
        ColumnType::Int64 => DataType::Int64,
        ColumnType::Float64 => DataType::Float64,
    }
}

fn build_array(column: &OutputColumn, rows: &[Flow]) -> ArrayRef {
    match &column.data_type {
        DataType::Utf8 => Arc::new(StringArray::from_iter_values(
            rows.iter().map(|flow| string_value(flow, column.source)),
        )),
        DataType::UInt8 => Arc::new(UInt8Array::from_iter_values(
            rows.iter()
                .map(|flow| uint_value(flow, column.source) as u8),
        )),
        DataType::UInt16 => Arc::new(UInt16Array::from_iter_values(
            rows.iter()
                .map(|flow| uint_value(flow, column.source) as u16),
        )),
        DataType::UInt64 => Arc::new(UInt64Array::from_iter_values(
            rows.iter().map(|flow| uint_value(flow, column.source)),
        )),
        DataType::Int64 => Arc::new(Int64Array::from_iter_values(
            rows.iter().map(|flow| int_value(flow, column.source)),
        )),
        DataType::Float64 => Arc::new(Float64Array::from_iter_values(
            rows.iter().map(|flow| float_value(flow, column.source)),
        )),
        other => unreachable!("unsupported flow column type {other:?}"),
    }
}

fn compatibility_value(flow: &Flow, source: Source) -> &FeatureValue {
    let Source::Compatibility(index) = source else {
        unreachable!("not a compatibility column")
    };
    &flow.compatibility_values()[index]
}

fn string_value(flow: &Flow, source: Source) -> String {
    match source {
        Source::EndReason => flow.end_reason.as_str().to_owned(),
        Source::Minimal(1) => flow.end_reason.as_str().to_owned(),
        Source::Minimal(3) => flow.src_ip.to_string(),
        Source::Minimal(4) => flow.dst_ip.to_string(),
        Source::Compatibility(_) => match compatibility_value(flow, source) {
            FeatureValue::Utf8(value) => value.clone(),
            value => value.java_string(),
        },
        _ => unreachable!("not a string column"),
    }
}

fn uint_value(flow: &Flow, source: Source) -> u64 {
    match source {
        Source::FlowUid | Source::Minimal(0) => flow.flow_uid,
        Source::Minimal(2) => u64::from(flow.ip_version),
        Source::Minimal(5) => u64::from(flow.src_port),
        Source::Minimal(6) => u64::from(flow.dst_port),
        Source::Minimal(7) => u64::from(flow.protocol),
        Source::Minimal(11) => flow.fwd_packets,
        Source::Minimal(12) => flow.bwd_packets,
        Source::Minimal(13) => flow.fwd_ip_bytes,
        Source::Minimal(14) => flow.bwd_ip_bytes,
        Source::Minimal(15) => flow.fwd_payload_bytes,
        Source::Minimal(16) => flow.bwd_payload_bytes,
        Source::Minimal(17) => u64::from(flow.fwd_tcp_flags),
        Source::Minimal(18) => u64::from(flow.bwd_tcp_flags),
        Source::Minimal(19) => flow.first_index,
        Source::Minimal(20) => flow.last_index,
        Source::Compatibility(_) => match compatibility_value(flow, source) {
            FeatureValue::UInt64(value) => *value,
            FeatureValue::Int64(value) => *value as u64,
            _ => unreachable!("compatibility value type differs from schema"),
        },
        _ => unreachable!("not an unsigned column"),
    }
}

fn int_value(flow: &Flow, source: Source) -> i64 {
    match source {
        Source::Minimal(8) => flow.first_ts_ns,
        Source::Minimal(9) => flow.last_ts_ns,
        Source::Minimal(10) => flow.duration_ns,
        Source::Compatibility(_) => match compatibility_value(flow, source) {
            FeatureValue::Int64(value) => *value,
            FeatureValue::UInt64(value) => *value as i64,
            _ => unreachable!("compatibility value type differs from schema"),
        },
        _ => unreachable!("not a signed column"),
    }
}

fn float_value(flow: &Flow, source: Source) -> f64 {
    match compatibility_value(flow, source) {
        FeatureValue::Float64(value) => *value,
        FeatureValue::UInt64(value) => *value as f64,
        FeatureValue::Int64(value) => *value as f64,
        _ => unreachable!("compatibility value type differs from schema"),
    }
}

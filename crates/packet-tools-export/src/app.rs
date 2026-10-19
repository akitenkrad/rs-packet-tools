use std::{
    fs::{self, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use arrow::{
    array::{
        ArrayRef, BooleanArray, Int64Array, StringArray, UInt8Array, UInt16Array, UInt64Array,
    },
    csv,
    datatypes::{DataType, Field, Schema},
    record_batch::RecordBatch,
};
use packet_tools_app::{AppEvent, AppOutput, Common, DispatchRow};
use parquet::{arrow::ArrowWriter, basic::Compression, file::properties::WriterProperties};

use crate::{packets::Format, streams::Error};

pub fn write_app(
    directory: impl AsRef<Path>,
    format: Format,
    output: &AppOutput,
) -> Result<(), Error> {
    let mut writer = AppWriter::new(directory, format)?;
    writer.write_events(&output.events)?;
    writer.write_dispatch(&output.dispatch)?;
    writer.close()
}

pub struct AppWriter {
    dns: TableWriter,
    http: TableWriter,
    tls: TableWriter,
    heartbeat: TableWriter,
    ftp: TableWriter,
    ssh: TableWriter,
    smtp: TableWriter,
    telnet: TableWriter,
    dispatch: TableWriter,
}

impl AppWriter {
    pub fn new(directory: impl AsRef<Path>, format: Format) -> Result<Self, Error> {
        let directory = directory.as_ref();
        fs::create_dir_all(directory)?;
        let ext = match format {
            Format::Csv => "csv",
            Format::Parquet => "parquet",
        };
        let table = |name: &str| TableWriter::new(directory.join(format!("{name}.{ext}")), format);
        Ok(Self {
            dns: table("dns"),
            http: table("http"),
            tls: table("tls"),
            heartbeat: table("tls_heartbeat"),
            ftp: table("ftp"),
            ssh: table("ssh"),
            smtp: table("smtp"),
            telnet: table("telnet"),
            dispatch: table("dispatch"),
        })
    }

    pub fn write_events(&mut self, events: &[AppEvent]) -> Result<(), Error> {
        let dns = events
            .iter()
            .filter_map(|e| {
                if let AppEvent::Dns(v) = e {
                    Some(v)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let mut fields = common_fields();
        fields.extend([
            f("id", DataType::UInt16, false),
            f("is_response", DataType::Boolean, false),
            f("opcode", DataType::UInt8, false),
            f("rcode", DataType::UInt8, false),
            f("aa", DataType::Boolean, false),
            f("tc", DataType::Boolean, false),
            f("rd", DataType::Boolean, false),
            f("ra", DataType::Boolean, false),
            f("qname", DataType::Utf8, true),
            f("qtype", DataType::UInt16, true),
            f("qclass", DataType::UInt16, true),
            f("question_count", DataType::UInt16, false),
            f("answer_count", DataType::UInt16, false),
            f("authority_count", DataType::UInt16, false),
            f("additional_count", DataType::UInt16, false),
            f("answers", DataType::Utf8, false),
            f("malformed", DataType::Boolean, false),
        ]);
        let mut arrays = common_arrays(dns.iter().map(|v| &v.common).collect());
        arrays.extend([
            arc(UInt16Array::from_iter_values(dns.iter().map(|v| v.id))),
            arc(BooleanArray::from(
                dns.iter().map(|v| v.is_response).collect::<Vec<_>>(),
            )),
            arc(UInt8Array::from_iter_values(dns.iter().map(|v| v.opcode))),
            arc(UInt8Array::from_iter_values(dns.iter().map(|v| v.rcode))),
            arc(BooleanArray::from(
                dns.iter().map(|v| v.aa).collect::<Vec<_>>(),
            )),
            arc(BooleanArray::from(
                dns.iter().map(|v| v.tc).collect::<Vec<_>>(),
            )),
            arc(BooleanArray::from(
                dns.iter().map(|v| v.rd).collect::<Vec<_>>(),
            )),
            arc(BooleanArray::from(
                dns.iter().map(|v| v.ra).collect::<Vec<_>>(),
            )),
            arc(StringArray::from_iter(
                dns.iter().map(|v| v.qname.as_deref()),
            )),
            arc(UInt16Array::from_iter(dns.iter().map(|v| v.qtype))),
            arc(UInt16Array::from_iter(dns.iter().map(|v| v.qclass))),
            arc(UInt16Array::from_iter_values(
                dns.iter().map(|v| v.question_count),
            )),
            arc(UInt16Array::from_iter_values(
                dns.iter().map(|v| v.answer_count),
            )),
            arc(UInt16Array::from_iter_values(
                dns.iter().map(|v| v.authority_count),
            )),
            arc(UInt16Array::from_iter_values(
                dns.iter().map(|v| v.additional_count),
            )),
            arc(StringArray::from_iter_values(
                dns.iter().map(|v| json(&v.answers)),
            )),
            arc(BooleanArray::from(
                dns.iter().map(|v| v.malformed).collect::<Vec<_>>(),
            )),
        ]);
        self.dns.write(fields, arrays)?;

        let http = events
            .iter()
            .filter_map(|e| {
                if let AppEvent::Http(v) = e {
                    Some(v)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let mut fields = common_fields();
        fields.extend([
            f("transaction", DataType::UInt64, false),
            f("kind", DataType::Utf8, false),
            f("method", DataType::Utf8, true),
            f("uri", DataType::Utf8, true),
            f("version", DataType::Utf8, true),
            f("host", DataType::Utf8, true),
            f("user_agent", DataType::Utf8, true),
            f("referer", DataType::Utf8, true),
            f("content_type", DataType::Utf8, true),
            f("content_length", DataType::UInt64, true),
            f("transfer_encoding", DataType::Utf8, true),
            f("status", DataType::UInt16, true),
            f("reason", DataType::Utf8, true),
            f("body_len", DataType::UInt64, false),
        ]);
        let mut arrays = common_arrays(http.iter().map(|v| &v.common).collect());
        arrays.extend([
            arc(UInt64Array::from_iter_values(
                http.iter().map(|v| v.transaction),
            )),
            svals(http.iter().map(|v| v.kind.as_str())),
            sopts(http.iter().map(|v| v.method.as_deref())),
            sopts(http.iter().map(|v| v.uri.as_deref())),
            sopts(http.iter().map(|v| v.version.as_deref())),
            sopts(http.iter().map(|v| v.host.as_deref())),
            sopts(http.iter().map(|v| v.user_agent.as_deref())),
            sopts(http.iter().map(|v| v.referer.as_deref())),
            sopts(http.iter().map(|v| v.content_type.as_deref())),
            arc(UInt64Array::from_iter(
                http.iter().map(|v| v.content_length),
            )),
            sopts(http.iter().map(|v| v.transfer_encoding.as_deref())),
            arc(UInt16Array::from_iter(http.iter().map(|v| v.status))),
            sopts(http.iter().map(|v| v.reason.as_deref())),
            arc(UInt64Array::from_iter_values(
                http.iter().map(|v| v.body_len),
            )),
        ]);
        self.http.write(fields, arrays)?;

        let tls = events
            .iter()
            .filter_map(|e| {
                if let AppEvent::Tls(v) = e {
                    Some(v)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let mut fields = common_fields();
        fields.extend([
            f("kind", DataType::Utf8, false),
            f("record_version", DataType::UInt16, true),
            f("client_version", DataType::UInt16, true),
            f("selected_version", DataType::UInt16, true),
            f("supported_versions", DataType::Utf8, false),
            f("sni", DataType::Utf8, true),
            f("alpn", DataType::Utf8, false),
            f("cipher_suites", DataType::Utf8, false),
            f("selected_cipher", DataType::UInt16, true),
            f("extensions", DataType::Utf8, false),
            f("ja3", DataType::Utf8, true),
            f("ja3_md5", DataType::Utf8, true),
            f("ja4", DataType::Utf8, true),
            f("ja3s", DataType::Utf8, true),
            f("ja3s_md5", DataType::Utf8, true),
        ]);
        let mut arrays = common_arrays(tls.iter().map(|v| &v.common).collect());
        arrays.extend([
            svals(tls.iter().map(|v| v.kind.as_str())),
            arc(UInt16Array::from_iter(tls.iter().map(|v| v.record_version))),
            arc(UInt16Array::from_iter(tls.iter().map(|v| v.client_version))),
            arc(UInt16Array::from_iter(
                tls.iter().map(|v| v.selected_version),
            )),
            svals(tls.iter().map(|v| json(&v.supported_versions))),
            sopts(tls.iter().map(|v| v.sni.as_deref())),
            svals(tls.iter().map(|v| json(&v.alpn))),
            svals(tls.iter().map(|v| json(&v.cipher_suites))),
            arc(UInt16Array::from_iter(
                tls.iter().map(|v| v.selected_cipher),
            )),
            svals(tls.iter().map(|v| json(&v.extensions))),
            sopts(tls.iter().map(|v| v.ja3.as_deref())),
            sopts(tls.iter().map(|v| v.ja3_md5.as_deref())),
            sopts(tls.iter().map(|v| v.ja4.as_deref())),
            sopts(tls.iter().map(|v| v.ja3s.as_deref())),
            sopts(tls.iter().map(|v| v.ja3s_md5.as_deref())),
        ]);
        self.tls.write(fields, arrays)?;

        let hb = events
            .iter()
            .filter_map(|e| {
                if let AppEvent::TlsHeartbeat(v) = e {
                    Some(v)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let mut fields = common_fields();
        fields.extend([
            f("record_version", DataType::UInt16, false),
            f("record_length", DataType::UInt16, false),
            f("encrypted", DataType::Boolean, false),
            f("heartbeat_type", DataType::Utf8, true),
            f("declared_payload_length", DataType::UInt16, true),
            f("length_mismatch", DataType::Boolean, false),
        ]);
        let mut arrays = common_arrays(hb.iter().map(|v| &v.common).collect());
        arrays.extend([
            arc(UInt16Array::from_iter_values(
                hb.iter().map(|v| v.record_version),
            )),
            arc(UInt16Array::from_iter_values(
                hb.iter().map(|v| v.record_length),
            )),
            arc(BooleanArray::from(
                hb.iter().map(|v| v.encrypted).collect::<Vec<_>>(),
            )),
            sopts(hb.iter().map(|v| v.heartbeat_type.as_deref())),
            arc(UInt16Array::from_iter(
                hb.iter().map(|v| v.declared_payload_length),
            )),
            arc(BooleanArray::from(
                hb.iter().map(|v| v.length_mismatch).collect::<Vec<_>>(),
            )),
        ]);
        self.heartbeat.write(fields, arrays)?;

        write_ftp(&mut self.ftp, events)?;
        write_ssh(&mut self.ssh, events)?;
        write_smtp(&mut self.smtp, events)?;
        write_telnet(&mut self.telnet, events)
    }

    pub fn write_dispatch(&mut self, rows: &[DispatchRow]) -> Result<(), Error> {
        write_dispatch(&mut self.dispatch, rows)
    }

    pub fn close(mut self) -> Result<(), Error> {
        self.write_events(&[])?;
        self.write_dispatch(&[])?;
        self.dns.close()?;
        self.http.close()?;
        self.tls.close()?;
        self.heartbeat.close()?;
        self.ftp.close()?;
        self.ssh.close()?;
        self.smtp.close()?;
        self.telnet.close()?;
        self.dispatch.close()
    }
}

fn write_ftp(writer: &mut TableWriter, events: &[AppEvent]) -> Result<(), Error> {
    let rows = events
        .iter()
        .filter_map(|e| {
            if let AppEvent::Ftp(v) = e {
                Some(v)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let mut fields = common_fields();
    fields.extend([
        f("kind", DataType::Utf8, false),
        f("command", DataType::Utf8, true),
        f("argument", DataType::Utf8, true),
        f("code", DataType::UInt16, true),
        f("text", DataType::Utf8, true),
        f("login", DataType::Utf8, true),
    ]);
    let mut arrays = common_arrays(rows.iter().map(|v| &v.common).collect());
    arrays.extend([
        svals(rows.iter().map(|v| v.kind.as_str())),
        sopts(rows.iter().map(|v| v.command.as_deref())),
        sopts(rows.iter().map(|v| v.argument.as_deref())),
        arc(UInt16Array::from_iter(rows.iter().map(|v| v.code))),
        sopts(rows.iter().map(|v| v.text.as_deref())),
        sopts(rows.iter().map(|v| v.login.as_deref())),
    ]);
    writer.write(fields, arrays)
}
fn write_ssh(writer: &mut TableWriter, events: &[AppEvent]) -> Result<(), Error> {
    let rows = events
        .iter()
        .filter_map(|e| {
            if let AppEvent::Ssh(v) = e {
                Some(v)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let mut fields = common_fields();
    for name in [
        "kind",
        "proto_version",
        "software",
        "comments",
        "kex_algorithms",
        "host_key_algorithms",
        "encryption_c2s",
        "encryption_s2c",
        "mac_c2s",
        "mac_s2c",
        "compression_c2s",
        "compression_s2c",
    ] {
        fields.push(f(
            name,
            DataType::Utf8,
            !matches!(
                name,
                "kind"
                    | "kex_algorithms"
                    | "host_key_algorithms"
                    | "encryption_c2s"
                    | "encryption_s2c"
                    | "mac_c2s"
                    | "mac_s2c"
                    | "compression_c2s"
                    | "compression_s2c"
            ),
        ));
    }
    let mut arrays = common_arrays(rows.iter().map(|v| &v.common).collect());
    arrays.extend([
        svals(rows.iter().map(|v| v.kind.as_str())),
        sopts(rows.iter().map(|v| v.proto_version.as_deref())),
        sopts(rows.iter().map(|v| v.software.as_deref())),
        sopts(rows.iter().map(|v| v.comments.as_deref())),
        svals(rows.iter().map(|v| json(&v.kex_algorithms))),
        svals(rows.iter().map(|v| json(&v.host_key_algorithms))),
        svals(rows.iter().map(|v| json(&v.encryption_c2s))),
        svals(rows.iter().map(|v| json(&v.encryption_s2c))),
        svals(rows.iter().map(|v| json(&v.mac_c2s))),
        svals(rows.iter().map(|v| json(&v.mac_s2c))),
        svals(rows.iter().map(|v| json(&v.compression_c2s))),
        svals(rows.iter().map(|v| json(&v.compression_s2c))),
    ]);
    writer.write(fields, arrays)
}
fn write_smtp(writer: &mut TableWriter, events: &[AppEvent]) -> Result<(), Error> {
    let rows = events
        .iter()
        .filter_map(|e| {
            if let AppEvent::Smtp(v) = e {
                Some(v)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let mut fields = common_fields();
    fields.extend([
        f("kind", DataType::Utf8, false),
        f("command", DataType::Utf8, true),
        f("argument", DataType::Utf8, true),
        f("code", DataType::UInt16, true),
        f("text", DataType::Utf8, true),
        f("body_len", DataType::UInt64, true),
    ]);
    let mut arrays = common_arrays(rows.iter().map(|v| &v.common).collect());
    arrays.extend([
        svals(rows.iter().map(|v| v.kind.as_str())),
        sopts(rows.iter().map(|v| v.command.as_deref())),
        sopts(rows.iter().map(|v| v.argument.as_deref())),
        arc(UInt16Array::from_iter(rows.iter().map(|v| v.code))),
        sopts(rows.iter().map(|v| v.text.as_deref())),
        arc(UInt64Array::from_iter(rows.iter().map(|v| v.body_len))),
    ]);
    writer.write(fields, arrays)
}
fn write_telnet(writer: &mut TableWriter, events: &[AppEvent]) -> Result<(), Error> {
    let rows = events
        .iter()
        .filter_map(|e| {
            if let AppEvent::Telnet(v) = e {
                Some(v)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    let mut fields = common_fields();
    fields.extend([
        f("kind", DataType::Utf8, false),
        f("negotiation", DataType::Utf8, true),
        f("line", DataType::Utf8, true),
        f("truncated", DataType::Boolean, false),
    ]);
    let mut arrays = common_arrays(rows.iter().map(|v| &v.common).collect());
    arrays.extend([
        svals(rows.iter().map(|v| v.kind.as_str())),
        sopts(rows.iter().map(|v| v.negotiation.as_deref())),
        sopts(rows.iter().map(|v| v.line.as_deref())),
        arc(BooleanArray::from(
            rows.iter().map(|v| v.truncated).collect::<Vec<_>>(),
        )),
    ]);
    writer.write(fields, arrays)
}
fn write_dispatch(writer: &mut TableWriter, rows: &[DispatchRow]) -> Result<(), Error> {
    let fields = vec![
        f("stream_id", DataType::UInt64, true),
        f("flow_uid", DataType::UInt64, false),
        f("client_ip", DataType::Utf8, false),
        f("server_ip", DataType::Utf8, false),
        f("client_port", DataType::UInt16, false),
        f("server_port", DataType::UInt16, false),
        f("protocol", DataType::Utf8, false),
        f("probe_direction", DataType::Utf8, true),
        f("probe_bytes", DataType::UInt64, false),
        f("stop_reason", DataType::Utf8, true),
    ];
    let arrays = vec![
        arc(UInt64Array::from_iter(rows.iter().map(|v| v.stream_id))),
        arc(UInt64Array::from_iter_values(
            rows.iter().map(|v| v.flow_uid),
        )),
        svals(rows.iter().map(|v| v.client_ip.as_str())),
        svals(rows.iter().map(|v| v.server_ip.as_str())),
        arc(UInt16Array::from_iter_values(
            rows.iter().map(|v| v.client_port),
        )),
        arc(UInt16Array::from_iter_values(
            rows.iter().map(|v| v.server_port),
        )),
        svals(rows.iter().map(|v| v.protocol.as_str())),
        sopts(rows.iter().map(|v| v.probe_direction.as_deref())),
        arc(UInt64Array::from_iter_values(
            rows.iter().map(|v| v.probe_bytes),
        )),
        sopts(rows.iter().map(|v| v.stop_reason.as_deref())),
    ];
    writer.write(fields, arrays)
}

fn common_fields() -> Vec<Field> {
    vec![
        f("flow_uid", DataType::UInt64, false),
        f("stream_id", DataType::UInt64, true),
        f("index", DataType::UInt64, false),
        f("ts_ns", DataType::Int64, false),
        f("direction", DataType::Utf8, false),
        f("client_ip", DataType::Utf8, false),
        f("server_ip", DataType::Utf8, false),
        f("client_port", DataType::UInt16, false),
        f("server_port", DataType::UInt16, false),
        f("transport", DataType::Utf8, false),
    ]
}
fn common_arrays(rows: Vec<&Common>) -> Vec<ArrayRef> {
    vec![
        arc(UInt64Array::from_iter_values(
            rows.iter().map(|v| v.flow_uid),
        )),
        arc(UInt64Array::from_iter(rows.iter().map(|v| v.stream_id))),
        arc(UInt64Array::from_iter_values(rows.iter().map(|v| v.index))),
        arc(Int64Array::from_iter_values(rows.iter().map(|v| v.ts_ns))),
        svals(rows.iter().map(|v| v.direction.as_str())),
        svals(rows.iter().map(|v| v.client_ip.to_string())),
        svals(rows.iter().map(|v| v.server_ip.to_string())),
        arc(UInt16Array::from_iter_values(
            rows.iter().map(|v| v.client_port),
        )),
        arc(UInt16Array::from_iter_values(
            rows.iter().map(|v| v.server_port),
        )),
        svals(rows.iter().map(|v| v.transport.as_str())),
    ]
}
fn f(name: &str, data_type: DataType, nullable: bool) -> Field {
    Field::new(name, data_type, nullable)
}
fn arc<T: arrow::array::Array + 'static>(array: T) -> ArrayRef {
    Arc::new(array)
}
fn svals<'a, I, S>(values: I) -> ArrayRef
where
    I: IntoIterator<Item = S>,
    S: AsRef<str> + 'a,
{
    arc(StringArray::from_iter_values(values))
}
fn sopts<'a, I>(values: I) -> ArrayRef
where
    I: IntoIterator<Item = Option<&'a str>>,
{
    arc(StringArray::from_iter(values))
}
fn json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "[]".into())
}
struct TableWriter {
    path: PathBuf,
    format: Format,
    schema: Option<Arc<Schema>>,
    sink: Option<TableSink>,
}

enum TableSink {
    Csv(csv::Writer<BufWriter<File>>),
    Parquet(ArrowWriter<File>),
}

impl TableWriter {
    fn new(path: PathBuf, format: Format) -> Self {
        Self {
            path,
            format,
            schema: None,
            sink: None,
        }
    }

    fn write(&mut self, fields: Vec<Field>, arrays: Vec<ArrayRef>) -> Result<(), Error> {
        let schema = match &self.schema {
            Some(schema) => Arc::clone(schema),
            None => {
                let schema = Arc::new(Schema::new(fields));
                let file = File::create(&self.path)?;
                self.sink = Some(match self.format {
                    Format::Csv => {
                        let buffered = BufWriter::with_capacity(1024 * 1024, file);
                        TableSink::Csv(csv::WriterBuilder::new().with_header(true).build(buffered))
                    }
                    Format::Parquet => {
                        let props = WriterProperties::builder()
                            .set_compression(Compression::SNAPPY)
                            .build();
                        TableSink::Parquet(ArrowWriter::try_new(
                            file,
                            Arc::clone(&schema),
                            Some(props),
                        )?)
                    }
                });
                self.schema = Some(Arc::clone(&schema));
                schema
            }
        };
        let batch = RecordBatch::try_new(schema, arrays)?;
        match self.sink.as_mut().expect("sink initialized with schema") {
            TableSink::Csv(writer) => writer.write(&batch)?,
            TableSink::Parquet(writer) => writer.write(&batch)?,
        }
        Ok(())
    }

    fn close(self) -> Result<(), Error> {
        match self.sink {
            Some(TableSink::Csv(writer)) => writer.into_inner().flush().map_err(Error::from),
            Some(TableSink::Parquet(writer)) => {
                writer.close()?;
                Ok(())
            }
            None => Ok(()),
        }
    }
}

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant},
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use packet_tools_capture::{
    Capture, CaptureFormat, CaptureStats, Compression, Container, Endian, OpenOptions, TsResolution,
};
use packet_tools_dissect::{DecodeDepth, decode};
use packet_tools_export::{
    flows::{ColumnNames, FlowsWriter},
    packets::{Field, Format, PacketsWriter, parse_fields},
    streams::{DatagramRow, EventRow, StreamRow, write_datagrams, write_events, write_streams},
};
use packet_tools_flow::{FlowConfig, FlowTable, Policy, Preset};
use packet_tools_reassembly::{
    CloseReason, DefragConfig, Defragmenter, DeliveryMode, Direction, DirectionSummary, IpPolicy,
    RetainedSide, TcpConfig, TcpItem, TcpOutput, TcpPolicy, TcpReassembler,
};
use serde_json::json;
use sha2::{Digest, Sha256};

#[derive(Parser)]
#[command(version, about = "High-performance packet analysis tools")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate capture containers and summarize their records.
    Validate(ValidateArgs),
    /// Export one row per packet to Parquet or CSV.
    Packets(PacketsArgs),
    /// Build bidirectional flows and export one row per completed flow.
    Flows(FlowsArgs),
    /// Reassemble IP fragments and directional TCP byte streams.
    Streams(StreamsArgs),
}

#[derive(Args)]
struct ValidateArgs {
    /// Emit one JSON object per line.
    #[arg(long)]
    json: bool,
    /// Memory-map uncompressed regular files instead of reading them through a buffer.
    #[arg(long)]
    mmap: bool,
    /// Capture files to validate.
    #[arg(required = true)]
    files: Vec<PathBuf>,
}

#[derive(Args)]
struct PacketsArgs {
    /// Comma-separated output column names.
    #[arg(long)]
    fields: Option<String>,
    /// Output format; inferred from .parquet or .csv when omitted.
    #[arg(long, value_enum)]
    format: Option<OutputFormat>,
    /// Write at most this many packets.
    #[arg(long)]
    limit: Option<u64>,
    /// Deepest layer to decode.
    #[arg(long, value_enum, default_value = "l4")]
    depth: Depth,
    /// Output file.
    #[arg(short = 'o', long)]
    output: PathBuf,
    /// Input capture.
    input: PathBuf,
}

#[derive(Args)]
struct FlowsArgs {
    /// Flow grouping and termination policy.
    #[arg(long, value_enum, default_value = "corrected")]
    policy: FlowPolicy,
    /// Output feature preset.
    #[arg(long, value_enum, default_value = "cicflowmeter")]
    preset: FlowPreset,
    /// Maximum flow age in seconds for compatibility policies.
    #[arg(long, default_value = "120", value_parser = parse_seconds)]
    flow_timeout: f64,
    /// Gap in seconds used for Active/Idle feature statistics.
    #[arg(long, default_value = "5", value_parser = parse_seconds)]
    activity_timeout: f64,
    /// IdleOnly expiration in seconds.
    #[arg(long, default_value = "60", value_parser = parse_seconds)]
    idle_timeout: f64,
    /// Include the outermost VLAN identifier in IdleOnly flow keys.
    #[arg(long)]
    vlan_in_key: bool,
    /// Output column naming convention.
    #[arg(long, value_enum, default_value = "snake")]
    column_names: FlowColumnNames,
    /// Output format; inferred from .parquet or .csv when omitted.
    #[arg(long, value_enum)]
    format: Option<OutputFormat>,
    /// Output file.
    #[arg(short = 'o', long)]
    output: PathBuf,
    /// Input capture.
    input: PathBuf,
}

#[derive(Args)]
struct StreamsArgs {
    #[arg(long, default_value = "bsd")]
    ip_policy: String,
    #[arg(long, default_value = "bsd")]
    tcp_policy: String,
    #[arg(long, value_enum, default_value = "on-ack")]
    delivery: StreamDelivery,
    #[arg(long, default_value = "60", value_parser = parse_seconds)]
    defrag_timeout: f64,
    #[arg(long, default_value = "3600", value_parser = parse_seconds)]
    tcp_timeout: f64,
    #[arg(long, default_value = "4194304")]
    stream_memory: usize,
    #[arg(long, default_value = "1073741824")]
    memory: usize,
    #[arg(long)]
    vlan_in_key: bool,
    #[arg(long)]
    events: Option<PathBuf>,
    #[arg(long)]
    datagrams: Option<PathBuf>,
    #[arg(long)]
    dump_dir: Option<PathBuf>,
    #[arg(long, value_enum)]
    format: Option<OutputFormat>,
    #[arg(short = 'o', long)]
    output: PathBuf,
    input: PathBuf,
}

#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    Parquet,
    Csv,
}

#[derive(Clone, Copy, ValueEnum)]
enum Depth {
    L2,
    L3,
    L4,
}

#[derive(Clone, Copy, ValueEnum)]
enum FlowPolicy {
    Corrected,
    Cicflowmeter,
    IdleOnly,
}

#[derive(Clone, Copy, ValueEnum)]
enum FlowPreset {
    Cicflowmeter,
    Minimal,
}

#[derive(Clone, Copy, ValueEnum)]
enum FlowColumnNames {
    Snake,
    Original,
}

#[derive(Clone, Copy, ValueEnum)]
enum StreamDelivery {
    OnAck,
    Immediate,
}

struct FileReport {
    path: PathBuf,
    format: Option<CaptureFormat>,
    stats: CaptureStats,
    elapsed_secs: f64,
    error: Option<String>,
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Validate(args) => validate(args),
        Command::Packets(args) => packets(args),
        Command::Flows(args) => flows(args),
        Command::Streams(args) => streams(args),
    }
}

#[derive(Clone)]
struct StreamAggregate {
    start: packet_tools_reassembly::ConnectionStart,
    direction: Direction,
    byte_count: u64,
    digest: Sha256,
    dump_bytes: Option<Vec<u8>>,
    summary: DirectionSummary,
    last_ts_ns: i64,
    close_reason: CloseReason,
}

fn streams(args: StreamsArgs) -> ExitCode {
    let format = match output_format(args.format, &args.output) {
        Ok(format) => format,
        Err(error) => {
            eprintln!("packet-tools streams: {error}");
            return ExitCode::FAILURE;
        }
    };
    let ip_policy: IpPolicy = match args.ip_policy.parse() {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!("packet-tools streams: {error}");
            return ExitCode::FAILURE;
        }
    };
    let tcp_policy: TcpPolicy = match args.tcp_policy.parse() {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!("packet-tools streams: {error}");
            return ExitCode::FAILURE;
        }
    };
    let delivery = match args.delivery {
        StreamDelivery::OnAck => DeliveryMode::OnAck,
        StreamDelivery::Immediate => DeliveryMode::Immediate,
    };
    let mut capture = match Capture::open(&args.input) {
        Ok(capture) => capture,
        Err(error) => {
            eprintln!("packet-tools streams: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut defrag = Defragmenter::new(DefragConfig {
        policy: ip_policy,
        timeout: Duration::from_secs_f64(args.defrag_timeout),
        memory_limit: args.memory.min(64 * 1024 * 1024),
        vlan_in_key: args.vlan_in_key,
        ..DefragConfig::default()
    });
    let mut tcp = TcpReassembler::new(TcpConfig {
        policy: tcp_policy,
        delivery,
        established_timeout: Duration::from_secs_f64(args.tcp_timeout),
        stream_memory: args.stream_memory,
        memory_limit: args.memory,
        vlan_in_key: args.vlan_in_key,
        ..TcpConfig::default()
    });
    let mut aggregates = BTreeMap::new();
    let mut event_rows = Vec::new();
    let mut datagram_rows = Vec::new();
    let mut read_error = None;
    while let Some(result) = capture.next_record() {
        let record = match result {
            Ok(record) => record,
            Err(error) => {
                read_error = Some(error.to_string());
                break;
            }
        };
        let packet = decode(record.data, record.linktype, DecodeDepth::L4);
        let fragmented = packet
            .layer::<packet_tools_dissect::Ipv4View>()
            .is_some_and(|ip| ip.more_fragments() || ip.fragment_offset() != 0)
            || packet
                .layer::<packet_tools_dissect::Ipv6View>()
                .is_some_and(|ip| ip.fragment().is_some());
        let defrag_output = defrag.push(&record, &packet);
        event_rows.extend(defrag_output.events.into_iter().map(ip_event_row));
        if !fragmented {
            consume_tcp(
                tcp.push(&record, &packet),
                &mut aggregates,
                &mut event_rows,
                args.dump_dir.is_some(),
            );
        }
        for datagram in defrag_output.datagrams {
            datagram_rows.push(DatagramRow {
                index: datagram.last_index,
                ip_version: datagram.key.version,
                src_ip: datagram.key.src.to_string(),
                dst_ip: datagram.key.dst.to_string(),
                identification: datagram.key.identification,
                protocol: datagram.key.protocol,
                fragments: datagram.fragment_count as u64,
                reassembled_len: datagram.bytes.len() as u64,
                payload_sha256: sha256(datagram.payload()),
            });
            let synthetic = packet_tools_capture::PacketRecord {
                index: datagram.last_index,
                ts_ns: Some(datagram.last_ts_ns),
                caplen: datagram.bytes.len() as u32,
                origlen: datagram.bytes.len() as u32,
                linktype: packet_tools_capture::LinkType(101),
                interface: 0,
                data: &datagram.bytes,
            };
            let decoded = decode(&datagram.bytes, synthetic.linktype, DecodeDepth::L4);
            consume_tcp(
                tcp.push(&synthetic, &decoded),
                &mut aggregates,
                &mut event_rows,
                args.dump_dir.is_some(),
            );
        }
    }
    consume_tcp(
        tcp.finish(),
        &mut aggregates,
        &mut event_rows,
        args.dump_dir.is_some(),
    );
    let rows = aggregates.values().map(stream_row).collect::<Vec<_>>();
    if let Some(directory) = &args.dump_dir
        && let Err(error) = dump_streams(directory, &aggregates)
    {
        eprintln!("packet-tools streams: {error}");
        return ExitCode::FAILURE;
    }
    if let Err(error) = write_streams(&args.output, format, &rows) {
        eprintln!("packet-tools streams: {error}");
        return ExitCode::FAILURE;
    }
    if let Some(path) = &args.events
        && let Err(error) = write_events(path, format, &event_rows)
    {
        eprintln!("packet-tools streams: {error}");
        return ExitCode::FAILURE;
    }
    if let Some(path) = &args.datagrams
        && let Err(error) = write_datagrams(path, format, &datagram_rows)
    {
        eprintln!("packet-tools streams: {error}");
        return ExitCode::FAILURE;
    }
    if let Some(error) = read_error {
        eprintln!("packet-tools streams: {error}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn consume_tcp(
    output: TcpOutput,
    aggregates: &mut BTreeMap<(u64, Direction), StreamAggregate>,
    events: &mut Vec<EventRow>,
    retain_dump_bytes: bool,
) {
    for event in output.events {
        events.push(EventRow {
            index: event.index,
            ts_ns: event.ts_ns,
            kind: event.kind.as_str().to_owned(),
            stream_id: Some(event.stream_id),
            direction: Some(event.direction.as_str().to_owned()),
            position: Some(event.position),
            length: Some(event.len as u64),
            retained: event.retained.map(retained_name),
            previous_index: event.previous_index,
            ..EventRow::default()
        });
    }
    for item in output.items {
        match item {
            TcpItem::Start(start) => {
                for direction in [Direction::ClientToServer, Direction::ServerToClient] {
                    aggregates.insert(
                        (start.stream_id, direction),
                        StreamAggregate {
                            start: start.clone(),
                            direction,
                            byte_count: 0,
                            digest: Sha256::new(),
                            dump_bytes: retain_dump_bytes.then(Vec::new),
                            summary: DirectionSummary::default(),
                            last_ts_ns: start.first_ts_ns,
                            close_reason: CloseReason::EndOfCapture,
                        },
                    );
                }
            }
            TcpItem::Data(chunk) => {
                if let Some(row) = aggregates.get_mut(&(chunk.stream_id, chunk.direction)) {
                    row.byte_count += chunk.bytes.len() as u64;
                    row.digest.update(&chunk.bytes);
                    if let Some(bytes) = &mut row.dump_bytes {
                        bytes.extend_from_slice(&chunk.bytes);
                    }
                }
            }
            TcpItem::Gap(_) => {}
            TcpItem::PostClose(packet) => {
                if let Some(row) = aggregates.get_mut(&(packet.stream_id, packet.direction)) {
                    row.summary.post_close_packets += 1;
                    row.summary.post_close_bytes += packet.payload_len as u64;
                    row.last_ts_ns = packet.ts_ns;
                }
            }
            TcpItem::End(end) => {
                for direction in [Direction::ClientToServer, Direction::ServerToClient] {
                    if let Some(row) = aggregates.get_mut(&(end.stream_id, direction)) {
                        row.summary = end.directions[direction_index(direction)].clone();
                        row.last_ts_ns = end.last_ts_ns;
                        row.close_reason = end.reason;
                    }
                }
            }
        }
    }
}

fn ip_event_row(event: packet_tools_reassembly::IpEvent) -> EventRow {
    EventRow {
        index: event.index,
        ts_ns: event.ts_ns,
        kind: event.kind.as_str().to_owned(),
        ip_version: Some(event.key.version),
        src_ip: Some(event.key.src.to_string()),
        dst_ip: Some(event.key.dst.to_string()),
        identification: Some(event.key.identification),
        protocol: Some(event.key.protocol),
        vlan: event.key.vlan,
        position: event.offset.map(|value| value as u64),
        length: event.len.map(|value| value as u64),
        retained: event.retained.map(retained_name),
        previous_index: event.previous_index,
        ..EventRow::default()
    }
}

fn retained_name(side: RetainedSide) -> String {
    match side {
        RetainedSide::Existing => "existing",
        RetainedSide::New => "new",
    }
    .to_owned()
}

fn direction_index(direction: Direction) -> usize {
    match direction {
        Direction::ClientToServer => 0,
        Direction::ServerToClient => 1,
    }
}

fn stream_row(row: &StreamAggregate) -> StreamRow {
    StreamRow {
        stream_id: row.start.stream_id,
        flow_uid: row.start.flow_uid,
        direction: row.direction.as_str().to_owned(),
        client_ip: row.start.client_ip.to_string(),
        server_ip: row.start.server_ip.to_string(),
        client_port: row.start.client_port,
        server_port: row.start.server_port,
        first_ts_ns: row.start.first_ts_ns,
        last_ts_ns: row.last_ts_ns,
        midstream: row.start.midstream,
        bytes: row.byte_count,
        segments: row.summary.segments,
        gaps: row.summary.gaps,
        gap_bytes: row.summary.gap_bytes,
        overlaps: row.summary.overlaps,
        overlap_conflicts: row.summary.overlap_conflicts,
        retransmitted_bytes: row.summary.retransmitted_bytes,
        post_close_packets: row.summary.post_close_packets,
        post_close_bytes: row.summary.post_close_bytes,
        keepalives: row.summary.keepalives,
        close_reason: row.close_reason.as_str().to_owned(),
        sha256: row
            .digest
            .clone()
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    }
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn dump_streams(
    directory: &Path,
    streams: &BTreeMap<(u64, Direction), StreamAggregate>,
) -> std::io::Result<()> {
    fs::create_dir_all(directory)?;
    for ((stream_id, direction), stream) in streams {
        let suffix = match direction {
            Direction::ClientToServer => "c2s",
            Direction::ServerToClient => "s2c",
        };
        fs::write(
            directory.join(format!("{stream_id}.{suffix}.bin")),
            stream.dump_bytes.as_deref().unwrap_or_default(),
        )?;
    }
    Ok(())
}

fn flows(args: FlowsArgs) -> ExitCode {
    let format = match output_format(args.format, &args.output) {
        Ok(format) => format,
        Err(error) => {
            eprintln!("packet-tools flows: {error}");
            return ExitCode::FAILURE;
        }
    };
    let policy = match args.policy {
        FlowPolicy::Corrected => Policy::Corrected,
        FlowPolicy::Cicflowmeter => Policy::CicFlowMeter,
        FlowPolicy::IdleOnly => Policy::IdleOnly,
    };
    let preset = match args.preset {
        FlowPreset::Cicflowmeter => Preset::CicFlowMeter,
        FlowPreset::Minimal => Preset::Minimal,
    };
    let names = match args.column_names {
        FlowColumnNames::Snake => ColumnNames::Snake,
        FlowColumnNames::Original => ColumnNames::Original,
    };
    let mut writer = match FlowsWriter::create(&args.output, format, policy, preset, names) {
        Ok(writer) => writer,
        Err(error) => {
            eprintln!("packet-tools flows: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut capture = match Capture::open(&args.input) {
        Ok(capture) => capture,
        Err(error) => {
            eprintln!("packet-tools flows: {error}");
            let _ = writer.finish();
            return ExitCode::FAILURE;
        }
    };
    let mut table = FlowTable::new(FlowConfig {
        policy,
        preset,
        flow_timeout: Duration::from_secs_f64(args.flow_timeout),
        activity_timeout: Duration::from_secs_f64(args.activity_timeout),
        idle_timeout: Duration::from_secs_f64(args.idle_timeout),
        vlan_in_key: args.vlan_in_key,
    });
    let mut read_error = None;
    while let Some(result) = capture.next_record() {
        let record = match result {
            Ok(record) => record,
            Err(error) => {
                read_error = Some(error.to_string());
                break;
            }
        };
        let packet = decode(record.data, record.linktype, DecodeDepth::L4);
        for flow in table.push(&record, &packet) {
            if let Err(error) = writer.push(&flow) {
                eprintln!("packet-tools flows: {error}");
                return ExitCode::FAILURE;
            }
        }
    }
    for flow in table.finish() {
        if let Err(error) = writer.push(&flow) {
            eprintln!("packet-tools flows: {error}");
            return ExitCode::FAILURE;
        }
    }
    if let Err(error) = writer.finish() {
        eprintln!("packet-tools flows: {error}");
        return ExitCode::FAILURE;
    }
    if let Some(error) = read_error {
        eprintln!("packet-tools flows: {error}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn parse_seconds(value: &str) -> Result<f64, String> {
    let seconds = value
        .parse::<f64>()
        .map_err(|_| format!("invalid duration `{value}`"))?;
    if !seconds.is_finite() || seconds < 0.0 {
        return Err(format!(
            "duration must be a finite non-negative number: `{value}`"
        ));
    }
    Ok(seconds)
}

fn packets(args: PacketsArgs) -> ExitCode {
    let format = match output_format(args.format, &args.output) {
        Ok(format) => format,
        Err(error) => {
            eprintln!("packet-tools packets: {error}");
            return ExitCode::FAILURE;
        }
    };
    let selected;
    let fields = if let Some(list) = args.fields.as_deref() {
        match parse_fields(list) {
            Ok(fields) => {
                selected = fields;
                &selected[..]
            }
            Err(error) => {
                eprintln!("packet-tools packets: {error}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        Field::ALL
    };
    let mut writer = match PacketsWriter::create(&args.output, format, fields) {
        Ok(writer) => writer,
        Err(error) => {
            eprintln!("packet-tools packets: {error}");
            return ExitCode::FAILURE;
        }
    };
    let mut capture = match Capture::open(&args.input) {
        Ok(capture) => capture,
        Err(error) => {
            eprintln!("packet-tools packets: {error}");
            let _ = writer.finish();
            return ExitCode::FAILURE;
        }
    };
    let depth = match args.depth {
        Depth::L2 => DecodeDepth::L2,
        Depth::L3 => DecodeDepth::L3,
        Depth::L4 => DecodeDepth::L4,
    };
    let mut read_error = None;
    let mut written = 0u64;
    while args.limit.is_none_or(|limit| written < limit) {
        let Some(result) = capture.next_record() else {
            break;
        };
        let record = match result {
            Ok(record) => record,
            Err(error) => {
                read_error = Some(error.to_string());
                break;
            }
        };
        let packet = decode(record.data, record.linktype, depth);
        if let Err(error) = writer.push(&record, &packet) {
            eprintln!("packet-tools packets: {error}");
            return ExitCode::FAILURE;
        }
        written += 1;
    }
    if let Err(error) = writer.finish() {
        eprintln!("packet-tools packets: {error}");
        return ExitCode::FAILURE;
    }
    if let Some(error) = read_error {
        eprintln!("packet-tools packets: {error}");
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn output_format(explicit: Option<OutputFormat>, output: &Path) -> Result<Format, &'static str> {
    match explicit {
        Some(OutputFormat::Parquet) => Ok(Format::Parquet),
        Some(OutputFormat::Csv) => Ok(Format::Csv),
        None => match output
            .extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("parquet") => Ok(Format::Parquet),
            Some("csv") => Ok(Format::Csv),
            _ => Err(
                "cannot determine output format; use --format parquet|csv or a .parquet/.csv output extension",
            ),
        },
    }
}

fn validate(args: ValidateArgs) -> ExitCode {
    let mut reports = Vec::with_capacity(args.files.len());
    let mut failed = false;
    for path in args.files {
        let report = validate_file(&path, args.mmap);
        failed |= report.error.is_some() || report.stats.truncated_tail;
        if args.json {
            print_json(&report);
        } else {
            print_human(&report);
        }
        reports.push(report);
    }

    let packets = reports
        .iter()
        .map(|report| report.stats.packets)
        .sum::<u64>();
    let regressions = reports
        .iter()
        .map(|report| report.stats.timestamp_regressions)
        .sum::<u64>();
    if args.json {
        println!(
            "{}",
            json!({
                "type": "total",
                "files": reports.len(),
                "packets": packets,
                "regressions": regressions,
                "timestamp_regressions": regressions,
                "errors": reports.iter().filter(|report| report.error.is_some() || report.stats.truncated_tail).count(),
            })
        );
    } else if reports.len() > 1 {
        println!(
            "total files={} packets={} regressions={}",
            reports.len(),
            packets,
            regressions
        );
    }

    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn validate_file(path: &Path, mmap: bool) -> FileReport {
    let started = Instant::now();
    match Capture::open_with(path, OpenOptions { mmap }) {
        Ok(mut capture) => {
            let format = capture.format();
            let mut error = None;
            while let Some(record) = capture.next_record() {
                if let Err(read_error) = record {
                    error = Some(read_error.to_string());
                    break;
                }
            }
            FileReport {
                path: path.to_owned(),
                format: Some(format),
                stats: capture.stats().clone(),
                elapsed_secs: started.elapsed().as_secs_f64(),
                error,
            }
        }
        Err(error) => FileReport {
            path: path.to_owned(),
            format: None,
            stats: CaptureStats::default(),
            elapsed_secs: started.elapsed().as_secs_f64(),
            error: Some(error.to_string()),
        },
    }
}

fn print_human(report: &FileReport) {
    let packets_per_second = if report.elapsed_secs > 0.0 {
        report.stats.packets as f64 / report.elapsed_secs
    } else {
        0.0
    };
    let error = report
        .error
        .as_deref()
        .map(|value| format!(" error={value}"))
        .unwrap_or_default();
    println!(
        "{} format={} packets={} linktypes={} regressions={} max_regression={:.3}μs truncated_packets={} truncated tail={} skipped_blocks={} elapsed={:.6}s pkt/s={:.0}{}",
        report.path.display(),
        report.format.map(format_name).unwrap_or("unknown"),
        report.stats.packets,
        map_counts(&report.stats.linktypes),
        report.stats.timestamp_regressions,
        report.stats.max_regression_ns as f64 / 1_000.0,
        report.stats.truncated_packets,
        report.stats.truncated_tail,
        map_counts(&report.stats.skipped_blocks),
        report.elapsed_secs,
        packets_per_second,
        error,
    );
}

fn print_json(report: &FileReport) {
    println!(
        "{}",
        json!({
            "type": "file",
            "path": report.path,
            "format": report.format.map(format_name),
            "packets": report.stats.packets,
            "bytes_captured": report.stats.bytes_captured,
            "bytes_original": report.stats.bytes_original,
            "truncated_packets": report.stats.truncated_packets,
            "packets_without_timestamp": report.stats.packets_without_timestamp,
            "timestamp_regressions": report.stats.timestamp_regressions,
            "max_regression_ns": report.stats.max_regression_ns,
            "first_ts_ns": report.stats.first_ts_ns,
            "last_ts_ns": report.stats.last_ts_ns,
            "min_ts_ns": report.stats.min_ts_ns,
            "max_ts_ns": report.stats.max_ts_ns,
            "linktypes": report.stats.linktypes,
            "sections": report.stats.sections,
            "skipped_blocks": report.stats.skipped_blocks,
            "truncated_tail": report.stats.truncated_tail,
            "elapsed_secs": report.elapsed_secs,
            "error": report.error,
        })
    );
}

fn format_name(format: CaptureFormat) -> &'static str {
    let suffix = format.compression == Compression::Gzip;
    match format.container {
        Container::PcapNg => {
            if suffix {
                "pcapng+gzip"
            } else {
                "pcapng"
            }
        }
        Container::Pcap {
            endian,
            ts_resolution,
        } => match (endian, ts_resolution, suffix) {
            (Endian::Little, TsResolution::Pow10(6), false) => "pcap-le-usec",
            (Endian::Big, TsResolution::Pow10(6), false) => "pcap-be-usec",
            (Endian::Little, TsResolution::Pow10(9), false) => "pcap-le-nsec",
            (Endian::Big, TsResolution::Pow10(9), false) => "pcap-be-nsec",
            (Endian::Little, TsResolution::Pow10(6), true) => "pcap-le-usec+gzip",
            (Endian::Big, TsResolution::Pow10(6), true) => "pcap-be-usec+gzip",
            (Endian::Little, TsResolution::Pow10(9), true) => "pcap-le-nsec+gzip",
            (Endian::Big, TsResolution::Pow10(9), true) => "pcap-be-nsec+gzip",
            (_, _, false) => "pcap",
            (_, _, true) => "pcap+gzip",
        },
    }
}

fn map_counts<K: std::fmt::Display>(counts: &BTreeMap<K, u64>) -> String {
    if counts.is_empty() {
        return "-".to_owned();
    }
    counts
        .iter()
        .map(|(key, count)| format!("{key}:{count}"))
        .collect::<Vec<_>>()
        .join(",")
}

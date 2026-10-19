use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Instant,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use packet_tools_capture::{
    Capture, CaptureFormat, CaptureStats, Compression, Container, Endian, OpenOptions, TsResolution,
};
use packet_tools_dissect::{DecodeDepth, decode};
use packet_tools_export::packets::{Field, Format, PacketsWriter, parse_fields};
use serde_json::json;

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
    }
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

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    error::Error,
    ffi::OsStr,
    fs::{self, File},
    io::{self, Read},
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Output, Stdio},
    str::FromStr,
    time::Instant,
};

use clap::{Args, Parser, Subcommand, ValueEnum};
use runvault::{Dataset, Run, RunOptions};
use serde::Serialize;
use serde_json::{Map, Value, json};

type DynError = Box<dyn Error + Send + Sync>;

#[derive(Debug, Parser)]
#[command(name = "ptbench", about = "Reproducible packet-tools benchmarks")]
pub struct Cli {
    /// Write the run below results/_scratch.
    #[arg(long, global = true)]
    scratch: bool,
    #[command(subcommand)]
    command: Bench,
}

#[derive(Debug, Subcommand)]
enum Bench {
    /// Measure parser throughput and speedup on warm page cache.
    Speedup(SpeedupArgs),
    /// Measure end-to-end processing of a capture collection.
    E2e(E2eArgs),
}

#[derive(Clone, Debug)]
struct NamedPath {
    name: String,
    path: PathBuf,
}

impl FromStr for NamedPath {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (name, path) = value
            .split_once('=')
            .ok_or_else(|| "capture must be NAME=PATH".to_owned())?;
        if name.is_empty() || path.is_empty() {
            return Err("capture must have a non-empty NAME and PATH".to_owned());
        }
        Ok(Self {
            name: name.to_owned(),
            path: PathBuf::from(path),
        })
    }
}

#[derive(Clone, Debug)]
struct NamedCount {
    name: String,
    count: u64,
}

impl FromStr for NamedCount {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (name, count) = value
            .split_once('=')
            .ok_or_else(|| "scapy count must be NAME=N".to_owned())?;
        let count = count
            .parse::<u64>()
            .map_err(|_| format!("invalid Scapy packet count `{count}`"))?;
        if name.is_empty() || count == 0 {
            return Err("scapy count must have a non-empty NAME and positive N".to_owned());
        }
        Ok(Self {
            name: name.to_owned(),
            count,
        })
    }
}

#[derive(Debug, Args)]
struct SpeedupArgs {
    /// Named capture in NAME=PATH form; repeat for multiple captures.
    #[arg(long = "capture", required = true)]
    captures: Vec<NamedPath>,
    /// Named Scapy packet limit in NAME=N form.
    #[arg(long = "scapy-count")]
    scapy_counts: Vec<NamedCount>,
    #[arg(long, default_value = "9", value_parser = positive_usize)]
    runs: usize,
    #[arg(long, default_value = ".venv/bin/python")]
    python: PathBuf,
    #[arg(long, default_value = "target/release/rsbench")]
    rsbench: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, ValueEnum)]
enum E2eCommand {
    Rsbench,
    Flows,
    App,
}

impl E2eCommand {
    const fn name(self) -> &'static str {
        match self {
            Self::Rsbench => "rsbench",
            Self::Flows => "flows",
            Self::App => "app",
        }
    }
}

#[derive(Debug, Args)]
struct E2eArgs {
    #[arg(long, required = true, num_args = 1..)]
    inputs: Vec<PathBuf>,
    #[arg(long = "command", required = true)]
    commands: Vec<E2eCommand>,
    #[arg(long, default_value = "1", value_parser = positive_usize)]
    jobs: usize,
    #[arg(long, default_value = "target/release/packet-tools")]
    packet_tools: PathBuf,
    #[arg(long, default_value = "target/release/rsbench")]
    rsbench: PathBuf,
    #[arg(long, default_value = "bench/.work/ptbench")]
    out: PathBuf,
    #[arg(long)]
    scapy_pkt_per_sec: f64,
    #[arg(long)]
    sha256sums: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct Throughput {
    pub packets: u64,
    pub seconds: f64,
    pub pkt_per_sec: f64,
}

#[derive(Clone, Debug)]
struct Trial {
    capture: String,
    trial: usize,
    engine: String,
    order: usize,
    throughput: Throughput,
}

#[derive(Debug, Serialize)]
struct SpeedupParameters {
    captures: Vec<String>,
    scapy_counts: BTreeMap<String, u64>,
    runs: usize,
    python: String,
    rsbench: String,
    loadavg_start: [f64; 3],
}

#[derive(Debug, Serialize)]
struct E2eParameters {
    inputs: Vec<String>,
    commands: Vec<String>,
    jobs: usize,
    packet_tools: String,
    rsbench: String,
    output_dir: String,
    scapy_pkt_per_sec: f64,
    sha256sums: Option<String>,
}

pub fn main_entry() -> Result<(), DynError> {
    let cli = Cli::parse();
    match cli.command {
        Bench::Speedup(args) => speedup(args, cli.scratch),
        Bench::E2e(args) => e2e(args, cli.scratch),
    }
}

pub fn median(values: &[f64]) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut values = values.to_vec();
    values.sort_by(f64::total_cmp);
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        Some((values[middle - 1] + values[middle]) / 2.0)
    } else {
        Some(values[middle])
    }
}

pub fn rotated_order(trial: usize) -> [&'static str; 3] {
    const ENGINES: [&str; 3] = ["scapy", "etherparse", "packet-tools"];
    let shift = trial % ENGINES.len();
    [
        ENGINES[shift],
        ENGINES[(shift + 1) % ENGINES.len()],
        ENGINES[(shift + 2) % ENGINES.len()],
    ]
}

pub fn parse_scapy(output: &str) -> Result<Throughput, String> {
    let line = output
        .lines()
        .find(|line| line.starts_with("full dissect+5tuple:"))
        .ok_or_else(|| "Scapy output lacks `full dissect+5tuple`".to_owned())?;
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let packets = fields
        .get(2)
        .ok_or_else(|| "Scapy packet count is missing".to_owned())?
        .parse::<u64>()
        .map_err(|error| error.to_string())?;
    let seconds = fields
        .get(4)
        .ok_or_else(|| "Scapy elapsed time is missing".to_owned())?
        .trim_end_matches('s')
        .parse::<f64>()
        .map_err(|error| error.to_string())?;
    let pkt_per_sec = fields
        .get(5)
        .ok_or_else(|| "Scapy packet rate is missing".to_owned())?
        .replace(',', "")
        .parse::<f64>()
        .map_err(|error| error.to_string())?;
    Ok(Throughput {
        packets,
        seconds,
        pkt_per_sec,
    })
}

pub fn read_sha256sums(path: &Path) -> io::Result<HashMap<String, String>> {
    let text = fs::read_to_string(path)?;
    let mut hashes = HashMap::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let Some((digest, name)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let name = name.trim_start().trim_start_matches('*');
        if digest.len() == 64 && !name.is_empty() {
            hashes.insert(name.to_owned(), digest.to_ascii_lowercase());
        }
    }
    Ok(hashes)
}

fn speedup(args: SpeedupArgs, scratch: bool) -> Result<(), DynError> {
    ensure_unique(
        args.captures.iter().map(|capture| capture.name.as_str()),
        "capture",
    )?;
    let scapy_counts = args
        .scapy_counts
        .iter()
        .map(|item| (item.name.clone(), item.count))
        .collect::<BTreeMap<_, _>>();
    for capture in &args.captures {
        warm_file(&capture.path)?;
    }
    let loadavg_start = load_average()?;
    let parameters = SpeedupParameters {
        captures: args
            .captures
            .iter()
            .map(|capture| format!("{}={}", capture.name, capture.path.display()))
            .collect(),
        scapy_counts: scapy_counts.clone(),
        runs: args.runs,
        python: args.python.display().to_string(),
        rsbench: args.rsbench.display().to_string(),
        loadavg_start,
    };
    let data = args
        .captures
        .iter()
        .map(|capture| {
            Dataset::new("benchmark", capture.name.clone()).uri(capture.path.display().to_string())
        })
        .collect::<Vec<_>>();
    let mut run = start_run("speedup", &parameters, data, scratch)?;
    let artifacts = run.dir().join("artifacts");
    fs::create_dir_all(&artifacts)?;
    let mut trials = Vec::new();
    for capture in &args.captures {
        for trial in 0..args.runs {
            for (order, engine) in rotated_order(trial).into_iter().enumerate() {
                let throughput = match engine {
                    "scapy" => run_scapy(
                        &args.python,
                        &capture.path,
                        scapy_counts.get(&capture.name).copied().unwrap_or(100_000),
                    )?,
                    "etherparse" | "packet-tools" => {
                        run_rsbench(&args.rsbench, &capture.path, engine)?
                    }
                    _ => unreachable!(),
                };
                trials.push(Trial {
                    capture: capture.name.clone(),
                    trial,
                    engine: engine.to_owned(),
                    order,
                    throughput,
                });
            }
        }
    }
    write_trials(&artifacts.join("speedup_trials.csv"), &trials)?;
    let loadavg_end = load_average()?;
    fs::write(
        artifacts.join("loadavg.csv"),
        format!(
            "point,one_minute,five_minutes,fifteen_minutes\nstart,{},{},{}\nend,{},{},{}\n",
            loadavg_start[0],
            loadavg_start[1],
            loadavg_start[2],
            loadavg_end[0],
            loadavg_end[1],
            loadavg_end[2]
        ),
    )?;
    for capture in &args.captures {
        let rates = |engine: &str| {
            trials
                .iter()
                .filter(|trial| trial.capture == capture.name && trial.engine == engine)
                .map(|trial| trial.throughput.pkt_per_sec)
                .collect::<Vec<_>>()
        };
        let scapy = median(&rates("scapy")).expect("runs is positive");
        let etherparse = median(&rates("etherparse")).expect("runs is positive");
        let packet_tools = median(&rates("packet-tools")).expect("runs is positive");
        let packets = trials
            .iter()
            .find(|trial| trial.capture == capture.name && trial.engine == "packet-tools")
            .expect("each capture has a packet-tools trial")
            .throughput
            .packets;
        for (name, value) in [
            (format!("{}.scapy.pkt_per_sec_median", capture.name), scapy),
            (
                format!("{}.etherparse.pkt_per_sec_median", capture.name),
                etherparse,
            ),
            (
                format!("{}.packet-tools.pkt_per_sec_median", capture.name),
                packet_tools,
            ),
            (
                format!("{}.speedup_vs_scapy", capture.name),
                packet_tools / scapy,
            ),
            (
                format!("{}.speedup_vs_etherparse", capture.name),
                packet_tools / etherparse,
            ),
            (format!("{}.packets", capture.name), packets as f64),
        ] {
            run.log_metric(name, value).send()?;
        }
    }
    let finished = run.finish()?;
    println!("speedup -> {}", finished.display());
    Ok(())
}

fn e2e(args: E2eArgs, scratch: bool) -> Result<(), DynError> {
    ensure_unique(
        args.commands.iter().map(|command| command.name()),
        "command",
    )?;
    if !args.scapy_pkt_per_sec.is_finite() || args.scapy_pkt_per_sec <= 0.0 {
        return Err("--scapy-pkt-per-sec must be a finite positive number".into());
    }
    fs::create_dir_all(&args.out)?;
    let sums = args
        .sha256sums
        .as_deref()
        .map(read_sha256sums)
        .transpose()?
        .unwrap_or_default();
    let data = args
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input)| dataset_for_input(index, input, &sums))
        .collect::<Vec<_>>();
    let parameters = E2eParameters {
        inputs: args
            .inputs
            .iter()
            .map(|path| path.display().to_string())
            .collect(),
        commands: args
            .commands
            .iter()
            .map(|command| command.name().to_owned())
            .collect(),
        jobs: args.jobs,
        packet_tools: args.packet_tools.display().to_string(),
        rsbench: args.rsbench.display().to_string(),
        output_dir: args.out.display().to_string(),
        scapy_pkt_per_sec: args.scapy_pkt_per_sec,
        sha256sums: args
            .sha256sums
            .as_ref()
            .map(|path| path.display().to_string()),
    };
    let mut run = start_run("e2e", &parameters, data, scratch)?;
    let bytes = args.inputs.iter().try_fold(0_u64, |sum, input| {
        Ok::<_, io::Error>(sum.saturating_add(fs::metadata(input)?.len()))
    })?;

    let artifacts = run.dir().join("artifacts");
    fs::create_dir_all(&artifacts)?;
    let mut raw =
        String::from("command,seconds,cpu_seconds,max_rss_bytes,packets,bytes,mb_per_sec\n");
    let mut total_packets = None;
    for command in &args.commands {
        run_checked(&mut Command::new("sync"))?;
        let started = Instant::now();
        let (packets, usage) = run_e2e_command(*command, &args)?;
        let seconds = started.elapsed().as_secs_f64();
        if let Some(expected) = total_packets {
            if packets != expected {
                return Err(format!(
                    "{} reported {packets} packets; earlier command reported {expected}",
                    command.name()
                )
                .into());
            }
        } else {
            total_packets = Some(packets);
        }
        let cpu_seconds = usage.cpu_seconds;
        let mb_per_sec = bytes as f64 / 1_000_000.0 / seconds;
        let estimate = packets as f64 / args.scapy_pkt_per_sec;
        let prefix = format!("e2e.{}", command.name());
        for (name, value) in [
            (format!("{prefix}.seconds"), seconds),
            (format!("{prefix}.cpu_seconds"), cpu_seconds),
            (
                format!("{prefix}.max_rss_bytes"),
                usage.max_rss_bytes as f64,
            ),
            (format!("{prefix}.mb_per_sec"), mb_per_sec),
            (
                format!("{prefix}.speedup_vs_scapy_estimate"),
                estimate / seconds,
            ),
        ] {
            run.log_metric(name, value).send()?;
        }
        raw.push_str(&format!(
            "{},{seconds},{cpu_seconds},{},{packets},{bytes},{mb_per_sec}\n",
            command.name(),
            usage.max_rss_bytes
        ));
    }
    let packets = total_packets.expect("at least one command is required");
    run.log_metric("e2e.packets", packets as f64).send()?;
    run.log_metric("e2e.bytes", bytes as f64).send()?;
    run.log_metric(
        "e2e.scapy_estimate.seconds",
        packets as f64 / args.scapy_pkt_per_sec,
    )
    .send()?;
    fs::write(artifacts.join("e2e_commands.csv"), raw)?;
    let finished = run.finish()?;
    println!("e2e -> {}", finished.display());
    Ok(())
}

fn start_run<T: Serialize + ?Sized>(
    subcommand: &str,
    parameters: &T,
    data: Vec<Dataset>,
    scratch: bool,
) -> Result<Run, DynError> {
    let root = repository_root();
    let mut ext = Map::new();
    ext.insert("jira".to_owned(), json!(["MYTASK-3470"]));
    let options = RunOptions::new("bench", subcommand)
        .repo_id("rs-packet-tools")
        .domain("analysis")
        .results_root(root.join("results"))
        .repo_root(&root)
        .scratch(scratch)
        .parameters(parameters)?
        .data(data)
        .ext(ext)
        .cli_args(std::env::args().skip(1));
    Ok(Run::start(options)?)
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("ptbench is stored at bench/ptbench")
        .to_owned()
}

fn run_scapy(python: &Path, capture: &Path, count: u64) -> Result<Throughput, DynError> {
    let output = checked_output(
        Command::new(python)
            .arg(repository_root().join("bench/bench_scapy.py"))
            .arg(capture)
            .arg(count.to_string()),
    )?;
    parse_scapy(&String::from_utf8(output.stdout)?)
        .map_err(|error| format!("cannot parse Scapy output: {error}").into())
}

fn run_rsbench(rsbench: &Path, capture: &Path, engine: &str) -> Result<Throughput, DynError> {
    let output = checked_output(
        Command::new(rsbench)
            .args(["--engine", engine, "--json"])
            .arg(capture),
    )?;
    let value: Value = serde_json::from_slice(&output.stdout)?;
    Ok(Throughput {
        packets: json_u64(&value, "packets")?,
        seconds: json_f64(&value, "elapsed_secs")?,
        pkt_per_sec: json_f64(&value, "pkt_per_sec")?,
    })
}

fn run_e2e_command(command: E2eCommand, args: &E2eArgs) -> Result<(u64, Usage), DynError> {
    match command {
        E2eCommand::Rsbench => {
            let mut packets = 0_u64;
            let mut total = Usage {
                cpu_seconds: 0.0,
                max_rss_bytes: 0,
            };
            for input in &args.inputs {
                let (stdout, usage) = measured_output(
                    Command::new(&args.rsbench)
                        .args(["--engine", "packet-tools", "--json"])
                        .arg(input),
                )?;
                let value: Value = serde_json::from_slice(&stdout)?;
                packets = packets.saturating_add(json_u64(&value, "packets")?);
                total.cpu_seconds += usage.cpu_seconds;
                total.max_rss_bytes = total.max_rss_bytes.max(usage.max_rss_bytes);
            }
            Ok((packets, total))
        }
        E2eCommand::Flows | E2eCommand::App => {
            let destination = args.out.join(command.name());
            if destination.exists() {
                return Err(
                    format!("working output already exists: {}", destination.display()).into(),
                );
            }
            let mut process = Command::new(&args.packet_tools);
            process
                .arg(command.name())
                .args(["--jobs", &args.jobs.to_string(), "-o"])
                .arg(&destination)
                .args(&args.inputs);
            let (_, usage) = measured_output(&mut process)?;
            let manifest = fs::read_to_string(destination.join("inputs.csv"))?;
            let packets = packet_total_from_inputs_csv(&manifest)?;
            fs::remove_dir_all(&destination)?;
            Ok((packets, usage))
        }
    }
}

pub fn packet_total_from_inputs_csv(input: &str) -> Result<u64, String> {
    let records = parse_csv(input)?;
    let header = records
        .first()
        .ok_or_else(|| "inputs.csv is empty".to_owned())?;
    let packets_index = header
        .iter()
        .position(|field| field == "packets")
        .ok_or_else(|| "inputs.csv has no packets column".to_owned())?;
    let status_index = header
        .iter()
        .position(|field| field == "status")
        .ok_or_else(|| "inputs.csv has no status column".to_owned())?;
    records[1..].iter().try_fold(0_u64, |total, record| {
        let status = record
            .get(status_index)
            .ok_or_else(|| "inputs.csv row has no status".to_owned())?;
        if status != "ok" {
            return Err(format!("inputs.csv contains a {status} row"));
        }
        let packets = record
            .get(packets_index)
            .ok_or_else(|| "inputs.csv row has no packets value".to_owned())?
            .parse::<u64>()
            .map_err(|error| format!("invalid inputs.csv packet count: {error}"))?;
        Ok(total.saturating_add(packets))
    })
}

fn parse_csv(input: &str) -> Result<Vec<Vec<String>>, String> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = input.chars().peekable();
    while let Some(character) = chars.next() {
        if quoted {
            if character == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    quoted = false;
                }
            } else {
                field.push(character);
            }
            continue;
        }
        match character {
            '"' if field.is_empty() => quoted = true,
            ',' => record.push(std::mem::take(&mut field)),
            '\n' => {
                record.push(std::mem::take(&mut field));
                records.push(std::mem::take(&mut record));
            }
            '\r' if chars.peek() == Some(&'\n') => {}
            '"' => return Err("unexpected quote in inputs.csv".to_owned()),
            _ => field.push(character),
        }
    }
    if quoted {
        return Err("unterminated quoted field in inputs.csv".to_owned());
    }
    if !field.is_empty() || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    Ok(records)
}

fn dataset_for_input(index: usize, input: &Path, sums: &HashMap<String, String>) -> Dataset {
    let mut dataset =
        Dataset::new("benchmark", format!("input-{index}")).uri(input.display().to_string());
    let display = input.display().to_string();
    let basename = input
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default();
    if let Some(digest) = sums.get(&display).or_else(|| sums.get(basename)) {
        dataset.hash = Some(runvault::meta::Hash {
            algorithm: runvault::meta::Algorithm::Sha256,
            value: digest.clone(),
        });
        dataset.hash_scope = Some(runvault::meta::HashScope::File);
    }
    dataset
}

fn write_trials(path: &Path, trials: &[Trial]) -> io::Result<()> {
    let mut csv = String::from("capture,trial,engine,order,packets,seconds,pkt_per_sec\n");
    for trial in trials {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{}\n",
            csv_field(&trial.capture),
            trial.trial,
            trial.engine,
            trial.order,
            trial.throughput.packets,
            trial.throughput.seconds,
            trial.throughput.pkt_per_sec
        ));
    }
    fs::write(path, csv)
}

fn warm_file(path: &Path) -> io::Result<()> {
    let mut file = File::open(path)?;
    let mut buffer = [0_u8; 1024 * 1024];
    while file.read(&mut buffer)? != 0 {}
    Ok(())
}

fn load_average() -> io::Result<[f64; 3]> {
    let mut values = [0.0_f64; 3];
    // SAFETY: `values` points to storage for exactly three `f64` values.
    let read = unsafe { libc::getloadavg(values.as_mut_ptr(), values.len() as libc::c_int) };
    if read == values.len() as libc::c_int {
        Ok(values)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[derive(Clone, Copy)]
struct Usage {
    cpu_seconds: f64,
    max_rss_bytes: u64,
}

/// Runs one child to completion and returns its captured stdout with the
/// resource usage of that child alone.
///
/// `getrusage(RUSAGE_CHILDREN)` reports the largest RSS among every child
/// waited for so far, so a later command would inherit an earlier peak.
/// `wait4` reports the usage of the one process it reaps.
fn measured_output(command: &mut Command) -> Result<(Vec<u8>, Usage), DynError> {
    let display = format!("{command:?}");
    let mut child = command.stdout(Stdio::piped()).spawn()?;
    let mut stdout = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        pipe.read_to_end(&mut stdout)?;
    }
    let pid = child.id() as libc::pid_t;
    let mut raw_status: libc::c_int = 0;
    // SAFETY: a zeroed `rusage` is a valid output buffer for `wait4`.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let reaped = loop {
        // SAFETY: `pid` is our unreaped child; both pointers are valid and writable.
        let reaped = unsafe { libc::wait4(pid, &mut raw_status, 0, &mut usage) };
        if reaped == -1 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        break reaped;
    };
    if reaped != pid {
        return Err(io::Error::last_os_error().into());
    }
    let status = ExitStatus::from_raw(raw_status);
    if !status.success() {
        return Err(format!("{display} exited with {status}").into());
    }
    let timeval = |value: libc::timeval| value.tv_sec as f64 + value.tv_usec as f64 / 1_000_000.0;
    #[cfg(target_os = "macos")]
    let max_rss_bytes = usage.ru_maxrss as u64;
    #[cfg(not(target_os = "macos"))]
    let max_rss_bytes = (usage.ru_maxrss as u64).saturating_mul(1024);
    Ok((
        stdout,
        Usage {
            cpu_seconds: timeval(usage.ru_utime) + timeval(usage.ru_stime),
            max_rss_bytes,
        },
    ))
}

fn checked_output(command: &mut Command) -> Result<Output, DynError> {
    let display = format!("{command:?}");
    let output = command.output()?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(format!(
            "{display} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into())
    }
}

fn run_checked(command: &mut Command) -> Result<(), DynError> {
    let display = format!("{command:?}");
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{display} exited with {status}").into())
    }
}

fn json_u64(value: &Value, key: &str) -> Result<u64, DynError> {
    value[key]
        .as_u64()
        .ok_or_else(|| format!("JSON field `{key}` is not a u64").into())
}

fn json_f64(value: &Value, key: &str) -> Result<f64, DynError> {
    value[key]
        .as_f64()
        .ok_or_else(|| format!("JSON field `{key}` is not a number").into())
}

fn csv_field(value: &str) -> String {
    if value
        .chars()
        .any(|character| matches!(character, ',' | '"' | '\n' | '\r'))
    {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

fn ensure_unique<'a>(values: impl Iterator<Item = &'a str>, kind: &str) -> Result<(), DynError> {
    let mut seen = HashSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(format!("duplicate {kind}: {value}").into());
        }
    }
    Ok(())
}

fn positive_usize(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("expected a positive integer, got `{value}`"))
}

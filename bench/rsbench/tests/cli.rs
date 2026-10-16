use std::{path::PathBuf, process::Command};

#[test]
fn json_reports_legacy_pcap_metrics_on_one_line() {
    let value = run_json("be_usec.pcap");
    assert_eq!(value.matches(',').count(), 4);
    assert_eq!(integer_field(&value, "packets"), 19);
    assert_precise_rate(&value);
}

#[test]
fn json_reports_all_pcapng_interfaces() {
    let value = run_json("multi_iface.pcapng");
    assert_eq!(integer_field(&value, "packets"), 22);
    assert_precise_rate(&value);
}

#[test]
fn default_output_keeps_the_human_readable_format() {
    let output = Command::new(env!("CARGO_BIN_EXE_rsbench"))
        .arg(fixture("be_usec.pcap"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1);
    assert!(stdout.contains("19 pkts"));
    assert!(stdout.contains("M pkt/s"));
    assert!(!stdout.starts_with('{'));
}

#[test]
fn shell_json_rate_reads_the_machine_readable_value() {
    let output = bash(
        r#"source bench/run.sh
printf '%s\n' '{"packets":469340,"elapsed_secs":0.0245,"pkt_per_sec":19140000.25,"flows":26848,"errors":0}' | json_rate"#,
    );
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "19140000");
}

#[test]
fn shell_json_rate_rejects_a_non_numeric_rate() {
    let output = bash(
        r#"source bench/run.sh
printf '%s\n' '{"pkt_per_sec":"not-a-number"}' | json_rate"#,
    );
    assert!(!output.status.success());
}

#[test]
fn shell_rate_validation_rejects_missing_and_non_positive_values() {
    for value in ["", "not-a-number", "0"] {
        let output = bash(&format!(
            "source bench/run.sh\nvalidate_rate test '{value}'"
        ));
        assert!(!output.status.success(), "accepted {value:?}");
    }
    assert!(
        bash("source bench/run.sh\nvalidate_rate test '12.5'")
            .status
            .success()
    );
}

#[test]
fn shell_speedup_is_an_integer_ratio() {
    let output = bash("source bench/run.sh\nspeedup 19140000 1000000");
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "19");
}

fn run_json(name: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_rsbench"))
        .args(["--json", fixture(name).to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "rsbench failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1);
    assert!(stdout.starts_with('{') && stdout.trim_end().ends_with('}'));
    stdout
}

fn assert_precise_rate(value: &str) {
    let packets = integer_field(value, "packets") as f64;
    let elapsed = float_field(value, "elapsed_secs");
    let rate = float_field(value, "pkt_per_sec");
    assert!(elapsed > 0.0);
    assert!(rate > 0.0);
    assert!((rate - packets / elapsed).abs() / rate < 1e-12);
    let _ = integer_field(value, "flows");
    let _ = integer_field(value, "errors");
}

fn integer_field(value: &str, name: &str) -> u64 {
    field(value, name).parse().unwrap()
}

fn float_field(value: &str, name: &str) -> f64 {
    field(value, name).parse().unwrap()
}

fn field<'a>(value: &'a str, name: &str) -> &'a str {
    let marker = format!("\"{name}\":");
    value
        .split_once(&marker)
        .unwrap()
        .1
        .split([',', '}'])
        .next()
        .unwrap()
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

fn bash(script: &str) -> std::process::Output {
    Command::new("bash")
        .args(["-c", script])
        .current_dir(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .output()
        .unwrap()
}

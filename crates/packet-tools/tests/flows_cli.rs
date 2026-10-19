use std::{fs, path::PathBuf, process::Command};

#[test]
fn flows_defaults_to_corrected_snake_csv() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("flows.csv");
    let result = command()
        .args(["flows", "-o"])
        .arg(&output)
        .arg(fixture("le_usec.pcap"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let text = fs::read_to_string(output).unwrap();
    let header = text.lines().next().unwrap();
    assert!(header.starts_with("flow_uid,end_reason,flow_id,src_ip,"));
    assert_eq!(header.split(',').count(), 90);
    assert!(text.lines().count() > 1);
}

#[test]
fn flows_accepts_all_policy_timeout_and_output_options() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("minimal.data");
    let result = command()
        .args([
            "flows",
            "--policy",
            "idle-only",
            "--preset",
            "minimal",
            "--flow-timeout",
            "1.25",
            "--activity-timeout",
            "0.5",
            "--idle-timeout",
            "2",
            "--vlan-in-key",
            "--format",
            "csv",
            "-o",
        ])
        .arg(&output)
        .arg(fixture("le_usec.pcap"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let header = fs::read_to_string(output)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(header.split(',').count(), 21);
    assert!(header.starts_with("flow_uid,end_reason,ip_version"));
}

#[test]
fn flows_original_names_match_the_selected_policy() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("flows.csv");
    let result = command()
        .args([
            "flows",
            "--policy",
            "cicflowmeter",
            "--column-names",
            "original",
            "-o",
        ])
        .arg(&output)
        .arg(fixture("le_usec.pcap"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let text = fs::read_to_string(output).unwrap();
    let header = text.lines().next().unwrap();
    assert!(header.starts_with("Flow ID,Src IP,Src Port,Dst IP"));
    assert_eq!(header.split(',').count(), 83);
    assert!(!header.contains("Label"));
}

#[test]
fn flows_rejects_invalid_duration_and_original_minimal() {
    let directory = tempfile::tempdir().unwrap();
    let invalid = command()
        .args(["flows", "--idle-timeout", "-1", "-o"])
        .arg(directory.path().join("out.csv"))
        .arg(fixture("le_usec.pcap"))
        .output()
        .unwrap();
    assert!(!invalid.status.success());

    let conflict = command()
        .args([
            "flows",
            "--preset",
            "minimal",
            "--column-names",
            "original",
            "-o",
        ])
        .arg(directory.path().join("out.csv"))
        .arg(fixture("le_usec.pcap"))
        .output()
        .unwrap();
    assert!(!conflict.status.success());
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("cicflowmeter preset"));
}

#[test]
fn flows_closes_partial_csv_before_reporting_capture_error() {
    let bytes = fs::read(fixture("le_usec.pcap")).unwrap();
    let input = tempfile::NamedTempFile::new().unwrap();
    fs::write(input.path(), &bytes[..1_000]).unwrap();
    let output = tempfile::NamedTempFile::new().unwrap();
    let result = command()
        .args(["flows", "--format", "csv", "-o"])
        .arg(output.path())
        .arg(input.path())
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("truncated"));
    let text = fs::read_to_string(output.path()).unwrap();
    assert!(text.starts_with("flow_uid,end_reason,"));
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_packet-tools"))
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

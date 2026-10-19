use std::{fs, path::PathBuf, process::Command};

#[test]
fn packets_csv_writes_all_fixture_records() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("packets.csv");
    let result = command()
        .args(["packets", "-o"])
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
    assert_eq!(text.lines().count(), 20);
    assert!(text.starts_with("index,ts_ns,caplen,origlen,"));
}

#[test]
fn packets_fields_limit_depth_and_explicit_format_are_applied() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("selected.data");
    let result = command()
        .args([
            "packets",
            "--format",
            "csv",
            "--fields",
            "index,src_port,trailer_len",
            "--limit",
            "2",
            "--depth",
            "l3",
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
    assert_eq!(
        fs::read_to_string(output).unwrap(),
        "index,src_port,trailer_len\n0,,0\n1,,0\n"
    );
}

#[test]
fn packets_rejects_unknown_fields_and_missing_format() {
    let directory = tempfile::tempdir().unwrap();
    let unknown = command()
        .args(["packets", "--fields", "bogus", "-o"])
        .arg(directory.path().join("out.csv"))
        .arg(fixture("le_usec.pcap"))
        .output()
        .unwrap();
    assert!(!unknown.status.success());
    let stderr = String::from_utf8_lossy(&unknown.stderr);
    assert!(stderr.contains("unknown field `bogus`"), "{stderr}");
    assert!(stderr.contains("malformed"), "{stderr}");

    let missing = command()
        .args(["packets", "-o"])
        .arg(directory.path().join("out.data"))
        .arg(fixture("le_usec.pcap"))
        .output()
        .unwrap();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("cannot determine output format"));
}

#[test]
fn packets_closes_partial_csv_before_reporting_capture_error() {
    let bytes = fs::read(fixture("le_usec.pcap")).unwrap();
    let input = tempfile::NamedTempFile::new().unwrap();
    fs::write(input.path(), &bytes[..1_000]).unwrap();
    let output = tempfile::NamedTempFile::new().unwrap();
    let result = command()
        .args(["packets", "--format", "csv", "-o"])
        .arg(output.path())
        .arg(input.path())
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("truncated"));
    let text = fs::read_to_string(output.path()).unwrap();
    assert!(text.starts_with("index,"));
    assert!(text.lines().count() > 1);
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_packet-tools"))
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

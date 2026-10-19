use std::{fs, path::PathBuf, process::Command};

#[test]
fn app_writes_protocol_and_dispatch_tables() {
    let directory = tempfile::tempdir().unwrap();
    let result = command()
        .args(["app", "--format", "csv", "-o"])
        .arg(directory.path())
        .arg(fixture("le_usec.pcap"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    for name in [
        "dns",
        "http",
        "tls",
        "tls_heartbeat",
        "ftp",
        "ssh",
        "smtp",
        "telnet",
        "dispatch",
    ] {
        assert!(directory.path().join(format!("{name}.csv")).is_file());
    }
    assert!(
        fs::read_to_string(directory.path().join("dispatch.csv"))
            .unwrap()
            .starts_with("stream_id,flow_uid,")
    );
}

#[test]
fn app_accepts_memory_limits() {
    let directory = tempfile::tempdir().unwrap();
    let result = command()
        .args([
            "app",
            "--memory",
            "1048576",
            "--app-memory",
            "4096",
            "--format",
            "csv",
            "-o",
        ])
        .arg(directory.path())
        .arg(fixture("le_usec.pcap"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn app_rejects_unknown_protocol() {
    let directory = tempfile::tempdir().unwrap();
    let result = command()
        .args(["app", "--protocols", "dns,bogus", "--format", "csv", "-o"])
        .arg(directory.path())
        .arg(fixture("le_usec.pcap"))
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("unknown application protocol `bogus`")
    );
}

#[test]
fn app_fixture_covers_midstream_resync_and_visible_tls_failures() {
    let directory = tempfile::tempdir().unwrap();
    let result = command()
        .args(["app", "--delivery", "immediate", "--format", "csv", "-o"])
        .arg(directory.path())
        .arg(fixture("app/scenarios.pcap"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );

    let http = fs::read_to_string(directory.path().join("http.csv")).unwrap();
    assert!(http.contains(",POST,/after-keepalive,"));
    assert!(http.contains(",GET,/after-body,"));
    let tls = fs::read_to_string(directory.path().join("tls.csv")).unwrap();
    assert!(tls.contains(",server_hello,769,,769,"));
    assert!(tls.contains(",malformed,769,"));
    let dispatch = fs::read_to_string(directory.path().join("dispatch.csv")).unwrap();
    assert!(dispatch.contains("resynchronized; skipped 1 byte"));
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_packet-tools"))
}
fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

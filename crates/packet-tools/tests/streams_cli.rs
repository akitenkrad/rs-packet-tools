use std::{collections::BTreeMap, fs, path::PathBuf, process::Command};

use serde::Deserialize;
use sha2::{Digest, Sha256};

#[test]
fn streams_csv_has_the_stable_directional_schema() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("streams.csv");
    let events = directory.path().join("events.csv");
    let datagrams = directory.path().join("datagrams.csv");
    let result = command()
        .args(["streams", "--events"])
        .arg(&events)
        .args(["--datagrams"])
        .arg(&datagrams)
        .args(["-o"])
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
    assert!(text.starts_with("stream_id,flow_uid,direction,client_ip,server_ip,client_port,server_port,first_ts_ns,last_ts_ns,midstream,bytes,segments,gaps,gap_bytes,overlaps,overlap_conflicts,retransmitted_bytes,post_close_packets,post_close_bytes,keepalives,close_reason,sha256\n"));
    assert!(text.lines().count() >= 3);
    assert!(
        fs::read_to_string(events)
            .unwrap()
            .starts_with("index,ts_ns,kind,")
    );
    assert!(
        fs::read_to_string(datagrams)
            .unwrap()
            .starts_with("index,ip_version,src_ip,")
    );
}

#[test]
fn streams_accepts_all_documented_policy_delivery_and_limit_options() {
    let directory = tempfile::tempdir().unwrap();
    let result = command()
        .args([
            "streams",
            "--ip-policy",
            "last",
            "--tcp-policy",
            "old-linux",
            "--delivery",
            "immediate",
            "--defrag-timeout",
            "1.5",
            "--tcp-timeout",
            "2",
            "--stream-memory",
            "1024",
            "--memory",
            "4096",
            "--vlan-in-key",
            "--format",
            "csv",
            "-o",
        ])
        .arg(directory.path().join("out.data"))
        .arg(fixture("le_usec.pcap"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[derive(Deserialize)]
struct TcpVectors {
    cases: Vec<TcpCase>,
}

#[derive(Deserialize)]
struct TcpCase {
    policy: String,
    steps: Vec<TcpStep>,
}

#[derive(Deserialize)]
struct TcpStep {
    expected: String,
}

#[derive(Deserialize)]
struct IpVectors {
    expected: BTreeMap<String, BTreeMap<String, String>>,
}

#[test]
fn generated_capture_reaches_cli_with_sturges_novak_expected_bytes() {
    let tcp: TcpVectors = serde_json::from_str(include_str!(
        "../../../tests/fixtures/reassembly/sturges_novak_tcp.json"
    ))
    .unwrap();
    let ip: IpVectors = serde_json::from_str(include_str!(
        "../../../tests/fixtures/reassembly/sturges_novak_ip.json"
    ))
    .unwrap();
    for (tcp_policy, vector_policy) in [
        ("bsd", "bsd"),
        ("first", "vista"),
        ("linux", "linux"),
        ("old-linux", "old_linux"),
        ("solaris", "solaris"),
        ("last", "last"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let dump = directory.path().join("dump");
        let datagrams = directory.path().join("datagrams.csv");
        let result = command()
            .args([
                "streams",
                "--tcp-policy",
                tcp_policy,
                "--ip-policy",
                if tcp_policy == "old-linux" {
                    "bsd"
                } else {
                    tcp_policy
                },
                "--datagrams",
            ])
            .arg(&datagrams)
            .args(["--dump-dir"])
            .arg(&dump)
            .args(["-o"])
            .arg(directory.path().join("streams.csv"))
            .arg(fixture("reassembly/scenarios.pcap"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        for (stream_id, case) in tcp
            .cases
            .iter()
            .enumerate()
            .filter(|(_, case)| case.policy == vector_policy)
        {
            let expected = case.steps.last().unwrap().expected.replace('.', "");
            assert_eq!(
                fs::read(dump.join(format!("{stream_id}.c2s.bin"))).unwrap(),
                expected.as_bytes(),
                "TCP policy {tcp_policy} stream {stream_id}"
            );
        }
        if tcp_policy != "old-linux" {
            let text = fs::read_to_string(&datagrams).unwrap();
            for version in ["ipv4", "ipv6"] {
                let payload = ip.expected[tcp_policy][version]
                    .bytes()
                    .flat_map(|byte| std::iter::repeat_n(byte, 8))
                    .collect::<Vec<_>>();
                let digest = Sha256::digest(payload)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                assert!(text.contains(&digest), "IP policy {tcp_policy} {version}");
            }
        }
    }
}

#[test]
fn generated_capture_covers_closed_connections_and_keepalives() {
    let directory = tempfile::tempdir().unwrap();
    let streams = directory.path().join("streams.csv");
    let events = directory.path().join("events.csv");
    let result = command()
        .args(["streams", "--delivery", "immediate", "--events"])
        .arg(&events)
        .args(["-o"])
        .arg(&streams)
        .arg(fixture("reassembly/scenarios.pcap"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );

    let rows = csv_rows(&streams);
    let row = |port: &str, direction: &str| {
        rows.iter()
            .find(|row| row["client_port"] == port && row["direction"] == direction)
            .unwrap()
    };
    assert_eq!(row("31000", "server_to_client")["post_close_packets"], "1");
    assert_eq!(row("31000", "server_to_client")["post_close_bytes"], "4");
    assert_eq!(row("31001", "server_to_client")["post_close_packets"], "1");
    assert_eq!(row("31001", "server_to_client")["post_close_bytes"], "1");
    assert_eq!(row("31004", "client_to_server")["keepalives"], "2");
    assert_eq!(row("31004", "client_to_server")["bytes"], "4");
    assert_eq!(row("31004", "client_to_server")["overlap_conflicts"], "0");

    let timed_out = rows
        .iter()
        .filter(|row| row["client_port"] == "31002" || row["server_port"] == "31002")
        .collect::<Vec<_>>();
    assert_eq!(
        timed_out
            .iter()
            .filter(|row| row["midstream"] == "true")
            .count(),
        2,
        "the post-timeout connection has two directional rows"
    );
    let replacement = rows
        .iter()
        .filter(|row| row["client_port"] == "31003" || row["server_port"] == "31003")
        .collect::<Vec<_>>();
    assert_eq!(replacement.len(), 4);
    assert!(replacement.iter().all(|row| row["midstream"] == "false"));

    let keepalive_stream_id = row("31004", "client_to_server")["stream_id"].clone();
    let event_rows = csv_rows(&events);
    let event_text = fs::read_to_string(events).unwrap();
    assert_eq!(event_text.matches("tcp_data_after_close").count(), 2);
    assert!(!event_rows.iter().any(|event| {
        event["stream_id"] == keepalive_stream_id && event["kind"] == "tcp_late_overlap_conflict"
    }));
}

fn csv_rows(path: &std::path::Path) -> Vec<BTreeMap<String, String>> {
    let text = fs::read_to_string(path).unwrap();
    let mut lines = text.lines();
    let headers = lines
        .next()
        .unwrap()
        .split(',')
        .map(str::to_owned)
        .collect::<Vec<_>>();
    lines
        .map(|line| {
            headers
                .iter()
                .cloned()
                .zip(line.split(',').map(str::to_owned))
                .collect()
        })
        .collect()
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_packet-tools"))
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

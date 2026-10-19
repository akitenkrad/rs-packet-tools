use std::{collections::BTreeMap, fs, path::PathBuf, process::Command};

use serde::Deserialize;

#[derive(Deserialize)]
struct Manifest {
    files: BTreeMap<String, ManifestFile>,
}

#[derive(Deserialize)]
struct ManifestFile {
    packet_count: u64,
}

#[test]
fn validate_json_reports_every_fixture_and_a_total() {
    let root = fixture_root();
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_packet-tools"));
    command.args(["validate", "--json"]);
    for name in manifest.files.keys() {
        command.arg(root.join(name));
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let values = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(values.len(), manifest.files.len() + 1);
    for value in &values[..manifest.files.len()] {
        let name = PathBuf::from(value["path"].as_str().unwrap())
            .strip_prefix(&root)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(value["packets"], manifest.files[&name].packet_count);
        assert!(value["error"].is_null());
    }
    assert_eq!(values.last().unwrap()["type"], "total");
    assert_eq!(values.last().unwrap()["packets"], 139);
    assert_eq!(values.last().unwrap()["regressions"], 7);
}

#[test]
fn validate_returns_one_and_reports_a_truncated_tail() {
    let root = fixture_root();
    let bytes = fs::read(root.join("le_usec.pcap")).unwrap();
    let temp = tempfile::NamedTempFile::new().unwrap();
    fs::write(temp.path(), &bytes[..1_000]).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_packet-tools"))
        .args(["validate", temp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("truncated tail"), "{stdout}");
    assert!(stdout.contains("max_regression=0.000μs"), "{stdout}");
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures")
}

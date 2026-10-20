use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

#[test]
fn packets_flow_uid_matches_emitted_flow_packet_counts_for_every_policy() {
    for policy in ["corrected", "cicflowmeter", "idle-only"] {
        let directory = tempfile::tempdir().unwrap();
        let packets = directory.path().join("packets.csv");
        let flows = directory.path().join("flows.csv");
        run_ok(
            command()
                .args([
                    "packets", "--policy", policy, "--fields", "flow_uid", "--format", "csv", "-o",
                ])
                .arg(&packets)
                .arg(fixture("flows/scenarios.pcap")),
        );
        run_ok(
            command()
                .args([
                    "flows", "--policy", policy, "--preset", "minimal", "--format", "csv", "-o",
                ])
                .arg(&flows)
                .arg(fixture("flows/scenarios.pcap")),
        );

        let packet_counts = csv_rows(&packets)
            .into_iter()
            .filter_map(|row| row["flow_uid"].parse::<u64>().ok())
            .fold(BTreeMap::<u64, u64>::new(), |mut counts, uid| {
                *counts.entry(uid).or_default() += 1;
                counts
            });
        for row in csv_rows(&flows) {
            let uid = row["flow_uid"].parse::<u64>().unwrap();
            let expected = row["fwd_packets"].parse::<u64>().unwrap()
                + row["bwd_packets"].parse::<u64>().unwrap();
            assert_eq!(packet_counts.get(&uid), Some(&expected), "policy={policy}");
        }
    }
}

#[test]
fn multi_input_outputs_are_job_independent_and_match_single_input() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("captures/week5/tuesday/inside.pcap");
    let second = directory.path().join("captures/week4/monday/inside.pcap");
    copy_fixture(&first, "le_usec.pcap");
    copy_fixture(&second, "be_usec.pcap");

    for subcommand in ["packets", "flows", "streams", "app"] {
        let jobs_one = directory.path().join(format!("{subcommand}-j1"));
        let jobs_three = directory.path().join(format!("{subcommand}-j3"));
        run_multi(subcommand, 1, &jobs_one, [&first, &second]);
        run_multi(subcommand, 3, &jobs_three, [&first, &second]);
        assert_tree_eq(&jobs_one, &jobs_three);

        for (input, relative) in [
            (&first, "week5/tuesday/inside.pcap"),
            (&second, "week4/monday/inside.pcap"),
        ] {
            let single = directory.path().join(format!(
                "single-{subcommand}-{}",
                input
                    .parent()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
            ));
            match subcommand {
                "packets" | "flows" => {
                    let output = single.with_extension("csv");
                    run_ok(
                        command()
                            .args([subcommand, "--format", "csv", "-o"])
                            .arg(&output)
                            .arg(input),
                    );
                    assert_eq!(
                        fs::read(output).unwrap(),
                        fs::read(jobs_one.join(relative).join(format!("{subcommand}.csv")))
                            .unwrap()
                    );
                }
                "streams" => {
                    fs::create_dir_all(&single).unwrap();
                    run_ok(
                        command()
                            .args(["streams", "--format", "csv", "--events"])
                            .arg(single.join("events.csv"))
                            .args(["--datagrams"])
                            .arg(single.join("datagrams.csv"))
                            .args(["-o"])
                            .arg(single.join("streams.csv"))
                            .arg(input),
                    );
                    assert_tree_eq(&single, &jobs_one.join(relative));
                }
                "app" => {
                    run_ok(
                        command()
                            .args(["app", "--format", "csv", "-o"])
                            .arg(&single)
                            .arg(input),
                    );
                    assert_tree_eq(&single, &jobs_one.join(relative));
                }
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn multi_input_records_partial_failure_and_keeps_other_outputs() {
    let directory = tempfile::tempdir().unwrap();
    let good = directory.path().join("inputs/good/inside.pcap");
    let bad = directory.path().join("inputs/bad/inside.pcap");
    copy_fixture(&good, "le_usec.pcap");
    fs::create_dir_all(bad.parent().unwrap()).unwrap();
    fs::write(&bad, b"not a capture").unwrap();
    let output = directory.path().join("out");
    let result = command()
        .args(["packets", "--jobs", "3", "--format", "csv", "-o"])
        .arg(&output)
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(output.join("good/inside.pcap/packets.csv").is_file());
    let manifest = fs::read_to_string(output.join("inputs.csv")).unwrap();
    assert!(manifest.contains(",good/inside.pcap,"));
    assert!(manifest.contains(",ok,"));
    assert!(manifest.contains(",bad/inside.pcap,"));
    assert!(manifest.contains(",error,"));
    assert!(String::from_utf8_lossy(&result.stderr).contains("bad/inside.pcap"));
}

#[test]
fn validate_jobs_preserves_input_order() {
    let inputs = [fixture("be_usec.pcap"), fixture("le_usec.pcap")];
    for jobs in [1, 3] {
        let output = command()
            .args(["validate", "--json", "--jobs", &jobs.to_string()])
            .args(&inputs)
            .output()
            .unwrap();
        assert!(output.status.success());
        let lines = String::from_utf8(output.stdout).unwrap();
        let paths = lines
            .lines()
            .take(2)
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line).unwrap()["path"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            inputs
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
        );
    }
}

fn run_multi<const N: usize>(subcommand: &str, jobs: usize, output: &Path, inputs: [&PathBuf; N]) {
    run_ok(
        command()
            .arg(subcommand)
            .args(["--jobs", &jobs.to_string(), "--format", "csv", "-o"])
            .arg(output)
            .args(inputs),
    );
}

fn run_ok(command: &mut Command) {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn copy_fixture(path: &Path, name: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::copy(fixture(name), path).unwrap();
}

fn assert_tree_eq(left: &Path, right: &Path) {
    let left_files = tree(left);
    let right_files = tree(right);
    assert_eq!(
        left_files.keys().collect::<Vec<_>>(),
        right_files.keys().collect::<Vec<_>>()
    );
    for (path, bytes) in left_files {
        assert_eq!(bytes, right_files[&path], "{}", path.display());
    }
}

fn tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn visit(root: &Path, directory: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        let mut entries = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            if entry.file_type().unwrap().is_dir() {
                visit(root, &entry.path(), files);
            } else {
                files.insert(
                    entry.path().strip_prefix(root).unwrap().to_owned(),
                    fs::read(entry.path()).unwrap(),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}

fn csv_rows(path: &Path) -> Vec<BTreeMap<String, String>> {
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

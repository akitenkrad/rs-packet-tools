use std::{fs, path::Path, process::Command};

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_packet-tools-fixtures"))
}

#[test]
fn help_succeeds_without_writing_files() {
    let output = command().arg("--help").output().unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout).unwrap().contains("--out"));
}

#[test]
fn missing_out_argument_is_a_cli_error() {
    let output = command().output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8(output.stderr).unwrap().contains("--out"));
}

#[test]
fn nested_output_directory_is_created() {
    let temp = tempfile::tempdir().unwrap();
    let nested = temp.path().join("one/two/fixtures");
    let status = command()
        .args(["--out", nested.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(nested.join("manifest.json").is_file());
}

#[test]
fn repeated_generation_in_place_is_idempotent() {
    let temp = tempfile::tempdir().unwrap();
    run(temp.path());
    let before = fs::read(temp.path().join("manifest.json")).unwrap();
    run(temp.path());
    assert_eq!(before, fs::read(temp.path().join("manifest.json")).unwrap());
}

#[test]
fn output_path_that_is_a_file_fails_without_panicking() {
    let temp = tempfile::tempdir().unwrap();
    let output_path = temp.path().join("not-a-directory");
    fs::write(&output_path, b"occupied").unwrap();
    let output = command()
        .args(["--out", output_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("panicked")
    );
}

fn run(path: &Path) {
    assert!(
        command()
            .args(["--out", path.to_str().unwrap()])
            .status()
            .unwrap()
            .success()
    );
}

use std::{collections::BTreeMap, fs, path::PathBuf};

use packet_tools_capture::Capture;
use packet_tools_dissect::{DecodeDepth, decode};
use packet_tools_flow::{
    ColumnType, EndReason, Flow, FlowConfig, FlowTable, Policy, cicflowmeter_columns,
};

#[test]
fn deterministic_flow_scenarios_cover_each_policy_state_machine() {
    let corrected = summarize(Policy::Corrected);
    assert_eq!(corrected.values().sum::<usize>(), 10);
    assert_eq!(corrected[&EndReason::Fin], 1);
    assert_eq!(corrected[&EndReason::Rst], 1);
    assert_eq!(corrected[&EndReason::FlowTimeout], 1);
    assert_eq!(corrected[&EndReason::EndOfCapture], 7);

    let original = summarize(Policy::CicFlowMeter);
    assert_eq!(original.values().sum::<usize>(), 7);
    assert_eq!(original[&EndReason::Fin], 3);
    assert_eq!(original[&EndReason::EndOfCapture], 4);

    let idle = summarize(Policy::IdleOnly);
    assert_eq!(idle.values().sum::<usize>(), 11);
    assert_eq!(idle[&EndReason::IdleTimeout], 4);
    assert_eq!(idle[&EndReason::EndOfCapture], 7);
}

#[test]
fn deterministic_flow_scenarios_match_cicflowmeter_reference_csvs() {
    for (policy, filename) in [
        (Policy::CicFlowMeter, "scenarios.cicflowmeter-9d91f72.csv"),
        (Policy::Corrected, "scenarios.corrected-13a0615.csv"),
    ] {
        compare_reference(policy, filename);
    }
}

fn summarize(policy: Policy) -> BTreeMap<EndReason, usize> {
    let completed = collect_flows(policy);
    let mut reasons = BTreeMap::new();
    for flow in completed {
        *reasons.entry(flow.end_reason).or_default() += 1;
    }
    reasons
}

fn collect_flows(policy: Policy) -> Vec<Flow> {
    let mut capture = Capture::open(fixture()).unwrap();
    let mut table = FlowTable::new(FlowConfig {
        policy,
        ..FlowConfig::default()
    });
    let mut completed = Vec::new();
    while let Some(record) = capture.next_record() {
        let record = record.unwrap();
        let packet = decode(record.data, record.linktype, DecodeDepth::L4);
        completed.extend(table.push(&record, &packet));
    }
    completed.extend(table.finish());
    completed
}

fn compare_reference(policy: Policy, filename: &str) {
    let csv = fs::read_to_string(fixture().with_file_name(filename)).unwrap();
    let mut lines = csv.lines();
    let header = lines.next().unwrap().trim_end_matches('\r');
    let expected_header = cicflowmeter_columns(policy)
        .iter()
        .map(|column| column.original)
        .chain(std::iter::once("Label"))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(header, expected_header);

    let mut reference = group_rows(
        lines
            .map(|line| {
                let mut row = line
                    .trim_end_matches('\r')
                    .split(',')
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                row.pop();
                row
            })
            .collect(),
    );
    let actual = group_rows(
        collect_flows(policy)
            .iter()
            .map(|flow| {
                flow.compatibility_values()
                    .iter()
                    .map(|value| value.java_string())
                    .collect()
            })
            .collect(),
    );
    assert_eq!(
        actual.keys().collect::<Vec<_>>(),
        reference.keys().collect::<Vec<_>>()
    );
    for (key, actual_rows) in actual {
        let mut reference_rows = reference.remove(&key).unwrap();
        assert_eq!(
            actual_rows.len(),
            reference_rows.len(),
            "row count for {key:?}"
        );
        for actual in actual_rows {
            let position = reference_rows
                .iter()
                .position(|candidate| row_matches(policy, &actual, candidate))
                .unwrap_or_else(|| panic!("no all-column match for {key:?}: {actual:?}"));
            reference_rows.swap_remove(position);
        }
    }
}

fn group_rows(rows: Vec<Vec<String>>) -> BTreeMap<(String, String), Vec<Vec<String>>> {
    let mut groups = BTreeMap::new();
    for row in rows {
        groups
            .entry((row[0].clone(), row[6].clone()))
            .or_insert_with(Vec::new)
            .push(row);
    }
    groups
}

fn row_matches(policy: Policy, actual: &[String], reference: &[String]) -> bool {
    actual
        .iter()
        .zip(reference)
        .enumerate()
        .all(|(index, (actual, reference))| {
            same_value(
                actual,
                reference,
                cicflowmeter_columns(policy)[index].data_type,
            )
        })
}

fn same_value(actual: &str, reference: &str, data_type: ColumnType) -> bool {
    match data_type {
        ColumnType::Utf8 | ColumnType::UInt64 | ColumnType::Int64 => actual == reference,
        ColumnType::Float64 => {
            let Ok(actual) = actual.parse::<f64>() else {
                return false;
            };
            let Ok(reference) = reference.parse::<f64>() else {
                return false;
            };
            actual == reference
                || (actual.is_nan() && reference.is_nan())
                || (actual - reference).abs() <= 1e-9 * actual.abs().max(reference.abs()).max(1.0)
        }
    }
}

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/flows/scenarios.pcap")
}

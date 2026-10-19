use std::{collections::BTreeMap, env, fs, path::Path};

use packet_tools_capture::Capture;
use packet_tools_dissect::{DecodeDepth, decode};
use packet_tools_flow::{ColumnType, Flow, FlowConfig, FlowTable, Policy, cicflowmeter_columns};

#[test]
fn cicflowmeter_reference_csvs() {
    let Ok(root) = env::var("PACKET_TOOLS_CFM_REF") else {
        eprintln!("PACKET_TOOLS_CFM_REF is not set; skipping CICFlowMeter reference test");
        return;
    };
    let root = Path::new(&root);
    let mut reports = Vec::new();
    let mut files = fs::read_dir(root.join("in"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|file| file.ends_with(".pcap"))
        .collect::<Vec<_>>();
    files.sort();
    for file in &files {
        for (policy, reference_dir) in [
            (Policy::CicFlowMeter, "orig"),
            (Policy::Corrected, "engelen"),
        ] {
            reports.push(compare_one(root, file, policy, reference_dir));
        }
    }
    eprintln!("file\tpolicy\taccepted\tdiscarded\tmax_active\tactual\treference\tmatched");
    for report in &reports {
        eprintln!(
            "{}\t{:?}\t{}\t{}\t{}\t{}\t{}\t{}",
            report.file,
            report.policy,
            report.accepted,
            report.discarded,
            report.max_active,
            report.actual,
            report.reference,
            report.matched
        );
        if !report.mismatches.is_empty() {
            eprintln!("  mismatches: {:?}", report.mismatches);
        }
    }
    let failed = reports
        .iter()
        .filter(|report| report.actual != report.reference || !report.mismatches.is_empty())
        .collect::<Vec<_>>();
    assert!(
        failed.is_empty(),
        "{} of {} reference comparisons differed",
        failed.len(),
        reports.len(),
    );
}

#[test]
fn cicflowmeter_full_day_memory() {
    let Ok(path) = env::var("PACKET_TOOLS_CFM_DAY") else {
        eprintln!("PACKET_TOOLS_CFM_DAY is not set; skipping full-day memory test");
        return;
    };
    for policy in [Policy::CicFlowMeter, Policy::Corrected] {
        let mut capture = Capture::open(&path).unwrap();
        let mut table = FlowTable::new(FlowConfig {
            policy,
            ..FlowConfig::default()
        });
        let mut emitted = 0usize;
        while let Some(record) = capture.next_record() {
            let record = record.unwrap();
            let packet = decode(record.data, record.linktype, DecodeDepth::L4);
            emitted += table.push(&record, &packet).len();
        }
        let accepted = table.accepted_packets();
        let discarded = table.discarded_packets();
        let max_active = table.max_active_len();
        emitted += table.finish().len();
        eprintln!(
            "full-day\t{policy:?}\taccepted={accepted}\tdiscarded={discarded}\tmax_active={max_active}\temitted={emitted}"
        );
    }
}

struct Report {
    file: String,
    policy: Policy,
    accepted: u64,
    discarded: u64,
    max_active: usize,
    actual: usize,
    reference: usize,
    matched: usize,
    mismatches: BTreeMap<String, usize>,
}

fn compare_one(root: &Path, file: &str, policy: Policy, reference_dir: &str) -> Report {
    let mut capture = Capture::open(root.join("in").join(file)).unwrap();
    let mut table = FlowTable::new(FlowConfig {
        policy,
        ..FlowConfig::default()
    });
    let mut flows = Vec::new();
    while let Some(record) = capture.next_record() {
        let record = record.unwrap();
        let packet = decode(record.data, record.linktype, DecodeDepth::L4);
        flows.extend(table.push(&record, &packet));
    }
    let accepted = table.accepted_packets();
    let discarded = table.discarded_packets();
    let max_active = table.max_active_len();
    flows.extend(table.finish());

    let reference_path = root.join(reference_dir).join(format!("{file}_Flow.csv"));
    let csv = fs::read_to_string(reference_path).unwrap();
    let mut lines = csv.lines();
    let header = lines.next().unwrap().trim_end_matches('\r');
    let expected_header = cicflowmeter_columns(policy)
        .iter()
        .map(|column| column.original)
        .chain(std::iter::once("Label"))
        .collect::<Vec<_>>()
        .join(",");
    assert_eq!(header, expected_header);
    let reference_rows = lines
        .map(|line| {
            let mut values = line
                .trim_end_matches('\r')
                .split(',')
                .map(str::to_owned)
                .collect::<Vec<_>>();
            values.pop();
            values
        })
        .collect::<Vec<_>>();

    let actual_rows = flows.iter().map(actual_row).collect::<Vec<_>>();
    report_mismatch_spans(policy, &flows, &reference_rows);
    let (matched, mismatches) = compare_rows(policy, actual_rows, reference_rows.clone());
    Report {
        file: file.to_owned(),
        policy,
        accepted,
        discarded,
        max_active,
        actual: flows.len(),
        reference: reference_rows.len(),
        matched,
        mismatches,
    }
}

fn report_mismatch_spans(policy: Policy, flows: &[Flow], reference: &[Vec<String>]) {
    let reference = group(reference.to_vec());
    for flow in flows {
        let actual = actual_row(flow);
        let key = (actual[0].clone(), actual[6].clone());
        let matches = reference.get(&key).is_some_and(|candidates| {
            candidates.iter().any(|candidate| {
                actual
                    .iter()
                    .zip(candidate)
                    .enumerate()
                    .all(|(index, (actual, reference))| {
                        same_value(
                            actual,
                            reference,
                            cicflowmeter_columns(policy)[index].data_type,
                        )
                    })
            })
        });
        if !matches {
            eprintln!(
                "  mismatch flow {:?}: first_index={} last_index={}",
                key, flow.first_index, flow.last_index
            );
        }
    }
}

fn actual_row(flow: &Flow) -> Vec<String> {
    flow.compatibility_values()
        .iter()
        .map(|value| value.java_string())
        .collect()
}

fn compare_rows(
    policy: Policy,
    actual: Vec<Vec<String>>,
    reference: Vec<Vec<String>>,
) -> (usize, BTreeMap<String, usize>) {
    let mut actual_groups = group(actual);
    let mut reference_groups = group(reference);
    let mut mismatches = BTreeMap::new();
    let mut matched = 0;
    let mut shown = 0;
    let mut shown_values = 0;
    let keys = actual_groups
        .keys()
        .chain(reference_groups.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    for key in keys {
        let actual = actual_groups.remove(&key).unwrap_or_default();
        let mut reference = reference_groups.remove(&key).unwrap_or_default();
        if actual.len() != reference.len() {
            *mismatches.entry("<row_count>".to_owned()).or_default() +=
                actual.len().abs_diff(reference.len());
            if shown < 5 {
                eprintln!(
                    "  key {:?}: actual={} reference={}",
                    key,
                    actual.len(),
                    reference.len()
                );
                shown += 1;
            }
        }
        for actual in &actual {
            if reference.is_empty() {
                break;
            }
            let exact = reference.iter().position(|candidate| {
                actual
                    .iter()
                    .zip(candidate)
                    .enumerate()
                    .all(|(index, (actual, reference))| {
                        same_value(
                            actual,
                            reference,
                            cicflowmeter_columns(policy)[index].data_type,
                        )
                    })
            });
            if let Some(index) = exact {
                reference.swap_remove(index);
                matched += 1;
                continue;
            }
            let closest = reference
                .iter()
                .enumerate()
                .max_by_key(|(_, candidate)| {
                    actual
                        .iter()
                        .zip(*candidate)
                        .enumerate()
                        .filter(|(index, (actual, reference))| {
                            same_value(
                                actual,
                                reference,
                                cicflowmeter_columns(policy)[*index].data_type,
                            )
                        })
                        .count()
                })
                .map(|(index, _)| index)
                .unwrap_or(0);
            let reference = reference.swap_remove(closest);
            for (index, (actual, reference)) in actual.iter().zip(&reference).enumerate() {
                if !same_value(
                    actual,
                    reference,
                    cicflowmeter_columns(policy)[index].data_type,
                ) {
                    if shown_values < 8 {
                        eprintln!(
                            "  value {:?} {}: actual={} reference={}",
                            key,
                            cicflowmeter_columns(policy)[index].original,
                            actual,
                            reference
                        );
                        shown_values += 1;
                    }
                    *mismatches
                        .entry(cicflowmeter_columns(policy)[index].original.to_owned())
                        .or_default() += 1;
                }
            }
        }
    }
    (matched, mismatches)
}

fn group(rows: Vec<Vec<String>>) -> BTreeMap<(String, String), Vec<Vec<String>>> {
    let mut groups = BTreeMap::new();
    for row in rows {
        groups
            .entry((row[0].clone(), row[6].clone()))
            .or_insert_with(Vec::new)
            .push(row);
    }
    groups
}

fn same_value(actual: &str, reference: &str, data_type: ColumnType) -> bool {
    match data_type {
        ColumnType::Utf8 => actual == reference,
        ColumnType::UInt64 | ColumnType::Int64 => actual == reference,
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

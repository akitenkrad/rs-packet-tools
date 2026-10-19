use std::{path::PathBuf, time::Duration};

use packet_tools_capture::Capture;
use packet_tools_dissect::{DecodeDepth, decode};
use packet_tools_flow::{FlowConfig, FlowIdentityKey, FlowTable, Policy, Preset, flow_uid};

#[test]
fn public_flow_uid_matches_idle_only_output() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/le_usec.pcap");
    let mut capture = Capture::open(path).unwrap();
    let mut table = FlowTable::new(FlowConfig {
        policy: Policy::IdleOnly,
        preset: Preset::Minimal,
        idle_timeout: Duration::from_secs(60),
        ..FlowConfig::default()
    });
    while let Some(record) = capture.next_record() {
        let record = record.unwrap();
        let packet = decode(record.data, record.linktype, DecodeDepth::L4);
        let _ = table.push(&record, &packet);
    }
    let flow = table
        .finish()
        .into_iter()
        .find(|flow| flow.protocol == 6)
        .unwrap();
    let key = FlowIdentityKey::normalized(
        flow.src_ip,
        flow.dst_ip,
        flow.src_port,
        flow.dst_port,
        flow.protocol,
        None,
    );
    assert_eq!(flow.flow_uid, flow_uid(&key, flow.first_ts_ns));
}

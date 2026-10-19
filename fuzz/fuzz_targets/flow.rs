#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_tools_capture::{LinkType, PacketRecord};
use packet_tools_dissect::{DecodeDepth, decode};
use packet_tools_flow::{FlowConfig, FlowTable, Policy};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, packet_data)) = data.split_first() else {
        return;
    };
    let linktypes = [0, 1, 12, 14, 101, 108, 113, 276];
    let linktype = LinkType(linktypes[usize::from(selector) % linktypes.len()]);
    let policy = match selector % 3 {
        0 => Policy::CicFlowMeter,
        1 => Policy::Corrected,
        _ => Policy::IdleOnly,
    };
    let packet = decode(packet_data, linktype, DecodeDepth::L4);
    let record = PacketRecord {
        index: 0,
        ts_ns: Some(i64::from(selector) * 1_000_000_001),
        caplen: packet_data.len() as u32,
        origlen: packet_data.len() as u32,
        linktype,
        interface: 0,
        data: packet_data,
    };
    let mut table = FlowTable::new(FlowConfig {
        policy,
        ..FlowConfig::default()
    });
    let _ = table.push(&record, &packet);
    let _ = table.finish();
});

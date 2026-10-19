use std::io::Read;

use arrow::array::{StringArray, UInt64Array};
use packet_tools_capture::{LinkType, PacketRecord};
use packet_tools_dissect::{DecodeDepth, decode};
use packet_tools_export::{
    flows::{ColumnNames, FlowsWriter},
    packets::Format,
};
use packet_tools_flow::{Flow, FlowConfig, FlowTable, Policy, Preset};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

#[test]
fn minimal_csv_has_the_21_column_contract() {
    let output = tempfile::NamedTempFile::new().unwrap();
    let flow = one_flow(Policy::Corrected);
    let mut writer = FlowsWriter::new(
        output.reopen().unwrap(),
        Format::Csv,
        Policy::Corrected,
        Preset::Minimal,
        ColumnNames::Snake,
    )
    .unwrap();
    writer.push(&flow).unwrap();
    writer.finish().unwrap();

    let mut text = String::new();
    output.reopen().unwrap().read_to_string(&mut text).unwrap();
    let lines = text.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0].split(',').count(), 21);
    assert!(lines[0].starts_with("flow_uid,end_reason,ip_version,src_ip,dst_ip"));
    assert!(lines[0].ends_with("first_index,last_index"));
    assert!(lines[1].contains(",end_of_capture,4,10.0.0.1,10.0.0.2,"));
}

#[test]
fn original_names_exclude_packet_tools_metadata_and_label() {
    let output = tempfile::NamedTempFile::new().unwrap();
    let flow = one_flow(Policy::CicFlowMeter);
    let mut writer = FlowsWriter::new(
        output.reopen().unwrap(),
        Format::Csv,
        Policy::CicFlowMeter,
        Preset::CicFlowMeter,
        ColumnNames::Original,
    )
    .unwrap();
    writer.push(&flow).unwrap();
    writer.finish().unwrap();

    let header = std::fs::read_to_string(output.path())
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(header.split(',').count(), 83);
    assert!(header.starts_with("Flow ID,Src IP,Src Port,Dst IP,Dst Port,Protocol,Timestamp"));
    assert!(!header.contains("flow_uid"));
    assert!(!header.contains("Label"));
}

#[test]
fn corrected_parquet_uses_snappy_and_typed_columns() {
    let output = tempfile::NamedTempFile::new().unwrap();
    let flow = one_flow(Policy::Corrected);
    let mut writer = FlowsWriter::new(
        output.reopen().unwrap(),
        Format::Parquet,
        Policy::Corrected,
        Preset::CicFlowMeter,
        ColumnNames::Snake,
    )
    .unwrap();
    writer.push(&flow).unwrap();
    writer.finish().unwrap();

    let batches = ParquetRecordBatchReaderBuilder::try_new(output.reopen().unwrap())
        .unwrap()
        .build()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let batch = &batches[0];
    assert_eq!(batch.num_columns(), 90);
    assert_eq!(
        batch
            .column_by_name("flow_uid")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt64Array>()
            .unwrap()
            .value(0),
        flow.flow_uid
    );
    assert_eq!(
        batch
            .column_by_name("end_reason")
            .unwrap()
            .as_any()
            .downcast_ref::<StringArray>()
            .unwrap()
            .value(0),
        "end_of_capture"
    );
}

#[test]
fn original_names_are_rejected_for_minimal() {
    let output = tempfile::NamedTempFile::new().unwrap();
    let error = FlowsWriter::new(
        output.reopen().unwrap(),
        Format::Csv,
        Policy::Corrected,
        Preset::Minimal,
        ColumnNames::Original,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("original"));
    assert!(error.contains("cicflowmeter"));
}

fn one_flow(policy: Policy) -> Flow {
    let mut table = FlowTable::new(FlowConfig {
        policy,
        ..FlowConfig::default()
    });
    for (index, ts_ns, src, dst, sport, dport, flags) in [
        (
            0,
            1_700_000_000_000_000_000,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            0x02,
        ),
        (
            1,
            1_700_000_000_001_000_000,
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            80,
            1234,
            0x12,
        ),
    ] {
        let data = tcp_packet(src, dst, sport, dport, flags);
        let record = PacketRecord {
            index,
            ts_ns: Some(ts_ns),
            caplen: data.len() as u32,
            origlen: data.len() as u32,
            linktype: LinkType(1),
            interface: 0,
            data: &data,
        };
        let packet = decode(&data, record.linktype, DecodeDepth::L4);
        assert!(table.push(&record, &packet).is_empty());
    }
    table.finish().pop().unwrap()
}

fn tcp_packet(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8) -> Vec<u8> {
    let mut bytes = vec![0u8; 54];
    bytes[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    bytes[14] = 0x45;
    bytes[16..18].copy_from_slice(&40u16.to_be_bytes());
    bytes[22] = 64;
    bytes[23] = 6;
    bytes[26..30].copy_from_slice(&src);
    bytes[30..34].copy_from_slice(&dst);
    bytes[34..36].copy_from_slice(&sport.to_be_bytes());
    bytes[36..38].copy_from_slice(&dport.to_be_bytes());
    bytes[46] = 0x50;
    bytes[47] = flags;
    bytes
}

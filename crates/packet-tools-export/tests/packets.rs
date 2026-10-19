use std::{io::Read, path::PathBuf};

use arrow::array::{Array, BooleanArray, StringArray, UInt16Array, UInt32Array, UInt64Array};
use packet_tools_capture::Capture;
use packet_tools_dissect::{DecodeDepth, decode};
use packet_tools_export::packets::{Field, Format, PacketsWriter, parse_fields};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

#[test]
fn fixture_round_trips_all_columns_through_parquet() {
    let output = tempfile::NamedTempFile::new().unwrap();
    let mut writer =
        PacketsWriter::new(output.reopen().unwrap(), Format::Parquet, Field::ALL).unwrap();
    let mut capture = Capture::open(fixture("le_usec.pcap")).unwrap();
    while let Some(record) = capture.next_record() {
        let record = record.unwrap();
        let packet = decode(record.data, record.linktype, DecodeDepth::L4);
        writer.push(&record, &packet).unwrap();
    }
    writer.finish().unwrap();

    let batches = ParquetRecordBatchReaderBuilder::try_new(output.reopen().unwrap())
        .unwrap()
        .build()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        batches.iter().map(|batch| batch.num_rows()).sum::<usize>(),
        19
    );
    let batch = &batches[0];
    assert_eq!(batch.num_columns(), Field::ALL.len());
    assert_eq!(
        batch
            .column_by_name("index")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt64Array>()
            .unwrap()
            .value(17),
        17
    );
    assert_eq!(
        batch
            .column_by_name("vlan_id")
            .unwrap()
            .as_any()
            .downcast_ref::<UInt16Array>()
            .unwrap()
            .value(13),
        100
    );
    let src = batch
        .column_by_name("ip_src")
        .unwrap()
        .as_any()
        .downcast_ref::<StringArray>()
        .unwrap();
    assert_eq!(src.value(11), "2001:db8::1");
    let ports = batch
        .column_by_name("src_port")
        .unwrap()
        .as_any()
        .downcast_ref::<UInt16Array>()
        .unwrap();
    assert!(!ports.is_null(14));
    assert!(ports.is_null(15));
    let payload = batch
        .column_by_name("l4_payload_len")
        .unwrap()
        .as_any()
        .downcast_ref::<UInt32Array>()
        .unwrap();
    assert_eq!(payload.value(17), 4);
    let trailer = batch
        .column_by_name("trailer_len")
        .unwrap()
        .as_any()
        .downcast_ref::<UInt32Array>()
        .unwrap();
    assert_eq!(trailer.value(17), 14);
    let truncated = batch
        .column_by_name("ip_truncated")
        .unwrap()
        .as_any()
        .downcast_ref::<BooleanArray>()
        .unwrap();
    assert!(truncated.value(16));
}

#[test]
fn selected_csv_columns_have_exact_header_and_empty_nulls() {
    let output = tempfile::NamedTempFile::new().unwrap();
    let fields = parse_fields("index,ts_ns,src_port,ip_truncated").unwrap();
    let mut writer = PacketsWriter::new(output.reopen().unwrap(), Format::Csv, &fields).unwrap();
    let mut capture = Capture::open(fixture("le_usec.pcap")).unwrap();
    for _ in 0..2 {
        let record = capture.next_record().unwrap().unwrap();
        let packet = decode(record.data, record.linktype, DecodeDepth::L4);
        writer.push(&record, &packet).unwrap();
    }
    writer.finish().unwrap();
    let mut text = String::new();
    output.reopen().unwrap().read_to_string(&mut text).unwrap();
    let lines = text.lines().collect::<Vec<_>>();
    assert_eq!(lines[0], "index,ts_ns,src_port,ip_truncated");
    assert_eq!(lines[1], "0,1700000000000000000,49152,false");
}

#[test]
fn unknown_fields_list_every_available_name() {
    let error = parse_fields("index,no_such_column")
        .unwrap_err()
        .to_string();
    assert!(error.contains("no_such_column"));
    assert!(error.contains("index, ts_ns"));
    assert!(error.contains("malformed"));
}

#[test]
fn empty_csv_still_contains_the_selected_header() {
    let output = tempfile::NamedTempFile::new().unwrap();
    let fields = parse_fields("index,ip_src").unwrap();
    PacketsWriter::new(output.reopen().unwrap(), Format::Csv, &fields)
        .unwrap()
        .finish()
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(output.path()).unwrap(),
        "index,ip_src\n"
    );
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(name)
}

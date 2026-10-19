use std::net::{IpAddr, Ipv4Addr};

use arrow::array::StringArray;
use packet_tools_app::{AppEvent, AppOutput, Common, Direction, TelnetRow, Transport};
use packet_tools_export::{
    app::{AppWriter, write_app},
    packets::Format,
};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

#[test]
fn writes_all_app_tables_even_when_empty() {
    let directory = tempfile::tempdir().unwrap();
    write_app(directory.path(), Format::Csv, &AppOutput::default()).unwrap();
    for name in [
        "dns",
        "http",
        "tls",
        "tls_heartbeat",
        "ftp",
        "ssh",
        "smtp",
        "telnet",
        "dispatch",
    ] {
        let path = directory.path().join(format!("{name}.csv"));
        let contents = std::fs::read_to_string(path).unwrap();
        assert!(!contents.trim().is_empty(), "{name} has a header");
    }
    let dns = std::fs::read_to_string(directory.path().join("dns.csv")).unwrap();
    assert!(dns.starts_with("flow_uid,stream_id,index,ts_ns,direction,client_ip,server_ip,client_port,server_port,transport,"));
}

#[test]
fn incremental_csv_batches_match_one_shot_output() {
    let one_shot = tempfile::tempdir().unwrap();
    let incremental = tempfile::tempdir().unwrap();
    let common = Common {
        flow_uid: 7,
        stream_id: Some(3),
        index: 11,
        ts_ns: 22,
        direction: Direction::ClientToServer,
        client_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        server_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
        client_port: 50_000,
        server_port: 23,
        transport: Transport::Tcp,
    };
    let output = AppOutput {
        events: ["first", "second"]
            .into_iter()
            .map(|line| {
                AppEvent::Telnet(TelnetRow {
                    common: common.clone(),
                    kind: "line".into(),
                    negotiation: None,
                    line: Some(line.into()),
                    truncated: false,
                })
            })
            .collect(),
        dispatch: vec![],
    };
    write_app(one_shot.path(), Format::Csv, &output).unwrap();

    let mut writer = AppWriter::new(incremental.path(), Format::Csv).unwrap();
    writer.write_events(&output.events[..1]).unwrap();
    writer.write_events(&output.events[1..]).unwrap();
    writer.write_dispatch(&output.dispatch).unwrap();
    writer.close().unwrap();

    for name in [
        "dns",
        "http",
        "tls",
        "tls_heartbeat",
        "ftp",
        "ssh",
        "smtp",
        "telnet",
        "dispatch",
    ] {
        let expected = std::fs::read(one_shot.path().join(format!("{name}.csv"))).unwrap();
        let actual = std::fs::read(incremental.path().join(format!("{name}.csv"))).unwrap();
        assert_eq!(actual, expected, "{name}");
    }
}

#[test]
fn incremental_parquet_batches_preserve_rows_and_order() {
    let directory = tempfile::tempdir().unwrap();
    let common = Common {
        flow_uid: 7,
        stream_id: Some(3),
        index: 11,
        ts_ns: 22,
        direction: Direction::ClientToServer,
        client_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        server_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
        client_port: 50_000,
        server_port: 23,
        transport: Transport::Tcp,
    };
    let events = ["first", "second"]
        .into_iter()
        .map(|line| {
            AppEvent::Telnet(TelnetRow {
                common: common.clone(),
                kind: "line".into(),
                negotiation: None,
                line: Some(line.into()),
                truncated: false,
            })
        })
        .collect::<Vec<_>>();

    let mut writer = AppWriter::new(directory.path(), Format::Parquet).unwrap();
    writer.write_events(&events[..1]).unwrap();
    writer.write_events(&events[1..]).unwrap();
    writer.close().unwrap();

    let file = std::fs::File::open(directory.path().join("telnet.parquet")).unwrap();
    let batches = ParquetRecordBatchReaderBuilder::try_new(file)
        .unwrap()
        .build()
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(
        batches.iter().map(|batch| batch.num_rows()).sum::<usize>(),
        2
    );
    let lines = batches
        .iter()
        .flat_map(|batch| {
            batch
                .column_by_name("line")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap()
                .iter()
                .map(|value| value.unwrap().to_owned())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    assert_eq!(lines, ["first", "second"]);
}

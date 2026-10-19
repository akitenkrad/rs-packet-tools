use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use packet_tools_app::{AppAnalyzer, AppEvent, Protocol};
use packet_tools_reassembly::{
    CloseReason, ConnectionEnd, ConnectionStart, Direction, DirectionSummary, StreamChunk,
    StreamSource, TcpItem,
};

fn start() -> ConnectionStart {
    ConnectionStart {
        stream_id: 9,
        flow_uid: 77,
        client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        server_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        client_port: 50_000,
        server_port: 44_444,
        first_ts_ns: 1,
        midstream: false,
    }
}
fn data(direction: Direction, bytes: &[u8], index: u64) -> TcpItem {
    data_for(9, direction, bytes, index)
}
fn data_for(stream_id: u64, direction: Direction, bytes: &[u8], index: u64) -> TcpItem {
    TcpItem::Data(StreamChunk {
        stream_id,
        direction,
        position: 0,
        bytes: Arc::from(bytes),
        sources: Arc::from([StreamSource {
            offset: 0,
            len: bytes.len(),
            index,
            ts_ns: index as i64 * 10,
        }]),
    })
}

#[test]
fn dispatch_uses_payload_on_nonstandard_port_and_preserves_buffered_data() {
    let mut analyzer = AppAnalyzer::new(Protocol::ALL.to_vec());
    analyzer.consume(TcpItem::Start(start()));
    analyzer.consume(data(
        Direction::ClientToServer,
        b"GET /hidden HTTP/1.1\r\n",
        4,
    ));
    analyzer.consume(data(
        Direction::ClientToServer,
        b"Host: example.test\r\n\r\n",
        5,
    ));
    analyzer.consume(TcpItem::End(ConnectionEnd {
        stream_id: 9,
        reason: CloseReason::Fin,
        last_ts_ns: 99,
        directions: [DirectionSummary::default(), DirectionSummary::default()],
    }));
    let output = analyzer.finish();
    assert_eq!(output.dispatch.len(), 1);
    assert_eq!(output.dispatch[0].protocol, "http");
    assert_eq!(
        output.dispatch[0].probe_direction.as_deref(),
        Some("client_to_server")
    );
    assert!(output.events.iter().any(|event| matches!(event, AppEvent::Http(row) if row.uri.as_deref() == Some("/hidden") && row.common.index == 5)));
}

#[test]
fn unknown_stream_is_recorded_without_parsing() {
    let mut analyzer = AppAnalyzer::new(Protocol::ALL.to_vec());
    analyzer.consume(TcpItem::Start(start()));
    analyzer.consume(data(
        Direction::ClientToServer,
        &[1, 2, 3, 4, 5, 6, 7, 8, 9],
        4,
    ));
    let output = analyzer.finish();
    assert_eq!(output.dispatch[0].protocol, "unknown");
    assert!(output.events.is_empty());
}

#[test]
fn midstream_server_banner_corrects_the_endpoint_roles() {
    let mut analyzer = AppAnalyzer::new(vec![Protocol::Ftp]);
    let mut server_first = start();
    server_first.client_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    server_first.server_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    server_first.client_port = 21;
    server_first.server_port = 50_000;
    server_first.midstream = true;
    analyzer.consume(TcpItem::Start(server_first));
    analyzer.consume(data(Direction::ClientToServer, b"220 ready\r\n", 10));
    analyzer.consume(data(Direction::ServerToClient, b"USER alice\r\n", 11));
    let output = analyzer.finish();
    assert_eq!(output.dispatch[0].client_port, 50_000);
    assert_eq!(output.dispatch[0].server_port, 21);
    assert!(output.events.iter().any(|event| matches!(event, AppEvent::Ftp(row) if row.kind == "response" && row.common.direction == Direction::ServerToClient)));
    assert!(output.events.iter().any(|event| matches!(event, AppEvent::Ftp(row) if row.command.as_deref() == Some("USER") && row.common.direction == Direction::ClientToServer)));
}

#[test]
fn midstream_probe_keeps_waiting_in_the_other_direction_after_one_limit() {
    let mut analyzer = AppAnalyzer::new(vec![Protocol::Http]);
    let mut midstream = start();
    midstream.midstream = true;
    analyzer.consume(TcpItem::Start(midstream));
    analyzer.consume(data(Direction::ServerToClient, &vec![b'x'; 65_536], 10));
    analyzer.consume(data(
        Direction::ClientToServer,
        b"GET /later HTTP/1.1\r\nHost: update.test\r\n\r\n",
        11,
    ));

    let output = analyzer.finish();
    assert_eq!(output.dispatch[0].protocol, "http");
    assert_eq!(
        output.dispatch[0].probe_direction.as_deref(),
        Some("client_to_server")
    );
    assert!(
        output.events.iter().any(
            |event| matches!(event, AppEvent::Http(row) if row.uri.as_deref() == Some("/later"))
        )
    );
}

#[test]
fn dispatch_records_bytes_skipped_while_replaying_probe_data() {
    let mut analyzer = AppAnalyzer::new(vec![Protocol::Http]);
    let mut midstream = start();
    midstream.midstream = true;
    analyzer.consume(TcpItem::Start(midstream));
    analyzer.consume(data(
        Direction::ClientToServer,
        b"\0POST /after-keepalive HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
        12,
    ));

    let output = analyzer.finish();
    assert!(
        output.dispatch[0]
            .stop_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("skipped 1 byte"))
    );
}

#[test]
fn pending_probe_memory_limit_stops_the_oldest_stream_and_releases_storage() {
    let mut analyzer = AppAnalyzer::with_memory_limit(vec![Protocol::Http], 1_024);
    analyzer.consume(TcpItem::Start(start()));
    analyzer.consume(data(Direction::ServerToClient, &vec![b'x'; 2_048], 20));

    assert!(analyzer.estimated_buffer_memory_bytes() <= 1_024);
    let output = analyzer.finish();
    assert_eq!(output.dispatch[0].protocol, "unknown");
    assert_eq!(
        output.dispatch[0].stop_reason.as_deref(),
        Some("app memory limit exceeded before dispatch")
    );
}

#[test]
fn parser_memory_limit_discards_buffer_and_marks_resynchronization() {
    let mut analyzer = AppAnalyzer::with_memory_limit(vec![Protocol::Http], 1_024);
    analyzer.consume(TcpItem::Start(start()));
    analyzer.consume(data(
        Direction::ClientToServer,
        b"GET / HTTP/1.1\r\nHost: example.test\r\n",
        21,
    ));
    analyzer.consume(data(Direction::ClientToServer, &vec![b'x'; 2_048], 22));

    assert!(analyzer.estimated_buffer_memory_bytes() <= 1_024);
    let output = analyzer.finish();
    assert_eq!(output.dispatch[0].protocol, "http");
    assert!(
        output.dispatch[0]
            .stop_reason
            .as_deref()
            .is_some_and(|reason| reason.contains("app memory limit"))
    );
}

#[test]
fn memory_limit_evicts_the_oldest_buffered_stream_first() {
    let mut analyzer = AppAnalyzer::with_memory_limit(vec![Protocol::Http], 2_000);
    let first = start();
    let mut second = start();
    second.stream_id = 10;
    second.flow_uid = 78;
    second.client_port = 50_001;
    analyzer.consume(TcpItem::Start(first));
    analyzer.consume(data_for(9, Direction::ServerToClient, &vec![b'a'; 700], 30));
    analyzer.consume(TcpItem::Start(second));
    analyzer.consume(data_for(
        10,
        Direction::ServerToClient,
        &vec![b'b'; 700],
        31,
    ));

    let output = analyzer.finish();
    assert_eq!(
        output.dispatch[0].stop_reason.as_deref(),
        Some("app memory limit exceeded before dispatch")
    );
    assert_eq!(output.dispatch[1].stop_reason, None);
}

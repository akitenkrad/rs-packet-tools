use std::net::{IpAddr, Ipv4Addr};

use packet_tools_app::{
    AppChunk, AppEvent, AppParser, ByteSource, Confidence, DnsParser, FlowCtx, FtpParser,
    HttpParser, SmtpParser, SshParser, TelnetParser, TlsParser, Transport,
};
use packet_tools_reassembly::Direction;

fn context() -> FlowCtx {
    FlowCtx {
        flow_uid: 7,
        stream_id: Some(3),
        client_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        server_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
        client_port: 50_000,
        server_port: 44_444,
        transport: Transport::Tcp,
        midstream: false,
    }
}

fn feed(parser: &mut dyn AppParser, direction: Direction, bytes: &[u8], out: &mut Vec<AppEvent>) {
    parser.feed(
        direction,
        AppChunk {
            position: 0,
            bytes,
            sources: &[ByteSource {
                offset: 0,
                len: bytes.len(),
                index: 42,
                ts_ns: 123_000,
            }],
        },
        out,
    );
}

#[test]
fn dns_parses_compressed_answer_and_stops_pointer_loops() {
    let mut message = vec![
        0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 3, b'w', b'w', b'w', 7, b'e', b'x', b'a',
        b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0,
        0, 60, 0, 4, 192, 0, 2, 9,
    ];
    let mut parser = DnsParser::new(context(), false);
    let mut out = Vec::new();
    feed(&mut parser, Direction::ServerToClient, &message, &mut out);
    let AppEvent::Dns(row) = &out[0] else {
        panic!("DNS row")
    };
    assert_eq!(row.id, 0x1234);
    assert_eq!(row.qname.as_deref(), Some("www.example.com"));
    assert_eq!(row.answers, vec!["A 192.0.2.9"]);
    assert!(!row.malformed);
    assert_eq!((row.common.index, row.common.ts_ns), (42, 123_000));

    // The answer owner points to itself. Parsing must terminate and mark the row malformed.
    message[12] = 0xc0;
    message[13] = 0x0c;
    let mut parser = DnsParser::new(context(), false);
    let mut malformed = Vec::new();
    feed(
        &mut parser,
        Direction::ServerToClient,
        &message,
        &mut malformed,
    );
    let AppEvent::Dns(row) = &malformed[0] else {
        panic!("DNS row")
    };
    assert!(row.malformed);
}

#[test]
fn dns_probe_rejects_rip_payload_on_a_nonstandard_port() {
    let rip = [
        0x02, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0xc0, 0xa8, 0x01, 0x00,
        0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];
    let parser = DnsParser::new(context(), false);
    assert_eq!(
        parser.probe(&context(), Direction::ClientToServer, &rip),
        Confidence::No
    );

    let nbns = [
        0x80, 0x68, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, b'C', b'K',
        b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
        b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
        0x00, 0x00, 0x21, 0x00, 0x01,
    ];
    assert_eq!(
        parser.probe(&context(), Direction::ClientToServer, &nbns),
        Confidence::No
    );
}

#[test]
fn http_handles_pipeline_chunked_head_and_304() {
    let mut parser = HttpParser::new(context());
    let mut out = Vec::new();
    feed(
        &mut parser,
        Direction::ClientToServer,
        b"HEAD /a HTTP/1.1\r\nHost: example.test\r\n\r\nGET /b HTTP/1.1\r\nHost: example.test\r\n\r\n",
        &mut out,
    );
    feed(
        &mut parser,
        Direction::ServerToClient,
        b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\nHTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n",
        &mut out,
    );
    let rows = out
        .iter()
        .filter_map(|event| match event {
            AppEvent::Http(row) => Some(row),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 4);
    assert_eq!(
        rows.iter().map(|row| row.transaction).collect::<Vec<_>>(),
        [1, 2, 1, 2]
    );
    assert_eq!(rows[2].body_len, 0);
    assert_eq!(rows[3].body_len, 0);
}

#[test]
fn tls_records_cross_chunks_and_heartbeat_length_is_checked() {
    let mut parser = TlsParser::new(context());
    let record = [
        0x18, 0x03, 0x02, 0, 8, 1, 0, 10, b'a', b'b', b'c', b'd', b'e',
    ];
    let mut out = Vec::new();
    feed(
        &mut parser,
        Direction::ClientToServer,
        &record[..4],
        &mut out,
    );
    feed(
        &mut parser,
        Direction::ClientToServer,
        &record[4..],
        &mut out,
    );
    let heartbeat = out
        .iter()
        .find_map(|event| match event {
            AppEvent::TlsHeartbeat(row) => Some(row),
            _ => None,
        })
        .expect("heartbeat row");
    assert_eq!(heartbeat.record_length, 8);
    assert_eq!(heartbeat.heartbeat_type.as_deref(), Some("request"));
    assert_eq!(heartbeat.declared_payload_length, Some(10));
    assert!(heartbeat.length_mismatch);
}

#[test]
fn tls_server_hello_without_extensions_is_emitted_and_malformed_is_visible() {
    let mut parser = TlsParser::new(context());
    let mut hello = vec![0x03, 0x01];
    hello.extend_from_slice(&[0x11; 32]);
    hello.push(32);
    hello.extend_from_slice(&[0x22; 32]);
    hello.extend_from_slice(&[0x00, 0x2f, 0x00]);
    let mut record = vec![22, 0x03, 0x01, 0, (hello.len() + 4) as u8, 2, 0, 0];
    record.push(hello.len() as u8);
    record.extend_from_slice(&hello);

    let mut out = Vec::new();
    feed(&mut parser, Direction::ServerToClient, &record, &mut out);
    assert!(out.iter().any(|event| matches!(event, AppEvent::Tls(row)
        if row.kind == "server_hello"
            && row.selected_version == Some(0x0301)
            && row.selected_cipher == Some(0x002f)
            && row.extensions.is_empty())));

    let malformed = [22, 3, 1, 0, 8, 2, 0, 0, 4, 3, 1, 0, 0];
    feed(&mut parser, Direction::ServerToClient, &malformed, &mut out);
    assert!(
        out.iter()
            .any(|event| matches!(event, AppEvent::Tls(row) if row.kind == "malformed"))
    );
}

#[test]
fn line_protocols_parse_multiline_data_and_negotiation() {
    let mut ftp = FtpParser::new(context());
    let mut ftp_out = Vec::new();
    feed(
        &mut ftp,
        Direction::ServerToClient,
        b"220-first\r\nline\r\n220 ready\r\n",
        &mut ftp_out,
    );
    feed(
        &mut ftp,
        Direction::ClientToServer,
        b"USER alice\r\nPASS secret\r\n",
        &mut ftp_out,
    );
    feed(
        &mut ftp,
        Direction::ServerToClient,
        b"230 logged in\r\n",
        &mut ftp_out,
    );
    assert!(ftp_out.iter().any(|event| matches!(event, AppEvent::Ftp(row) if row.text.as_deref() == Some("first\nline\nready"))));
    assert!(ftp_out.iter().any(
        |event| matches!(event, AppEvent::Ftp(row) if row.login.as_deref() == Some("success"))
    ));

    let mut smtp = SmtpParser::new(context());
    let mut smtp_out = Vec::new();
    feed(
        &mut smtp,
        Direction::ClientToServer,
        b"EHLO host\r\nDATA\r\nhello\r\n..dot\r\n.\r\n",
        &mut smtp_out,
    );
    assert!(smtp_out.iter().any(|event| matches!(event, AppEvent::Smtp(row) if row.command.as_deref() == Some("DATA") && row.body_len == Some(14))));

    let mut telnet = TelnetParser::new(context());
    let mut telnet_out = Vec::new();
    for byte in b"login\r\n" {
        feed(
            &mut telnet,
            Direction::ClientToServer,
            &[*byte],
            &mut telnet_out,
        );
    }
    feed(
        &mut telnet,
        Direction::ServerToClient,
        &[255, 251, 1],
        &mut telnet_out,
    );
    assert!(telnet_out.iter().any(
        |event| matches!(event, AppEvent::Telnet(row) if row.line.as_deref() == Some("login"))
    ));
    assert!(telnet_out.iter().any(|event| matches!(event, AppEvent::Telnet(row) if row.negotiation.as_deref() == Some("IAC WILL 1"))));
}

#[test]
fn ssh_identification_and_kexinit_and_probes_work_off_standard_ports() {
    let ctx = context();
    let mut ssh = SshParser::new(ctx.clone());
    assert_eq!(
        ssh.probe(&ctx, Direction::ClientToServer, b"SSH-2.0-OpenSSH_9.9\r\n"),
        Confidence::Certain
    );
    let mut out = Vec::new();
    feed(
        &mut ssh,
        Direction::ClientToServer,
        b"SSH-2.0-OpenSSH_9.9 comment\r\n",
        &mut out,
    );
    assert!(out.iter().any(|event| matches!(event, AppEvent::Ssh(row) if row.software.as_deref() == Some("OpenSSH_9.9"))));

    let http = HttpParser::new(ctx.clone());
    assert_eq!(
        http.probe(&ctx, Direction::ClientToServer, b"GET / HTTP/1.1\r\n"),
        Confidence::Certain
    );
    let tls = TlsParser::new(ctx);
    assert_eq!(
        tls.probe(
            &context(),
            Direction::ClientToServer,
            &[22, 3, 3, 0, 4, 1, 0, 0, 0]
        ),
        Confidence::Certain
    );
}

#[test]
fn arbitrary_bytes_do_not_panic_any_parser() {
    for bytes in [Vec::new(), vec![0xff], (0..=255).collect::<Vec<_>>()] {
        let mut parsers: Vec<Box<dyn AppParser>> = vec![
            Box::new(DnsParser::new(context(), false)),
            Box::new(DnsParser::new(context(), true)),
            Box::new(HttpParser::new(context())),
            Box::new(TlsParser::new(context())),
            Box::new(FtpParser::new(context())),
            Box::new(SshParser::new(context())),
            Box::new(SmtpParser::new(context())),
            Box::new(TelnetParser::new(context())),
        ];
        for parser in &mut parsers {
            let mut out = Vec::new();
            feed(parser.as_mut(), Direction::ClientToServer, &bytes, &mut out);
            parser.gap(Direction::ClientToServer, 5, &mut out);
            parser.finish(&mut out);
        }
    }
}

#[test]
fn line_parser_discards_the_partial_line_after_a_gap() {
    let mut ftp = FtpParser::new(context());
    let mut out = Vec::new();
    feed(
        &mut ftp,
        Direction::ClientToServer,
        b"USER before",
        &mut out,
    );
    ftp.gap(Direction::ClientToServer, 20, &mut out);
    feed(
        &mut ftp,
        Direction::ClientToServer,
        b"missing-tail\r\nUSER after\r\n",
        &mut out,
    );
    assert!(!out.iter().any(|event| matches!(event, AppEvent::Ftp(row) if row.command.as_deref() == Some("MISSING-TAIL"))));
    assert!(out.iter().any(|event| matches!(event, AppEvent::Ftp(row) if row.command.as_deref() == Some("USER") && row.argument.as_deref() == Some("after"))));
}

#[test]
fn line_protocol_probe_and_parser_resume_at_a_later_line() {
    let ctx = context();
    let mut ftp = FtpParser::new(ctx.clone());
    let bytes = b"\0damaged\r\nUSER after\r\n";
    assert_eq!(
        ftp.probe(&ctx, Direction::ClientToServer, bytes),
        Confidence::Certain
    );
    let mut out = Vec::new();
    feed(&mut ftp, Direction::ClientToServer, bytes, &mut out);
    assert!(out.iter().any(|event| matches!(event, AppEvent::Ftp(row)
        if row.command.as_deref() == Some("USER") && row.argument.as_deref() == Some("after"))));
    assert!(out.iter().any(
        |event| matches!(event, AppEvent::Stopped { protocol, reason, .. }
        if protocol == "ftp" && reason.contains("skipped"))
    ));

    let smtp = SmtpParser::new(ctx.clone());
    assert_eq!(
        smtp.probe(
            &ctx,
            Direction::ClientToServer,
            b"damaged tail\r\nEHLO later.example\r\n"
        ),
        Confidence::Certain
    );
}

#[test]
fn http_midstream_skips_to_a_certain_start_line() {
    let mut ctx = context();
    ctx.midstream = true;
    let mut http = HttpParser::new(ctx);
    let mut out = Vec::new();
    feed(
        &mut http,
        Direction::ClientToServer,
        b"partial tail\r\nGET /resumed HTTP/1.1\r\nHost: example.test\r\n\r\n",
        &mut out,
    );
    assert!(out.iter().any(
        |event| matches!(event, AppEvent::Http(row) if row.uri.as_deref() == Some("/resumed"))
    ));
}

#[test]
fn http_resynchronizes_after_a_leading_keepalive_byte() {
    let mut ctx = context();
    ctx.midstream = true;
    let mut http = HttpParser::new(ctx);
    let mut out = Vec::new();
    feed(
        &mut http,
        Direction::ClientToServer,
        b"\0POST /resumed HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n",
        &mut out,
    );
    assert!(out.iter().any(
        |event| matches!(event, AppEvent::Http(row) if row.uri.as_deref() == Some("/resumed"))
    ));
    assert!(out.iter().any(
        |event| matches!(event, AppEvent::Stopped { protocol, reason, .. }
        if protocol == "http" && reason.contains("skipped 1 byte"))
    ));
}

#[test]
fn http_counts_close_delimited_response_without_retaining_it_as_a_new_header() {
    let mut http = HttpParser::new(context());
    let mut out = Vec::new();
    feed(
        &mut http,
        Direction::ClientToServer,
        b"GET /download HTTP/1.0\r\n\r\n",
        &mut out,
    );
    feed(
        &mut http,
        Direction::ServerToClient,
        b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nabc",
        &mut out,
    );
    feed(&mut http, Direction::ServerToClient, b"def", &mut out);
    assert_eq!(
        out.iter()
            .filter(|event| matches!(event, AppEvent::Http(_)))
            .count(),
        1
    );
    http.finish(&mut out);
    assert!(out.iter().any(
        |event| matches!(event, AppEvent::Http(row) if row.kind == "response" && row.body_len == 6)
    ));
}

#[test]
fn http_streams_a_large_fixed_body_and_parses_the_next_response() {
    let mut http = HttpParser::new(context());
    let mut out = Vec::new();
    feed(
        &mut http,
        Direction::ClientToServer,
        b"GET /large HTTP/1.1\r\n\r\nGET /next HTTP/1.1\r\n\r\n",
        &mut out,
    );
    feed(
        &mut http,
        Direction::ServerToClient,
        b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n",
        &mut out,
    );
    for _ in 0..100 {
        feed(
            &mut http,
            Direction::ServerToClient,
            &[b'x'; 1_000],
            &mut out,
        );
    }
    feed(
        &mut http,
        Direction::ServerToClient,
        b"HTTP/1.1 204 No Content\r\n\r\n",
        &mut out,
    );
    let responses = out
        .iter()
        .filter_map(|event| match event {
            AppEvent::Http(row) if row.kind == "response" => Some(row),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(responses.len(), 2);
    assert_eq!(responses[0].body_len, 100_000);
    assert_eq!(responses[1].status, Some(204));
    assert_eq!(responses[1].transaction, 2);
}

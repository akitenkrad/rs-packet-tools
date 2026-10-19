#![no_main]

use std::net::{IpAddr, Ipv4Addr};

use libfuzzer_sys::fuzz_target;
use packet_tools_app::{AppChunk, AppEvent, AppParser, ByteSource, DnsParser, FlowCtx, FtpParser, HttpParser, SmtpParser, SshParser, TelnetParser, TlsParser, Transport};
use packet_tools_reassembly::Direction;

fuzz_target!(|data: &[u8]| {
    let context = FlowCtx { flow_uid: 1, stream_id: Some(1), client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST), server_ip: IpAddr::V4(Ipv4Addr::new(127,0,0,2)), client_port: 40_000, server_port: 44_444, transport: Transport::Tcp, midstream: true };
    let mut parsers: Vec<Box<dyn AppParser>> = vec![Box::new(DnsParser::new(context.clone(),false)),Box::new(DnsParser::new(context.clone(),true)),Box::new(HttpParser::new(context.clone())),Box::new(TlsParser::new(context.clone())),Box::new(FtpParser::new(context.clone())),Box::new(SshParser::new(context.clone())),Box::new(SmtpParser::new(context.clone())),Box::new(TelnetParser::new(context))];
    let split=data.len()/2; let parts=[&data[..split],&data[split..]]; let mut events=Vec::<AppEvent>::new();
    for parser in &mut parsers { for (index,bytes) in parts.iter().enumerate() { let source=[ByteSource{offset:0,len:bytes.len(),index:index as u64,ts_ns:index as i64}]; parser.feed(if index==0{Direction::ClientToServer}else{Direction::ServerToClient},AppChunk{position:0,bytes,sources:&source},&mut events); } parser.gap(Direction::ClientToServer,1,&mut events); parser.finish(&mut events); events.clear(); }
});

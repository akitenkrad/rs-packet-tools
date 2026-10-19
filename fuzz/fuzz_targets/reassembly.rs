#![no_main]

use libfuzzer_sys::fuzz_target;
use packet_tools_capture::{LinkType, PacketRecord};
use packet_tools_dissect::{DecodeDepth, decode};
use packet_tools_reassembly::{DefragConfig, Defragmenter, TcpConfig, TcpReassembler};

fuzz_target!(|data: &[u8]| {
    let mut defrag = Defragmenter::new(DefragConfig {
        max_fragments: 32,
        max_datagram_bytes: 65_535,
        memory_limit: 1024 * 1024,
        ..DefragConfig::default()
    });
    let mut tcp = TcpReassembler::new(TcpConfig {
        stream_memory: 64 * 1024,
        memory_limit: 1024 * 1024,
        ..TcpConfig::default()
    });
    let mut cursor = 0usize;
    let mut index = 0u64;
    while cursor < data.len() {
        let width = usize::from(data[cursor]).saturating_add(1);
        cursor += 1;
        let end = cursor.saturating_add(width).min(data.len());
        let bytes = &data[cursor..end];
        cursor = end;
        let record = PacketRecord {
            index,
            ts_ns: Some(index as i64),
            caplen: bytes.len() as u32,
            origlen: bytes.len() as u32,
            linktype: LinkType(101),
            interface: 0,
            data: bytes,
        };
        let packet = decode(bytes, LinkType(101), DecodeDepth::L4);
        let output = defrag.push(&record, &packet);
        let _ = tcp.push(&record, &packet);
        for datagram in output.datagrams {
            let complete = PacketRecord {
                index,
                ts_ns: Some(index as i64),
                caplen: datagram.bytes.len() as u32,
                origlen: datagram.bytes.len() as u32,
                linktype: LinkType(101),
                interface: 0,
                data: &datagram.bytes,
            };
            let packet = decode(&datagram.bytes, LinkType(101), DecodeDepth::L4);
            let _ = tcp.push(&complete, &packet);
        }
        index += 1;
    }
    let _ = tcp.finish();
});

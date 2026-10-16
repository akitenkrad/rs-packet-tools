use std::{
    fs,
    io::{self, Cursor, Read},
};

use packet_tools_capture::{Capture, CaptureError};

const MIB: usize = 1024 * 1024;

#[derive(Debug, Eq, PartialEq)]
struct Packet {
    index: u64,
    ts_ns: Option<i64>,
    caplen: u32,
    origlen: u32,
    data: Vec<u8>,
}

#[test]
fn record_crossing_stream_buffer_end_matches_mmap() {
    let bytes = pcap(&[
        patterned(4 * MIB - 80, 0x11),
        patterned(257, 0x22),
        patterned(31, 0x33),
    ]);

    assert_streams_match_mmap(bytes);
}

#[test]
fn record_larger_than_initial_stream_capacity_matches_mmap() {
    let bytes = pcap(&[patterned(5 * MIB + 123, 0x44), patterned(97, 0x55)]);

    assert_streams_match_mmap(bytes);
}

#[test]
fn reader_returning_one_byte_at_a_time_matches_mmap() {
    let bytes = pcap(&[patterned(0, 0), patterned(1, 0x66), patterned(65_537, 0x77)]);
    let expected = read_mmap(&bytes);
    let actual = read_all(Capture::from_reader(OneByteReader::new(bytes)).unwrap());

    assert_eq!(actual, expected);
}

#[test]
fn stream_reads_directly_into_at_least_one_mibibyte_of_spare_capacity() {
    let bytes = pcap(&[patterned(128, 0x88)]);
    let capture = Capture::from_reader(LargeBufferReader::new(bytes)).unwrap();

    assert_eq!(read_all(capture).len(), 1);
}

#[test]
fn truncated_record_offset_stays_absolute_after_compaction() {
    let first = patterned(4 * MIB - 80, 0x99);
    let expected_offset = 24 + 16 + first.len();
    let mut bytes = pcap(&[first]);
    bytes.extend_from_slice(&[0; 8]);
    let mut capture = Capture::from_reader(Cursor::new(bytes)).unwrap();

    assert!(capture.next_record().unwrap().is_ok());
    assert!(matches!(
        capture.next_record(),
        Some(Err(CaptureError::TruncatedRecord { index: 1, offset }))
            if offset == expected_offset as u64
    ));
    assert!(capture.next_record().is_none());
}

fn assert_streams_match_mmap(bytes: Vec<u8>) {
    let expected = read_mmap(&bytes);
    let cursor = read_all(Capture::from_reader(Cursor::new(bytes)).unwrap());

    assert_eq!(cursor, expected);
}

fn read_mmap(bytes: &[u8]) -> Vec<Packet> {
    let file = tempfile::NamedTempFile::new().unwrap();
    fs::write(file.path(), bytes).unwrap();
    read_all(Capture::open(file.path()).unwrap())
}

fn read_all(mut capture: Capture) -> Vec<Packet> {
    let mut packets = Vec::new();
    while let Some(record) = capture.next_record() {
        let record = record.unwrap();
        packets.push(Packet {
            index: record.index,
            ts_ns: record.ts_ns,
            caplen: record.caplen,
            origlen: record.origlen,
            data: record.data.to_vec(),
        });
    }
    packets
}

fn pcap(payloads: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f, 1, 0,
        0, 0,
    ];
    for (index, payload) in payloads.iter().enumerate() {
        bytes.extend_from_slice(&(index as u32 + 1).to_le_bytes());
        bytes.extend_from_slice(&(index as u32).to_le_bytes());
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(payload);
    }
    bytes
}

fn patterned(length: usize, seed: u8) -> Vec<u8> {
    (0..length)
        .map(|index| seed.wrapping_add(index as u8))
        .collect()
}

struct OneByteReader {
    inner: Cursor<Vec<u8>>,
}

impl OneByteReader {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: Cursor::new(bytes),
        }
    }
}

impl Read for OneByteReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let length = buffer.len().min(1);
        self.inner.read(&mut buffer[..length])
    }
}

struct LargeBufferReader {
    inner: Cursor<Vec<u8>>,
    prefix_read: bool,
}

impl LargeBufferReader {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: Cursor::new(bytes),
            prefix_read: false,
        }
    }
}

impl Read for LargeBufferReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.prefix_read && buffer.len() < MIB {
            return Err(io::Error::other("stream read buffer is smaller than 1 MiB"));
        }
        self.prefix_read = true;
        self.inner.read(buffer)
    }
}

use std::{
    fs::File,
    io::{self, Read},
};

use memmap2::{Mmap, MmapOptions};

const STREAM_BUFFER_CAPACITY: usize = 4 * 1024 * 1024;
const STREAM_READ_SIZE: usize = 1024 * 1024;

pub(crate) enum Input {
    Mmap {
        data: Mmap,
        cursor: usize,
    },
    Stream {
        reader: Box<dyn Read + Send>,
        buffer: Vec<u8>,
        cursor: usize,
        filled: usize,
        base_offset: u64,
        eof: bool,
    },
}

impl Input {
    pub(crate) fn mmap(file: &File) -> io::Result<Self> {
        // SAFETY: The mapping is read-only. Capture's public documentation requires callers
        // not to modify the mapped file for the lifetime of the Capture.
        let data = unsafe { MmapOptions::new().map(file)? };
        Ok(Self::Mmap { data, cursor: 0 })
    }

    pub(crate) fn stream(reader: Box<dyn Read + Send>, prefix: Vec<u8>) -> Self {
        let filled = prefix.len();
        let mut buffer = vec![0; STREAM_BUFFER_CAPACITY.max(filled)];
        buffer[..filled].copy_from_slice(&prefix);
        Self::Stream {
            reader,
            buffer,
            cursor: 0,
            filled,
            base_offset: 0,
            eof: false,
        }
    }

    pub(crate) fn ensure(&mut self, required: usize) -> io::Result<bool> {
        match self {
            Self::Mmap { data, cursor } => Ok(data.len().saturating_sub(*cursor) >= required),
            Self::Stream {
                reader,
                buffer,
                cursor,
                filled,
                base_offset,
                eof,
            } => {
                while filled.saturating_sub(*cursor) < required && !*eof {
                    let available = filled.saturating_sub(*cursor);
                    let read_size = required.saturating_sub(available).max(STREAM_READ_SIZE);
                    let free = buffer.len().saturating_sub(*filled);
                    if free < read_size && *cursor > buffer.len() / 2 {
                        buffer.copy_within(*cursor..*filled, 0);
                        *filled -= *cursor;
                        *base_offset = base_offset.saturating_add(*cursor as u64);
                        *cursor = 0;
                    }
                    let required_storage = filled.saturating_add(read_size);
                    if buffer.len() < required_storage {
                        let grown = buffer.len().saturating_mul(2).max(required_storage);
                        buffer.resize(grown, 0);
                    }
                    let read = reader.read(&mut buffer[*filled..])?;
                    if read == 0 {
                        *eof = true;
                    } else {
                        *filled += read;
                    }
                }
                Ok(filled.saturating_sub(*cursor) >= required)
            }
        }
    }

    pub(crate) fn cursor(&self) -> usize {
        match self {
            Self::Mmap { cursor, .. } | Self::Stream { cursor, .. } => *cursor,
        }
    }

    pub(crate) fn offset(&self) -> u64 {
        match self {
            Self::Mmap { cursor, .. } => *cursor as u64,
            Self::Stream {
                cursor,
                base_offset,
                ..
            } => base_offset.saturating_add(*cursor as u64),
        }
    }

    pub(crate) fn advance(&mut self, count: usize) {
        match self {
            Self::Mmap { cursor, .. } | Self::Stream { cursor, .. } => *cursor += count,
        }
    }

    pub(crate) fn slice(&self, start: usize, end: usize) -> &[u8] {
        match self {
            Self::Mmap { data, .. } => &data[start..end],
            Self::Stream { buffer, .. } => &buffer[start..end],
        }
    }

    pub(crate) fn peek_array<const N: usize>(&self) -> [u8; N] {
        let start = self.cursor();
        self.slice(start, start + N)
            .try_into()
            .expect("ensure checked the requested byte count")
    }

    pub(crate) fn available_bytes(&self) -> &[u8] {
        let start = self.cursor();
        match self {
            Self::Mmap { data, .. } => &data[start..],
            Self::Stream { buffer, filled, .. } => &buffer[start..*filled],
        }
    }
}

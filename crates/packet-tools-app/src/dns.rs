use std::collections::BTreeSet;

use crate::{
    AppChunk, AppEvent, AppParser, Buffer, Confidence, Direction, DnsRow, FlowCtx, dir_index,
    utf8_lossy,
};

pub struct DnsParser {
    ctx: FlowCtx,
    tcp: bool,
    buffers: [Buffer; 2],
}

impl DnsParser {
    pub fn new(ctx: FlowCtx, tcp: bool) -> Self {
        Self {
            ctx,
            tcp,
            buffers: Default::default(),
        }
    }

    fn emit(&mut self, dir: Direction, out: &mut Vec<AppEvent>) {
        let buffer = &mut self.buffers[dir_index(dir)];
        loop {
            let available = buffer.available();
            let (prefix, length) = if self.tcp {
                if available.len() < 2 {
                    break;
                }
                (
                    2,
                    usize::from(u16::from_be_bytes([available[0], available[1]])),
                )
            } else {
                (0, available.len())
            };
            if available.len() < prefix + length || length == 0 {
                break;
            }
            let absolute_end = buffer.cursor + prefix + length;
            let source = buffer.source_at_end(absolute_end);
            let message = &available[prefix..prefix + length];
            let row = parse_message(&self.ctx, dir, source, message);
            out.push(AppEvent::Dns(row));
            buffer.consume(prefix + length);
            if !self.tcp {
                break;
            }
        }
    }
}

impl AppParser for DnsParser {
    fn name(&self) -> &'static str {
        "dns"
    }
    fn probe(&self, ctx: &FlowCtx, _dir: Direction, head: &[u8]) -> Confidence {
        let message = if self.tcp {
            if head.len() < 14 {
                return Confidence::Possible;
            }
            let len = usize::from(u16::from_be_bytes([head[0], head[1]]));
            if !(12..=65_535).contains(&len) {
                return Confidence::No;
            }
            if head.len() < len + 2 {
                return Confidence::Possible;
            }
            &head[2..len + 2]
        } else {
            head
        };
        if message.len() < 12 {
            return Confidence::Possible;
        }
        let flags = u16::from_be_bytes([message[2], message[3]]);
        let opcode = (flags >> 11) & 0x0f;
        let counts =
            [4, 6, 8, 10].map(|offset| u16::from_be_bytes([message[offset], message[offset + 1]]));
        let parsed = parse_message(ctx, Direction::ClientToServer, None, message);
        let meaningful = counts[0] > 0 || (flags & 0x8000 != 0 && counts[1] > 0);
        let plausible_question = counts[0] == 0
            || (parsed.qtype.unwrap_or_default() != 0
                && parsed.qclass.unwrap_or_default() != 0
                && parsed.qname.as_deref().is_some_and(|name| {
                    !name.is_empty()
                        && name.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric()
                                || matches!(byte, b'.' | b'-' | b'_' | b'*')
                        })
                }));
        let looks_like_nbns = parse_name(message, 12)
            .ok()
            .is_some_and(|(name, consumed)| {
                let kind_at = 12usize.saturating_add(consumed);
                let kind = message
                    .get(kind_at..kind_at + 2)
                    .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]));
                name.len() == 32
                    && !name.contains('.')
                    && name.bytes().all(|byte| (b'A'..=b'P').contains(&byte))
                    && matches!(kind, Some(0x20 | 0x21))
            });
        if opcode <= 6
            && meaningful
            && plausible_question
            && !looks_like_nbns
            && flags & 0x0040 == 0
            && counts.iter().copied().map(u32::from).sum::<u32>() <= 4096
            && !parsed.malformed
        {
            Confidence::Certain
        } else {
            Confidence::No
        }
    }
    fn feed(&mut self, dir: Direction, chunk: AppChunk<'_>, out: &mut Vec<AppEvent>) {
        self.buffers[dir_index(dir)].push(chunk);
        self.emit(dir, out);
    }
    fn gap(&mut self, dir: Direction, _len: u64, out: &mut Vec<AppEvent>) {
        self.buffers[dir_index(dir)].clear_for_gap();
        out.push(AppEvent::Stopped {
            common: self.ctx.common(dir, None),
            protocol: "dns".into(),
            reason: "gap".into(),
        });
    }
    fn allocated_bytes(&self) -> usize {
        self.buffers.iter().map(Buffer::allocated_bytes).sum()
    }
    fn release_buffered(&mut self) -> bool {
        self.buffers = Default::default();
        false
    }
}

fn parse_message(
    ctx: &FlowCtx,
    dir: Direction,
    source: Option<crate::ByteSource>,
    data: &[u8],
) -> DnsRow {
    let mut malformed = data.len() < 12;
    let get16 = |at: usize| {
        data.get(at..at + 2)
            .map(|v| u16::from_be_bytes([v[0], v[1]]))
            .unwrap_or(0)
    };
    let id = get16(0);
    let flags = get16(2);
    let qd = get16(4);
    let an = get16(6);
    let ns = get16(8);
    let ar = get16(10);
    let mut offset = 12usize;
    let mut qname = None;
    let mut qtype = None;
    let mut qclass = None;
    for index in 0..usize::from(qd) {
        match parse_name(data, offset) {
            Ok((name, consumed)) if offset.saturating_add(consumed + 4) <= data.len() => {
                offset += consumed;
                if index == 0 {
                    qname = Some(name);
                    qtype = Some(get16(offset));
                    qclass = Some(get16(offset + 2));
                }
                offset += 4;
            }
            _ => {
                malformed = true;
                break;
            }
        }
    }
    let mut answers = Vec::new();
    for section in 0..3 {
        let count = [an, ns, ar][section];
        for _ in 0..usize::from(count) {
            match parse_rr(data, offset) {
                Ok((next, value)) => {
                    if section == 0 {
                        answers.push(value);
                    }
                    offset = next;
                }
                Err(()) => {
                    malformed = true;
                    break;
                }
            }
        }
    }
    DnsRow {
        common: ctx.common(dir, source),
        id,
        is_response: flags & 0x8000 != 0,
        opcode: ((flags >> 11) & 0xf) as u8,
        rcode: (flags & 0xf) as u8,
        aa: flags & 0x0400 != 0,
        tc: flags & 0x0200 != 0,
        rd: flags & 0x0100 != 0,
        ra: flags & 0x0080 != 0,
        qname,
        qtype,
        qclass,
        question_count: qd,
        answer_count: an,
        authority_count: ns,
        additional_count: ar,
        answers,
        malformed,
    }
}

fn parse_name(data: &[u8], start: usize) -> Result<(String, usize), ()> {
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut consumed = 0;
    let mut jumped = false;
    let mut seen = BTreeSet::new();
    for _ in 0..128 {
        let length = *data.get(cursor).ok_or(())?;
        if length & 0xc0 == 0xc0 {
            let low = *data.get(cursor + 1).ok_or(())?;
            let pointer = usize::from((u16::from(length & 0x3f) << 8) | u16::from(low));
            if !jumped {
                consumed += 2;
            }
            if pointer >= data.len() || !seen.insert(pointer) {
                return Err(());
            }
            cursor = pointer;
            jumped = true;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(());
        }
        cursor += 1;
        if !jumped {
            consumed += 1;
        }
        if length == 0 {
            return Ok((labels.join("."), consumed));
        }
        let len = usize::from(length);
        let label = data.get(cursor..cursor + len).ok_or(())?;
        labels.push(utf8_lossy(label));
        cursor += len;
        if !jumped {
            consumed += len;
        }
    }
    Err(())
}

fn parse_rr(data: &[u8], start: usize) -> Result<(usize, String), ()> {
    let (_, name_len) = parse_name(data, start)?;
    let header = start + name_len;
    let h = data.get(header..header + 10).ok_or(())?;
    let kind = u16::from_be_bytes([h[0], h[1]]);
    let rdlen = usize::from(u16::from_be_bytes([h[8], h[9]]));
    let rstart = header + 10;
    let rend = rstart
        .checked_add(rdlen)
        .filter(|end| *end <= data.len())
        .ok_or(())?;
    let rdata = &data[rstart..rend];
    let value = match kind {
        1 if rdata.len() == 4 => format!("A {}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3]),
        28 if rdata.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            format!("AAAA {}", std::net::Ipv6Addr::from(octets))
        }
        2 | 5 | 12 => {
            let (name, _) = parse_name(data, rstart)?;
            format!("{} {}", rr_name(kind), name)
        }
        15 if rdata.len() >= 3 => {
            let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
            let (name, _) = parse_name(data, rstart + 2)?;
            format!("MX {pref} {name}")
        }
        16 => {
            let mut at = 0;
            let mut parts = Vec::new();
            while at < rdata.len() {
                let len = usize::from(rdata[at]);
                at += 1;
                let text = rdata.get(at..at + len).ok_or(())?;
                parts.push(utf8_lossy(text));
                at += len;
            }
            format!("TXT {}", parts.join(" "))
        }
        6 => {
            let (mname, a) = parse_name(data, rstart)?;
            let (rname, b) = parse_name(data, rstart + a)?;
            let nums = data.get(rstart + a + b..rstart + a + b + 20).ok_or(())?;
            let vals = nums
                .as_chunks::<4>()
                .0
                .iter()
                .map(|v| u32::from_be_bytes([v[0], v[1], v[2], v[3]]).to_string())
                .collect::<Vec<_>>();
            format!("SOA {mname} {rname} {}", vals.join(" "))
        }
        33 if rdata.len() >= 7 => {
            let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
            let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
            let port = u16::from_be_bytes([rdata[4], rdata[5]]);
            let (target, _) = parse_name(data, rstart + 6)?;
            format!("SRV {priority} {weight} {port} {target}")
        }
        _ => format!(
            "{} {}",
            rr_name(kind),
            rdata.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ),
    };
    Ok((rend, value))
}

fn rr_name(kind: u16) -> String {
    match kind {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        _ => return format!("TYPE{kind}"),
    }
    .into()
}

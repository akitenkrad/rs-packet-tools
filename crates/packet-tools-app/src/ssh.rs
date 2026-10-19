use crate::{
    AppChunk, AppEvent, AppParser, Buffer, Confidence, Direction, FlowCtx, SshRow, dir_index,
    utf8_lossy,
};

pub struct SshParser {
    ctx: FlowCtx,
    buffers: [Buffer; 2],
    identified: [bool; 2],
    kex_seen: [bool; 2],
}
impl SshParser {
    pub fn new(ctx: FlowCtx) -> Self {
        Self {
            ctx,
            buffers: Default::default(),
            identified: [false; 2],
            kex_seen: [false; 2],
        }
    }
    fn parse(&mut self, dir: Direction, out: &mut Vec<AppEvent>) {
        let index = dir_index(dir);
        if !self.identified[index] {
            loop {
                let Some(len) = self.buffers[index]
                    .available()
                    .iter()
                    .position(|b| *b == b'\n')
                    .map(|v| v + 1)
                else {
                    return;
                };
                let end = self.buffers[index].cursor + len;
                let source = self.buffers[index].source_at_end(end);
                let mut line = self.buffers[index].available()[..len].to_vec();
                self.buffers[index].consume(len);
                while matches!(line.last(), Some(b'\r' | b'\n')) {
                    line.pop();
                }
                if !line.starts_with(b"SSH-") {
                    continue;
                }
                let text = utf8_lossy(&line);
                let rest = text.strip_prefix("SSH-").unwrap_or(&text);
                let (proto, software_comments) = rest.split_once('-').unwrap_or((rest, ""));
                let (software, comments) = software_comments
                    .split_once(' ')
                    .map_or((software_comments, None), |(a, b)| (a, Some(b.to_owned())));
                out.push(AppEvent::Ssh(SshRow {
                    common: self.ctx.common(dir, source),
                    kind: "identification".into(),
                    proto_version: Some(proto.into()),
                    software: Some(software.into()),
                    comments,
                    kex_algorithms: vec![],
                    host_key_algorithms: vec![],
                    encryption_c2s: vec![],
                    encryption_s2c: vec![],
                    mac_c2s: vec![],
                    mac_s2c: vec![],
                    compression_c2s: vec![],
                    compression_s2c: vec![],
                }));
                self.identified[index] = true;
                break;
            }
        }
        while !self.kex_seen[index] {
            let data = self.buffers[index].available();
            if data.len() < 5 {
                break;
            }
            let packet_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
            if !(2..=35_000).contains(&packet_len) || data.len() < packet_len + 4 {
                break;
            }
            let padding = usize::from(data[4]);
            let payload_end = packet_len + 4 - padding;
            if payload_end <= 5 || payload_end > data.len() {
                self.kex_seen[index] = true;
                break;
            }
            let payload = &data[5..payload_end];
            let consumed = packet_len + 4;
            let absolute_end = self.buffers[index].cursor + consumed;
            let source = self.buffers[index].source_at_end(absolute_end);
            if payload.first() == Some(&20) {
                if let Some(lists) = parse_kexinit(payload) {
                    out.push(AppEvent::Ssh(SshRow {
                        common: self.ctx.common(dir, source),
                        kind: "kexinit".into(),
                        proto_version: None,
                        software: None,
                        comments: None,
                        kex_algorithms: lists[0].clone(),
                        host_key_algorithms: lists[1].clone(),
                        encryption_c2s: lists[2].clone(),
                        encryption_s2c: lists[3].clone(),
                        mac_c2s: lists[4].clone(),
                        mac_s2c: lists[5].clone(),
                        compression_c2s: lists[6].clone(),
                        compression_s2c: lists[7].clone(),
                    }));
                }
                self.kex_seen[index] = true;
            }
            self.buffers[index].consume(consumed);
        }
    }
}
impl AppParser for SshParser {
    fn name(&self) -> &'static str {
        "ssh"
    }
    fn probe(&self, _ctx: &FlowCtx, _dir: Direction, head: &[u8]) -> Confidence {
        if head.windows(4).any(|w| w == b"SSH-") {
            Confidence::Certain
        } else if head.len() < 255 {
            Confidence::Possible
        } else {
            Confidence::No
        }
    }
    fn feed(&mut self, dir: Direction, chunk: AppChunk<'_>, out: &mut Vec<AppEvent>) {
        self.buffers[dir_index(dir)].push(chunk);
        self.parse(dir, out);
    }
    fn gap(&mut self, dir: Direction, _len: u64, out: &mut Vec<AppEvent>) {
        self.buffers[dir_index(dir)].clear_for_gap();
        self.kex_seen[dir_index(dir)] = true;
        out.push(AppEvent::Stopped {
            common: self.ctx.common(dir, None),
            protocol: "ssh".into(),
            reason: "gap before encrypted transport".into(),
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

fn parse_kexinit(payload: &[u8]) -> Option<[Vec<String>; 8]> {
    if payload.len() < 17 || payload[0] != 20 {
        return None;
    }
    let mut cursor = 17;
    let mut all = Vec::new();
    for _ in 0..10 {
        let len_bytes = payload.get(cursor..cursor + 4)?;
        let len =
            u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]) as usize;
        cursor += 4;
        let value = payload.get(cursor..cursor + len)?;
        cursor += len;
        all.push(
            utf8_lossy(value)
                .split(',')
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        );
    }
    Some([
        all[0].clone(),
        all[1].clone(),
        all[2].clone(),
        all[3].clone(),
        all[4].clone(),
        all[5].clone(),
        all[6].clone(),
        all[7].clone(),
    ])
}

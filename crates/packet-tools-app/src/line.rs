use crate::{
    AppChunk, AppEvent, AppParser, Buffer, ByteSource, Confidence, Direction, FlowCtx, FtpRow,
    SmtpRow, TelnetRow, dir_index, utf8_lossy,
};

fn take_line(buffer: &mut Buffer) -> Option<(Vec<u8>, Option<ByteSource>)> {
    let len = buffer.available().iter().position(|byte| *byte == b'\n')? + 1;
    let end = buffer.cursor + len;
    let source = buffer.source_at_end(end);
    let mut line = buffer.available()[..len].to_vec();
    buffer.consume(len);
    while matches!(line.last(), Some(b'\n' | b'\r')) {
        line.pop();
    }
    Some((line, source))
}

fn recover_line(buffer: &mut Buffer, recovering: &mut bool) -> bool {
    if !*recovering {
        return true;
    }
    let Some(len) = buffer
        .available()
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|value| value + 1)
    else {
        return false;
    };
    buffer.consume(len);
    *recovering = false;
    true
}

fn probe_lines(head: &[u8]) -> impl Iterator<Item = &[u8]> {
    head.split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
}

fn valid_command(command: &str) -> bool {
    !command.is_empty()
        && command.len() <= 32
        && command
            .bytes()
            .all(|byte| byte.is_ascii_alphabetic() || byte == b'-')
}

pub struct FtpParser {
    ctx: FlowCtx,
    buffers: [Buffer; 2],
    multiline: Option<(u16, Vec<String>, Option<ByteSource>)>,
    login_pending: bool,
    recovering: [bool; 2],
}

impl FtpParser {
    pub fn new(ctx: FlowCtx) -> Self {
        Self {
            ctx,
            buffers: Default::default(),
            multiline: None,
            login_pending: false,
            recovering: [false; 2],
        }
    }
    fn parse(&mut self, dir: Direction, out: &mut Vec<AppEvent>) {
        let index = dir_index(dir);
        if !recover_line(&mut self.buffers[index], &mut self.recovering[index]) {
            return;
        }
        while let Some((line, source)) = take_line(&mut self.buffers[dir_index(dir)]) {
            let text = utf8_lossy(&line);
            if dir == Direction::ClientToServer {
                let (command, argument) = split_command(&text);
                if !valid_command(&command) {
                    out.push(AppEvent::Stopped {
                        common: self.ctx.common(dir, source),
                        protocol: "ftp".into(),
                        reason: format!("resynchronized; skipped {} bytes", line.len()),
                    });
                    continue;
                }
                let command = command.to_ascii_uppercase();
                if matches!(command.as_str(), "USER" | "PASS") {
                    self.login_pending = true;
                }
                out.push(AppEvent::Ftp(FtpRow {
                    common: self.ctx.common(dir, source),
                    kind: "command".into(),
                    command: Some(command),
                    argument,
                    code: None,
                    text: None,
                    login: None,
                }));
                continue;
            }
            if let Some((code, lines, last_source)) = &mut self.multiline {
                let terminator = format!("{code} ");
                lines.push(text.strip_prefix(&terminator).unwrap_or(&text).to_owned());
                *last_source = source;
                if text.starts_with(&terminator) {
                    let (code, lines, source) = self.multiline.take().expect("present");
                    self.emit_response(dir, code, lines.join("\n"), source, out);
                }
                continue;
            }
            let Some(code) = text.get(..3).and_then(|v| v.parse::<u16>().ok()) else {
                continue;
            };
            if text.as_bytes().get(3) == Some(&b'-') {
                self.multiline = Some((
                    code,
                    vec![text.get(4..).unwrap_or_default().to_owned()],
                    source,
                ));
            } else {
                self.emit_response(
                    dir,
                    code,
                    text.get(4..).unwrap_or_default().to_owned(),
                    source,
                    out,
                );
            }
        }
    }
    fn emit_response(
        &mut self,
        dir: Direction,
        code: u16,
        text: String,
        source: Option<ByteSource>,
        out: &mut Vec<AppEvent>,
    ) {
        let login = if self.login_pending && code == 230 {
            self.login_pending = false;
            Some("success".into())
        } else if self.login_pending && matches!(code, 430 | 530) {
            self.login_pending = false;
            Some("failure".into())
        } else {
            None
        };
        out.push(AppEvent::Ftp(FtpRow {
            common: self.ctx.common(dir, source),
            kind: "response".into(),
            command: None,
            argument: None,
            code: Some(code),
            text: Some(text),
            login,
        }));
    }
}

impl AppParser for FtpParser {
    fn name(&self) -> &'static str {
        "ftp"
    }
    fn probe(&self, ctx: &FlowCtx, _dir: Direction, head: &[u8]) -> Confidence {
        let ftp_cmd = [
            "USER ", "PASS ", "ACCT ", "CWD ", "PWD", "TYPE ", "PORT ", "PASV", "RETR ", "STOR ",
            "LIST", "QUIT",
        ];
        let command_match = probe_lines(head).any(|line| {
            let upper = utf8_lossy(line).to_ascii_uppercase();
            ftp_cmd.iter().any(|cmd| upper.starts_with(cmd))
        });
        let response_match = probe_lines(head).any(|line| {
            line.len() >= 4
                && line[..3].iter().all(u8::is_ascii_digit)
                && matches!(line[3], b' ' | b'-')
        }) && (ctx.client_port == 21 || ctx.server_port == 21);
        if command_match || response_match {
            Confidence::Certain
        } else if head.len() < 8 {
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
        self.recovering[dir_index(dir)] = true;
        self.multiline = None;
        out.push(AppEvent::Stopped {
            common: self.ctx.common(dir, None),
            protocol: "ftp".into(),
            reason: "gap; resuming at next line".into(),
        });
    }
    fn allocated_bytes(&self) -> usize {
        let multiline = self.multiline.as_ref().map_or(0, |(_, lines, _)| {
            lines
                .len()
                .saturating_mul(std::mem::size_of::<String>())
                .saturating_add(lines.iter().map(String::len).sum())
        });
        self.buffers
            .iter()
            .map(Buffer::allocated_bytes)
            .sum::<usize>()
            .saturating_add(multiline)
    }
    fn release_buffered(&mut self) -> bool {
        self.buffers = Default::default();
        self.multiline = None;
        self.recovering = [true; 2];
        true
    }
}

pub struct SmtpParser {
    ctx: FlowCtx,
    buffers: [Buffer; 2],
    data: bool,
    data_start_source: Option<ByteSource>,
    starttls_pending: bool,
    stopped: bool,
    recovering: [bool; 2],
}
impl SmtpParser {
    pub fn new(ctx: FlowCtx) -> Self {
        Self {
            ctx,
            buffers: Default::default(),
            data: false,
            data_start_source: None,
            starttls_pending: false,
            stopped: false,
            recovering: [false; 2],
        }
    }
    fn parse(&mut self, dir: Direction, out: &mut Vec<AppEvent>) {
        if self.stopped {
            return;
        }
        let index = dir_index(dir);
        if !recover_line(&mut self.buffers[index], &mut self.recovering[index]) {
            return;
        }
        loop {
            if dir == Direction::ClientToServer && self.data {
                let Some(end) = self.buffers[index]
                    .available()
                    .windows(5)
                    .position(|w| w == b"\r\n.\r\n")
                else {
                    break;
                };
                let body_len = end + 2;
                let consumed = end + 5;
                let absolute_end = self.buffers[index].cursor + consumed;
                let source = self.buffers[index]
                    .source_at_end(absolute_end)
                    .or(self.data_start_source);
                self.buffers[index].consume(consumed);
                self.data = false;
                out.push(AppEvent::Smtp(SmtpRow {
                    common: self.ctx.common(dir, source),
                    kind: "command".into(),
                    command: Some("DATA".into()),
                    argument: None,
                    code: None,
                    text: None,
                    body_len: Some(body_len as u64),
                }));
                continue;
            }
            let Some((line, source)) = take_line(&mut self.buffers[index]) else {
                break;
            };
            let text = utf8_lossy(&line);
            if dir == Direction::ClientToServer {
                let (command, argument) = smtp_command(&text);
                if !valid_command(command.split_whitespace().next().unwrap_or_default()) {
                    out.push(AppEvent::Stopped {
                        common: self.ctx.common(dir, source),
                        protocol: "smtp".into(),
                        reason: format!("resynchronized; skipped {} bytes", line.len()),
                    });
                    continue;
                }
                let command = command.to_ascii_uppercase();
                if command == "DATA" {
                    self.data = true;
                    self.data_start_source = source;
                    continue;
                }
                if command == "STARTTLS" {
                    self.starttls_pending = true;
                }
                out.push(AppEvent::Smtp(SmtpRow {
                    common: self.ctx.common(dir, source),
                    kind: "command".into(),
                    command: Some(command),
                    argument,
                    code: None,
                    text: None,
                    body_len: None,
                }));
            } else if let Some(code) = text.get(..3).and_then(|value| value.parse::<u16>().ok()) {
                out.push(AppEvent::Smtp(SmtpRow {
                    common: self.ctx.common(dir, source),
                    kind: "response".into(),
                    command: None,
                    argument: None,
                    code: Some(code),
                    text: Some(text.get(4..).unwrap_or_default().into()),
                    body_len: None,
                }));
                if self.starttls_pending && code == 220 {
                    self.stopped = true;
                    break;
                }
            }
        }
    }
}
impl AppParser for SmtpParser {
    fn name(&self) -> &'static str {
        "smtp"
    }
    fn probe(&self, ctx: &FlowCtx, _dir: Direction, head: &[u8]) -> Confidence {
        let commands = [
            "HELO ",
            "EHLO ",
            "MAIL FROM:",
            "RCPT TO:",
            "DATA\r",
            "AUTH ",
            "STARTTLS",
            "QUIT",
        ];
        let command_match = probe_lines(head).any(|line| {
            let upper = utf8_lossy(line).to_ascii_uppercase();
            commands.iter().any(|cmd| upper.starts_with(cmd))
        });
        let response_match = (ctx.client_port == 25
            || ctx.server_port == 25
            || ctx.client_port == 587
            || ctx.server_port == 587)
            && probe_lines(head)
                .any(|line| line.len() >= 4 && line[..3].iter().all(u8::is_ascii_digit));
        if command_match || response_match {
            Confidence::Certain
        } else if head.len() < 12 {
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
        self.recovering[dir_index(dir)] = true;
        self.data = false;
        out.push(AppEvent::Stopped {
            common: self.ctx.common(dir, None),
            protocol: "smtp".into(),
            reason: "gap; resuming at next line".into(),
        });
    }
    fn allocated_bytes(&self) -> usize {
        self.buffers.iter().map(Buffer::allocated_bytes).sum()
    }
    fn release_buffered(&mut self) -> bool {
        self.buffers = Default::default();
        self.data = false;
        self.data_start_source = None;
        self.recovering = [true; 2];
        true
    }
}

fn split_command(text: &str) -> (String, Option<String>) {
    match text.split_once(' ') {
        Some((a, b)) => (a.into(), Some(b.into())),
        None => (text.into(), None),
    }
}
fn smtp_command(text: &str) -> (String, Option<String>) {
    let upper = text.to_ascii_uppercase();
    for command in ["MAIL FROM", "RCPT TO"] {
        if upper.starts_with(command) {
            return (
                command.into(),
                text.get(command.len()..)
                    .map(|v| v.trim_start_matches([' ', ':']).to_owned())
                    .filter(|v| !v.is_empty()),
            );
        }
    }
    split_command(text)
}

#[derive(Clone, Copy)]
enum IacState {
    Data,
    Iac,
    Command(u8),
    Subnegotiation,
    SubIac,
}
struct TelnetDirection {
    line: Vec<u8>,
    line_source: Option<ByteSource>,
    state: IacState,
    truncated: bool,
}
impl Default for TelnetDirection {
    fn default() -> Self {
        Self {
            line: Vec::new(),
            line_source: None,
            state: IacState::Data,
            truncated: false,
        }
    }
}
pub struct TelnetParser {
    ctx: FlowCtx,
    directions: [TelnetDirection; 2],
    recovering: [bool; 2],
}
impl TelnetParser {
    pub fn new(ctx: FlowCtx) -> Self {
        Self {
            ctx,
            directions: Default::default(),
            recovering: [false; 2],
        }
    }
    fn emit_line(
        ctx: &FlowCtx,
        dir: Direction,
        state: &mut TelnetDirection,
        out: &mut Vec<AppEvent>,
    ) {
        if state.line.last() == Some(&b'\r') {
            state.line.pop();
        }
        let line = utf8_lossy(&state.line);
        out.push(AppEvent::Telnet(TelnetRow {
            common: ctx.common(dir, state.line_source),
            kind: "line".into(),
            negotiation: None,
            line: Some(line),
            truncated: state.truncated,
        }));
        state.line.clear();
        state.line_source = None;
        state.truncated = false;
    }
}
impl AppParser for TelnetParser {
    fn name(&self) -> &'static str {
        "telnet"
    }
    fn probe(&self, ctx: &FlowCtx, _dir: Direction, head: &[u8]) -> Confidence {
        let standard_port = ctx.client_port == 23 || ctx.server_port == 23;
        let negotiation = standard_port
            && head
                .windows(2)
                .any(|w| w[0] == 255 && matches!(w[1], 251..=254));
        let line = standard_port
            && head.iter().all(|b| b.is_ascii() || *b == 255)
            && head.contains(&b'\n');
        if negotiation || line {
            Confidence::Certain
        } else if head.len() < 16 {
            Confidence::Possible
        } else {
            Confidence::No
        }
    }
    fn feed(&mut self, dir: Direction, chunk: AppChunk<'_>, out: &mut Vec<AppEvent>) {
        let state = &mut self.directions[dir_index(dir)];
        for (offset, byte) in chunk.bytes.iter().copied().enumerate() {
            if self.recovering[dir_index(dir)] {
                if byte == b'\n' {
                    self.recovering[dir_index(dir)] = false;
                }
                continue;
            }
            let source = chunk
                .sources
                .iter()
                .find(|s| offset >= s.offset && offset < s.offset + s.len)
                .copied();
            match state.state {
                IacState::Data if byte == 255 => state.state = IacState::Iac,
                IacState::Data if byte == b'\n' => {
                    state.line_source = source;
                    Self::emit_line(&self.ctx, dir, state, out);
                }
                IacState::Data => {
                    if state.line.len() < 1024 {
                        state.line.push(byte);
                    } else {
                        state.truncated = true;
                        Self::emit_line(&self.ctx, dir, state, out);
                        state.line.push(byte);
                    }
                    state.line_source = source;
                }
                IacState::Iac if matches!(byte, 251..=254) => state.state = IacState::Command(byte),
                IacState::Iac if byte == 250 => state.state = IacState::Subnegotiation,
                IacState::Iac if byte == 255 => {
                    state.line.push(255);
                    state.state = IacState::Data;
                }
                IacState::Iac => state.state = IacState::Data,
                IacState::Command(command) => {
                    let name = match command {
                        251 => "WILL",
                        252 => "WONT",
                        253 => "DO",
                        254 => "DONT",
                        _ => "?",
                    };
                    out.push(AppEvent::Telnet(TelnetRow {
                        common: self.ctx.common(dir, source),
                        kind: "negotiation".into(),
                        negotiation: Some(format!("IAC {name} {byte}")),
                        line: None,
                        truncated: false,
                    }));
                    state.state = IacState::Data;
                }
                IacState::Subnegotiation if byte == 255 => state.state = IacState::SubIac,
                IacState::Subnegotiation => {}
                IacState::SubIac if byte == 240 => state.state = IacState::Data,
                IacState::SubIac => state.state = IacState::Subnegotiation,
            }
        }
    }
    fn gap(&mut self, dir: Direction, _len: u64, out: &mut Vec<AppEvent>) {
        self.directions[dir_index(dir)] = TelnetDirection::default();
        self.recovering[dir_index(dir)] = true;
        out.push(AppEvent::Stopped {
            common: self.ctx.common(dir, None),
            protocol: "telnet".into(),
            reason: "gap; resuming at next line".into(),
        });
    }
    fn finish(&mut self, out: &mut Vec<AppEvent>) {
        for dir in [Direction::ClientToServer, Direction::ServerToClient] {
            let state = &mut self.directions[dir_index(dir)];
            if !state.line.is_empty() {
                Self::emit_line(&self.ctx, dir, state, out);
            }
        }
    }
    fn allocated_bytes(&self) -> usize {
        self.directions
            .iter()
            .map(|direction| direction.line.len())
            .sum()
    }
    fn release_buffered(&mut self) -> bool {
        self.directions = Default::default();
        self.recovering = [true; 2];
        true
    }
}

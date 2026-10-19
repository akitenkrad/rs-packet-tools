use std::collections::VecDeque;

use crate::{
    AppChunk, AppEvent, AppParser, Buffer, ByteSource, Confidence, Direction, FlowCtx, HttpRow,
    dir_index,
};

pub struct HttpParser {
    ctx: FlowCtx,
    buffers: [Buffer; 2],
    next_transaction: u64,
    requests: VecDeque<(u64, String)>,
    recovering: [bool; 2],
    aligned: [bool; 2],
    search_skipped: [usize; 2],
    fixed: [Option<FixedBody>; 2],
    closing: [Option<ClosingResponse>; 2],
}

impl HttpParser {
    pub fn new(ctx: FlowCtx) -> Self {
        let aligned = [!ctx.midstream; 2];
        Self {
            ctx,
            buffers: Default::default(),
            next_transaction: 1,
            requests: VecDeque::new(),
            recovering: [false; 2],
            aligned,
            search_skipped: [0; 2],
            fixed: Default::default(),
            closing: Default::default(),
        }
    }

    fn parse_direction(&mut self, dir: Direction, out: &mut Vec<AppEvent>) {
        let recovery_index = dir_index(dir);
        if let Some(closing) = self.closing[recovery_index].as_mut() {
            let available = self.buffers[recovery_index].available().len();
            if available > 0 {
                let end = self.buffers[recovery_index].cursor + available;
                closing.source = self.buffers[recovery_index]
                    .source_at_end(end)
                    .or(closing.source);
                closing.parsed.body_len += available;
                self.buffers[recovery_index].consume(available);
            }
            return;
        }
        if self.recovering[recovery_index] {
            let Some(len) = self.buffers[recovery_index]
                .available()
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|value| value + 1)
            else {
                return;
            };
            self.buffers[recovery_index].consume(len);
            self.recovering[recovery_index] = false;
        }
        if !self.aligned[recovery_index] {
            let Some(offset) = http_start_offset(self.buffers[recovery_index].available()) else {
                let available = self.buffers[recovery_index].available().len();
                let partial = partial_http_start_offset(self.buffers[recovery_index].available());
                let retained = partial.map_or(64, |offset| available.saturating_sub(offset));
                let retain = if retained > 65_536 { 64 } else { retained };
                if available > retain {
                    let skipped = available - retain;
                    self.buffers[recovery_index].consume(skipped);
                    self.search_skipped[recovery_index] =
                        self.search_skipped[recovery_index].saturating_add(skipped);
                }
                return;
            };
            let skipped = self.search_skipped[recovery_index].saturating_add(offset);
            self.report_skip(dir, skipped, out);
            self.search_skipped[recovery_index] = 0;
            self.buffers[recovery_index].consume(offset);
            self.aligned[recovery_index] = true;
        }
        loop {
            let index = dir_index(dir);
            if let Some(fixed) = self.fixed[index].as_mut() {
                let available = self.buffers[index].available().len();
                let consumed = available.min(fixed.remaining);
                if consumed > 0 {
                    let absolute_end = self.buffers[index].cursor + consumed;
                    fixed.source = self.buffers[index]
                        .source_at_end(absolute_end)
                        .or(fixed.source);
                    fixed.parsed.body_len += consumed;
                    fixed.remaining -= consumed;
                    self.buffers[index].consume(consumed);
                }
                if fixed.remaining > 0 {
                    break;
                }
                let fixed = self.fixed[index].take().expect("fixed body is present");
                out.push(http_event(
                    &self.ctx,
                    dir,
                    fixed.transaction,
                    fixed.parsed,
                    fixed.source,
                ));
                continue;
            }
            let request = dir == Direction::ClientToServer;
            let head_method = (!request)
                .then(|| self.requests.front().map(|entry| entry.1.as_str()))
                .flatten();
            let Some((mut parsed, framing)) =
                parse_header(self.buffers[index].available(), request, head_method)
            else {
                let available = self.buffers[index].available();
                let complete_invalid = available.windows(4).any(|window| window == b"\r\n\r\n");
                let next = complete_invalid
                    .then(|| http_start_offset(available.get(1..).unwrap_or_default()))
                    .flatten()
                    .map(|offset| offset + 1);
                if let Some(skipped) = next {
                    self.report_skip(dir, skipped, out);
                    self.buffers[index].consume(skipped);
                    continue;
                }
                break;
            };
            let header_end = parsed.consumed;
            let absolute_header_end = self.buffers[index].cursor + header_end;
            let mut source = self.buffers[index].source_at_end(absolute_header_end);
            match framing {
                BodyFraming::None => {
                    let transaction = self.begin_transaction(request, &parsed);
                    self.buffers[index].consume(header_end);
                    out.push(http_event(&self.ctx, dir, transaction, parsed, source));
                }
                BodyFraming::Fixed(length) => {
                    let transaction = self.begin_transaction(request, &parsed);
                    self.buffers[index].consume(header_end);
                    self.fixed[index] = Some(FixedBody {
                        parsed,
                        transaction,
                        remaining: length,
                        source,
                    });
                }
                BodyFraming::Chunked => {
                    let Some((wire, decoded)) =
                        parse_chunked(&self.buffers[index].available()[header_end..])
                    else {
                        break;
                    };
                    let transaction = self.begin_transaction(request, &parsed);
                    let consumed = header_end + wire;
                    let absolute_end = self.buffers[index].cursor + consumed;
                    source = self.buffers[index].source_at_end(absolute_end).or(source);
                    parsed.body_len = decoded;
                    self.buffers[index].consume(consumed);
                    out.push(http_event(&self.ctx, dir, transaction, parsed, source));
                }
                BodyFraming::CloseDelimited => {
                    let transaction = self.begin_transaction(request, &parsed);
                    let available = self.buffers[index].available().len();
                    let absolute_end = self.buffers[index].cursor + available;
                    source = self.buffers[index].source_at_end(absolute_end).or(source);
                    parsed.body_len = available - header_end;
                    self.buffers[index].consume(available);
                    self.closing[index] = Some(ClosingResponse {
                        parsed,
                        transaction,
                        source,
                    });
                    break;
                }
            }
        }
    }

    fn begin_transaction(&mut self, request: bool, parsed: &Parsed) -> u64 {
        if request {
            let transaction = self.next_transaction;
            self.next_transaction += 1;
            self.requests
                .push_back((transaction, parsed.method.clone().unwrap_or_default()));
            transaction
        } else {
            let transaction = self.requests.front().map_or(0, |entry| entry.0);
            if !matches!(parsed.status, Some(100..=199)) {
                self.requests.pop_front();
            }
            transaction
        }
    }

    fn report_skip(&self, dir: Direction, skipped: usize, out: &mut Vec<AppEvent>) {
        if skipped == 0 {
            return;
        }
        out.push(AppEvent::Stopped {
            common: self.ctx.common(dir, None),
            protocol: "http".into(),
            reason: format!(
                "resynchronized; skipped {skipped} byte{}",
                if skipped == 1 { "" } else { "s" }
            ),
        });
    }
}

impl AppParser for HttpParser {
    fn name(&self) -> &'static str {
        "http"
    }
    fn probe(&self, _ctx: &FlowCtx, _dir: Direction, head: &[u8]) -> Confidence {
        if http_start_offset(head).is_some() {
            return Confidence::Certain;
        }
        if head.len() < 16 {
            Confidence::Possible
        } else {
            Confidence::No
        }
    }
    fn feed(&mut self, dir: Direction, chunk: AppChunk<'_>, out: &mut Vec<AppEvent>) {
        self.buffers[dir_index(dir)].push(chunk);
        self.parse_direction(dir, out);
    }
    fn gap(&mut self, dir: Direction, _len: u64, out: &mut Vec<AppEvent>) {
        let index = dir_index(dir);
        if let Some(closing) = self.closing[index].take() {
            out.push(http_event(
                &self.ctx,
                dir,
                closing.transaction,
                closing.parsed,
                closing.source,
            ));
        }
        let buffer = &mut self.buffers[index];
        buffer.clear_for_gap();
        self.fixed[index] = None;
        self.recovering[dir_index(dir)] = true;
        self.aligned[dir_index(dir)] = true;
        self.search_skipped[dir_index(dir)] = 0;
        out.push(AppEvent::Stopped {
            common: self.ctx.common(dir, None),
            protocol: "http".into(),
            reason: "gap; resuming at next message line".into(),
        });
    }
    fn finish(&mut self, out: &mut Vec<AppEvent>) {
        for dir in [Direction::ClientToServer, Direction::ServerToClient] {
            let index = dir_index(dir);
            if let Some(closing) = self.closing[index].take() {
                out.push(http_event(
                    &self.ctx,
                    dir,
                    closing.transaction,
                    closing.parsed,
                    closing.source,
                ));
            }
        }
    }
    fn allocated_bytes(&self) -> usize {
        let requests = self
            .requests
            .capacity()
            .saturating_mul(std::mem::size_of::<(u64, String)>())
            .saturating_add(
                self.requests
                    .iter()
                    .map(|(_, method)| method.capacity())
                    .sum(),
            );
        self.buffers
            .iter()
            .map(Buffer::allocated_bytes)
            .sum::<usize>()
            .saturating_add(requests)
            .saturating_add(
                self.fixed
                    .iter()
                    .flatten()
                    .map(|body| parsed_allocated_bytes(&body.parsed))
                    .sum(),
            )
            .saturating_add(
                self.closing
                    .iter()
                    .flatten()
                    .map(|body| parsed_allocated_bytes(&body.parsed))
                    .sum(),
            )
    }
    fn release_buffered(&mut self) -> bool {
        self.buffers = Default::default();
        self.requests = VecDeque::new();
        self.fixed = Default::default();
        self.closing = Default::default();
        self.recovering = [false; 2];
        self.aligned = [false; 2];
        self.search_skipped = [0; 2];
        true
    }
}

fn http_start_offset(data: &[u8]) -> Option<usize> {
    let mut line_offset = 0;
    for raw_line in data.split_inclusive(|byte| *byte == b'\n') {
        let raw_len = raw_line.len();
        let line = raw_line.strip_suffix(b"\n").unwrap_or(raw_line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let search = if line_offset == 0 {
            line.len().min(9)
        } else {
            1.min(line.len())
        };
        for at in 0..search {
            if looks_like_http_line(&line[at..]) {
                return Some(line_offset + at);
            }
        }
        line_offset += raw_len;
    }
    None
}

fn looks_like_http_line(line: &[u8]) -> bool {
    if line.starts_with(b"HTTP/1.0 ") || line.starts_with(b"HTTP/1.1 ") {
        return true;
    }
    let Some(space) = line.iter().take(33).position(|byte| *byte == b' ') else {
        return false;
    };
    let method = &line[..space];
    !method.is_empty()
        && method.len() <= 32
        && method
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || *byte == b'-')
        && line.windows(8).any(|window| window == b" HTTP/1.")
}

fn partial_http_start_offset(data: &[u8]) -> Option<usize> {
    let mut line_offset = 0;
    for raw_line in data.split_inclusive(|byte| *byte == b'\n') {
        let raw_len = raw_line.len();
        let line = raw_line.strip_suffix(b"\n").unwrap_or(raw_line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let search = if line_offset == 0 {
            line.len().min(9)
        } else {
            1.min(line.len())
        };
        for at in 0..search {
            let tail = &line[at..];
            if b"HTTP/1.".starts_with(tail) || tail.starts_with(b"HTTP/1.") {
                return Some(line_offset + at);
            }
            if let Some(space) = tail.iter().take(33).position(|byte| *byte == b' ') {
                let method = &tail[..space];
                if !method.is_empty()
                    && method
                        .iter()
                        .all(|byte| byte.is_ascii_uppercase() || *byte == b'-')
                {
                    return Some(line_offset + at);
                }
            }
        }
        line_offset += raw_len;
    }
    None
}

struct Parsed {
    consumed: usize,
    method: Option<String>,
    uri: Option<String>,
    version: Option<String>,
    host: Option<String>,
    user_agent: Option<String>,
    referer: Option<String>,
    content_type: Option<String>,
    content_length: Option<u64>,
    transfer_encoding: Option<String>,
    status: Option<u16>,
    reason: Option<String>,
    body_len: usize,
}

enum BodyFraming {
    None,
    Fixed(usize),
    Chunked,
    CloseDelimited,
}

struct FixedBody {
    parsed: Parsed,
    transaction: u64,
    remaining: usize,
    source: Option<ByteSource>,
}

struct ClosingResponse {
    parsed: Parsed,
    transaction: u64,
    source: Option<ByteSource>,
}

fn parsed_allocated_bytes(parsed: &Parsed) -> usize {
    [
        &parsed.method,
        &parsed.uri,
        &parsed.version,
        &parsed.host,
        &parsed.user_agent,
        &parsed.referer,
        &parsed.content_type,
        &parsed.transfer_encoding,
        &parsed.reason,
    ]
    .into_iter()
    .flatten()
    .map(String::capacity)
    .sum()
}

fn http_event(
    ctx: &FlowCtx,
    dir: Direction,
    transaction: u64,
    parsed: Parsed,
    source: Option<ByteSource>,
) -> AppEvent {
    AppEvent::Http(HttpRow {
        common: ctx.common(dir, source),
        transaction,
        kind: if dir == Direction::ClientToServer {
            "request"
        } else {
            "response"
        }
        .into(),
        method: parsed.method,
        uri: parsed.uri,
        version: parsed.version,
        host: parsed.host,
        user_agent: parsed.user_agent,
        referer: parsed.referer,
        content_type: parsed.content_type,
        content_length: parsed.content_length,
        transfer_encoding: parsed.transfer_encoding,
        status: parsed.status,
        reason: parsed.reason,
        body_len: parsed.body_len as u64,
    })
}

fn parse_header(
    data: &[u8],
    request: bool,
    request_method: Option<&str>,
) -> Option<(Parsed, BodyFraming)> {
    let header_end = data
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?
        .checked_add(4)?;
    let mut header_storage = [httparse::EMPTY_HEADER; 64];
    let (method, uri, version, status, reason, headers) = if request {
        let mut parsed = httparse::Request::new(&mut header_storage);
        parsed
            .parse(&data[..header_end])
            .ok()?
            .is_complete()
            .then_some(())?;
        (
            parsed.method.map(str::to_owned),
            parsed.path.map(str::to_owned),
            parsed.version.map(|v| format!("HTTP/1.{v}")),
            None,
            None,
            parsed.headers,
        )
    } else {
        let mut parsed = httparse::Response::new(&mut header_storage);
        parsed
            .parse(&data[..header_end])
            .ok()?
            .is_complete()
            .then_some(())?;
        (
            None,
            None,
            parsed.version.map(|v| format!("HTTP/1.{v}")),
            parsed.code,
            parsed.reason.map(str::to_owned),
            parsed.headers,
        )
    };
    let header = |name: &str| {
        headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| String::from_utf8_lossy(h.value).trim().to_owned())
    };
    let host = header("host");
    let user_agent = header("user-agent");
    let referer = header("referer");
    let content_type = header("content-type");
    let content_length = header("content-length").and_then(|value| value.parse::<u64>().ok());
    let transfer_encoding = header("transfer-encoding");
    let bodyless = !request
        && (request_method == Some("HEAD") || matches!(status, Some(100..=199 | 204 | 304)));
    let framing = if bodyless {
        BodyFraming::None
    } else if transfer_encoding.as_deref().is_some_and(|value| {
        value
            .split(',')
            .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
    }) {
        BodyFraming::Chunked
    } else if let Some(length) = content_length {
        BodyFraming::Fixed(usize::try_from(length).ok()?)
    } else if !request {
        BodyFraming::CloseDelimited
    } else {
        BodyFraming::None
    };
    Some((
        Parsed {
            consumed: header_end,
            method,
            uri,
            version,
            host,
            user_agent,
            referer,
            content_type,
            content_length,
            transfer_encoding,
            status,
            reason,
            body_len: 0,
        },
        framing,
    ))
}

fn parse_chunked(data: &[u8]) -> Option<(usize, usize)> {
    let mut cursor = 0;
    let mut decoded = 0;
    loop {
        let line_end = data[cursor..].windows(2).position(|w| w == b"\r\n")? + cursor;
        let size_text = std::str::from_utf8(&data[cursor..line_end])
            .ok()?
            .split(';')
            .next()?;
        let size = usize::from_str_radix(size_text.trim(), 16).ok()?;
        cursor = line_end + 2;
        if size == 0 {
            if data.get(cursor..cursor + 2) == Some(b"\r\n") {
                return Some((cursor + 2, decoded));
            }
            let trailers = data[cursor..].windows(4).position(|w| w == b"\r\n\r\n")?;
            return Some((cursor + trailers + 4, decoded));
        }
        if data.len() < cursor + size + 2
            || data.get(cursor + size..cursor + size + 2) != Some(b"\r\n")
        {
            return None;
        }
        decoded += size;
        cursor += size + 2;
    }
}

//! IPv4/IPv6 fragment reassembly and TCP stream reconstruction.

use std::{fmt, str::FromStr};

mod ip;
pub use ip::*;
mod tcp;
pub use tcp::*;

/// Target policy used to resolve overlapping IP fragments.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum IpPolicy {
    First,
    Last,
    #[default]
    Bsd,
    Linux,
    Windows,
    Solaris,
}

impl FromStr for IpPolicy {
    type Err = ParsePolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().replace('_', "-").as_str() {
            "first" => Ok(Self::First),
            "last" => Ok(Self::Last),
            "bsd" => Ok(Self::Bsd),
            "linux" => Ok(Self::Linux),
            "windows" => Ok(Self::Windows),
            "solaris" => Ok(Self::Solaris),
            _ => Err(ParsePolicyError(value.to_owned())),
        }
    }
}

/// Target policy used to resolve overlapping TCP segments.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TcpPolicy {
    First,
    Last,
    #[default]
    Bsd,
    Linux,
    OldLinux,
    Solaris,
}

impl FromStr for TcpPolicy {
    type Err = ParsePolicyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().replace('_', "-").as_str() {
            "first" | "vista" => Ok(Self::First),
            "last" => Ok(Self::Last),
            "bsd" | "windows" | "macos" | "hpux10" | "irix" => Ok(Self::Bsd),
            "linux" => Ok(Self::Linux),
            "old-linux" => Ok(Self::OldLinux),
            "solaris" | "hpux11" => Ok(Self::Solaris),
            _ => Err(ParsePolicyError(value.to_owned())),
        }
    }
}

/// An invalid overlap policy name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsePolicyError(String);

impl fmt::Display for ParsePolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unknown reassembly policy '{}'", self.0)
    }
}

impl std::error::Error for ParsePolicyError {}

/// Which input was retained for a conflicting overlap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedSide {
    Existing,
    New,
}

/// One contiguous overlapping range observed while inserting data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverlapEvent {
    pub offset: usize,
    pub len: usize,
    pub conflict: bool,
    pub retained: RetainedSide,
    pub previous_index: u64,
    pub new_index: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Span {
    start: usize,
    end: usize,
    packet_index: u64,
}

#[derive(Clone, Debug)]
struct Interval {
    start: usize,
    bytes: Vec<u8>,
    owner: Span,
}

impl Interval {
    fn end(&self) -> usize {
        self.start.saturating_add(self.bytes.len())
    }

    fn slice(&self, start: usize, end: usize) -> Self {
        Self {
            start,
            bytes: self.bytes[start - self.start..end - self.start].to_vec(),
            owner: self.owner,
        }
    }
}

/// Result of adding one IP fragment to a FragmentBuffer.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FragmentInsert {
    pub complete: Option<Vec<u8>>,
    pub events: Vec<OverlapEvent>,
}

/// Policy-aware IP fragment payload buffer.
///
/// This low-level type validates target policies independently of packet parsing.
#[derive(Clone, Debug)]
pub struct FragmentBuffer {
    policy: IpPolicy,
    intervals: Vec<Interval>,
    final_len: Option<usize>,
    overlaps: usize,
    conflicts: usize,
}

impl FragmentBuffer {
    pub fn new(policy: IpPolicy) -> Self {
        Self {
            policy,
            intervals: Vec::new(),
            final_len: None,
            overlaps: 0,
            conflicts: 0,
        }
    }

    pub fn insert(
        &mut self,
        offset: usize,
        more_fragments: bool,
        data: &[u8],
        packet_index: u64,
    ) -> FragmentInsert {
        let end = offset.saturating_add(data.len());
        if !more_fragments {
            self.final_len = Some(end);
        }
        let new_owner = Span {
            start: offset,
            end,
            packet_index,
        };
        let (intervals, events) = overlay_intervals(
            std::mem::take(&mut self.intervals),
            new_owner,
            data,
            0,
            |new, old| ip_new_wins(self.policy, new, old),
        );
        self.intervals = intervals;
        self.overlaps += events.len();
        self.conflicts += events.iter().filter(|event| event.conflict).count();

        let complete = self.final_len.and_then(|length| {
            let mut cursor = 0;
            for interval in &self.intervals {
                if interval.start > cursor {
                    return None;
                }
                cursor = cursor.max(interval.end());
                if cursor >= length {
                    let mut payload = Vec::with_capacity(length);
                    for interval in &self.intervals {
                        if interval.start >= length {
                            break;
                        }
                        let copy_end = interval.end().min(length);
                        payload.extend_from_slice(&interval.bytes[..copy_end - interval.start]);
                    }
                    return Some(payload);
                }
            }
            (length == 0).then(Vec::new)
        });
        FragmentInsert { complete, events }
    }

    pub fn overlap_count(&self) -> usize {
        self.overlaps
    }

    pub fn conflict_count(&self) -> usize {
        self.conflicts
    }

    /// Estimated heap allocation for payload and interval metadata.
    pub fn allocated_bytes(&self) -> usize {
        interval_allocated_bytes(&self.intervals)
    }

    /// Number of disjoint stored payload intervals.
    pub fn interval_count(&self) -> usize {
        self.intervals.len()
    }
}

fn ip_new_wins(policy: IpPolicy, new: Span, old: Span) -> bool {
    match policy {
        IpPolicy::First => false,
        IpPolicy::Last => true,
        IpPolicy::Bsd => new.start < old.start,
        IpPolicy::Linux => new.start <= old.start,
        IpPolicy::Windows => new.start < old.start && new.end > old.end,
        IpPolicy::Solaris => new.start < old.start && new.end >= old.end,
    }
}

/// Policy-aware TCP receive buffer anchored at a 32-bit initial sequence number.
#[derive(Clone, Debug)]
pub struct TcpSegmentBuffer {
    policy: TcpPolicy,
    pub(crate) isn: u32,
    intervals: Vec<Interval>,
    immutable_prefix: usize,
    end: usize,
    contiguous: usize,
    history_bytes: usize,
}

impl TcpSegmentBuffer {
    pub fn new(policy: TcpPolicy, isn: u32) -> Self {
        Self::with_history_bytes(policy, isn, 1024 * 1024)
    }

    pub(crate) fn with_history_bytes(policy: TcpPolicy, isn: u32, history_bytes: usize) -> Self {
        Self {
            policy,
            isn,
            intervals: Vec::new(),
            immutable_prefix: 0,
            end: 0,
            contiguous: 0,
            history_bytes,
        }
    }

    /// Inserts payload whose first byte has the supplied TCP sequence number.
    pub fn insert(&mut self, sequence: u32, data: &[u8], packet_index: u64) -> Vec<OverlapEvent> {
        let Some(start) = self.position(sequence) else {
            return Vec::new();
        };
        let end = start.saturating_add(data.len());
        self.end = self.end.max(end);
        let new_owner = Span {
            start,
            end,
            packet_index,
        };
        let (intervals, events) = overlay_intervals(
            std::mem::take(&mut self.intervals),
            new_owner,
            data,
            self.immutable_prefix,
            |new, old| tcp_new_wins(self.policy, new, old),
        );
        self.intervals = intervals;
        self.extend_contiguous();
        events
    }

    /// Renders the receive buffer from ISN+1, using the supplied byte for gaps.
    pub fn render(&self, length: usize, gap: u8) -> Vec<u8> {
        let mut rendered = vec![gap; length];
        for interval in &self.intervals {
            if interval.start >= length {
                break;
            }
            let end = interval.end().min(length);
            rendered[interval.start..end].copy_from_slice(&interval.bytes[..end - interval.start]);
        }
        rendered
    }

    pub(crate) fn len(&self) -> usize {
        self.end
    }

    pub(crate) fn set_immutable_prefix(&mut self, position: usize) {
        self.immutable_prefix = self.immutable_prefix.max(position);
        self.trim_history();
    }

    pub(crate) fn contiguous_len(&self) -> usize {
        self.contiguous
    }

    pub(crate) fn position(&self, sequence: u32) -> Option<usize> {
        let start = sequence.wrapping_sub(self.isn).wrapping_sub(1);
        (start <= i32::MAX as u32).then_some(start as usize)
    }

    pub(crate) fn release_storage(&mut self) {
        self.intervals = Vec::new();
    }

    /// Number of received bytes currently held by this interval buffer.
    pub fn buffered_bytes(&self) -> usize {
        self.intervals
            .iter()
            .map(|interval| interval.bytes.len())
            .sum()
    }

    pub(crate) fn next_present(&self, position: usize, end: usize) -> Option<usize> {
        self.intervals
            .iter()
            .find(|interval| interval.end() > position && interval.start < end)
            .map(|interval| interval.start.max(position))
    }

    pub(crate) fn data_at(&self, position: usize, end: usize) -> Option<(usize, Vec<u8>)> {
        let first = self
            .intervals
            .iter()
            .position(|interval| interval.start <= position && interval.end() > position)?;
        let mut cursor = position;
        let mut bytes = Vec::new();
        for interval in &self.intervals[first..] {
            if interval.start > cursor || cursor >= end {
                break;
            }
            let copy_end = interval.end().min(end);
            bytes.extend_from_slice(
                &interval.bytes[cursor.saturating_sub(interval.start)..copy_end - interval.start],
            );
            cursor = copy_end;
        }
        Some((cursor, bytes))
    }

    pub(crate) fn oldest_pending_end(&self, position: usize) -> Option<usize> {
        self.intervals
            .iter()
            .find(|interval| interval.end() > position)
            .map(Interval::end)
    }

    /// Estimated heap allocation for payload and interval metadata.
    pub fn allocated_bytes(&self) -> usize {
        interval_allocated_bytes(&self.intervals)
    }

    /// Number of disjoint stored payload intervals.
    pub fn interval_count(&self) -> usize {
        self.intervals.len()
    }

    pub(crate) fn drop_delivered_history(&mut self) {
        self.remove_before(self.immutable_prefix);
    }

    fn extend_contiguous(&mut self) {
        let mut cursor = self.contiguous;
        for interval in &self.intervals {
            if interval.end() <= cursor {
                continue;
            }
            if interval.start > cursor {
                break;
            }
            cursor = interval.end();
        }
        self.contiguous = cursor;
    }

    fn trim_history(&mut self) {
        self.remove_before(self.immutable_prefix.saturating_sub(self.history_bytes));
    }

    fn remove_before(&mut self, position: usize) {
        let mut kept = Vec::with_capacity(self.intervals.len());
        for interval in std::mem::take(&mut self.intervals) {
            if interval.end() <= position {
                continue;
            }
            if interval.start < position {
                kept.push(interval.slice(position, interval.end()));
            } else {
                kept.push(interval);
            }
        }
        kept.shrink_to_fit();
        self.intervals = kept;
    }
}

fn interval_allocated_bytes(intervals: &Vec<Interval>) -> usize {
    intervals.capacity() * std::mem::size_of::<Interval>()
        + intervals
            .iter()
            .map(|interval| interval.bytes.capacity())
            .sum::<usize>()
}

fn overlay_intervals(
    existing: Vec<Interval>,
    new_owner: Span,
    data: &[u8],
    immutable_prefix: usize,
    new_wins: impl Fn(Span, Span) -> bool,
) -> (Vec<Interval>, Vec<OverlapEvent>) {
    let mut output = Vec::with_capacity(existing.len().saturating_add(2));
    let mut events = Vec::new();
    let mut new_cursor = new_owner.start;

    for old in existing {
        let old_end = old.end();
        if old_end <= new_owner.start {
            push_interval(&mut output, old);
            continue;
        }
        if old.start >= new_owner.end {
            if new_cursor < new_owner.end {
                push_new_interval(&mut output, new_owner, data, new_cursor, new_owner.end);
                new_cursor = new_owner.end;
            }
            push_interval(&mut output, old);
            continue;
        }

        if old.start < new_owner.start {
            push_interval(&mut output, old.slice(old.start, new_owner.start));
        }
        if new_cursor < old.start {
            let gap_end = old.start.min(new_owner.end);
            let gap_start = new_cursor.max(immutable_prefix);
            if gap_start < gap_end {
                push_new_interval(&mut output, new_owner, data, gap_start, gap_end);
            }
            new_cursor = gap_end;
        }

        let overlap_start = old.start.max(new_owner.start);
        let overlap_end = old_end.min(new_owner.end);
        let policy_replaces = new_wins(new_owner, old.owner);
        let split = overlap_start.max(immutable_prefix).min(overlap_end);
        append_overlap(
            &mut output,
            &mut events,
            &old,
            new_owner,
            data,
            overlap_start..split,
            false,
        );
        append_overlap(
            &mut output,
            &mut events,
            &old,
            new_owner,
            data,
            split..overlap_end,
            policy_replaces,
        );
        new_cursor = new_cursor.max(overlap_end);

        if old_end > new_owner.end {
            push_interval(&mut output, old.slice(new_owner.end, old_end));
        }
    }

    let remaining_start = new_cursor.max(immutable_prefix);
    if remaining_start < new_owner.end {
        push_new_interval(&mut output, new_owner, data, remaining_start, new_owner.end);
    }
    (output, events)
}

fn append_overlap(
    output: &mut Vec<Interval>,
    events: &mut Vec<OverlapEvent>,
    old: &Interval,
    new_owner: Span,
    data: &[u8],
    range: std::ops::Range<usize>,
    replace: bool,
) {
    let start = range.start;
    let end = range.end;
    if start >= end {
        return;
    }
    let retained = if replace {
        RetainedSide::New
    } else {
        RetainedSide::Existing
    };
    for position in start..end {
        let old_byte = old.bytes[position - old.start];
        let new_byte = data[position - new_owner.start];
        push_event(
            events,
            position,
            old_byte != new_byte,
            retained,
            old.owner.packet_index,
            new_owner.packet_index,
        );
    }
    if replace {
        push_new_interval(output, new_owner, data, start, end);
    } else {
        push_interval(output, old.slice(start, end));
    }
}

fn push_new_interval(
    output: &mut Vec<Interval>,
    owner: Span,
    data: &[u8],
    start: usize,
    end: usize,
) {
    if start < end {
        push_interval(
            output,
            Interval {
                start,
                bytes: data[start - owner.start..end - owner.start].to_vec(),
                owner,
            },
        );
    }
}

fn push_interval(output: &mut Vec<Interval>, interval: Interval) {
    if interval.bytes.is_empty() {
        return;
    }
    if let Some(last) = output.last_mut()
        && last.end() == interval.start
        && last.owner == interval.owner
    {
        last.bytes.extend_from_slice(&interval.bytes);
    } else {
        output.push(interval);
    }
}

fn tcp_new_wins(policy: TcpPolicy, new: Span, old: Span) -> bool {
    match policy {
        TcpPolicy::First => false,
        TcpPolicy::Last => true,
        TcpPolicy::Bsd => new.start < old.start,
        TcpPolicy::Linux => new.start < old.start || (new.start == old.start && new.end > old.end),
        TcpPolicy::OldLinux => {
            new.start < old.start || (new.start == old.start && new.end >= old.end)
        }
        TcpPolicy::Solaris => {
            (new.start == old.start && new.end >= old.end)
                || (new.start < old.start && new.end >= old.end)
                || (new.start > old.start && new.end > old.end)
        }
    }
}

fn push_event(
    events: &mut Vec<OverlapEvent>,
    offset: usize,
    conflict: bool,
    retained: RetainedSide,
    previous_index: u64,
    new_index: u64,
) {
    if let Some(last) = events.last_mut()
        && last.offset + last.len == offset
        && last.conflict == conflict
        && last.retained == retained
        && last.previous_index == previous_index
    {
        last.len += 1;
        return;
    }
    events.push(OverlapEvent {
        offset,
        len: 1,
        conflict,
        retained,
        previous_index,
        new_index,
    });
}

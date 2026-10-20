//! IPv4/IPv6 fragment reassembly and TCP stream reconstruction.

use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    str::FromStr,
    sync::Arc,
};

use ahash::AHashMap;

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
    ts_ns: i64,
}

#[derive(Clone, Debug)]
struct Interval {
    start: usize,
    bytes: Arc<[u8]>,
    allocation_id: u64,
    data_start: usize,
    data_end: usize,
    owner: Span,
}

impl Interval {
    fn end(&self) -> usize {
        self.start.saturating_add(self.len())
    }

    fn len(&self) -> usize {
        self.data_end.saturating_sub(self.data_start)
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[self.data_start..self.data_end]
    }

    fn slice(&self, start: usize, end: usize) -> Self {
        Self {
            start,
            bytes: Arc::clone(&self.bytes),
            allocation_id: self.allocation_id,
            data_start: self.data_start + start - self.start,
            data_end: self.data_start + end - self.start,
            owner: self.owner,
        }
    }

    fn compact_backing(mut self, next_allocation_id: &mut u64) -> Self {
        if self.bytes.len() > self.len().saturating_mul(2) {
            self.bytes = Arc::from(self.as_slice());
            self.allocation_id = *next_allocation_id;
            *next_allocation_id = next_allocation_id.wrapping_add(1);
            self.data_start = 0;
            self.data_end = self.bytes.len();
        }
        self
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
    next_allocation_id: u64,
}

impl FragmentBuffer {
    pub fn new(policy: IpPolicy) -> Self {
        Self {
            policy,
            intervals: Vec::new(),
            final_len: None,
            overlaps: 0,
            conflicts: 0,
            next_allocation_id: 0,
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
            ts_ns: 0,
        };
        let allocation_id = self.next_allocation_id;
        self.next_allocation_id = self.next_allocation_id.wrapping_add(1);
        let (intervals, events) = overlay_intervals(
            std::mem::take(&mut self.intervals),
            new_owner,
            Arc::from(data),
            allocation_id,
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
                        payload
                            .extend_from_slice(&interval.as_slice()[..copy_end - interval.start]);
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

    /// Capacity-independent estimate of retained payload and interval metadata.
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
    intervals: BTreeMap<usize, Interval>,
    payload_refs: AHashMap<u64, (usize, usize)>,
    payload_bytes: usize,
    stored_bytes: usize,
    immutable_prefix: usize,
    end: usize,
    contiguous: usize,
    history_bytes: usize,
    next_allocation_id: u64,
}

impl TcpSegmentBuffer {
    pub fn new(policy: TcpPolicy, isn: u32) -> Self {
        Self::with_history_bytes(policy, isn, 1024 * 1024)
    }

    pub(crate) fn with_history_bytes(policy: TcpPolicy, isn: u32, history_bytes: usize) -> Self {
        Self {
            policy,
            isn,
            intervals: BTreeMap::new(),
            payload_refs: AHashMap::new(),
            payload_bytes: 0,
            stored_bytes: 0,
            immutable_prefix: 0,
            end: 0,
            contiguous: 0,
            history_bytes,
            next_allocation_id: 0,
        }
    }

    /// Inserts payload whose first byte has the supplied TCP sequence number.
    pub fn insert(&mut self, sequence: u32, data: &[u8], packet_index: u64) -> Vec<OverlapEvent> {
        self.insert_with_timestamp(sequence, data, packet_index, 0)
    }

    pub(crate) fn insert_with_timestamp(
        &mut self,
        sequence: u32,
        data: &[u8],
        packet_index: u64,
        ts_ns: i64,
    ) -> Vec<OverlapEvent> {
        let Some(start) = self.position(sequence) else {
            return Vec::new();
        };
        if data.is_empty() {
            return Vec::new();
        }
        let end = start.saturating_add(data.len());
        self.end = self.end.max(end);
        let new_owner = Span {
            start,
            end,
            packet_index,
            ts_ns,
        };
        let mut keys = Vec::new();
        if let Some((&key, interval)) = self.intervals.range(..=start).next_back()
            && interval.end() > start
        {
            keys.push(key);
        }
        let predecessor = keys.first().copied();
        keys.extend(
            self.intervals
                .range(start..end)
                .map(|(&key, _)| key)
                .filter(|key| predecessor != Some(*key)),
        );
        let mut overlapping = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(interval) = self.intervals.remove(&key) {
                self.uncharge(&interval);
                overlapping.push(interval);
            }
        }
        let allocation_id = self.next_allocation_id;
        self.next_allocation_id = self.next_allocation_id.wrapping_add(1);
        let (intervals, events) = overlay_intervals(
            overlapping,
            new_owner,
            Arc::from(data),
            allocation_id,
            self.immutable_prefix,
            |new, old| tcp_new_wins(self.policy, new, old),
        );
        for interval in intervals {
            self.insert_interval(interval);
        }
        self.extend_contiguous();
        events
    }

    /// Renders the receive buffer from ISN+1, using the supplied byte for gaps.
    pub fn render(&self, length: usize, gap: u8) -> Vec<u8> {
        let mut rendered = vec![gap; length];
        for interval in self.intervals.values() {
            if interval.start >= length {
                break;
            }
            let end = interval.end().min(length);
            rendered[interval.start..end]
                .copy_from_slice(&interval.as_slice()[..end - interval.start]);
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
        self.intervals = BTreeMap::new();
        self.payload_refs.clear();
        self.payload_bytes = 0;
        self.stored_bytes = 0;
    }

    /// Number of received bytes currently held by this interval buffer.
    pub fn buffered_bytes(&self) -> usize {
        self.stored_bytes
    }

    pub(crate) fn next_present(&self, position: usize, end: usize) -> Option<usize> {
        if let Some(interval) = self
            .intervals
            .range(..=position)
            .next_back()
            .map(|(_, interval)| interval)
            && interval.end() > position
        {
            return Some(position);
        }
        self.intervals
            .range(position..end)
            .next()
            .map(|(&start, _)| start)
    }

    pub(crate) fn data_at(
        &self,
        position: usize,
        end: usize,
    ) -> Option<(usize, Vec<u8>, Vec<crate::StreamSource>)> {
        let (&first, interval) = self.intervals.range(..=position).next_back()?;
        if interval.end() <= position {
            return None;
        }
        let mut cursor = position;
        let mut bytes = Vec::new();
        let mut sources: Vec<crate::StreamSource> = Vec::new();
        for interval in self.intervals.range(first..).map(|(_, interval)| interval) {
            if interval.start > cursor || cursor >= end {
                break;
            }
            let copy_end = interval.end().min(end);
            bytes.extend_from_slice(
                &interval.as_slice()
                    [cursor.saturating_sub(interval.start)..copy_end - interval.start],
            );
            let len = copy_end - cursor;
            if let Some(last) = sources.last_mut()
                && last.index == interval.owner.packet_index
                && last.ts_ns == interval.owner.ts_ns
                && last.offset + last.len == bytes.len() - len
            {
                last.len += len;
            } else {
                sources.push(crate::StreamSource {
                    offset: bytes.len() - len,
                    len,
                    index: interval.owner.packet_index,
                    ts_ns: interval.owner.ts_ns,
                });
            }
            cursor = copy_end;
        }
        Some((cursor, bytes, sources))
    }

    pub(crate) fn oldest_pending_end(&self, position: usize) -> Option<usize> {
        if let Some(interval) = self
            .intervals
            .range(..=position)
            .next_back()
            .map(|(_, interval)| interval)
            && interval.end() > position
        {
            return Some(interval.end());
        }
        self.intervals
            .range(position..)
            .next()
            .map(|(_, interval)| interval.end())
    }

    /// Capacity-independent estimate of retained payload and interval metadata.
    pub fn allocated_bytes(&self) -> usize {
        self.payload_bytes
            .saturating_add(self.intervals.len().saturating_mul(
                std::mem::size_of::<(usize, Interval)>() + 3 * std::mem::size_of::<usize>(),
            ))
            .saturating_add(
                self.payload_refs
                    .len()
                    .saturating_mul(std::mem::size_of::<(u64, (usize, usize))>()),
            )
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
        while let Some(interval) = self
            .intervals
            .range(..=cursor)
            .next_back()
            .map(|(_, interval)| interval)
        {
            if interval.end() <= cursor {
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
        let keys = self
            .intervals
            .range(..position)
            .map(|(&key, _)| key)
            .collect::<Vec<_>>();
        let mut tail = None;
        for key in keys {
            let interval = self.intervals.remove(&key).expect("collected key");
            self.uncharge(&interval);
            if interval.end() > position {
                tail = Some(
                    interval
                        .slice(position, interval.end())
                        .compact_backing(&mut self.next_allocation_id),
                );
            }
        }
        if let Some(interval) = tail {
            self.insert_interval(interval);
        }
    }

    fn insert_interval(&mut self, interval: Interval) {
        if interval.len() == 0 {
            return;
        }
        self.charge(&interval);
        let replaced = self.intervals.insert(interval.start, interval);
        debug_assert!(replaced.is_none());
    }

    fn charge(&mut self, interval: &Interval) {
        self.stored_bytes = self.stored_bytes.saturating_add(interval.len());
        let entry = self
            .payload_refs
            .entry(interval.allocation_id)
            .or_insert((interval.bytes.len(), 0));
        if entry.1 == 0 {
            self.payload_bytes = self.payload_bytes.saturating_add(entry.0);
        }
        entry.1 += 1;
    }

    fn uncharge(&mut self, interval: &Interval) {
        self.stored_bytes = self.stored_bytes.saturating_sub(interval.len());
        let key = interval.allocation_id;
        let remove = if let Some(entry) = self.payload_refs.get_mut(&key) {
            entry.1 -= 1;
            if entry.1 == 0 {
                self.payload_bytes = self.payload_bytes.saturating_sub(entry.0);
                true
            } else {
                false
            }
        } else {
            false
        };
        if remove {
            self.payload_refs.remove(&key);
        }
    }

    #[cfg(test)]
    fn backing_allocation_count(&self) -> usize {
        self.payload_refs.len()
    }
}

fn interval_allocated_bytes(intervals: &[Interval]) -> usize {
    let mut seen = HashSet::new();
    std::mem::size_of_val(intervals)
        + intervals
            .iter()
            .filter(|interval| seen.insert(interval.allocation_id))
            .map(|interval| interval.bytes.len())
            .sum::<usize>()
}

fn overlay_intervals(
    existing: Vec<Interval>,
    new_owner: Span,
    data: Arc<[u8]>,
    allocation_id: u64,
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
                push_new_interval(
                    &mut output,
                    new_owner,
                    &data,
                    allocation_id,
                    new_cursor,
                    new_owner.end,
                );
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
                push_new_interval(
                    &mut output,
                    new_owner,
                    &data,
                    allocation_id,
                    gap_start,
                    gap_end,
                );
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
            NewInterval {
                owner: new_owner,
                data: &data,
                allocation_id,
            },
            overlap_start..split,
            false,
        );
        append_overlap(
            &mut output,
            &mut events,
            &old,
            NewInterval {
                owner: new_owner,
                data: &data,
                allocation_id,
            },
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
        push_new_interval(
            &mut output,
            new_owner,
            &data,
            allocation_id,
            remaining_start,
            new_owner.end,
        );
    }
    (output, events)
}

fn append_overlap(
    output: &mut Vec<Interval>,
    events: &mut Vec<OverlapEvent>,
    old: &Interval,
    new: NewInterval<'_>,
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
        let old_byte = old.as_slice()[position - old.start];
        let new_byte = new.data[position - new.owner.start];
        push_event(
            events,
            position,
            old_byte != new_byte,
            retained,
            old.owner.packet_index,
            new.owner.packet_index,
        );
    }
    if replace {
        push_new_interval(output, new.owner, new.data, new.allocation_id, start, end);
    } else {
        push_interval(output, old.slice(start, end));
    }
}

#[derive(Clone, Copy)]
struct NewInterval<'a> {
    owner: Span,
    data: &'a Arc<[u8]>,
    allocation_id: u64,
}

fn push_new_interval(
    output: &mut Vec<Interval>,
    owner: Span,
    data: &Arc<[u8]>,
    allocation_id: u64,
    start: usize,
    end: usize,
) {
    if start < end {
        push_interval(
            output,
            Interval {
                start,
                bytes: Arc::clone(data),
                allocation_id,
                data_start: start - owner.start,
                data_end: end - owner.start,
                owner,
            },
        );
    }
}

fn push_interval(output: &mut Vec<Interval>, interval: Interval) {
    if interval.len() == 0 {
        return;
    }
    if let Some(last) = output.last_mut()
        && last.end() == interval.start
        && last.owner == interval.owner
        && last.allocation_id == interval.allocation_id
        && last.data_end == interval.data_start
    {
        last.data_end = interval.data_end;
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

#[cfg(test)]
mod tcp_storage_tests {
    use super::{FragmentBuffer, IpPolicy, TcpPolicy, TcpSegmentBuffer};

    #[test]
    fn overlap_splits_share_the_original_payload_allocation() {
        let mut buffer = TcpSegmentBuffer::new(TcpPolicy::Last, 0);
        buffer.insert(1, &vec![b'a'; 64 * 1024], 1);
        buffer.insert(16 * 1024 + 1, &vec![b'b'; 4 * 1024], 2);

        assert_eq!(buffer.interval_count(), 3);
        assert_eq!(buffer.backing_allocation_count(), 2);
        assert_eq!(buffer.buffered_bytes(), 64 * 1024);
    }

    #[test]
    fn memory_estimates_ignore_spare_container_capacity() {
        let mut fragments = FragmentBuffer::new(IpPolicy::First);
        fragments.insert(0, true, b"fragment", 1);
        let fragment_bytes = fragments.allocated_bytes();
        fragments.intervals.reserve(1_024);
        assert_eq!(fragments.allocated_bytes(), fragment_bytes);

        let mut stream = TcpSegmentBuffer::new(TcpPolicy::First, 0);
        stream.insert(1, b"segment", 1);
        let stream_bytes = stream.allocated_bytes();
        stream.payload_refs.reserve(1_024);
        assert_eq!(stream.allocated_bytes(), stream_bytes);
    }
}

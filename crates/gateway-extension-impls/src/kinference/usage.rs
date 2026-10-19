//! Bounded capture of a completion response for `ReportFinalToken`:
//! model from the head, usage from the tail, chunk-arrival gaps
//! bucketed. Raw scans over capped bytes work for SSE and plain
//! JSON alike; the body is never retained beyond the caps.

use std::time::Instant;

/// The model always appears in the response's opening bytes.
const HEAD_CAP: usize = 2 * 1024;
/// The usage object rides at or near the end.
const TAIL_CAP: usize = 64 * 1024;

/// Bounded head + rolling tail of the response body.
#[derive(Default)]
pub(crate) struct Capture {
    head: Vec<u8>,
    tail: Vec<u8>,
}

impl Capture {
    pub(crate) fn feed(&mut self, chunk: &[u8]) {
        if self.head.len() < HEAD_CAP {
            let room = HEAD_CAP - self.head.len();
            self.head.extend_from_slice(&chunk[..chunk.len().min(room)]);
        }
        self.tail.extend_from_slice(chunk);
        if self.tail.len() > TAIL_CAP {
            let drain = self.tail.len() - TAIL_CAP;
            self.tail.drain(0..drain);
        }
    }

    /// The served model, `""` when none was found in the head.
    pub(crate) fn model(&self) -> String {
        extract_model(&self.head).unwrap_or_default()
    }

    pub(crate) fn prompt_tokens(&self) -> Option<u64> {
        extract_usage_uint(&self.tail, "prompt_tokens")
    }

    pub(crate) fn completion_tokens(&self) -> Option<u64> {
        extract_usage_uint(&self.tail, "completion_tokens")
    }

    /// Cached prompt tokens, reported under `prompt_tokens_details`
    /// by providers that serve a prefix from cache; absent otherwise.
    pub(crate) fn cached_tokens(&self) -> Option<u64> {
        extract_usage_uint(&self.tail, "cached_tokens")
    }
}

/// First `"model": "…"` in the head. Best-effort scan — the head is
/// usually a truncated document.
fn extract_model(head: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(head);
    let mut from = 0;
    while let Some(rel) = text[from..].find("\"model\"") {
        let after = from + rel + "\"model\"".len();
        let rest = text[after..].trim_start();
        if let Some(rest) = rest.strip_prefix(':') {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('"')
                && let Some(end) = rest.find('"')
            {
                let val = &rest[..end];
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
        from = after;
    }
    None
}

/// An integer `usage` field out of the tail, anchored on the last
/// `"usage"`. The quoted needle keeps `prompt_tokens` from matching
/// `prompt_tokens_details`.
fn extract_usage_uint(tail: &[u8], field: &str) -> Option<u64> {
    let text = String::from_utf8_lossy(tail);
    let start = text.rfind("\"usage\"").unwrap_or(0);
    let hay = &text[start..];
    let needle = format!("\"{field}\"");
    let mut last = None;
    let mut from = 0;
    while let Some(rel) = hay[from..].find(&needle) {
        let after = from + rel + needle.len();
        if let Some(n) = parse_first_uint(&hay[after..]) {
            last = Some(n);
        }
        from = after;
    }
    last
}

/// The first unsigned integer in `s`, past a leading `:` and spaces.
fn parse_first_uint(s: &str) -> Option<u64> {
    let mut seen_digit = false;
    let mut acc: u64 = 0;
    for c in s.chars() {
        if c.is_ascii_digit() {
            seen_digit = true;
            acc = acc
                .saturating_mul(10)
                .saturating_add(u64::from(c as u8 - b'0'));
        } else if seen_digit {
            break;
        } else if c != ':' && !c.is_whitespace() {
            return None;
        }
    }
    seen_digit.then_some(acc)
}

/// Upper edges of ITL bucket layout 1 (ms); past the last edge is
/// the overflow bucket.
const EDGES_MS: [u128; 14] = [5, 10, 15, 20, 30, 40, 50, 75, 100, 150, 200, 300, 500, 1000];

/// Layout-1 identifier for `ReportFinalTokenRequest.itl_bucket_layout`.
pub(crate) const ITL_LAYOUT: u32 = 1;

/// Response-chunk arrival gaps, bucketed per layout 1 — the
/// measurable stand-in for inter-token latency. A chunk carries one
/// token when the upstream flushes per token; under batching it
/// carries several whose gaps go unseen, so the histogram reports
/// fewer, larger gaps than the tokens truly had.
#[derive(Default)]
pub(crate) struct Itl {
    last: Option<Instant>,
    counts: [u32; 15],
    gaps: u32,
}

impl Itl {
    pub(crate) fn record(&mut self, now: Instant) {
        if let Some(prev) = self.last {
            let gap_ms = now.saturating_duration_since(prev).as_millis();
            let bucket = EDGES_MS
                .iter()
                .position(|edge| gap_ms <= *edge)
                .unwrap_or(EDGES_MS.len());
            self.counts[bucket] = self.counts[bucket].saturating_add(1);
            self.gaps += 1;
        }
        self.last = Some(now);
    }

    /// Empty when fewer than two chunks arrived.
    pub(crate) fn counts(&self) -> Vec<u32> {
        if self.gaps == 0 {
            Vec::new()
        } else {
            self.counts.to_vec()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn sse_stream_yields_model_and_usage() {
        let mut c = Capture::default();
        // Chunk boundaries land mid-line; the scans don't care.
        c.feed(b"data: {\"model\": \"llama-3\", \"choices\": [{\"delta\"");
        c.feed(b": {\"content\": \"hi\"}}]}\n\n");
        c.feed(b"data: {\"usage\": {\"prompt_tokens\": 7, \"completion_tokens\": 42}}\n\n");
        c.feed(b"data: [DONE]\n");
        assert_eq!(c.model(), "llama-3");
        assert_eq!(c.prompt_tokens(), Some(7));
        assert_eq!(c.completion_tokens(), Some(42));
    }

    #[test]
    fn plain_json_completion_yields_model_and_usage() {
        let mut c = Capture::default();
        c.feed(
            b"{\"model\": \"m\", \"choices\": [], \"usage\": {\"prompt_tokens\": 2, \"completion_tokens\": 5}}",
        );
        assert_eq!(c.model(), "m");
        assert_eq!(c.prompt_tokens(), Some(2));
        assert_eq!(c.completion_tokens(), Some(5));
    }

    #[test]
    fn usage_details_do_not_shadow_the_counts() {
        let mut c = Capture::default();
        c.feed(
            b"{\"usage\": {\"prompt_tokens\": 3, \"prompt_tokens_details\": {\"cached_tokens\": 99}, \"completion_tokens\": 9}}",
        );
        assert_eq!(c.prompt_tokens(), Some(3));
        assert_eq!(c.completion_tokens(), Some(9));
        assert_eq!(c.cached_tokens(), Some(99));
    }

    #[test]
    fn absent_fields_stay_absent() {
        let mut c = Capture::default();
        c.feed(b"data: {\"choices\": []}\n");
        assert_eq!(c.model(), "");
        assert_eq!(c.prompt_tokens(), None);
        assert_eq!(c.completion_tokens(), None);
        assert_eq!(c.cached_tokens(), None);
    }

    #[test]
    fn capture_stays_bounded_without_newlines() {
        let mut c = Capture::default();
        // A newline-free megabyte: the tail must stay capped.
        for _ in 0..256 {
            c.feed(&[b'x'; 4096]);
        }
        assert_eq!(c.head.len(), HEAD_CAP);
        assert_eq!(c.tail.len(), TAIL_CAP);
    }

    #[test]
    fn itl_buckets_by_layout_one_edges() {
        let mut itl = Itl::default();
        let t0 = Instant::now();
        itl.record(t0);
        // 5ms → bucket 0 (upper-inclusive), 6ms gap → bucket 1,
        // 2000ms gap → overflow bucket 14.
        itl.record(t0 + Duration::from_millis(5));
        itl.record(t0 + Duration::from_millis(11));
        itl.record(t0 + Duration::from_millis(2011));
        let counts = itl.counts();
        assert_eq!(counts.len(), 15);
        assert_eq!(counts[0], 1);
        assert_eq!(counts[1], 1);
        assert_eq!(counts[14], 1);
        assert_eq!(counts.iter().sum::<u32>(), 3);
    }

    #[test]
    fn itl_is_empty_under_two_chunks() {
        let mut itl = Itl::default();
        assert!(itl.counts().is_empty(), "{:?}", itl.counts());
        itl.record(Instant::now());
        assert!(itl.counts().is_empty(), "one arrival leaves no gap");
    }
}

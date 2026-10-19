//! What a response says about the inference behind it, read as it
//! streams past: when the first token arrived, the arrival gaps of
//! the ones after it, the token usage, and whether the upstream
//! reported an error in-band.
//!
//! How to read a response is the request's mode, which the request
//! path decided before the pick; nothing here sniffs the response for
//! its format. Whether it streamed is the response's own
//! `content-type`: an event stream is read event by event, anything
//! else as one document.
//!
//! The first token is a token, not the first byte: an engine sends
//! headers, and in a stream an opening role-only chunk or a
//! `message_start`, before prefill is done.
//!
//! - Chat-completions stream: the first event whose delta carries non-empty
//!   content, reasoning or a tool call. Inter-token gaps and usage are
//!   read as they were before modes existed: every chunk's arrival,
//!   and the scans over the captured tail.
//! - Anthropic stream: the first `content_block_delta`, which is also
//!   the only event that counts toward inter-token gaps; the other
//!   events carry no tokens. Usage is the last seen, `message_delta`'s
//!   over `message_start`'s, field by field.
//! - Either format, not streamed: the first chunk, since the whole
//!   document arrives at once. The picker knows the request did not
//!   stream and does not take this as a TTFT sample.

use std::time::Instant;

use http::HeaderMap;
use serde::Deserialize;
use serde::de::IgnoredAny;

use super::proto::pick_request::Mode;
use super::usage::{AnthropicUsage, Capture, Itl};
use crate::sse::Splitter;

/// Per-request response state for the token reports.
pub(crate) struct Observer {
    mode: Mode,
    /// Whether the upstream answered with an event stream.
    streamed: bool,
    first_token: bool,
    /// An Anthropic `error` event arrived inside the stream.
    error_event: bool,
    sse: Splitter,
    capture: Capture,
    /// Accumulated from an Anthropic stream's events; a non-streamed
    /// response's usage is read from `capture` at the end instead.
    anthropic: AnthropicUsage,
    itl: Itl,
}

/// The usage a response reported, mapped to the picker's terms.
pub(crate) struct Usage {
    pub(crate) model: String,
    pub(crate) prompt: Option<u64>,
    pub(crate) completion: Option<u64>,
    pub(crate) cached: Option<u64>,
}

impl Observer {
    pub(crate) fn new(mode: Mode) -> Self {
        Self {
            mode,
            streamed: false,
            first_token: false,
            error_event: false,
            sse: Splitter::default(),
            capture: Capture::default(),
            anthropic: AnthropicUsage::default(),
            itl: Itl::default(),
        }
    }

    /// Read the response head.
    pub(crate) fn start(&mut self, headers: &HeaderMap) {
        self.streamed = headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .and_then(|ct| ct.split(';').next())
            .is_some_and(|ct| ct.trim().eq_ignore_ascii_case("text/event-stream"));
    }

    /// Read one non-empty response chunk that arrived at `now`.
    /// Returns true for the chunk that carried the first token, and
    /// only for that one.
    pub(crate) fn feed(&mut self, chunk: &[u8], now: Instant) -> bool {
        let before = self.first_token;
        match self.mode {
            Mode::OpenaiChatCompletions => self.feed_openai(chunk, now),
            Mode::AnthropicMessages => self.feed_anthropic(chunk, now),
            // Runs no inference, so there is nothing to read.
            Mode::AnthropicCountTokens => {}
        }
        !before && self.first_token
    }

    fn feed_openai(&mut self, chunk: &[u8], now: Instant) {
        self.capture.feed(chunk);
        self.itl.record(now);
        if self.first_token {
            return;
        }
        if !self.streamed {
            self.first_token = true;
            return;
        }
        let mut token = false;
        self.sse.feed(chunk, |event| {
            // Only a delta with content gets past the cap, so a cut
            // event is one.
            token |= event.truncated || openai_delta_has_token(event.data);
        });
        if token {
            self.first_token = true;
            // Nothing after the first token is read event by event.
            self.sse = Splitter::default();
        }
    }

    fn feed_anthropic(&mut self, chunk: &[u8], now: Instant) {
        // The model, from the head; and for a document, the usage
        // from the tail.
        self.capture.feed(chunk);
        if !self.streamed {
            self.first_token = true;
            return;
        }
        let mut delta = false;
        let (anthropic, error_event) = (&mut self.anthropic, &mut self.error_event);
        self.sse.feed(chunk, |event| match event.kind {
            b"content_block_delta" => delta = true,
            b"message_start" | b"message_delta" => anthropic.overlay(event.data),
            b"error" => *error_event = true,
            _ => {}
        });
        // One arrival per chunk however many deltas it carried, the
        // same measure an OpenAI response gets.
        if delta {
            self.itl.record(now);
            self.first_token = true;
        }
    }

    pub(crate) fn usage(&self) -> Usage {
        let model = self.capture.model();
        match self.mode {
            Mode::OpenaiChatCompletions => Usage {
                model,
                prompt: self.capture.prompt_tokens(),
                completion: self.capture.completion_tokens(),
                cached: self.capture.cached_tokens(),
            },
            Mode::AnthropicMessages | Mode::AnthropicCountTokens => {
                let usage = if self.streamed {
                    self.anthropic
                } else {
                    self.capture.anthropic_usage()
                };
                Usage {
                    model,
                    prompt: usage.prompt_tokens(),
                    completion: usage.completion_tokens(),
                    cached: usage.cached_tokens(),
                }
            }
        }
    }

    /// Per-bucket inter-token gap counts; empty with fewer than two
    /// counted arrivals.
    pub(crate) fn itl_counts(&self) -> Vec<u32> {
        self.itl.counts()
    }

    /// Whether an Anthropic stream carried an `error` event, which
    /// arrives inside a 200 response.
    pub(crate) fn saw_error_event(&self) -> bool {
        self.error_event
    }
}

/// One chat-completions stream chunk, as far as finding a token needs. Unknown
/// fields are ignored and every field is optional, so any chunk shape
/// parses.
#[derive(Deserialize)]
struct ChatChunk {
    #[serde(default)]
    choices: Vec<ChatChoice>,
}

#[derive(Deserialize)]
struct ChatChoice {
    delta: Option<ChatDelta>,
}

#[derive(Deserialize)]
struct ChatDelta {
    content: Option<String>,
    /// vLLM's reasoning field, under its older and newer names.
    reasoning_content: Option<String>,
    reasoning: Option<String>,
    tool_calls: Option<Vec<IgnoredAny>>,
}

/// Whether one chat-completions stream event's data carries a token: a delta
/// with non-empty content, reasoning or a tool call. `[DONE]`, an
/// error object, and anything else that is not a chunk carry none.
fn openai_delta_has_token(data: &[u8]) -> bool {
    let Ok(chunk) = serde_json::from_slice::<ChatChunk>(data) else {
        return false;
    };
    let non_empty = |s: &Option<String>| s.as_deref().is_some_and(|s| !s.is_empty());
    chunk
        .choices
        .iter()
        .filter_map(|c| c.delta.as_ref())
        .any(|d| {
            non_empty(&d.content)
                || non_empty(&d.reasoning_content)
                || non_empty(&d.reasoning)
                || d.tool_calls.as_ref().is_some_and(|t| !t.is_empty())
        })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn observer(mode: Mode, content_type: &str) -> Observer {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONTENT_TYPE, content_type.parse().unwrap());
        let mut o = Observer::new(mode);
        o.start(&headers);
        o
    }

    fn openai_stream() -> Observer {
        observer(Mode::OpenaiChatCompletions, "text/event-stream")
    }

    fn anthropic_stream() -> Observer {
        observer(Mode::AnthropicMessages, "text/event-stream; charset=utf-8")
    }

    /// Feed `chunks` one millisecond apart from `t0`; the index of
    /// every chunk `feed` called the first token.
    fn firsts(o: &mut Observer, t0: Instant, chunks: &[&[u8]]) -> Vec<usize> {
        let mut at = t0;
        let mut firsts = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            if o.feed(chunk, at) {
                firsts.push(i);
            }
            at += Duration::from_millis(1);
        }
        firsts
    }

    const OPENAI_ROLE: &[u8] =
        b"data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}\n\n";
    const OPENAI_HI: &[u8] =
        b"data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi\"}}]}\n\n";

    #[test]
    fn content_type_decides_streamed() {
        assert!(anthropic_stream().streamed);
        assert!(observer(Mode::AnthropicMessages, "Text/Event-Stream").streamed);
        assert!(!observer(Mode::AnthropicMessages, "application/json").streamed);
        assert!(!Observer::new(Mode::AnthropicMessages).streamed);
    }

    #[test]
    fn openai_first_token_skips_empty_deltas() {
        let mut o = openai_stream();
        let empty = b"data: {\"choices\":[{\"delta\":{\"content\":null,\"tool_calls\":[]}}]}\n\n";
        assert_eq!(
            firsts(
                &mut o,
                Instant::now(),
                &[OPENAI_ROLE, empty, OPENAI_HI, OPENAI_HI]
            ),
            vec![2]
        );
    }

    #[test]
    fn openai_reasoning_and_tool_calls_are_tokens() {
        for token in [
            &b"data: {\"choices\":[{\"delta\":{\"reasoning_content\":\"hm\"}}]}\n\n"[..],
            &b"data: {\"choices\":[{\"delta\":{\"reasoning\":\"hm\"}}]}\n\n"[..],
            &b"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c\"}]}}]}\n\n"
                [..],
        ] {
            let mut o = openai_stream();
            assert_eq!(
                firsts(&mut o, Instant::now(), &[OPENAI_ROLE, token]),
                vec![1]
            );
        }
    }

    #[test]
    fn openai_done_and_usage_chunks_are_not_tokens() {
        let mut o = openai_stream();
        let usage =
            b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":0}}\n\n";
        assert!(
            firsts(
                &mut o,
                Instant::now(),
                &[OPENAI_ROLE, usage, b"data: [DONE]\n\n"]
            )
            .is_empty()
        );
    }

    /// The token is found when its event completes, so a delta split
    /// across chunks is the token of the chunk that ends it.
    #[test]
    fn a_split_token_event_counts_where_it_completes() {
        let (a, b) = OPENAI_HI.split_at(20);
        let mut o = openai_stream();
        assert_eq!(
            firsts(&mut o, Instant::now(), &[OPENAI_ROLE, a, b]),
            vec![2]
        );

        let delta = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\"}\n\n";
        let (a, b) = delta.split_at(30);
        let mut o = anthropic_stream();
        assert_eq!(firsts(&mut o, Instant::now(), &[a, b]), vec![1]);
    }

    /// Chat-completions gaps are what they were: every chunk's arrival, the
    /// role-only opener included.
    #[test]
    fn openai_gaps_count_every_chunk() {
        let mut o = openai_stream();
        firsts(&mut o, Instant::now(), &[OPENAI_ROLE, OPENAI_HI, OPENAI_HI]);
        assert_eq!(o.itl_counts().iter().sum::<u32>(), 2);
    }

    #[test]
    fn openai_usage_reads_the_tail() {
        let mut o = openai_stream();
        firsts(
            &mut o,
            Instant::now(),
            &[
                b"data: {\"model\":\"llama\",\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\n",
                b"data: {\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":2,\"prompt_tokens_details\":{\"cached_tokens\":4}}}\n\n",
            ],
        );
        let usage = o.usage();
        assert_eq!(usage.model, "llama");
        assert_eq!(usage.prompt, Some(7));
        assert_eq!(usage.completion, Some(2));
        assert_eq!(usage.cached, Some(4));
    }

    #[test]
    fn a_document_is_its_own_first_token() {
        for mode in [Mode::OpenaiChatCompletions, Mode::AnthropicMessages] {
            let mut o = observer(mode, "application/json");
            assert_eq!(
                firsts(&mut o, Instant::now(), &[b"{\"id\":", b"\"x\"}"]),
                vec![0]
            );
        }
    }

    const MESSAGE_START: &[u8] = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude\",\"content\":[],\"usage\":{\"input_tokens\":10,\"cache_creation_input_tokens\":5,\"cache_read_input_tokens\":30,\"output_tokens\":1}}}\n\n";
    const BLOCK_START: &[u8] = b"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n";
    const PING: &[u8] = b"event: ping\ndata: {\"type\": \"ping\"}\n\n";
    const DELTA: &[u8] = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\n";
    const BLOCK_STOP: &[u8] =
        b"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n";
    const MESSAGE_DELTA: &[u8] = b"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":42}}\n\n";
    const MESSAGE_STOP: &[u8] = b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";

    #[test]
    fn anthropic_first_token_is_the_first_content_block_delta() {
        let mut o = anthropic_stream();
        assert_eq!(
            firsts(
                &mut o,
                Instant::now(),
                &[MESSAGE_START, BLOCK_START, PING, DELTA, DELTA, BLOCK_STOP]
            ),
            vec![3]
        );
    }

    /// Only the chunks carrying a `content_block_delta` are arrivals:
    /// the long waits around them, on `message_start`, a ping, and the
    /// closing events, must not reach the histogram.
    #[test]
    fn anthropic_gaps_count_only_content_block_deltas() {
        let mut o = anthropic_stream();
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let two_deltas = [DELTA, DELTA].concat();
        for (chunk, at) in [
            (MESSAGE_START, t0),
            (BLOCK_START, t0 + ms(400)),
            (PING, t0 + ms(800)),
            (DELTA, t0 + ms(1200)),
            // Two deltas in one chunk are one arrival.
            (&two_deltas[..], t0 + ms(1203)),
            (DELTA, t0 + ms(1260)),
            (BLOCK_STOP, t0 + ms(3000)),
            (MESSAGE_DELTA, t0 + ms(3000)),
            (MESSAGE_STOP, t0 + ms(3000)),
        ] {
            o.feed(chunk, at);
        }
        let counts = o.itl_counts();
        assert_eq!(counts.iter().sum::<u32>(), 2, "{counts:?}");
        assert_eq!(counts[0], 1, "3ms gap");
        assert_eq!(counts[7], 1, "57ms gap");
    }

    #[test]
    fn anthropic_stream_usage_takes_message_delta_over_message_start() {
        let mut o = anthropic_stream();
        firsts(
            &mut o,
            Instant::now(),
            &[MESSAGE_START, DELTA, MESSAGE_DELTA, MESSAGE_STOP],
        );
        let usage = o.usage();
        assert_eq!(usage.model, "claude");
        assert_eq!(usage.prompt, Some(45), "10 input + 30 read + 5 written");
        assert_eq!(usage.completion, Some(42), "message_delta's count wins");
        assert_eq!(usage.cached, Some(30));
        assert!(!o.saw_error_event());
    }

    /// A stream cut off before `message_delta` still reports what
    /// `message_start` said.
    #[test]
    fn anthropic_stream_usage_falls_back_to_message_start() {
        let mut o = anthropic_stream();
        firsts(&mut o, Instant::now(), &[MESSAGE_START, DELTA]);
        let usage = o.usage();
        assert_eq!(usage.prompt, Some(45));
        assert_eq!(usage.completion, Some(1));
    }

    #[test]
    fn anthropic_stream_usage_without_cache_fields() {
        let mut o = anthropic_stream();
        firsts(
            &mut o,
            Instant::now(),
            &[
                b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"m\",\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n",
                DELTA,
                b"event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":10,\"output_tokens\":42}}\n\n",
            ],
        );
        let usage = o.usage();
        assert_eq!(usage.prompt, Some(10));
        assert_eq!(usage.completion, Some(42));
        assert_eq!(usage.cached, None, "absent is unknown, not 0");
    }

    #[test]
    fn anthropic_document_usage_is_top_level() {
        let mut o = observer(Mode::AnthropicMessages, "application/json");
        o.feed(
            b"{\"id\":\"msg_1\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude\",\"content\":[{\"type\":\"text\",\"text\":\"Hi\"}],\"stop_reason\":\"end_turn\",\"usage\":{\"input_tokens\":10,\"cache_read_input_tokens\":30,\"output_tokens\":2}}",
            Instant::now(),
        );
        let usage = o.usage();
        assert_eq!(usage.model, "claude");
        assert_eq!(usage.prompt, Some(40));
        assert_eq!(usage.completion, Some(2));
        assert_eq!(usage.cached, Some(30));
        assert!(o.itl_counts().is_empty(), "a document has no deltas");
    }

    #[test]
    fn an_anthropic_error_event_is_seen() {
        let mut o = anthropic_stream();
        firsts(
            &mut o,
            Instant::now(),
            &[
                MESSAGE_START,
                DELTA,
                b"event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}\n\n",
            ],
        );
        assert!(o.saw_error_event());
    }
}

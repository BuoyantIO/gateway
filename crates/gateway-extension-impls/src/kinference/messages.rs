//! Scanner for the server-sent events of an Anthropic Messages stream.
//! It counts `content_block_delta` events and reads the model and the
//! usage counts from `message_start` and `message_delta`. The scanner
//! keeps at most one line of the body.

use serde::Deserialize;

use super::usage::Usage;

/// A partial line longer than the cap is dropped whole.
const LINE_CAP: usize = 64 * 1024;

/// What one body chunk held.
#[derive(Default)]
pub(crate) struct Fed {
    /// `content_block_delta` events in the chunk.
    pub(crate) tokens: u32,
    /// An `error` event arrived before the stream's first
    /// `content_block_delta`.
    pub(crate) error: bool,
}

#[derive(Default)]
pub(crate) struct Events {
    line: Vec<u8>,
    overflowed: bool,
    event: Kind,
    started: bool,
    model: String,
    counts: Counts,
}

/// The event that the next `data:` line belongs to.
#[derive(Default, Clone, Copy)]
enum Kind {
    #[default]
    Other,
    MessageStart,
    MessageDelta,
}

#[derive(Deserialize)]
struct Start {
    message: Message,
}

#[derive(Deserialize)]
struct Message {
    #[serde(default)]
    model: String,
    usage: Option<Counts>,
}

#[derive(Deserialize)]
struct Delta {
    usage: Option<Counts>,
}

#[derive(Deserialize, Default, Clone, Copy)]
struct Counts {
    #[serde(rename = "input_tokens")]
    input: Option<u64>,
    #[serde(rename = "output_tokens")]
    output: Option<u64>,
    #[serde(rename = "cache_read_input_tokens")]
    cache_read: Option<u64>,
    #[serde(rename = "cache_creation_input_tokens")]
    cache_creation: Option<u64>,
}

impl Counts {
    /// A count that `later` holds replaces the earlier count.
    fn merge(&mut self, later: Counts) {
        self.input = later.input.or(self.input);
        self.output = later.output.or(self.output);
        self.cache_read = later.cache_read.or(self.cache_read);
        self.cache_creation = later.cache_creation.or(self.cache_creation);
    }
}

impl Events {
    pub(crate) fn feed(&mut self, mut chunk: &[u8]) -> Fed {
        let mut fed = Fed::default();
        while let Some(newline) = chunk.iter().position(|b| *b == b'\n') {
            let (line, rest) = chunk.split_at(newline);
            chunk = &rest[1..];
            if self.line.is_empty() && !self.overflowed {
                self.on_line(line, &mut fed);
                continue;
            }
            self.keep(line);
            let line = std::mem::take(&mut self.line);
            if !std::mem::take(&mut self.overflowed) {
                self.on_line(&line, &mut fed);
            }
        }
        self.keep(chunk);
        fed
    }

    pub(crate) fn usage(&self) -> Usage {
        Usage::messages(
            self.model.clone(),
            self.counts.input,
            self.counts.output,
            self.counts.cache_read,
            self.counts.cache_creation,
        )
    }

    fn keep(&mut self, partial: &[u8]) {
        if self.overflowed || self.line.len() + partial.len() > LINE_CAP {
            self.overflowed = true;
            self.line.clear();
        } else {
            self.line.extend_from_slice(partial);
        }
    }

    fn on_line(&mut self, line: &[u8], fed: &mut Fed) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            self.event = Kind::Other;
        } else if let Some(name) = line.strip_prefix(b"event:") {
            self.event = match name.trim_ascii() {
                b"content_block_delta" => {
                    self.started = true;
                    fed.tokens += 1;
                    Kind::Other
                }
                b"error" => {
                    fed.error |= !self.started;
                    Kind::Other
                }
                b"message_start" => Kind::MessageStart,
                b"message_delta" => Kind::MessageDelta,
                _ => Kind::Other,
            };
        } else if let Some(data) = line.strip_prefix(b"data:") {
            match self.event {
                Kind::MessageStart => {
                    if let Ok(start) = serde_json::from_slice::<Start>(data) {
                        self.model = start.message.model;
                        self.counts.merge(start.message.usage.unwrap_or_default());
                    }
                }
                Kind::MessageDelta => {
                    if let Ok(delta) = serde_json::from_slice::<Delta>(data) {
                        self.counts.merge(delta.usage.unwrap_or_default());
                    }
                }
                Kind::Other => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STREAM: &str = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-x\",",
        "\"usage\":{\"input_tokens\":25,\"cache_read_input_tokens\":100,",
        "\"cache_creation_input_tokens\":null,\"output_tokens\":1}}}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0}\n\n",
        "event: ping\ndata: {\"type\":\"ping\"}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"Hel\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"lo\"}}\n\n",
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},",
        "\"usage\":{\"input_tokens\":null,\"output_tokens\":15}}\n\n",
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
    );

    /// A whole stream in one chunk yields its tokens, model and counts.
    #[test]
    fn a_stream_yields_tokens_model_and_usage() {
        let mut events = Events::default();
        let fed = events.feed(STREAM.as_bytes());
        assert_eq!(fed.tokens, 2);
        assert!(!fed.error);
        let usage = events.usage();
        assert_eq!(usage.model, "claude-x");
        assert_eq!(usage.prompt_tokens, Some(125));
        assert_eq!(usage.cached_tokens, Some(100));
        assert_eq!(usage.completion_tokens, Some(15));
    }

    /// Chunk boundaries inside a line change nothing.
    #[test]
    fn chunk_boundaries_carry_no_meaning() {
        let mut events = Events::default();
        let mut tokens = 0;
        for byte in STREAM.as_bytes() {
            tokens += events.feed(std::slice::from_ref(byte)).tokens;
        }
        assert_eq!(tokens, 2);
        let usage = events.usage();
        assert_eq!(usage.model, "claude-x");
        assert_eq!(usage.prompt_tokens, Some(125));
        assert_eq!(usage.completion_tokens, Some(15));
    }

    /// CRLF line endings parse as LF line endings do.
    #[test]
    fn crlf_lines_parse() {
        let mut events = Events::default();
        let fed = events.feed(STREAM.replace('\n', "\r\n").as_bytes());
        assert_eq!(fed.tokens, 2);
        assert_eq!(events.usage().completion_tokens, Some(15));
    }

    /// An `error` event counts only before the first token.
    #[test]
    fn an_error_counts_only_before_the_first_token() {
        let error = b"event: error\ndata: {\"type\":\"error\"}\n\n";
        let mut events = Events::default();
        assert!(events.feed(error).error);

        let mut events = Events::default();
        events.feed(b"event: content_block_delta\ndata: {}\n\n");
        assert!(!events.feed(error).error);
    }

    /// A stream without usage reports no counts.
    #[test]
    fn absent_usage_stays_absent() {
        let mut events = Events::default();
        events.feed(b"event: message_start\ndata: {\"message\":{\"model\":\"m\"}}\n\n");
        let usage = events.usage();
        assert_eq!(usage.model, "m");
        assert_eq!(usage.prompt_tokens, None);
        assert_eq!(usage.cached_tokens, None);
        assert_eq!(usage.completion_tokens, None);
    }

    /// A line past the cap is dropped, and the next line still parses.
    #[test]
    fn an_oversized_line_is_dropped() {
        let mut events = Events::default();
        events.feed(b"data: ");
        for _ in 0..32 {
            events.feed(&[b'x'; 4096]);
            assert!(events.line.len() <= LINE_CAP);
        }
        let fed = events.feed(b"\nevent: content_block_delta\n");
        assert_eq!(fed.tokens, 1);
    }
}

//! Reassembling a response event stream into the one document the
//! same call would have answered without streaming, so the `response
//! end` line reads as a message rather than as its framing.
//!
//! Two stream formats are understood, told apart by the first event
//! whose data is a JSON object:
//!
//! - Anthropic Messages, an event whose `type` is one of that
//!   stream's event types. `message_start` gives the message and
//!   `content_block_start` each block. A `content_block_delta` grows
//!   its block: every string in the delta is appended to the block's
//!   field of the same name (`text`, `thinking`, `signature`),
//!   `partial_json` builds the block's `input`, parsed at the end, and
//!   `citation` is pushed onto `citations`. `message_delta` sets the
//!   stop fields and updates `usage` field by field, and an `error`
//!   event is kept as the message's `error`.
//! - Chat completions, a chunk with `choices`. The first chunk's
//!   top-level fields are the document's, `object` becomes
//!   `chat.completion`, and the last non-null `usage` wins. Each
//!   choice's deltas build its `message`: `role` is set, every other
//!   string is appended (`content`, `reasoning_content`, `refusal`),
//!   and `tool_calls` merge by `index`, with `function.arguments`
//!   appended. `logprobs` are not kept.
//!
//! Any other stream, or one with no JSON event at all, is not
//! reassembled, and the caller logs its raw prefix instead.
//!
//! The document is bounded by what it stores, not by what the wire
//! carried; a stream spends most of its bytes on framing, so the
//! document is far smaller than the body. Appended text is capped at
//! the caller's budget, cut on a character boundary, and nothing is
//! appended after the cut, so the text kept is the stream's own, in
//! order. Everything
//! else (ids, usage, stop reasons, the block and choice structure) is
//! charged against [`STRUCTURE_CAP`] by an estimate of its serialized
//! size, and what does not fit is dropped whole. Either cut, or an
//! event whose data is not JSON, marks the document truncated.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt;

use serde_json::{Map, Value};

use crate::sse::Splitter;

/// Allowance for everything in a document besides its appended text.
const STRUCTURE_CAP: usize = 16 * 1024;

/// What a key costs on top of its name: the quotes, colon and comma.
const KEY_COST: usize = 4;

/// What a new block, choice or tool call costs before its fields.
const ENTRY_COST: usize = 4;

/// The `type`s of an Anthropic Messages stream's events.
const ANTHROPIC_EVENTS: [&str; 8] = [
    "message_start",
    "content_block_start",
    "content_block_delta",
    "content_block_stop",
    "message_delta",
    "message_stop",
    "ping",
    "error",
];

/// Keys in the order the providers' own documents use; any other key
/// follows them, alphabetically.
const KEY_ORDER: [&str; 25] = [
    "type",
    "object",
    "id",
    "created",
    "index",
    "role",
    "model",
    "name",
    "reasoning_content",
    "reasoning",
    "thinking",
    "signature",
    "content",
    "text",
    "input",
    "arguments",
    "choices",
    "message",
    "tool_calls",
    "function",
    "finish_reason",
    "stop_reason",
    "stop_sequence",
    "usage",
    "error",
];

/// One response stream's reassembly, fed chunk by chunk.
pub(super) struct Destream {
    sse: Splitter,
    budget: Budget,
    format: Format,
    events: u64,
}

/// What [`Destream::finish`] made of a stream it understood.
pub(super) struct Reassembled {
    /// `anthropic` or `chat_completions`.
    pub(super) format: &'static str,
    /// Events the stream carried, whether or not they added anything.
    pub(super) events: u64,
    pub(super) truncated: bool,
    pub(super) document: Value,
}

enum Format {
    /// No JSON event yet.
    Undecided,
    Anthropic(Anthropic),
    Chat(Chat),
    /// The first JSON event was neither format's.
    Other,
}

impl Destream {
    /// `text_cap` bounds the document's appended text.
    pub(super) fn new(text_cap: usize) -> Self {
        Self {
            sse: Splitter::default(),
            budget: Budget {
                text_left: text_cap,
                structure_left: STRUCTURE_CAP,
                truncated: false,
            },
            format: Format::Undecided,
            events: 0,
        }
    }

    pub(super) fn feed(&mut self, chunk: &[u8]) {
        let Self {
            sse,
            budget,
            format,
            events,
        } = self;
        sse.feed(chunk, |event| {
            *events += 1;
            budget.truncated |= event.truncated;
            on_event(format, budget, event.data);
        });
    }

    /// Whether the stream is one this reassembles. Once it is, the
    /// raw prefix is no longer needed as a fallback.
    pub(super) fn understood(&self) -> bool {
        matches!(self.format, Format::Anthropic(_) | Format::Chat(_))
    }

    /// The reassembled document, or `None` for a stream this does not
    /// understand.
    pub(super) fn finish(self) -> Option<Reassembled> {
        let (format, document) = match self.format {
            Format::Anthropic(message) => ("anthropic", message.finish()),
            Format::Chat(chat) => ("chat_completions", chat.finish()),
            Format::Undecided | Format::Other => return None,
        };
        Some(Reassembled {
            format,
            events: self.events,
            truncated: self.budget.truncated,
            document,
        })
    }
}

fn on_event(format: &mut Format, budget: &mut Budget, data: &[u8]) {
    // A chat-completions stream's last event, and not JSON.
    if data == b"[DONE]" {
        return;
    }
    let Ok(Value::Object(event)) = serde_json::from_slice::<Value>(data) else {
        budget.truncated = true;
        return;
    };
    if matches!(format, Format::Undecided) {
        *format = if event
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|t| ANTHROPIC_EVENTS.contains(&t))
        {
            Format::Anthropic(Anthropic::default())
        } else if event.contains_key("choices") {
            Format::Chat(Chat::default())
        } else {
            Format::Other
        };
    }
    match format {
        Format::Anthropic(message) => message.event(event, budget),
        Format::Chat(chat) => chat.chunk(event, budget),
        Format::Undecided | Format::Other => {}
    }
}

/// An Anthropic message as its events build it.
#[derive(Default)]
struct Anthropic {
    /// The message's fields, `content` aside.
    message: Map<String, Value>,
    /// The content blocks, by index.
    blocks: BTreeMap<u64, Block>,
}

#[derive(Default)]
struct Block {
    fields: Map<String, Value>,
    /// The `partial_json` so far, parsed into `input` at the end.
    json: String,
}

impl Anthropic {
    fn event(&mut self, mut event: Map<String, Value>, budget: &mut Budget) {
        let index = event.get("index").and_then(Value::as_u64).unwrap_or(0);
        let kind = event.remove("type");
        match kind.as_ref().and_then(Value::as_str).unwrap_or("") {
            "message_start" => {
                if let Some(Value::Object(message)) = event.remove("message") {
                    for (key, value) in message {
                        // The blocks are the stream's to deliver.
                        if key != "content" {
                            budget.set(&mut self.message, &key, value);
                        }
                    }
                }
            }
            "content_block_start" => {
                if let Some(Value::Object(start)) = event.remove("content_block")
                    && let Some(block) = self.block(index, budget)
                {
                    for (key, value) in start {
                        budget.set(&mut block.fields, &key, value);
                    }
                }
            }
            "content_block_delta" => {
                if let Some(Value::Object(delta)) = event.remove("delta")
                    && let Some(block) = self.block(index, budget)
                {
                    block.delta(delta, budget);
                }
            }
            "message_delta" => {
                if let Some(Value::Object(delta)) = event.remove("delta") {
                    for (key, value) in delta {
                        budget.set(&mut self.message, &key, value);
                    }
                }
                if let Some(Value::Object(usage)) = event.remove("usage")
                    && let Some(into) = object(&mut self.message, "usage", budget)
                {
                    for (key, value) in usage {
                        if !value.is_null() {
                            budget.set(into, &key, value);
                        }
                    }
                }
            }
            "error" => {
                if let Some(error) = event.remove("error") {
                    budget.set(&mut self.message, "error", error);
                }
            }
            _ => {}
        }
    }

    fn block(&mut self, index: u64, budget: &mut Budget) -> Option<&mut Block> {
        match self.blocks.entry(index) {
            Entry::Occupied(block) => Some(block.into_mut()),
            Entry::Vacant(slot) => budget
                .take(ENTRY_COST)
                .then(|| slot.insert(Block::default())),
        }
    }

    fn finish(self) -> Value {
        let mut message = self.message;
        let content = self.blocks.into_values().map(Block::finish).collect();
        message.insert("content".to_owned(), Value::Array(content));
        Value::Object(message)
    }
}

impl Block {
    fn delta(&mut self, delta: Map<String, Value>, budget: &mut Budget) {
        for (key, value) in delta {
            match (key.as_str(), value) {
                ("type", _) => {}
                ("partial_json", Value::String(json)) => budget.append(&mut self.json, &json),
                ("citation", citation) => push(&mut self.fields, "citations", citation, budget),
                (_, Value::String(text)) => append(&mut self.fields, &key, &text, budget),
                _ => {}
            }
        }
    }

    /// A tool input cut short by the budget does not parse, and is
    /// kept as the string it got to.
    fn finish(mut self) -> Value {
        if !self.json.is_empty() {
            let input = serde_json::from_str(&self.json).unwrap_or(Value::String(self.json));
            self.fields.insert("input".to_owned(), input);
        }
        Value::Object(self.fields)
    }
}

/// A chat completion as its chunks build it.
#[derive(Default)]
struct Chat {
    /// The top-level fields, `choices` aside.
    doc: Map<String, Value>,
    choices: BTreeMap<u64, Choice>,
}

#[derive(Default)]
struct Choice {
    /// The choice's fields beside `delta`: `finish_reason`, and
    /// whatever else the server adds.
    fields: Map<String, Value>,
    message: Map<String, Value>,
    tool_calls: BTreeMap<u64, Map<String, Value>>,
}

impl Chat {
    fn chunk(&mut self, mut chunk: Map<String, Value>, budget: &mut Budget) {
        let choices = chunk.remove("choices");
        if let Some(usage) = chunk.remove("usage")
            && !usage.is_null()
        {
            budget.set(&mut self.doc, "usage", usage);
        }
        for (key, value) in chunk {
            // The first chunk's wins; later chunks repeat it.
            if !self.doc.contains_key(&key) {
                budget.set(&mut self.doc, &key, value);
            }
        }
        let Some(Value::Array(choices)) = choices else {
            return;
        };
        for (position, choice) in choices.into_iter().enumerate() {
            let Value::Object(mut choice) = choice else {
                continue;
            };
            let index = choice
                .get("index")
                .and_then(Value::as_u64)
                .unwrap_or(position as u64);
            let Some(state) = self.choice(index, budget) else {
                continue;
            };
            let delta = choice.remove("delta");
            for (key, value) in choice {
                if !(value.is_null() || key == "index" || key == "logprobs") {
                    budget.set(&mut state.fields, &key, value);
                }
            }
            if let Some(Value::Object(delta)) = delta {
                state.delta(delta, budget);
            }
        }
    }

    fn choice(&mut self, index: u64, budget: &mut Budget) -> Option<&mut Choice> {
        match self.choices.entry(index) {
            Entry::Occupied(choice) => Some(choice.into_mut()),
            Entry::Vacant(slot) => budget
                .take(ENTRY_COST)
                .then(|| slot.insert(Choice::default())),
        }
    }

    fn finish(self) -> Value {
        let mut doc = self.doc;
        doc.insert("object".to_owned(), "chat.completion".into());
        let choices = self
            .choices
            .into_iter()
            .map(|(index, choice)| choice.finish(index))
            .collect();
        doc.insert("choices".to_owned(), Value::Array(choices));
        Value::Object(doc)
    }
}

impl Choice {
    fn delta(&mut self, delta: Map<String, Value>, budget: &mut Budget) {
        for (key, value) in delta {
            match (key.as_str(), value) {
                (_, Value::Null) => {}
                ("tool_calls", Value::Array(calls)) => {
                    for (position, call) in calls.into_iter().enumerate() {
                        if let Value::Object(call) = call {
                            self.tool_call(position, call, budget);
                        }
                    }
                }
                ("role", role) => budget.set(&mut self.message, "role", role),
                (_, Value::String(text)) => append(&mut self.message, &key, &text, budget),
                (_, value) => budget.set(&mut self.message, &key, value),
            }
        }
    }

    fn tool_call(&mut self, position: usize, call: Map<String, Value>, budget: &mut Budget) {
        let index = call
            .get("index")
            .and_then(Value::as_u64)
            .unwrap_or(position as u64);
        let state = match self.tool_calls.entry(index) {
            Entry::Occupied(state) => state.into_mut(),
            Entry::Vacant(slot) => {
                if !budget.take(ENTRY_COST) {
                    return;
                }
                slot.insert(Map::new())
            }
        };
        for (key, value) in call {
            match (key.as_str(), value) {
                ("index", _) | (_, Value::Null) => {}
                ("function", Value::Object(function)) => {
                    let Some(into) = object(state, "function", budget) else {
                        continue;
                    };
                    for (key, value) in function {
                        match (key.as_str(), value) {
                            (_, Value::Null) => {}
                            ("arguments", Value::String(piece)) => {
                                append(into, "arguments", &piece, budget);
                            }
                            (_, value) => budget.set(into, &key, value),
                        }
                    }
                }
                (_, value) => budget.set(state, &key, value),
            }
        }
    }

    fn finish(self, index: u64) -> Value {
        let mut message = self.message;
        if !self.tool_calls.is_empty() {
            let calls = self.tool_calls.into_values().map(Value::Object).collect();
            message.insert("tool_calls".to_owned(), Value::Array(calls));
        }
        let mut choice = self.fields;
        choice.insert("index".to_owned(), index.into());
        choice.insert("message".to_owned(), Value::Object(message));
        Value::Object(choice)
    }
}

/// What a document may still store, and whether anything was cut.
struct Budget {
    text_left: usize,
    structure_left: usize,
    truncated: bool,
}

impl Budget {
    /// Append as much of `text` as the text allowance holds, cut on a
    /// character boundary. A cut is final: text after it, which would
    /// not follow on from what was kept, is dropped.
    fn append(&mut self, to: &mut String, text: &str) {
        let fits = text.floor_char_boundary(self.text_left);
        to.push_str(&text[..fits]);
        self.text_left -= fits;
        if fits < text.len() {
            self.text_left = 0;
            self.truncated = true;
        }
    }

    /// Spend `cost` of the structure allowance if it holds that much.
    fn take(&mut self, cost: usize) -> bool {
        if cost <= self.structure_left {
            self.structure_left -= cost;
            true
        } else {
            self.truncated = true;
            false
        }
    }

    /// Set `key`, charged for what it adds; a replacement costs only
    /// what it grows by.
    fn set(&mut self, map: &mut Map<String, Value>, key: &str, value: Value) {
        let cost = match map.get(key) {
            Some(old) => weight(&value).saturating_sub(weight(old)),
            None => key.len() + KEY_COST + weight(&value),
        };
        if self.take(cost) {
            map.insert(key.to_owned(), value);
        }
    }
}

/// Append `text` to the string at `key`, starting it when absent.
fn append(map: &mut Map<String, Value>, key: &str, text: &str, budget: &mut Budget) {
    if let Some(Value::String(to)) = map.get_mut(key) {
        budget.append(to, text);
        return;
    }
    if !budget.take(key.len() + KEY_COST + 2) {
        return;
    }
    let mut to = String::new();
    budget.append(&mut to, text);
    map.insert(key.to_owned(), Value::String(to));
}

/// Push `value` onto the array at `key`, starting it when absent.
fn push(map: &mut Map<String, Value>, key: &str, value: Value, budget: &mut Budget) {
    if let Some(Value::Array(items)) = map.get_mut(key) {
        if budget.take(weight(&value) + 1) {
            items.push(value);
        }
        return;
    }
    if budget.take(key.len() + KEY_COST + weight(&value) + 2) {
        map.insert(key.to_owned(), Value::Array(vec![value]));
    }
}

/// The object at `key`, started (and charged) when absent or not an
/// object.
fn object<'m>(
    map: &'m mut Map<String, Value>,
    key: &str,
    budget: &mut Budget,
) -> Option<&'m mut Map<String, Value>> {
    if !matches!(map.get(key), Some(Value::Object(_))) {
        if !budget.take(key.len() + KEY_COST + 2) {
            return None;
        }
        map.insert(key.to_owned(), Value::Object(Map::new()));
    }
    match map.get_mut(key) {
        Some(Value::Object(inner)) => Some(inner),
        _ => None,
    }
}

/// Roughly `value`'s serialized size: what the budget is charged.
fn weight(value: &Value) -> usize {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => 8,
        Value::String(s) => s.len() + 2,
        Value::Array(items) => 2 + items.iter().map(|v| weight(v) + 1).sum::<usize>(),
        Value::Object(map) => {
            2 + map
                .iter()
                .map(|(k, v)| k.len() + KEY_COST + weight(v))
                .sum::<usize>()
        }
    }
}

/// A document written as compact JSON, with each object's keys in
/// [`KEY_ORDER`] and the rest after them, alphabetically.
pub(super) struct Ordered<'a>(pub(super) &'a Value);

impl fmt::Display for Ordered<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Value::Object(map) => {
                let mut entries: Vec<(&String, &Value)> = map.iter().collect();
                entries.sort_by(|(a, _), (b, _)| rank(a).cmp(&rank(b)).then_with(|| a.cmp(b)));
                f.write_str("{")?;
                for (i, (key, value)) in entries.into_iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{}:{}", Value::from(key.as_str()), Ordered(value))?;
                }
                f.write_str("}")
            }
            Value::Array(items) => {
                f.write_str("[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{}", Ordered(item))?;
                }
                f.write_str("]")
            }
            scalar => write!(f, "{scalar}"),
        }
    }
}

fn rank(key: &str) -> usize {
    KEY_ORDER
        .iter()
        .position(|k| *k == key)
        .unwrap_or(KEY_ORDER.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    /// An event stream of `(event, data)` pairs; an empty event name
    /// writes no `event:` line, as chat-completions streams do.
    fn stream(events: &[(&str, Value)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (name, data) in events {
            if !name.is_empty() {
                out.extend_from_slice(b"event: ");
                out.extend_from_slice(name.as_bytes());
                out.push(b'\n');
            }
            out.extend_from_slice(b"data: ");
            out.extend_from_slice(data.to_string().as_bytes());
            out.extend_from_slice(b"\n\n");
        }
        out
    }

    fn reassemble(body: &[u8], text_cap: usize) -> Reassembled {
        let mut destream = Destream::new(text_cap);
        destream.feed(body);
        destream.finish().expect("an understood stream")
    }

    fn anthropic_stream() -> Vec<u8> {
        let delta = |index: u64, delta: Value| {
            (
                "content_block_delta",
                json!({"type": "content_block_delta", "index": index, "delta": delta}),
            )
        };
        let mut events = vec![
            (
                "message_start",
                json!({"type": "message_start", "message": {
                    "id": "msg_1", "type": "message", "role": "assistant", "content": [],
                    "model": "glm", "stop_reason": null, "stop_sequence": null,
                    "usage": {"input_tokens": 20, "output_tokens": 1},
                }}),
            ),
            (
                "content_block_start",
                json!({"type": "content_block_start", "index": 0,
                       "content_block": {"type": "thinking", "thinking": ""}}),
            ),
            delta(0, json!({"type": "thinking_delta", "thinking": "Let me "})),
            delta(0, json!({"type": "thinking_delta", "thinking": "think."})),
            delta(0, json!({"type": "signature_delta", "signature": "c2ln"})),
            (
                "content_block_stop",
                json!({"type": "content_block_stop", "index": 0}),
            ),
            ("ping", json!({"type": "ping"})),
            (
                "content_block_start",
                json!({"type": "content_block_start", "index": 1,
                       "content_block": {"type": "text", "text": ""}}),
            ),
            delta(1, json!({"type": "text_delta", "text": "Hello,\n"})),
            delta(1, json!({"type": "text_delta", "text": "world"})),
            (
                "content_block_start",
                json!({"type": "content_block_start", "index": 2, "content_block":
                       {"type": "tool_use", "id": "toolu_1", "name": "weather", "input": {}}}),
            ),
            delta(
                2,
                json!({"type": "input_json_delta", "partial_json": "{\"city\": "}),
            ),
            delta(
                2,
                json!({"type": "input_json_delta", "partial_json": "\"Paris\"}"}),
            ),
        ];
        events.extend([
            (
                "message_delta",
                json!({"type": "message_delta",
                       "delta": {"stop_reason": "tool_use", "stop_sequence": null},
                       "usage": {"output_tokens": 42}}),
            ),
            ("message_stop", json!({"type": "message_stop"})),
        ]);
        stream(&events)
    }

    #[test]
    fn an_anthropic_stream_reassembles_into_its_message() {
        let r = reassemble(&anthropic_stream(), 4096);
        assert_eq!(r.format, "anthropic");
        assert_eq!(r.events, 15);
        assert!(!r.truncated);
        assert_eq!(
            r.document,
            json!({
                "id": "msg_1", "type": "message", "role": "assistant", "model": "glm",
                "content": [
                    {"type": "thinking", "thinking": "Let me think.", "signature": "c2ln"},
                    {"type": "text", "text": "Hello,\nworld"},
                    {"type": "tool_use", "id": "toolu_1", "name": "weather",
                     "input": {"city": "Paris"}},
                ],
                "stop_reason": "tool_use", "stop_sequence": null,
                "usage": {"input_tokens": 20, "output_tokens": 42},
            })
        );
    }

    /// Wherever the chunks split the stream, the document is the same.
    #[test]
    fn chunk_boundaries_do_not_change_the_document() {
        let body = anthropic_stream();
        let whole = reassemble(&body, 4096).document;
        for at in (1..body.len()).step_by(7) {
            let mut destream = Destream::new(4096);
            destream.feed(&body[..at]);
            destream.feed(&body[at..]);
            assert_eq!(destream.finish().unwrap().document, whole, "split at {at}");
        }
    }

    #[test]
    fn a_chat_completions_stream_reassembles_into_its_completion() {
        let chunk = |choices: Value, usage: Value| {
            (
                "",
                json!({"id": "chatcmpl-1", "object": "chat.completion.chunk", "created": 7,
                       "model": "glm", "choices": choices, "usage": usage}),
            )
        };
        let delta = |delta: Value, finish: Value| json!([{"index": 0, "delta": delta, "logprobs": null, "finish_reason": finish}]);
        let mut body = stream(&[
            chunk(
                delta(json!({"role": "assistant", "content": ""}), Value::Null),
                Value::Null,
            ),
            chunk(
                delta(json!({"reasoning_content": "Hmm."}), Value::Null),
                Value::Null,
            ),
            chunk(delta(json!({"content": "Hi "}), Value::Null), Value::Null),
            chunk(delta(json!({"content": "there"}), Value::Null), Value::Null),
            chunk(
                delta(
                    json!({"content": null, "tool_calls": [{"index": 0, "id": "call_1",
                        "type": "function", "function": {"name": "weather", "arguments": ""}}]}),
                    Value::Null,
                ),
                Value::Null,
            ),
            chunk(
                delta(
                    json!({"tool_calls": [{"index": 0,
                        "function": {"arguments": "{\"city\":\"Paris\"}"}}]}),
                    Value::Null,
                ),
                Value::Null,
            ),
            chunk(delta(json!({}), json!("tool_calls")), Value::Null),
            chunk(
                json!([]),
                json!({"prompt_tokens": 5, "completion_tokens": 9, "total_tokens": 14}),
            ),
        ]);
        body.extend_from_slice(b"data: [DONE]\n\n");

        let r = reassemble(&body, 4096);
        assert_eq!(r.format, "chat_completions");
        assert!(!r.truncated, "[DONE] is not a malformed event");
        assert_eq!(
            r.document,
            json!({
                "id": "chatcmpl-1", "object": "chat.completion", "created": 7, "model": "glm",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant", "reasoning_content": "Hmm.", "content": "Hi there",
                        "tool_calls": [{"id": "call_1", "type": "function",
                            "function": {"name": "weather", "arguments": "{\"city\":\"Paris\"}"}}],
                    },
                    "finish_reason": "tool_calls",
                }],
                "usage": {"prompt_tokens": 5, "completion_tokens": 9, "total_tokens": 14},
            })
        );
    }

    /// Text past the cap is cut on a character boundary, and the
    /// fields after it, the stop reason and usage, still arrive.
    #[test]
    fn text_is_capped_but_the_ending_survives() {
        let text = |t: &str| {
            (
                "content_block_delta",
                json!({"type": "content_block_delta", "index": 0,
                       "delta": {"type": "text_delta", "text": t}}),
            )
        };
        let body = stream(&[
            (
                "message_start",
                json!({"type": "message_start", "message": {"id": "msg_1", "usage": {}}}),
            ),
            (
                "content_block_start",
                json!({"type": "content_block_start", "index": 0,
                       "content_block": {"type": "text", "text": ""}}),
            ),
            text("abc"),
            text("dé"),
            text("never"),
            (
                "message_delta",
                json!({"type": "message_delta", "delta": {"stop_reason": "max_tokens"},
                       "usage": {"output_tokens": 3}}),
            ),
        ]);
        // `é` is two bytes; a cap of 5 lands inside it.
        let r = reassemble(&body, 5);
        assert!(r.truncated);
        assert_eq!(r.document["content"][0]["text"], "abcd");
        assert_eq!(r.document["stop_reason"], "max_tokens");
        assert_eq!(r.document["usage"]["output_tokens"], 3);
    }

    /// The budget's cut of a tool input leaves JSON that does not
    /// parse; the input is the string it got to.
    #[test]
    fn a_cut_tool_input_is_kept_as_a_string() {
        let body = stream(&[
            (
                "content_block_start",
                json!({"type": "content_block_start", "index": 0,
                       "content_block": {"type": "tool_use", "id": "t", "input": {}}}),
            ),
            (
                "content_block_delta",
                json!({"type": "content_block_delta", "index": 0,
                       "delta": {"type": "input_json_delta", "partial_json": "{\"city\": \"Paris\"}"}}),
            ),
        ]);
        let r = reassemble(&body, 6);
        assert!(r.truncated);
        assert_eq!(r.document["content"][0]["input"], "{\"city");
    }

    #[test]
    fn a_malformed_event_marks_the_document_truncated() {
        let mut body = stream(&[(
            "message_start",
            json!({"type": "message_start", "message": {"id": "msg_1"}}),
        )]);
        body.extend_from_slice(b"event: content_block_delta\ndata: {\"type\": \n\n");
        let r = reassemble(&body, 4096);
        assert!(r.truncated);
        assert_eq!(r.document["id"], "msg_1");
    }

    /// The structure allowance bounds what a stream of nothing but new
    /// blocks can make the document hold.
    #[test]
    fn the_structure_allowance_bounds_the_document() {
        let mut destream = Destream::new(4096);
        for index in 0..5_000 {
            destream.feed(
                stream(&[(
                    "content_block_start",
                    json!({"type": "content_block_start", "index": index,
                           "content_block": {"type": "text", "text": ""}}),
                )])
                .as_slice(),
            );
        }
        let r = destream.finish().unwrap();
        assert!(r.truncated);
        assert!(
            r.document.to_string().len() <= STRUCTURE_CAP,
            "{}",
            r.document
        );
    }

    /// Another stream format, here the Responses API's, is not
    /// reassembled, nor is a stream that carried no JSON.
    #[test]
    fn other_streams_are_not_understood() {
        let mut responses = Destream::new(4096);
        responses.feed(&stream(&[(
            "response.created",
            json!({"type": "response.created", "response": {}}),
        )]));
        assert!(!responses.understood());
        assert!(responses.finish().is_none());

        let mut text = Destream::new(4096);
        text.feed(b"data: hello\n\n");
        assert!(text.finish().is_none());
    }

    #[test]
    fn keys_are_written_in_the_providers_order() {
        let doc = json!({
            "usage": {"output_tokens": 1}, "stop_reason": "end_turn", "role": "assistant",
            "model": "m", "id": "msg_1", "type": "message", "zeta": 1, "alpha": "a\"b",
            "content": [{"text": "hi", "type": "text"}],
        });
        assert_eq!(
            Ordered(&doc).to_string(),
            r#"{"type":"message","id":"msg_1","role":"assistant","model":"m","content":[{"type":"text","text":"hi"}],"stop_reason":"end_turn","usage":{"output_tokens":1},"alpha":"a\"b","zeta":1}"#
        );
    }
}

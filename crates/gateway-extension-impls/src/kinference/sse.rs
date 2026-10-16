//! A bounded, incremental Server-Sent Events splitter: response
//! chunks in, whole events out, wherever the chunk boundaries fall.
//!
//! Only the `event` and `data` fields mean anything here; `id`,
//! `retry` and comments are skipped. Lines end at `\n`, with a
//! trailing `\r` dropped, which covers the `\n` and `\r\n` framings
//! inference servers emit; a bare `\r` line ending is not recognized.
//!
//! Every buffer is capped, so a line of any length costs at most the
//! cap. The field name leads its line and always survives the cut; an
//! event any of whose lines was cut short is flagged `truncated`
//! rather than dropped, so a caller still learns that it happened and
//! what kind it was.

/// Cap on one buffered line.
const LINE_CAP: usize = 16 * 1024;
/// Cap on one event's joined data.
const DATA_CAP: usize = 16 * 1024;

/// One dispatched event, borrowed from the splitter until the
/// callback returns.
pub(crate) struct Event<'a> {
    /// The `event` field; empty when the event named none.
    pub(crate) kind: &'a [u8],
    /// The `data` lines, joined with `\n`.
    pub(crate) data: &'a [u8],
    /// Whether a line of this event ran past a cap, cutting its data
    /// short.
    pub(crate) truncated: bool,
}

/// Splitter state carried between chunks: the partial line, and the
/// fields of the event that line belongs to.
#[derive(Default)]
pub(crate) struct Splitter {
    line: Vec<u8>,
    /// The line in `line` ran past [`LINE_CAP`]; the rest of it is
    /// being skipped.
    line_truncated: bool,
    kind: Vec<u8>,
    data: Vec<u8>,
    /// Whether the event has a `data` field at all. The spec only
    /// dispatches events that do, and an empty `data:` line counts.
    has_data: bool,
    truncated: bool,
}

impl Splitter {
    /// Feed one chunk, calling `on_event` for every event the chunk
    /// completes, in order.
    pub(crate) fn feed(&mut self, chunk: &[u8], mut on_event: impl FnMut(Event<'_>)) {
        let mut rest = chunk;
        while let Some(nl) = rest.iter().position(|&b| b == b'\n') {
            self.push_line(&rest[..nl]);
            self.end_line(&mut on_event);
            rest = &rest[nl + 1..];
        }
        self.push_line(rest);
    }

    fn push_line(&mut self, bytes: &[u8]) {
        let room = LINE_CAP - self.line.len();
        if bytes.len() > room {
            self.line_truncated = true;
        }
        self.line.extend_from_slice(&bytes[..bytes.len().min(room)]);
    }

    fn end_line(&mut self, on_event: &mut impl FnMut(Event<'_>)) {
        let mut line = std::mem::take(&mut self.line);
        let truncated = std::mem::take(&mut self.line_truncated);
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.is_empty() {
            self.dispatch(on_event);
        } else {
            self.field(&line, truncated);
        }
        // Keep the allocation for the next line.
        line.clear();
        self.line = line;
    }

    fn field(&mut self, line: &[u8], truncated: bool) {
        let (name, value) = match line.iter().position(|&b| b == b':') {
            // A leading ':' is a comment.
            Some(0) => return,
            Some(i) => {
                let value = &line[i + 1..];
                (&line[..i], value.strip_prefix(b" ").unwrap_or(value))
            }
            None => (line, &[][..]),
        };
        match name {
            b"event" => {
                self.kind.clear();
                self.kind.extend_from_slice(value);
                self.truncated |= truncated;
            }
            b"data" => {
                if self.has_data {
                    self.push_data(b"\n");
                }
                self.push_data(value);
                self.has_data = true;
                self.truncated |= truncated;
            }
            _ => {}
        }
    }

    fn push_data(&mut self, bytes: &[u8]) {
        let room = DATA_CAP - self.data.len();
        if bytes.len() > room {
            self.truncated = true;
        }
        self.data.extend_from_slice(&bytes[..bytes.len().min(room)]);
    }

    fn dispatch(&mut self, on_event: &mut impl FnMut(Event<'_>)) {
        if self.has_data {
            on_event(Event {
                kind: &self.kind,
                data: &self.data,
                truncated: self.truncated,
            });
        }
        self.kind.clear();
        self.data.clear();
        self.has_data = false;
        self.truncated = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a feed dispatched, owned.
    #[derive(Debug, PartialEq, Eq)]
    struct Seen {
        kind: String,
        data: String,
        truncated: bool,
    }

    fn feed_all(splitter: &mut Splitter, chunks: &[&[u8]]) -> Vec<Seen> {
        let mut seen = Vec::new();
        for chunk in chunks {
            splitter.feed(chunk, |e| {
                seen.push(Seen {
                    kind: String::from_utf8_lossy(e.kind).into_owned(),
                    data: String::from_utf8_lossy(e.data).into_owned(),
                    truncated: e.truncated,
                });
            });
        }
        seen
    }

    fn seen(kind: &str, data: &str) -> Seen {
        Seen {
            kind: kind.into(),
            data: data.into(),
            truncated: false,
        }
    }

    #[test]
    fn events_survive_any_chunk_boundary() {
        let stream = b"event: message_start\ndata: {\"a\":1}\n\nevent: ping\ndata: {}\n\n";
        let whole = feed_all(&mut Splitter::default(), &[stream]);
        assert_eq!(
            whole,
            vec![seen("message_start", "{\"a\":1}"), seen("ping", "{}")]
        );
        // Every split point, including mid-field-name and between the
        // two newlines that end an event.
        for at in 1..stream.len() {
            let (a, b) = stream.split_at(at);
            assert_eq!(
                feed_all(&mut Splitter::default(), &[a, b]),
                whole,
                "split at {at}"
            );
        }
    }

    #[test]
    fn an_event_dispatches_only_at_its_blank_line() {
        let mut s = Splitter::default();
        assert!(feed_all(&mut s, &[b"event: content_block_delta\ndata: {}\n"]).is_empty());
        assert_eq!(
            feed_all(&mut s, &[b"\n"]),
            vec![seen("content_block_delta", "{}")]
        );
    }

    #[test]
    fn crlf_comments_and_multiline_data() {
        let events = feed_all(
            &mut Splitter::default(),
            &[b": keepalive\r\nevent:x\r\ndata: one\r\ndata:two\r\nid: 3\r\n\r\n"],
        );
        assert_eq!(events, vec![seen("x", "one\ntwo")]);
    }

    /// Chat-completions streams name no event; the kind is empty, and an event
    /// with no data at all is not dispatched.
    #[test]
    fn unnamed_events_and_dataless_events() {
        let events = feed_all(
            &mut Splitter::default(),
            &[b"data: {\"choices\":[]}\n\nevent: lonely\n\ndata: [DONE]\n\n"],
        );
        assert_eq!(
            events,
            vec![seen("", "{\"choices\":[]}"), seen("", "[DONE]")]
        );
    }

    #[test]
    fn an_oversized_line_is_cut_and_flagged_but_keeps_its_kind() {
        let mut s = Splitter::default();
        let big = vec![b'x'; 3 * LINE_CAP];
        let mut events = Vec::new();
        for chunk in [
            &b"event: content_block_delta\ndata: "[..],
            &big,
            &big,
            &b"\n\n"[..],
        ] {
            s.feed(chunk, |e| {
                events.push((e.kind.to_vec(), e.data.len(), e.truncated));
            });
            assert!(s.line.len() <= LINE_CAP, "the line buffer stays capped");
            assert!(s.data.len() <= DATA_CAP, "the data buffer stays capped");
        }
        assert_eq!(events.len(), 1);
        let (kind, len, truncated) = &events[0];
        assert_eq!(kind, b"content_block_delta");
        assert!(*len <= DATA_CAP);
        assert!(truncated);

        // The next event starts clean.
        assert_eq!(
            feed_all(&mut s, &[b"event: ping\ndata: {}\n\n"]),
            vec![seen("ping", "{}")]
        );
    }
}

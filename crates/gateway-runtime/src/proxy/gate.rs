//! Request-body gate: delivers body chunks to the route's extension
//! members. Two tiers, picked by the rule's strictest declared mode.
//! `Buffer` drains the body before dispatch ([`run`]); `Stream` pumps
//! frames toward an already-dispatched upstream ([`pump`]). Routes
//! whose members declare neither never enter this module.

use std::time::Duration;

use bytes::Bytes;
use http_body::{Body, Frame};
use http_body_util::{BodyExt, Full};
use tokio::sync::mpsc;

use crate::extension::{Action, BodyMode, Cx, LocalResponse, Member};
use crate::proxy::body::{BoxError, UpstreamBody};

/// Buffer-tier size cap. A memory bound: the whole body is held until
/// dispatch. Provisional global; per-extension caps arrive with the
/// extension config object.
pub(super) const REQUEST_BODY_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Stream-tier size cap. A denial-of-service bound, not a memory
/// bound — nothing is retained on this tier.
pub(super) const STREAM_BODY_MAX_BYTES: u64 = 1024 * 1024 * 1024;

/// Longest wait for the next body frame, both tiers. Per-frame rather
/// than a whole-body deadline, so a large upload that keeps moving is
/// never failed for being large.
pub(super) const REQUEST_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(15);

/// Stream-tier channel depth. Small, so a slow upstream backpressures
/// the client read instead of accumulating frames here.
pub(super) const BODY_PIPE_CAPACITY: usize = 4;

/// What the drain does with the bytes it reads.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum DrainMode {
    /// Accumulate and forward what was drained — the buffer tier on
    /// rules without a selector.
    ForwardBuffered,
    /// Accumulate and park in [`Cx::request_buffer`]; the selection
    /// phase decides what to forward.
    RetainForSelection,
    /// Deliver chunks to the hooks and retain nothing — a streaming
    /// rule whose selector supplies the forwarded body itself.
    DeliverOnly,
}

/// How a drain ended.
pub(super) enum GateOutcome {
    /// Body fully drained; forward this upstream.
    /// (`DrainMode::ForwardBuffered` only.)
    Forward(UpstreamBody),
    /// Body fully drained and delivered; selection decides next.
    Drained,
    Halt(Halt),
}

/// How the stream-tier pump ended. On `Halt` an error has been
/// injected into the pipe, so the upstream send is reset rather than
/// half-closed — a clean half-close would read as a complete body.
pub(super) enum PumpOutcome {
    Done,
    Halt(Halt),
}

/// A body phase that ends the request instead of forwarding it. The
/// caller maps each variant to its status and metrics reason.
/// The response is boxed: `Halt` travels as a `Result` error, and a
/// large `Err` variant fails `clippy::result_large_err`.
pub(super) enum Halt {
    Respond(Box<LocalResponse>),
    Failed,
    TooLarge,
    TimedOut,
}

/// What one round of hook delivery decided.
enum Delivery {
    Continue,
    Respond(LocalResponse),
    Failed,
}

/// Buffer tier: drain the whole body before dispatch, delivering each
/// chunk to the body members and accumulating into
/// [`Cx::request_buffer`]. Generic over the body so tests can drive
/// it with synthetic frames.
pub(super) async fn run<B>(
    members: &mut [Member],
    parts: &http::request::Parts,
    mut body: B,
    cx: &mut Cx,
    mode: DrainMode,
) -> GateOutcome
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    // Retaining modes are memory-bounded; deliver-only retains
    // nothing and gets the abuse bound instead.
    let cap = match mode {
        DrainMode::ForwardBuffered | DrainMode::RetainForSelection => REQUEST_BODY_MAX_BYTES,
        DrainMode::DeliverOnly => STREAM_BODY_MAX_BYTES,
    };

    // A declared length past the cap needs no reading to reject.
    if content_length(parts).is_some_and(|len| len > cap) {
        return GateOutcome::Halt(Halt::TooLarge);
    }

    let retain = mode != DrainMode::DeliverOnly;
    if retain {
        // `Some` from the first hook call on, empty body included —
        // the accessor's contract is "Some exactly when a buffering
        // drain ran".
        cx.append_request_buffer(&[]);
    }

    let mut total: u64 = 0;
    loop {
        let Ok(polled) = tokio::time::timeout(REQUEST_BODY_IDLE_TIMEOUT, body.frame()).await else {
            return GateOutcome::Halt(Halt::TimedOut);
        };
        let frame = match polled {
            // The stream is exhausted without having signalled
            // end-of-stream on a data frame (chunked bodies end
            // here): the terminal call carries an empty chunk.
            None => {
                return match deliver(members, &Bytes::new(), true, cx).await {
                    Delivery::Continue => drained(mode, cx),
                    Delivery::Respond(resp) => GateOutcome::Halt(Halt::Respond(Box::new(resp))),
                    Delivery::Failed => GateOutcome::Halt(Halt::Failed),
                };
            }
            Some(Err(e)) => {
                tracing::warn!(error = %e.into(), "reading request body failed");
                return GateOutcome::Halt(Halt::Failed);
            }
            Some(Ok(frame)) => frame,
        };
        // Trailer frames are dropped on this tier: the buffered body
        // is re-sent as a plain `Full`, which cannot carry them.
        let Ok(data) = frame.into_data() else {
            continue;
        };
        total += data.len() as u64;
        if total > cap {
            return GateOutcome::Halt(Halt::TooLarge);
        }
        if retain {
            cx.append_request_buffer(&data);
        }
        // A content-length body ends here, right after its last data
        // frame; its terminal `None` is never polled. Chunked bodies
        // stay `false` and end at the `None` arm above — between the
        // two, the end-of-stream call fires exactly once.
        let end_of_stream = body.is_end_stream();
        match deliver(members, &data, end_of_stream, cx).await {
            Delivery::Continue => {}
            Delivery::Respond(resp) => return GateOutcome::Halt(Halt::Respond(Box::new(resp))),
            Delivery::Failed => return GateOutcome::Halt(Halt::Failed),
        }
        if end_of_stream {
            return drained(mode, cx);
        }
    }
}

/// A drain that ran to the end: materialize the forwarded body, or
/// hand control back for selection with the buffer parked in `cx`.
fn drained(mode: DrainMode, cx: &mut Cx) -> GateOutcome {
    match mode {
        DrainMode::ForwardBuffered => forward_buffered(cx),
        DrainMode::RetainForSelection | DrainMode::DeliverOnly => GateOutcome::Drained,
    }
}

/// Stream tier: read frames, run the hooks, forward each frame into
/// `tx` toward the already-dispatched upstream. Nothing is retained
/// and [`Cx::request_buffer`] stays `None`. The caller joins this
/// with the response future.
pub(super) async fn pump<B>(
    members: &mut [Member],
    mut body: B,
    tx: mpsc::Sender<Result<Frame<Bytes>, BoxError>>,
    cx: &mut Cx,
) -> PumpOutcome
where
    B: Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    let mut total: u64 = 0;
    loop {
        let Ok(polled) = tokio::time::timeout(REQUEST_BODY_IDLE_TIMEOUT, body.frame()).await else {
            return abort(&tx, "request body idle timeout", Halt::TimedOut).await;
        };
        let frame = match polled {
            None => {
                return match deliver(members, &Bytes::new(), true, cx).await {
                    // Dropping `tx` half-closes the upstream body.
                    Delivery::Continue => PumpOutcome::Done,
                    Delivery::Respond(resp) => {
                        abort(&tx, "extension responded", Halt::Respond(Box::new(resp))).await
                    }
                    Delivery::Failed => abort(&tx, "request body hook failed", Halt::Failed).await,
                };
            }
            Some(Err(e)) => {
                let e = e.into();
                tracing::warn!(error = %e, "reading request body failed");
                let _ = tx.send(Err(e)).await;
                return PumpOutcome::Halt(Halt::Failed);
            }
            Some(Ok(frame)) => frame,
        };
        // Trailers pass through untouched and uncounted; hooks only
        // see data.
        let data = match frame.into_data() {
            Ok(data) => data,
            Err(trailers) => {
                if tx.send(Ok(trailers)).await.is_err() {
                    return PumpOutcome::Done;
                }
                continue;
            }
        };
        total += data.len() as u64;
        if total > STREAM_BODY_MAX_BYTES {
            return abort(&tx, "request body over stream cap", Halt::TooLarge).await;
        }
        let end_of_stream = body.is_end_stream();
        match deliver(members, &data, end_of_stream, cx).await {
            Delivery::Continue => {}
            Delivery::Respond(resp) => {
                return abort(&tx, "extension responded", Halt::Respond(Box::new(resp))).await;
            }
            Delivery::Failed => {
                return abort(&tx, "request body hook failed", Halt::Failed).await;
            }
        }
        if tx.send(Ok(Frame::data(data))).await.is_err() {
            // The upstream stopped reading; its response (or error)
            // tells the rest of the story.
            return PumpOutcome::Done;
        }
        if end_of_stream {
            return PumpOutcome::Done;
        }
    }
}

/// One chunk through every body-mode member, in list order.
async fn deliver(
    members: &mut [Member],
    chunk: &Bytes,
    end_of_stream: bool,
    cx: &mut Cx,
) -> Delivery {
    for member in members
        .iter_mut()
        .filter(|m| m.decl.request_body != BodyMode::None)
    {
        match member
            .ext
            .on_request_body(chunk.clone(), end_of_stream, cx)
            .await
        {
            Ok(Action::Continue) => {}
            Ok(Action::Respond(resp)) => return Delivery::Respond(resp),
            Err(e) => {
                tracing::warn!(error = %e, "request body hook failed");
                return Delivery::Failed;
            }
        }
    }
    Delivery::Continue
}

/// Inject an error into the pipe so hyper resets the upstream send,
/// then return the outcome. A reset, not a half-close: the upstream
/// must not mistake a truncated body for a complete one.
async fn abort(
    tx: &mpsc::Sender<Result<Frame<Bytes>, BoxError>>,
    why: &'static str,
    halt: Halt,
) -> PumpOutcome {
    let _ = tx.send(Err(why.into())).await;
    PumpOutcome::Halt(halt)
}

/// The drained body, re-materialized for the upstream. `Full`'s exact
/// size hint gives hyper the content length.
fn forward_buffered(cx: &mut Cx) -> GateOutcome {
    let buffered = cx.take_request_buffer().unwrap_or_default();
    GateOutcome::Forward(UpstreamBody::Full(Full::new(buffered.freeze())))
}

fn content_length(parts: &http::request::Parts) -> Option<u64> {
    parts
        .headers
        .get(http::header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use futures::stream;
    use http_body_util::StreamBody;
    use tokio_stream::wrappers::ReceiverStream;

    use crate::extension::Error;

    /// Records every chunk its body hook saw; optionally responds or
    /// errors at a given call index.
    struct Recorder {
        calls: Vec<(Vec<u8>, bool)>,
        buffer_seen: Vec<Option<usize>>,
        respond_at: Option<usize>,
    }

    struct Handle(std::sync::Arc<std::sync::Mutex<Recorder>>);

    #[async_trait]
    impl crate::extension::Extension for Handle {
        async fn on_request_body(
            &mut self,
            chunk: Bytes,
            end_of_stream: bool,
            cx: &mut Cx,
        ) -> Result<Action, Error> {
            let mut rec = self.0.lock().unwrap();
            rec.calls.push((chunk.to_vec(), end_of_stream));
            rec.buffer_seen.push(cx.request_buffer().map(<[u8]>::len));
            if rec.respond_at == Some(rec.calls.len() - 1) {
                return Ok(Action::Respond(LocalResponse {
                    status: http::StatusCode::TOO_MANY_REQUESTS,
                    headers: http::HeaderMap::new(),
                    body: Bytes::new(),
                }));
            }
            Ok(Action::Continue)
        }
    }

    fn member(
        mode: BodyMode,
        respond_at: Option<usize>,
    ) -> (Member, std::sync::Arc<std::sync::Mutex<Recorder>>) {
        let rec = std::sync::Arc::new(std::sync::Mutex::new(Recorder {
            calls: Vec::new(),
            buffer_seen: Vec::new(),
            respond_at,
        }));
        let member = Member {
            decl: crate::extension::Declarations {
                request_body: mode,
                ..Default::default()
            },
            ext: Box::new(Handle(std::sync::Arc::clone(&rec))),
        };
        (member, rec)
    }

    fn parts() -> http::request::Parts {
        let (parts, ()) = http::Request::new(()).into_parts();
        parts
    }

    fn parts_with_len(len: u64) -> http::request::Parts {
        let mut p = parts();
        p.headers.insert(http::header::CONTENT_LENGTH, len.into());
        p
    }

    /// A body that yields the given data frames and ends at the
    /// terminal `None` — `is_end_stream` stays false throughout, like
    /// a chunked upload.
    fn chunked(frames: &[&[u8]]) -> impl Body<Data = Bytes, Error = BoxError> + Unpin {
        let frames: Vec<Result<Frame<Bytes>, BoxError>> = frames
            .iter()
            .map(|c| Ok(Frame::data(Bytes::copy_from_slice(c))))
            .collect();
        StreamBody::new(stream::iter(frames))
    }

    #[tokio::test]
    async fn empty_body_delivers_one_terminal_call() {
        let (m, rec) = member(BodyMode::Buffer, None);
        let mut members = [m];
        let mut cx = Cx::new();
        let out = run(
            &mut members,
            &parts(),
            chunked(&[]),
            &mut cx,
            DrainMode::ForwardBuffered,
        )
        .await;
        assert!(matches!(out, GateOutcome::Forward(_)));

        let rec = rec.lock().unwrap();
        assert_eq!(rec.calls, vec![(vec![], true)]);
        // The buffer exists (empty) even for an empty body.
        assert_eq!(rec.buffer_seen, vec![Some(0)]);
    }

    #[tokio::test]
    async fn chunked_body_accumulates_and_flags_the_terminal_call() {
        let (m, rec) = member(BodyMode::Buffer, None);
        let mut members = [m];
        let mut cx = Cx::new();
        let out = run(
            &mut members,
            &parts(),
            chunked(&[b"hel", b"lo"]),
            &mut cx,
            DrainMode::ForwardBuffered,
        )
        .await;

        let GateOutcome::Forward(UpstreamBody::Full(full)) = out else {
            panic!("expected a buffered forward");
        };
        let forwarded = full.collect().await.unwrap().to_bytes();
        assert_eq!(forwarded, Bytes::from_static(b"hello"));

        let rec = rec.lock().unwrap();
        // Chunked bodies end at the terminal None: an empty final call.
        assert_eq!(
            rec.calls,
            vec![
                (b"hel".to_vec(), false),
                (b"lo".to_vec(), false),
                (vec![], true),
            ]
        );
        // The buffer includes the current chunk at every call.
        assert_eq!(rec.buffer_seen, vec![Some(3), Some(5), Some(5)]);
    }

    #[tokio::test]
    async fn content_length_body_ends_on_its_last_frame_exactly_once() {
        // `Full` reports end-of-stream right after its single frame;
        // its terminal `None` must never produce a second call.
        let (m, rec) = member(BodyMode::Buffer, None);
        let mut members = [m];
        let mut cx = Cx::new();
        let body = Full::new(Bytes::from_static(b"payload"));
        let out = run(
            &mut members,
            &parts_with_len(7),
            body,
            &mut cx,
            DrainMode::ForwardBuffered,
        )
        .await;
        assert!(matches!(out, GateOutcome::Forward(_)));

        let rec = rec.lock().unwrap();
        assert_eq!(rec.calls, vec![(b"payload".to_vec(), true)]);
    }

    #[tokio::test]
    async fn over_cap_rejects_on_both_paths() {
        // Declared up front: rejected before a single hook call.
        let (m, rec) = member(BodyMode::Buffer, None);
        let mut members = [m];
        let mut cx = Cx::new();
        let out = run(
            &mut members,
            &parts_with_len(REQUEST_BODY_MAX_BYTES + 1),
            chunked(&[b"never read"]),
            &mut cx,
            DrainMode::ForwardBuffered,
        )
        .await;
        assert!(matches!(out, GateOutcome::Halt(Halt::TooLarge)));
        assert!(rec.lock().unwrap().calls.is_empty());

        // Undeclared: rejected from the running total mid-body.
        let (m, _rec) = member(BodyMode::Buffer, None);
        let mut members = [m];
        let mut cx = Cx::new();
        let big = vec![0u8; usize::try_from(REQUEST_BODY_MAX_BYTES).unwrap() + 1];
        let out = run(
            &mut members,
            &parts(),
            chunked(&[&big]),
            &mut cx,
            DrainMode::ForwardBuffered,
        )
        .await;
        assert!(matches!(out, GateOutcome::Halt(Halt::TooLarge)));
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_client_times_out() {
        let (m, _rec) = member(BodyMode::Buffer, None);
        let mut members = [m];
        let mut cx = Cx::new();
        let body = StreamBody::new(stream::pending::<Result<Frame<Bytes>, BoxError>>());
        let out = run(
            &mut members,
            &parts(),
            body,
            &mut cx,
            DrainMode::ForwardBuffered,
        )
        .await;
        assert!(matches!(out, GateOutcome::Halt(Halt::TimedOut)));
    }

    #[tokio::test]
    async fn respond_mid_body_stops_the_drain() {
        let (m, rec) = member(BodyMode::Buffer, Some(0));
        let mut members = [m];
        let mut cx = Cx::new();
        let out = run(
            &mut members,
            &parts(),
            chunked(&[b"a", b"b"]),
            &mut cx,
            DrainMode::ForwardBuffered,
        )
        .await;
        let GateOutcome::Halt(Halt::Respond(resp)) = out else {
            panic!("expected the extension's response");
        };
        assert_eq!(resp.status, http::StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(rec.lock().unwrap().calls.len(), 1);
    }

    #[tokio::test]
    async fn mixed_rule_delivers_to_stream_members_too() {
        let (buffered, rec_b) = member(BodyMode::Buffer, None);
        let (streaming, rec_s) = member(BodyMode::Stream, None);
        let (none, rec_n) = member(BodyMode::None, None);
        let mut members = [buffered, streaming, none];
        let mut cx = Cx::new();
        let out = run(
            &mut members,
            &parts(),
            chunked(&[b"x"]),
            &mut cx,
            DrainMode::ForwardBuffered,
        )
        .await;
        assert!(matches!(out, GateOutcome::Forward(_)));
        assert_eq!(rec_b.lock().unwrap().calls.len(), 2);
        assert_eq!(rec_s.lock().unwrap().calls.len(), 2);
        assert!(rec_n.lock().unwrap().calls.is_empty());
    }

    #[tokio::test]
    async fn pump_forwards_chunks_and_leaves_the_buffer_empty() {
        let (m, rec) = member(BodyMode::Stream, None);
        let mut members = [m];
        let mut cx = Cx::new();
        let (tx, rx) = mpsc::channel(BODY_PIPE_CAPACITY);
        let collect = tokio::spawn(async move {
            StreamBody::new(ReceiverStream::new(rx))
                .collect()
                .await
                .map(http_body_util::Collected::to_bytes)
        });
        let out = pump(&mut members, chunked(&[b"one", b"two"]), tx, &mut cx).await;
        assert!(matches!(out, PumpOutcome::Done));
        assert_eq!(
            collect.await.unwrap().unwrap(),
            Bytes::from_static(b"onetwo")
        );

        let rec = rec.lock().unwrap();
        assert_eq!(rec.calls.len(), 3);
        // Nothing retained on the stream tier.
        assert_eq!(rec.buffer_seen, vec![None, None, None]);
    }

    #[tokio::test]
    async fn pump_respond_injects_an_error_into_the_pipe() {
        let (m, _rec) = member(BodyMode::Stream, Some(0));
        let mut members = [m];
        let mut cx = Cx::new();
        let (tx, mut rx) = mpsc::channel(BODY_PIPE_CAPACITY);
        let out = pump(&mut members, chunked(&[b"a"]), tx, &mut cx).await;
        assert!(matches!(out, PumpOutcome::Halt(Halt::Respond(_))));
        // The pipe carries the injected error, so hyper resets the
        // upstream instead of half-closing a truncated body.
        assert!(rx.recv().await.unwrap().is_err());
    }
}

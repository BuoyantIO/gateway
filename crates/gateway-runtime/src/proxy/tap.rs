//! Response-side extension hooks. The instances outlive the request
//! handler — they have to, because the response is still streaming
//! when it returns — so they move into a body wrapper that taps each
//! frame on its way to the client and fires the terminal hook once,
//! however the response ends.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::StatusCode;
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;

use crate::extension::{Cx, Instance, ResponseEnd, ResponseMode};
use crate::proxy::body::BoxError;
use crate::proxy::http::ResponseBody;

/// Whether a route's instances need the response phase at all. A route
/// whose instances only touch the request — every core filter — is
/// handed back untouched: no wrapper, no box, no extra poll on each
/// frame.
pub(super) fn wants_response_phase(instances: &[Instance]) -> bool {
    instances
        .iter()
        .any(|m| m.decl.response != ResponseMode::None)
}

/// Wrap `body` so the instances see it stream past and hear about its
/// ending. Consumes the instances and the context: the request phase is
/// over and nothing needs them back.
pub(super) fn tap(
    body: ResponseBody,
    instances: Vec<Instance>,
    cx: Cx,
    status: StatusCode,
    upstream: bool,
) -> ResponseBody {
    TappedBody {
        inner: body,
        instances,
        cx,
        status,
        upstream,
        bytes: 0,
        armed: true,
    }
    .boxed_unsync()
}

/// Fire the terminal on instances that never reached the response
/// phase — a request answered before an upstream response existed.
/// The status is whatever was synthesized, so an extension settling
/// a reservation sees the same shape it would on a served request.
pub(super) fn end_without_response(instances: &mut [Instance], cx: &mut Cx, status: StatusCode) {
    let end = ResponseEnd {
        status,
        body_bytes: 0,
        complete: false,
        upstream: false,
    };
    for instance in instances
        .iter_mut()
        .rev()
        .filter(|m| m.decl.response != ResponseMode::None)
    {
        instance.ext.on_response_end(&end, cx);
    }
}

struct TappedBody {
    inner: ResponseBody,
    instances: Vec<Instance>,
    cx: Cx,
    status: StatusCode,
    /// Whether the status came from an upstream response — false for
    /// a response synthesized after dispatch (a dial-failure 502).
    upstream: bool,
    bytes: u64,
    /// Cleared when the terminal fires. Still set in `Drop` means the
    /// response never finished — the client went away mid-stream.
    armed: bool,
}

impl TappedBody {
    /// Runs the terminal hook once. Every later call is a no-op, so
    /// the end-of-stream paths and `Drop` can all call it freely.
    fn end(&mut self, complete: bool) {
        if !self.armed {
            return;
        }
        self.armed = false;
        let end = ResponseEnd {
            status: self.status,
            body_bytes: self.bytes,
            complete,
            upstream: self.upstream,
        };
        for instance in self
            .instances
            .iter_mut()
            .rev()
            .filter(|m| m.decl.response != ResponseMode::None)
        {
            instance.ext.on_response_end(&end, &mut self.cx);
        }
    }

    fn deliver(&mut self, chunk: &Bytes, end_of_stream: bool) {
        for instance in self
            .instances
            .iter_mut()
            .rev()
            .filter(|m| m.decl.response == ResponseMode::Tap)
        {
            instance
                .ext
                .on_response_body(chunk.clone(), end_of_stream, &mut self.cx);
        }
    }
}

impl Body for TappedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.bytes += data.len() as u64;
                    // A content-length response ends right after its
                    // last data frame; its terminal `None` is never
                    // polled. Chunked responses stay `false` here and
                    // end below. `armed` keeps the two from firing
                    // twice between them.
                    let end_of_stream = this.inner.is_end_stream();
                    this.deliver(data, end_of_stream);
                    if end_of_stream {
                        this.end(true);
                    }
                }
            }
            Poll::Ready(None) => {
                // Ended on a frame boundary: the terminal chunk is
                // empty, matching the request side's contract.
                if this.armed {
                    this.deliver(&Bytes::new(), true);
                    this.end(true);
                }
            }
            Poll::Ready(Some(Err(_))) => this.end(false),
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for TappedBody {
    fn drop(&mut self) {
        // Still armed means the response never completed — most often
        // the client disconnected while it was streaming.
        self.end(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use futures::StreamExt as _;
    use futures::stream;
    use http_body_util::{Full, StreamBody};

    use crate::extension::Extension;

    /// What one instance's response hooks observed.
    #[derive(Default)]
    struct Seen {
        chunks: Vec<(Vec<u8>, bool)>,
        ends: Vec<ResponseEnd>,
    }

    struct Probe {
        label: &'static str,
        seen: Arc<Mutex<Seen>>,
        order: Arc<Mutex<Vec<&'static str>>>,
    }

    #[async_trait]
    impl Extension for Probe {
        fn on_response_body(&mut self, chunk: Bytes, end_of_stream: bool, _cx: &mut Cx) {
            self.seen
                .lock()
                .unwrap()
                .chunks
                .push((chunk.to_vec(), end_of_stream));
            self.order.lock().unwrap().push(self.label);
        }

        fn on_response_end(&mut self, end: &ResponseEnd, _cx: &mut Cx) {
            self.seen.lock().unwrap().ends.push(*end);
        }
    }

    fn instance(
        label: &'static str,
        mode: ResponseMode,
        order: &Arc<Mutex<Vec<&'static str>>>,
    ) -> (Instance, Arc<Mutex<Seen>>) {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let instance = Instance {
            decl: crate::extension::Declarations {
                response: mode,
                ..Default::default()
            },
            failure_mode: gateway_config::extension::FailureMode::Closed,
            ext: Box::new(Probe {
                label,
                seen: Arc::clone(&seen),
                order: Arc::clone(order),
            }),
        };
        (instance, seen)
    }

    /// Ends at the terminal `None`, like a chunked response.
    fn chunked(frames: &[&[u8]]) -> ResponseBody {
        let frames: Vec<Result<Frame<Bytes>, BoxError>> = frames
            .iter()
            .map(|c| Ok(Frame::data(Bytes::copy_from_slice(c))))
            .collect();
        StreamBody::new(stream::iter(frames)).boxed_unsync()
    }

    /// Reports end-of-stream on its last data frame, like a
    /// content-length response.
    fn sized(bytes: &'static [u8]) -> ResponseBody {
        Full::new(Bytes::from_static(bytes))
            .map_err(|never: std::convert::Infallible| match never {})
            .boxed_unsync()
    }

    async fn drain(body: ResponseBody) -> Bytes {
        body.collect().await.expect("collect").to_bytes()
    }

    #[tokio::test]
    async fn chunks_reach_members_in_reverse_order_and_pass_through_intact() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let (first, seen_first) = instance("first", ResponseMode::Tap, &order);
        let (second, seen_second) = instance("second", ResponseMode::Tap, &order);

        let body = tap(
            chunked(&[b"one", b"two"]),
            vec![first, second],
            Cx::new(),
            StatusCode::OK,
            true,
        );
        assert_eq!(drain(body).await, Bytes::from_static(b"onetwo"));

        // Response side runs reverse-of-request.
        assert_eq!(
            *order.lock().unwrap(),
            vec!["second", "first", "second", "first", "second", "first"]
        );
        let chunks = &seen_first.lock().unwrap().chunks;
        assert_eq!(
            *chunks,
            vec![
                (b"one".to_vec(), false),
                (b"two".to_vec(), false),
                (vec![], true),
            ]
        );
        assert_eq!(seen_second.lock().unwrap().chunks.len(), 3);
    }

    #[tokio::test]
    async fn a_sized_response_fires_the_terminal_exactly_once() {
        // Ends via `is_end_stream` after its last frame; the terminal
        // `None` never arrives, so the latch is what prevents a miss.
        let order = Arc::new(Mutex::new(Vec::new()));
        let (m, seen) = instance("m", ResponseMode::Tap, &order);
        let body = tap(sized(b"payload"), vec![m], Cx::new(), StatusCode::OK, true);
        assert_eq!(drain(body).await, Bytes::from_static(b"payload"));

        let seen = seen.lock().unwrap();
        assert_eq!(seen.chunks, vec![(b"payload".to_vec(), true)]);
        assert_eq!(
            seen.ends,
            vec![ResponseEnd {
                status: StatusCode::OK,
                body_bytes: 7,
                complete: true,
                upstream: true,
            }]
        );
    }

    #[tokio::test]
    async fn a_chunked_response_fires_the_terminal_exactly_once() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let (m, seen) = instance("m", ResponseMode::Tap, &order);
        let body = tap(
            chunked(&[b"ab"]),
            vec![m],
            Cx::new(),
            StatusCode::CREATED,
            true,
        );
        drain(body).await;

        let seen = seen.lock().unwrap();
        assert_eq!(
            seen.ends,
            vec![ResponseEnd {
                status: StatusCode::CREATED,
                body_bytes: 2,
                complete: true,
                upstream: true,
            }]
        );
    }

    #[tokio::test]
    async fn a_synthesized_response_reports_no_upstream() {
        // A dial-failure 502 streams through the wrapper like any
        // response; the terminal says no upstream answered.
        let order = Arc::new(Mutex::new(Vec::new()));
        let (m, seen) = instance("m", ResponseMode::End, &order);
        let body = tap(
            sized(b"bad gateway"),
            vec![m],
            Cx::new(),
            StatusCode::BAD_GATEWAY,
            false,
        );
        drain(body).await;

        let seen = seen.lock().unwrap();
        assert_eq!(
            seen.ends,
            vec![ResponseEnd {
                status: StatusCode::BAD_GATEWAY,
                body_bytes: 11,
                complete: true,
                upstream: false,
            }]
        );
    }

    #[tokio::test]
    async fn dropping_mid_stream_fires_the_terminal_as_incomplete() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let (m, seen) = instance("m", ResponseMode::Tap, &order);
        let mut body = tap(
            chunked(&[b"first", b"second"]),
            vec![m],
            Cx::new(),
            StatusCode::OK,
            true,
        );

        // One frame, then walk away — the client disconnect case.
        let frame = body.frame().await.expect("a frame").expect("ok");
        assert_eq!(frame.into_data().unwrap(), Bytes::from_static(b"first"));
        drop(body);

        let seen = seen.lock().unwrap();
        assert_eq!(
            seen.ends,
            vec![ResponseEnd {
                status: StatusCode::OK,
                body_bytes: 5,
                complete: false,
                upstream: true,
            }]
        );
    }

    #[tokio::test]
    async fn a_member_without_response_access_sees_no_chunks_but_still_ends() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let (m, seen) = instance("m", ResponseMode::End, &order);
        let body = tap(
            chunked(&[b"data"]),
            vec![m],
            Cx::new(),
            StatusCode::OK,
            true,
        );
        drain(body).await;

        let seen = seen.lock().unwrap();
        assert!(seen.chunks.is_empty());
        // The terminal is not gated on body access: a limiter that
        // never reads a byte still has to settle.
        assert_eq!(seen.ends.len(), 1);
    }

    /// A tapped response must reach the client frame by frame. If the
    /// wrapper ever buffered, a stream that never ends would hang
    /// here instead of yielding its first frame.
    #[tokio::test]
    async fn a_tapped_response_streams_rather_than_buffering() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let (m, seen) = instance("m", ResponseMode::Tap, &order);

        // Two frames, then a pending tail that never completes.
        let head = stream::iter(vec![
            Ok::<_, BoxError>(Frame::data(Bytes::from_static(b"event: one\n"))),
            Ok(Frame::data(Bytes::from_static(b"event: two\n"))),
        ]);
        let never_ends = head.chain(stream::pending());
        let body = tap(
            StreamBody::new(never_ends).boxed_unsync(),
            vec![m],
            Cx::new(),
            StatusCode::OK,
            true,
        );
        let mut body = body;

        for expected in [&b"event: one\n"[..], &b"event: two\n"[..]] {
            let frame = tokio::time::timeout(std::time::Duration::from_secs(1), body.frame())
                .await
                .expect("frame withheld — the tap buffered")
                .expect("a frame")
                .expect("ok");
            assert_eq!(frame.into_data().unwrap(), Bytes::copy_from_slice(expected));
        }

        // Both frames reached the tap as they passed, with the stream
        // still open.
        assert_eq!(seen.lock().unwrap().chunks.len(), 2);
    }

    #[test]
    fn a_request_only_route_is_not_wrapped_at_all() {
        // The core filters are this: they touch headers on the way in
        // and want nothing on the way back. Wrapping them would cost
        // a box and a poll per frame to drive no-op hooks.
        let order = Arc::new(Mutex::new(Vec::new()));
        let (request_only, _) = instance("m", ResponseMode::None, &order);
        assert!(!wants_response_phase(std::slice::from_ref(&request_only)));

        // Either interest above `None` earns the wrapper.
        let (tapping, _) = instance("t", ResponseMode::Tap, &order);
        assert!(wants_response_phase(std::slice::from_ref(&tapping)));

        let (settling, _) = instance("s", ResponseMode::End, &order);
        assert!(wants_response_phase(std::slice::from_ref(&settling)));
    }

    #[test]
    fn short_circuited_requests_still_reach_the_terminal() {
        let order = Arc::new(Mutex::new(Vec::new()));
        let (m, seen) = instance("m", ResponseMode::End, &order);
        let mut instances = vec![m];
        let mut cx = Cx::new();
        end_without_response(&mut instances, &mut cx, StatusCode::PAYLOAD_TOO_LARGE);

        let seen = seen.lock().unwrap();
        assert_eq!(
            seen.ends,
            vec![ResponseEnd {
                status: StatusCode::PAYLOAD_TOO_LARGE,
                body_bytes: 0,
                complete: false,
                upstream: false,
            }]
        );
    }
}

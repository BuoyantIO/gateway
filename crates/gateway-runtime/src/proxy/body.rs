//! Request bodies on their way upstream: the shapes they can take,
//! and the framing headers each shape implies. The gate produces the
//! first two; an extension that rewrites a request supplies the rest.

use bytes::{Bytes, BytesMut};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{Full, StreamBody, combinators::BoxBody};
use hyper::body::Incoming;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio_stream::wrappers::ReceiverStream;

use crate::extension::BodySource;

pub(super) type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Request body forwarded upstream. An enum, not a boxed body: every
/// source is known at compile time, and only routes that declare body
/// access pay for anything beyond the passthrough.
pub(super) enum UpstreamBody {
    /// The client's own stream, forwarded as-is.
    Incoming(Incoming),
    /// A complete body the gate drained and re-materialized.
    Full(Full<Bytes>),
    /// Frames pumped through the extension hooks while the request is
    /// in flight. Unknown size hint: the client's own content-length
    /// header (if any) frames the request.
    Stream(StreamBody<ReceiverStream<Result<Frame<Bytes>, BoxError>>>),
    /// A body an extension supplied. Boxed because its source is
    /// arbitrary — the allocation is confined to this path.
    /// Constructed only through [`apply_body_source`], so it stays
    /// unreachable until selection can return a `BodySource`.
    #[allow(dead_code)]
    Supplied(BoxBody<Bytes, BoxError>),
}

// Every variant is `Unpin`, so no pin projection is needed.
impl Body for UpstreamBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            Self::Incoming(b) => Pin::new(b)
                .poll_frame(cx)
                .map(|frame| frame.map(|r| r.map_err(Into::into))),
            Self::Full(b) => Pin::new(b)
                .poll_frame(cx)
                .map(|frame| frame.map(|r| r.map_err(Into::into))),
            Self::Stream(b) => Pin::new(b).poll_frame(cx),
            Self::Supplied(b) => Pin::new(b).poll_frame(cx),
        }
    }

    // Forwarded, not defaulted: hyper picks content-length vs chunked
    // framing from `size_hint`.
    fn is_end_stream(&self) -> bool {
        match self {
            Self::Incoming(b) => b.is_end_stream(),
            Self::Full(b) => b.is_end_stream(),
            Self::Stream(b) => b.is_end_stream(),
            Self::Supplied(b) => b.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Incoming(b) => b.size_hint(),
            Self::Full(b) => b.size_hint(),
            Self::Stream(b) => b.size_hint(),
            Self::Supplied(b) => b.size_hint(),
        }
    }
}

/// A body source the host cannot honor.
#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub(super) enum SupplyError {
    #[error("extension asked to forward the original body, but none was kept")]
    NothingHeld,
}

/// Turn an extension's chosen body source into the body that goes
/// upstream, fixing `parts` so the framing describes the bytes that
/// will actually be sent.
///
/// `content-length` is the whole difficulty. Hyper honors an explicit
/// header over the body's size hint, so a stale length left on a
/// rewritten request is sent verbatim and the upstream reads a
/// truncated or over-long body. `transfer-encoding` needs no handling
/// here: `forward` strips it as a hop-by-hop header.
///
/// # Errors
/// `Original` when the gate kept nothing to forward.
// Reachable once selection can return a `BodySource`; until then the
// unit tests below are the only callers.
#[allow(dead_code)]
pub(super) fn apply_body_source(
    source: BodySource,
    parts: &mut http::request::Parts,
    held: Option<BytesMut>,
) -> Result<UpstreamBody, SupplyError> {
    match source {
        // Unaltered bytes, so whatever the client declared is still
        // true. Nothing to fix.
        BodySource::Original => held
            .map(|buf| UpstreamBody::Full(Full::new(buf.freeze())))
            .ok_or(SupplyError::NothingHeld),

        // Different bytes, so the client's length is now a lie.
        // Removing it lets hyper set the true one from `Full`'s exact
        // size hint, which cannot drift from the body.
        BodySource::Replace(bytes) => {
            parts.headers.remove(http::header::CONTENT_LENGTH);
            Ok(UpstreamBody::Full(Full::new(bytes)))
        }

        // A declared total is the only thing that lets the upstream
        // tell a truncated request from a complete one, since neither
        // it nor we will ever hold the whole body. `Counted` makes
        // the claim binding.
        BodySource::Stream(body, Some(len)) => {
            parts
                .headers
                .insert(http::header::CONTENT_LENGTH, len.into());
            Ok(UpstreamBody::Supplied(BoxBody::new(Counted::new(
                body, len,
            ))))
        }

        // Length unknown: the client's content-length described a
        // different body, so it has to go. Chunked from here.
        BodySource::Stream(body, None) => {
            parts.headers.remove(http::header::CONTENT_LENGTH);
            Ok(UpstreamBody::Supplied(body))
        }
    }
}

/// Holds a streamed body to the length it declared. A body that ends
/// short or long fails instead of completing, so hyper resets the
/// upstream request rather than letting it look like a complete one.
struct Counted {
    inner: BoxBody<Bytes, BoxError>,
    declared: u64,
    seen: u64,
}

impl Counted {
    fn new(inner: BoxBody<Bytes, BoxError>, declared: u64) -> Self {
        Self {
            inner,
            declared,
            seen: 0,
        }
    }

    fn mismatch(&self) -> Option<BoxError> {
        (self.seen != self.declared).then(|| {
            BoxError::from(format!(
                "supplied body length mismatch: declared {}, got {}",
                self.declared, self.seen
            ))
        })
    }
}

impl Body for Counted {
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
                    this.seen += data.len() as u64;
                }
                // A body that declared its length ends on its last
                // data frame; its terminal `None` may never be
                // polled, so the check has to happen here too.
                if this.inner.is_end_stream()
                    && let Some(err) = this.mismatch()
                {
                    return Poll::Ready(Some(Err(err)));
                }
            }
            Poll::Ready(None) => {
                if let Some(err) = this.mismatch() {
                    return Poll::Ready(Some(Err(err)));
                }
            }
            Poll::Ready(Some(Err(_))) | Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.declared)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use http_body_util::{BodyExt, StreamBody};

    fn parts_with_len(len: Option<u64>) -> http::request::Parts {
        let (mut parts, ()) = http::Request::new(()).into_parts();
        if let Some(len) = len {
            parts
                .headers
                .insert(http::header::CONTENT_LENGTH, len.into());
        }
        parts
    }

    fn declared(parts: &http::request::Parts) -> Option<u64> {
        parts
            .headers
            .get(http::header::CONTENT_LENGTH)?
            .to_str()
            .ok()?
            .parse()
            .ok()
    }

    async fn drain(body: UpstreamBody) -> Result<Bytes, BoxError> {
        body.collect()
            .await
            .map(http_body_util::Collected::to_bytes)
    }

    /// A body of `chunks` whose declared size hint is unknown, so it
    /// stands in for anything an extension might supply.
    fn supplied(chunks: &[&[u8]]) -> BoxBody<Bytes, BoxError> {
        let frames: Vec<Result<Frame<Bytes>, BoxError>> = chunks
            .iter()
            .map(|c| Ok(Frame::data(Bytes::copy_from_slice(c))))
            .collect();
        BoxBody::new(StreamBody::new(futures::stream::iter(frames)))
    }

    #[test]
    fn upstream_body_forwards_full_framing() {
        let empty = UpstreamBody::Full(Full::new(Bytes::new()));
        assert!(empty.is_end_stream());
        assert_eq!(empty.size_hint().exact(), Some(0));

        let filled = UpstreamBody::Full(Full::new(Bytes::from_static(b"hello")));
        assert!(!filled.is_end_stream());
        assert_eq!(filled.size_hint().exact(), Some(5));
    }

    #[tokio::test]
    async fn upstream_body_full_yields_its_bytes() {
        let body = UpstreamBody::Full(Full::new(Bytes::from_static(b"payload")));
        assert_eq!(drain(body).await.unwrap(), Bytes::from_static(b"payload"));
    }

    #[tokio::test]
    async fn original_forwards_held_bytes_and_keeps_the_declared_length() {
        let mut parts = parts_with_len(Some(5));
        let held = BytesMut::from(&b"hello"[..]);
        let body = apply_body_source(BodySource::Original, &mut parts, Some(held)).unwrap();
        // Bytes are unaltered, so the client's length still describes
        // them and must survive untouched.
        assert_eq!(declared(&parts), Some(5));
        assert_eq!(drain(body).await.unwrap(), Bytes::from_static(b"hello"));
    }

    #[test]
    fn original_without_a_held_body_is_an_error() {
        let mut parts = parts_with_len(Some(5));
        let err = apply_body_source(BodySource::Original, &mut parts, None);
        // Never a silent empty body: the request would reach the
        // upstream stripped of its payload.
        assert!(matches!(err, Err(SupplyError::NothingHeld)));
    }

    #[tokio::test]
    async fn replace_drops_the_stale_length_so_hyper_recomputes_it() {
        // Longer and shorter than what the client declared: both must
        // leave no length behind for hyper to trust.
        for replacement in [&b"much longer than eleven"[..], &b"tiny"[..]] {
            let mut parts = parts_with_len(Some(11));
            let bytes = Bytes::copy_from_slice(replacement);
            let body =
                apply_body_source(BodySource::Replace(bytes.clone()), &mut parts, None).unwrap();
            assert_eq!(declared(&parts), None, "stale length survived a replace");
            // The exact size hint is what hyper frames from instead.
            assert_eq!(body.size_hint().exact(), Some(replacement.len() as u64));
            assert_eq!(drain(body).await.unwrap(), bytes);
        }
    }

    #[tokio::test]
    async fn supplied_stream_declares_the_length_it_was_given() {
        let mut parts = parts_with_len(Some(11));
        let source = BodySource::Stream(supplied(&[b"one", b"two"]), Some(6));
        let body = apply_body_source(source, &mut parts, None).unwrap();
        assert_eq!(declared(&parts), Some(6));
        assert_eq!(drain(body).await.unwrap(), Bytes::from_static(b"onetwo"));
    }

    #[tokio::test]
    async fn supplied_stream_without_a_length_goes_chunked() {
        let mut parts = parts_with_len(Some(11));
        let source = BodySource::Stream(supplied(&[b"body"]), None);
        let body = apply_body_source(source, &mut parts, None).unwrap();
        // The client's length described a different body, so it goes;
        // an unknown size hint leaves hyper to chunk it.
        assert_eq!(declared(&parts), None);
        assert_eq!(body.size_hint().exact(), None);
        assert_eq!(drain(body).await.unwrap(), Bytes::from_static(b"body"));
    }

    #[tokio::test]
    async fn a_stream_that_ends_short_or_long_fails_instead_of_completing() {
        for (chunks, declared_len) in [
            (&[&b"short"[..]][..], 99),
            (&[&b"much too long"[..]][..], 2),
        ] {
            let mut parts = parts_with_len(None);
            let source = BodySource::Stream(supplied(chunks), Some(declared_len));
            let body = apply_body_source(source, &mut parts, None).unwrap();
            let err = drain(body).await.expect_err("length mismatch must fail");
            assert!(
                err.to_string().contains("length mismatch"),
                "unexpected error: {err}"
            );
        }
    }

    #[tokio::test]
    async fn a_stream_matching_its_declared_length_passes_through() {
        let mut parts = parts_with_len(None);
        let source = BodySource::Stream(supplied(&[b"ab", b"cd"]), Some(4));
        let body = apply_body_source(source, &mut parts, None).unwrap();
        assert_eq!(drain(body).await.unwrap(), Bytes::from_static(b"abcd"));
    }
}

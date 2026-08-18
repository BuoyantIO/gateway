//! Data-plane metric schema.
//!
//! Every series follows the same label policy: identity labels are
//! config-derived names (`bind`, `listener`, `route`) whose
//! cardinality is bounded by the applied config, never by traffic;
//! `status` and `reason` live on the request counter only, so the
//! histogram stays cheap; `reason` is a closed enum and absent
//! identities encode as `"unknown"`. Raw request attributes (path,
//! host, client address) are never labels.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use prometheus_client::encoding::{EncodeLabelSet, EncodeLabelValue, LabelValueEncoder};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::{Registry, Unit};

/// Request-duration buckets, in seconds. Deliberately coarse: each
/// bucket is a full time series per label combination.
const DURATION_BUCKETS: [f64; 7] = [0.005, 0.025, 0.1, 0.5, 1.0, 5.0, 10.0];

/// Label value for an identity the request never acquired (no
/// listener matched, no route matched).
const UNKNOWN: &str = "unknown";

/// Handles to every data-plane metric family. Cheap to clone via
/// `Arc`; construction does not require a registry so tests and
/// registry-less callers can record into detached families.
#[derive(Debug)]
pub struct Metrics {
    requests: Family<RequestLabels, Counter>,
    duration: Family<DurationLabels, Histogram>,
}

impl Metrics {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            requests: Family::default(),
            duration: Family::new_with_constructor(|| {
                Histogram::new(DURATION_BUCKETS.iter().copied())
            }),
        })
    }

    /// Register the families. The registry's prefix supplies the
    /// `gateway_` namespace; the library appends `_total` and unit
    /// suffixes.
    pub fn register(&self, registry: &mut Registry) {
        registry.register(
            "requests",
            "HTTP requests served, by matched route, response status, and reason",
            self.requests.clone(),
        );
        registry.register_with_unit(
            "request_duration",
            "End-to-end request duration, by matched route",
            Unit::Seconds,
            self.duration.clone(),
        );
    }

    /// Record one completed request. `listener`/`route` are `None`
    /// when the request never matched one. Called by the proxy; public
    /// so out-of-crate tests can seed families.
    pub fn record_request(
        &self,
        bind: &str,
        listener: Option<&str>,
        route: Option<&str>,
        status: u16,
        reason: Reason,
        elapsed: Duration,
    ) {
        let listener = listener.unwrap_or(UNKNOWN);
        let route = route.unwrap_or(UNKNOWN);
        self.requests
            .get_or_create(&RequestLabels {
                bind: bind.to_string(),
                listener: listener.to_string(),
                route: route.to_string(),
                status: u32::from(status),
                reason,
            })
            .inc();
        self.duration
            .get_or_create(&DurationLabels {
                bind: bind.to_string(),
                listener: listener.to_string(),
                route: route.to_string(),
            })
            .observe(elapsed.as_secs_f64());
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RequestLabels {
    bind: String,
    listener: String,
    route: String,
    status: u32,
    reason: Reason,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct DurationLabels {
    bind: String,
    listener: String,
    route: String,
}

/// Why a request ended the way it did — disambiguates what a status
/// code alone conflates (a 503 from "route has no backend" vs "no
/// healthy endpoint"). Closed set: only failure variants fan out
/// into extra series, and only when they occur. `Draining` is
/// reserved for a response-producing drain path; today draining
/// closes connections instead.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum Reason {
    Ok,
    NoRoute,
    NoBackend,
    BackendUnresolved,
    NoEndpoint,
    DialFailure,
    #[allow(dead_code)]
    Draining,
    Internal,
    /// The request body exceeded the gate's size cap.
    BodyTooLarge,
    /// The client stalled past the gate's idle bound mid-body.
    BodyTimeout,
}

impl Reason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Reason::Ok => "ok",
            Reason::NoRoute => "no_route",
            Reason::NoBackend => "no_backend",
            Reason::BackendUnresolved => "backend_unresolved",
            Reason::NoEndpoint => "no_endpoint",
            Reason::DialFailure => "dial_failure",
            Reason::Draining => "draining",
            Reason::Internal => "internal",
            Reason::BodyTooLarge => "body_too_large",
            Reason::BodyTimeout => "body_timeout",
        }
    }
}

impl EncodeLabelValue for Reason {
    fn encode(&self, encoder: &mut LabelValueEncoder<'_>) -> Result<(), fmt::Error> {
        EncodeLabelValue::encode(&self.as_str(), encoder)
    }
}

#[cfg(test)]
mod tests {
    use prometheus_client::encoding::text::encode;

    use super::*;

    fn render(metrics: &Metrics) -> String {
        let mut registry = Registry::with_prefix("gateway");
        metrics.register(&mut registry);
        let mut out = String::new();
        encode(&mut out, &registry).expect("encode");
        out
    }

    #[test]
    fn recorded_request_renders_counter_and_histogram() {
        let metrics = Metrics::new();
        metrics.record_request(
            "b1",
            Some("web"),
            Some("route-a"),
            200,
            Reason::Ok,
            Duration::from_millis(30),
        );
        metrics.record_request(
            "b1",
            Some("web"),
            Some("route-a"),
            200,
            Reason::Ok,
            Duration::from_millis(700),
        );

        let out = render(&metrics);
        let counter = out
            .lines()
            .find(|l| l.starts_with("gateway_requests_total") && l.contains("route=\"route-a\""))
            .expect("counter line");
        for part in [
            "bind=\"b1\"",
            "listener=\"web\"",
            "status=\"200\"",
            "reason=\"ok\"",
        ] {
            assert!(counter.contains(part), "{part} missing in {counter}");
        }
        assert!(counter.ends_with(" 2"), "count of 2 in {counter}");

        let hist_count = out
            .lines()
            .find(|l| {
                l.starts_with("gateway_request_duration_seconds_count")
                    && l.contains("route=\"route-a\"")
            })
            .expect("histogram count line");
        assert!(hist_count.ends_with(" 2"), "observed twice: {hist_count}");
        // No status/reason on the histogram — that's the policy.
        assert!(!hist_count.contains("status="));
        assert!(!hist_count.contains("reason="));
    }

    #[test]
    fn unmatched_identities_encode_as_unknown() {
        let metrics = Metrics::new();
        metrics.record_request(
            "b1",
            None,
            None,
            404,
            Reason::NoRoute,
            Duration::from_millis(1),
        );

        let out = render(&metrics);
        let line = out
            .lines()
            .find(|l| l.starts_with("gateway_requests_total"))
            .expect("counter line");
        for part in [
            "listener=\"unknown\"",
            "route=\"unknown\"",
            "status=\"404\"",
            "reason=\"no_route\"",
        ] {
            assert!(line.contains(part), "{part} missing in {line}");
        }
    }
}

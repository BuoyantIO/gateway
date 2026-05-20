use rand::Rng;

use crate::lb::{Candidate, EndpointInfo, Picker};

/// P2C-EWMA picker scoring parameters. Picker-specific; the
/// state-policy values (EWMA alpha, `failure_threshold`,
/// `eviction_duration`) live on `EndpointStateConfig`.
#[derive(Debug, Clone)]
pub struct P2cConfig {
    /// Score penalty per in-flight connection.
    pub load_penalty: f64,
    /// Score penalty per millisecond of EWMA dial latency.
    pub latency_penalty_ms: f64,
}

impl Default for P2cConfig {
    fn default() -> Self {
        Self {
            load_penalty: 0.1,
            latency_penalty_ms: 0.001,
        }
    }
}

#[derive(Default)]
pub struct P2cEwma {
    pub config: P2cConfig,
}

impl P2cEwma {
    pub fn new(config: P2cConfig) -> Self {
        Self { config }
    }

    fn score(&self, info: &EndpointInfo) -> f64 {
        let s = info.snapshot();
        #[allow(clippy::cast_precision_loss)]
        let load = s.in_flight as f64;
        s.health
            / (1.0
                + s.latency_ms * self.config.latency_penalty_ms
                + load * self.config.load_penalty)
    }
}

impl Picker for P2cEwma {
    fn pick<'a>(&self, candidates: &'a [Candidate<'a>]) -> Option<&'a Candidate<'a>> {
        let n = candidates.len();
        if n == 0 {
            return None;
        }
        let mut rng = rand::rng();
        let a = rng.random_range(0..n);
        let b = if n > 1 { rng.random_range(0..n) } else { a };
        let pa = self.score(&candidates[a].info);
        let pb = self.score(&candidates[b].info);
        Some(if pa >= pb {
            &candidates[a]
        } else {
            &candidates[b]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::time::Duration;

    use gateway_config::backend::Endpoint;

    use crate::lb::state::EndpointInfo;

    fn ep(name: &str, port: u16) -> Endpoint {
        Endpoint {
            name: name.into(),
            address: "127.0.0.1".parse().unwrap(),
            port,
        }
    }

    fn info_with_failures(n: u64) -> Arc<EndpointInfo> {
        let i = Arc::new(EndpointInfo::new(1.0, 1000, Duration::from_secs(1)));
        for _ in 0..n {
            i.record_failure();
        }
        i
    }

    #[test]
    fn returns_none_on_empty() {
        let p = P2cEwma::default();
        assert!(p.pick(&[]).is_none());
    }

    #[test]
    fn single_candidate_always_picked() {
        let p = P2cEwma::default();
        let e = ep("e0", 1);
        let info = Arc::new(EndpointInfo::new(0.1, 5, Duration::from_secs(30)));
        let candidates = [Candidate {
            endpoint: &e,
            info: Arc::clone(&info),
        }];
        for _ in 0..100 {
            let c = p.pick(&candidates).unwrap();
            assert_eq!(c.endpoint.name, "e0");
        }
    }

    #[test]
    fn picks_better_score_more_often() {
        // alpha = 1.0: each update fully replaces the EWMA, so we can
        // control the health values deterministically.
        let p = P2cEwma::default();
        let e0 = ep("good", 1);
        let e1 = ep("bad", 2);
        let good = Arc::new(EndpointInfo::new(1.0, 1000, Duration::from_secs(1)));
        good.record_success(0.0);
        let bad = info_with_failures(1); // health drops to ~0
        let candidates = [
            Candidate {
                endpoint: &e0,
                info: good,
            },
            Candidate {
                endpoint: &e1,
                info: bad,
            },
        ];
        let mut good_picks = 0;
        let n = 10_000;
        for _ in 0..n {
            let c = p.pick(&candidates).unwrap();
            if c.endpoint.name == "good" {
                good_picks += 1;
            }
        }
        // With P2C and ~1.0 vs ~0 health, the good one should win
        // nearly every time (only ties when same index sampled twice).
        // Expected: ~75% (when one of the two samples hits "good").
        // We assert >= 70% to be robust to rng variance.
        let frac = f64::from(good_picks) / f64::from(n);
        assert!(
            frac > 0.70,
            "expected good endpoint picked >70% of the time, got {frac}"
        );
    }
}

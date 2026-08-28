//! Per-Gateway annotation knobs for the provisioner.
//!
//! Every knob follows the same contract: read the annotation, parse
//! and validate it, and on anything invalid warn once (with the
//! gateway identity, the annotation name, and the offending value)
//! and fall back to the default. Validation is load-bearing, not
//! cosmetic: an invalid value passed through to the apiserver would
//! be rejected on every apply and wedge that object's reconcile in
//! retries.

use std::collections::BTreeMap;

use gateway_api::apis::standard::gateways::Gateway;
use k8s_openapi::api::core::v1::ResourceRequirements;
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use kube::Resource;

use super::{
    DP_CPU_LIMIT_ANNOTATION, DP_CPU_REQUEST_ANNOTATION, DP_LOG_FILTER_ANNOTATION,
    DP_MEMORY_LIMIT_ANNOTATION, DP_MEMORY_REQUEST_ANNOTATION, DP_REPLICAS_ANNOTATION,
    SERVICE_NAME_ANNOTATION, SERVICE_TYPE_ANNOTATION,
};

/// The Service types the annotation may select. Anything else falls
/// back to the default with a warning — passing a bad value through
/// would produce a Service the apiserver never accepts and wedge the
/// apply loop on permanent retries.
const SERVICE_TYPES: [&str; 3] = ["ClusterIP", "NodePort", "LoadBalancer"];

const DEFAULT_SERVICE_TYPE: &str = "LoadBalancer";

/// A Gateway metadata annotation by key.
pub(super) fn annotation<'a>(gw: &'a Gateway, key: &str) -> Option<&'a str> {
    gw.meta()
        .annotations
        .as_ref()
        .and_then(|a| a.get(key))
        .map(String::as_str)
}

/// Replica count for the provisioned Deployment: the annotation as a
/// positive integer, or 1 (also the fallback for anything that isn't
/// one, with a warning).
pub(super) fn dp_replicas(gw: &Gateway) -> i32 {
    match annotation(gw, DP_REPLICAS_ANNOTATION) {
        None => 1,
        Some(v) => match v.parse::<i32>() {
            Ok(n) if n > 0 => n,
            _ => {
                tracing::warn!(
                    gateway = identity(gw),
                    value = %v,
                    annotation = DP_REPLICAS_ANNOTATION,
                    "replicas must be a positive integer; using 1"
                );
                1
            }
        },
    }
}

/// The annotation verbatim, or `info`.
pub(super) fn dp_log_filter(gw: &Gateway) -> String {
    match annotation(gw, DP_LOG_FILTER_ANNOTATION) {
        Some(v) if !v.is_empty() => v.to_owned(),
        _ => "info".to_owned(),
    }
}

/// Resource requests and limits for the provisioned container, from
/// the four annotations. Each entry is independent; an invalid
/// quantity is skipped with a warning without discarding the others
/// (an unvalidated string would be rejected by the apiserver on
/// every apply and wedge that object's reconcile in retries). `None`
/// when nothing valid is set.
pub(super) fn dp_resources(gw: &Gateway) -> Option<ResourceRequirements> {
    let mut requests: BTreeMap<String, Quantity> = BTreeMap::new();
    let mut limits: BTreeMap<String, Quantity> = BTreeMap::new();
    for (key, resource, is_limit) in [
        (DP_CPU_REQUEST_ANNOTATION, "cpu", false),
        (DP_MEMORY_REQUEST_ANNOTATION, "memory", false),
        (DP_CPU_LIMIT_ANNOTATION, "cpu", true),
        (DP_MEMORY_LIMIT_ANNOTATION, "memory", true),
    ] {
        let Some(v) = annotation(gw, key) else {
            continue;
        };
        if is_quantity(v) {
            let map = if is_limit { &mut limits } else { &mut requests };
            map.insert(resource.to_string(), Quantity(v.to_string()));
        } else {
            tracing::warn!(
                gateway = identity(gw),
                value = %v,
                annotation = key,
                "not a Kubernetes quantity; skipping"
            );
        }
    }
    if requests.is_empty() && limits.is_empty() {
        return None;
    }
    Some(ResourceRequirements {
        requests: (!requests.is_empty()).then_some(requests),
        limits: (!limits.is_empty()).then_some(limits),
        ..Default::default()
    })
}

/// A non-negative Kubernetes quantity: digits with an optional
/// decimal part, then optionally an exponent (`e`/`E`, optional
/// sign) or one of the standard suffixes.
fn is_quantity(v: &str) -> bool {
    const SUFFIXES: [&str; 15] = [
        "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "n", "u", "m", "k", "M", "G", "T", "P", "E",
    ];
    let number_end = v
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(v.len());
    let (number, rest) = v.split_at(number_end);
    let mut parts = number.split('.');
    let int_ok = parts.next().is_some_and(|p| !p.is_empty());
    let frac = parts.next();
    let frac_ok = frac.is_none_or(|p| p.chars().all(|c| c.is_ascii_digit()));
    if !(int_ok && frac_ok && parts.next().is_none()) {
        return false;
    }
    if rest.is_empty() {
        return true;
    }
    if SUFFIXES.contains(&rest) {
        return true;
    }
    // Exponent form: e or E, optional sign, at least one digit.
    let mut chars = rest.chars();
    if !matches!(chars.next(), Some('e' | 'E')) {
        return false;
    }
    let digits: String = chars.collect();
    let digits = digits.strip_prefix(['+', '-']).unwrap_or(&digits);
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
}

/// The operator-owned `Service` this Gateway attaches to instead of
/// a provisioned one, resolved in the Gateway's own namespace. An
/// empty value cannot name a Service and is treated as unset (with a
/// warning). `pub(crate)`: address writeback reads it too.
pub(crate) fn service_name(gw: &Gateway) -> Option<&str> {
    let v = annotation(gw, SERVICE_NAME_ANNOTATION)?;
    if v.is_empty() {
        tracing::warn!(
            gateway = identity(gw),
            annotation = SERVICE_NAME_ANNOTATION,
            "empty service name; ignoring"
        );
        return None;
    }
    Some(v)
}

/// The `Service` type for the provisioned Service: the annotation
/// when it names a supported type, the default otherwise (with a
/// warning).
pub(super) fn service_type(gw: &Gateway) -> String {
    match annotation(gw, SERVICE_TYPE_ANNOTATION) {
        Some(v) if SERVICE_TYPES.contains(&v) => v.to_string(),
        Some(v) => {
            tracing::warn!(
                gateway = identity(gw),
                value = %v,
                annotation = SERVICE_TYPE_ANNOTATION,
                "unsupported service type; using {DEFAULT_SERVICE_TYPE}"
            );
            DEFAULT_SERVICE_TYPE.to_string()
        }
        None => DEFAULT_SERVICE_TYPE.to_string(),
    }
}

/// `namespace/name` for warn messages.
fn identity(gw: &Gateway) -> String {
    format!(
        "{}/{}",
        gw.meta().namespace.as_deref().unwrap_or_default(),
        gw.meta().name.as_deref().unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use gateway_api::apis::standard::gateways::GatewaySpec;
    use kube::api::ObjectMeta;

    fn gw_with(annotations: &[(&str, &str)]) -> Gateway {
        Gateway {
            metadata: ObjectMeta {
                namespace: Some("demo".into()),
                name: Some("web".into()),
                annotations: Some(
                    annotations
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                ),
                ..Default::default()
            },
            spec: GatewaySpec::default(),
            status: None,
        }
    }

    #[test]
    fn service_name_requires_a_nonempty_value() {
        assert_eq!(service_name(&gw_with(&[])), None);
        assert_eq!(
            service_name(&gw_with(&[(SERVICE_NAME_ANNOTATION, "edge")])),
            Some("edge")
        );
        assert_eq!(
            service_name(&gw_with(&[(SERVICE_NAME_ANNOTATION, "")])),
            None
        );
    }

    #[test]
    fn dp_log_filter_defaults_to_info() {
        assert_eq!(dp_log_filter(&gw_with(&[])), "info");
        assert_eq!(
            dp_log_filter(&gw_with(&[(
                DP_LOG_FILTER_ANNOTATION,
                "info,gateway_extension_impls=debug"
            )])),
            "info,gateway_extension_impls=debug"
        );
        assert_eq!(
            dp_log_filter(&gw_with(&[(DP_LOG_FILTER_ANNOTATION, "")])),
            "info"
        );
    }

    #[test]
    fn quantity_grammar() {
        for ok in [
            "100m", "0.5", "64Mi", "1Gi", "1e3", "1E-2", "0", "2", "1500u",
        ] {
            assert!(is_quantity(ok), "{ok:?} should be a valid quantity");
        }
        for bad in ["", "-1", "10x", "Mi", "1.2.3", "lots", "1e", "1e+", ".5Mi."] {
            assert!(!is_quantity(bad), "{bad:?} should be rejected");
        }
    }
}

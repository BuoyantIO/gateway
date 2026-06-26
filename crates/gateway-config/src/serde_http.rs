//! Minimal serde helpers for `http` crate types that don't ship
//! their own Deserialize impls. The schema in `route.rs` holds these
//! types directly; YAML parses them via `#[serde(with = "...")]` per
//! field. Config is deserialize-only — there are no serialize halves.

use serde::{Deserialize, Deserializer};

/// `Option<http::Method>` via `String` (uppercase token).
pub mod method_opt {
    use super::{Deserialize, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<http::Method>, D::Error> {
        let s: Option<String> = Option::deserialize(d)?;
        match s {
            None => Ok(None),
            Some(s) => http::Method::from_bytes(s.as_bytes())
                .map(Some)
                .map_err(serde::de::Error::custom),
        }
    }
}

/// `http::HeaderName` via `String`. `HeaderName` equality is
/// case-insensitive; deserialization preserves the canonical
/// lowercase form.
pub mod header_name {
    use super::{Deserialize, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<http::HeaderName, D::Error> {
        let s = String::deserialize(d)?;
        http::HeaderName::from_bytes(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

/// `http::HeaderValue` via `String`. Invalid header bytes (NUL,
/// CR/LF, etc.) fail at deserialization time.
pub mod header_value {
    use super::{Deserialize, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<http::HeaderValue, D::Error> {
        let s = String::deserialize(d)?;
        http::HeaderValue::try_from(s).map_err(serde::de::Error::custom)
    }
}

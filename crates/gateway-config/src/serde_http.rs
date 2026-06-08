//! Minimal serde helpers for `http` crate types that don't ship
//! their own Serialize/Deserialize impls. The schema in `route.rs`
//! holds these types directly; YAML parses them via
//! `#[serde(with = "...")]` per field.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// `Option<http::Method>` via `String` (uppercase token).
pub mod method_opt {
    use super::{Deserialize, Deserializer, Serialize, Serializer};

    #[allow(clippy::ref_option)]
    pub fn serialize<S: Serializer>(m: &Option<http::Method>, s: S) -> Result<S::Ok, S::Error> {
        match m {
            Some(m) => m.as_str().serialize(s),
            None => s.serialize_none(),
        }
    }

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
/// case-insensitive; serialization preserves the canonical
/// lowercase form.
pub mod header_name {
    use super::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(n: &http::HeaderName, s: S) -> Result<S::Ok, S::Error> {
        n.as_str().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<http::HeaderName, D::Error> {
        let s = String::deserialize(d)?;
        http::HeaderName::from_bytes(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

/// `http::HeaderValue` via `String`. Invalid header bytes (NUL,
/// CR/LF, etc.) fail at deserialization time.
pub mod header_value {
    use super::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &http::HeaderValue, s: S) -> Result<S::Ok, S::Error> {
        v.to_str().map_err(serde::ser::Error::custom)?.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<http::HeaderValue, D::Error> {
        let s = String::deserialize(d)?;
        http::HeaderValue::try_from(s).map_err(serde::de::Error::custom)
    }
}

//! Secret material, as the gateway holds it once it is past the
//! config boundary.
//!
//! Two shapes ride in one namespace: TLS material, parsed to DER on
//! the way in, and opaque credentials, kept as bytes under
//! operator-chosen data keys. Both are named the same way, arrive
//! through the same upsert, and are told apart by [`Secret`]; a
//! consumer asks for the shape it can use and gets `None` when the
//! secret is the other one.
//!
//! Nothing here prints its material. [`SecretValue`] redacts under
//! both `Debug` and `Display` and has no way to be serialized, so a
//! type holding one is safe to `derive(Debug)`.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Deserializer};

/// Data key holding the certificate chain of a TLS secret, matching
/// the `kubernetes.io/tls` layout the material comes from.
pub const TLS_CERT_KEY: &str = "tls.crt";
/// Data key holding the private key of a TLS secret. Present but
/// empty for a CA-only secret, which is what a `kubernetes.io/tls`
/// Secret distributing only trust roots looks like.
pub const TLS_KEY_KEY: &str = "tls.key";

/// What a credential prints as, everywhere it prints.
const REDACTED: &str = "<redacted>";

/// One registered secret, whatever its material.
///
/// Both variants are behind an `Arc`: a secret is registered once and
/// handed to every listener and backend that names it, and cloning
/// this is how they take their share.
#[derive(Debug, Clone)]
pub enum Secret {
    /// A certificate chain
    Tls(Arc<TlsSecret>),
    /// Credentials the gateway never interprets, keyed by the data
    /// key a [`SecretRef`] names.
    Opaque(Arc<OpaqueSecret>),
}

impl Secret {
    /// Namespace of the underlying Secret. Empty for a flat local
    /// config, which has no namespaces.
    pub fn namespace(&self) -> &str {
        match self {
            Self::Tls(s) => &s.namespace,
            Self::Opaque(s) => &s.namespace,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Tls(s) => &s.name,
            Self::Opaque(s) => &s.name,
        }
    }

    /// The TLS material, or `None` when this secret carries
    /// credentials instead.
    ///
    /// Terminating listeners and a dialable backend's trust roots go
    /// through here, which is what makes TLS material a requirement
    /// they state rather than something they hope to find: an opaque
    /// secret named where a certificate belongs reads exactly like a
    /// secret that has not arrived.
    pub fn as_tls(&self) -> Option<&Arc<TlsSecret>> {
        match self {
            Self::Tls(s) => Some(s),
            Self::Opaque(_) => None,
        }
    }

    /// The opaque material, or `None` when this secret carries a
    /// certificate instead.
    pub fn as_opaque(&self) -> Option<&Arc<OpaqueSecret>> {
        match self {
            Self::Opaque(s) => Some(s),
            Self::Tls(_) => None,
        }
    }
}

impl From<TlsSecret> for Secret {
    fn from(s: TlsSecret) -> Self {
        Self::Tls(Arc::new(s))
    }
}

impl From<OpaqueSecret> for Secret {
    fn from(s: OpaqueSecret) -> Self {
        Self::Opaque(Arc::new(s))
    }
}

// Deserialized through a derived shadow enum so each variant lands in
// its `Arc` without the `serde` `rc` feature, and so the tag stays
// declarative.
impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "type")]
        enum Raw {
            Tls(TlsSecret),
            Opaque(OpaqueSecret),
        }
        Ok(match Raw::deserialize(deserializer)? {
            Raw::Tls(s) => s.into(),
            Raw::Opaque(s) => s.into(),
        })
    }
}

/// A TLS secret with its cert chain — and, when it carries one, its
/// private key — already parsed to DER.
///
/// Two shapes travel in this one type, told apart by `key`: a
/// keypair a terminating listener serves, and a CA-only secret the
/// gateway verifies an upstream against when it originates TLS.
pub struct TlsSecret {
    /// Kubernetes namespace of the Secret. Empty for a flat local
    /// config, which has no namespaces.
    pub namespace: String,
    pub name: String,
    pub certs: Vec<CertificateDer<'static>>,
    /// `None` for a CA-only secret. A terminating listener needs a
    /// key and is not promoted by a secret without one; trust roots
    /// never look at it.
    pub key: Option<PrivateKeyDer<'static>>,
}

impl Clone for TlsSecret {
    fn clone(&self) -> Self {
        Self {
            namespace: self.namespace.clone(),
            name: self.name.clone(),
            certs: self.certs.clone(),
            key: self.key.as_ref().map(PrivateKeyDer::clone_key),
        }
    }
}

impl TlsSecret {
    /// Parse PEM cert chain + private key into a `TlsSecret`. Requires
    /// at least one certificate and a private key.
    ///
    /// # Errors
    /// Returns [`TlsSecretError`] if the PEM is malformed, has no
    /// certificate, or has no private key.
    pub fn new(
        namespace: impl Into<String>,
        name: impl Into<String>,
        cert_pem: &str,
        key_pem: &str,
    ) -> Result<Self, TlsSecretError> {
        let certs = parse_certs(cert_pem)?;
        let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
            .map_err(|e| TlsSecretError::Malformed(e.to_string()))?
            .ok_or(TlsSecretError::NoPrivateKey)?;
        Ok(Self {
            namespace: namespace.into(),
            name: name.into(),
            certs,
            key: Some(key),
        })
    }

    /// Parse a PEM bundle of certificates with no private key: the
    /// trust roots a dialable backend verifies its upstream against.
    ///
    /// # Errors
    /// Returns [`TlsSecretError`] if the PEM is malformed or has no
    /// certificate.
    pub fn ca(
        namespace: impl Into<String>,
        name: impl Into<String>,
        cert_pem: &str,
    ) -> Result<Self, TlsSecretError> {
        Ok(Self {
            namespace: namespace.into(),
            name: name.into(),
            certs: parse_certs(cert_pem)?,
            key: None,
        })
    }
}

// Redacting `Debug` — never print private key bytes.
impl fmt::Debug for TlsSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsSecret")
            .field("namespace", &self.namespace)
            .field("name", &self.name)
            .field("certs", &self.certs.len())
            .field("key", &self.key.as_ref().map_or("<none>", |_| REDACTED))
            .finish()
    }
}

// Parse on the way in: deserialize the PEM-bearing shape, then build a
// `TlsSecret` (which parses). Malformed PEM becomes a deserialize error.
impl<'de> Deserialize<'de> for TlsSecret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            #[serde(default)]
            namespace: String,
            name: String,
            cert_pem: String,
            /// Absent (or empty) makes this a CA-only secret.
            #[serde(default)]
            key_pem: String,
        }
        let raw = Raw::deserialize(deserializer)?;
        let name = raw.name.clone();
        let parsed = if raw.key_pem.is_empty() {
            Self::ca(raw.namespace, raw.name, &raw.cert_pem)
        } else {
            Self::new(raw.namespace, raw.name, &raw.cert_pem, &raw.key_pem)
        };
        parsed.map_err(|e| serde::de::Error::custom(format!("invalid secret `{name}`: {e}")))
    }
}

/// Credentials the gateway carries but never interprets, held under
/// the data keys of the Secret they came from.
///
/// A value is reached by the data key a [`SecretRef`] names, the same
/// way a `kubernetes.io/tls` secret's material is reached by
/// [`TLS_CERT_KEY`]; nothing here assumes what any particular key
/// means.
#[derive(Clone)]
pub struct OpaqueSecret {
    /// Kubernetes namespace of the Secret. Empty for a flat local
    /// config, which has no namespaces.
    pub namespace: String,
    pub name: String,
    /// Ordered so `Debug` lists the data keys the same way twice.
    data: BTreeMap<String, SecretValue>,
}

impl OpaqueSecret {
    pub fn new(
        namespace: impl Into<String>,
        name: impl Into<String>,
        data: BTreeMap<String, SecretValue>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
            data,
        }
    }

    /// The value under `key`, or `None` when the secret has no such
    /// data key — which is what a reference to a key the operator
    /// never set looks like.
    pub fn get(&self, key: &str) -> Option<&SecretValue> {
        self.data.get(key)
    }

    /// The data keys this secret carries. Key names are not material
    /// and are what makes a missing reference diagnosable.
    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.data.keys().map(String::as_str)
    }
}

// Redacting `Debug` — the data keys are named, the values never are.
impl fmt::Debug for OpaqueSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueSecret")
            .field("namespace", &self.namespace)
            .field("name", &self.name)
            .field("keys", &self.data.keys())
            .finish()
    }
}

impl<'de> Deserialize<'de> for OpaqueSecret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            #[serde(default)]
            namespace: String,
            name: String,
            #[serde(default)]
            data: BTreeMap<String, SecretValue>,
        }
        let raw = Raw::deserialize(deserializer)?;
        Ok(Self::new(raw.namespace, raw.name, raw.data))
    }
}

/// One credential value.
///
/// The material is reachable only through [`SecretValue::expose`] and
/// [`SecretValue::expose_str`], and both `Debug` and `Display`
/// redact, so a struct holding one prints safely in a log line or a
/// `{:?}` of the whole config. There is deliberately no `Serialize`:
/// nothing turns a credential back into config.
///
/// Equality is the store's "did this actually change" test, asked of
/// a resolved backend holding one — a rotation has to bump the
/// revision, and a re-send of the same material must not. It is a
/// comparison of two copies of our own config, never of a credential
/// against one someone presented, so it is deliberately the ordinary
/// byte comparison and not a constant-time one.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// The material, for the one place that puts it on the wire.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// The material as text, or `None` when it is not UTF-8. A
    /// credential that goes into a header or a form body has to be
    /// text; one that isn't is a misconfigured secret, not a
    /// request-time surprise.
    pub fn expose_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Display for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(Self::new(String::deserialize(deserializer)?))
    }
}

/// A reference to one value inside a secret: the secret's identity,
/// plus the data key the material lives under.
///
/// TLS references carry no data key — a `kubernetes.io/tls` secret
/// fixes [`TLS_CERT_KEY`] and [`TLS_KEY_KEY`] — so this is what
/// credentials are named by.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretRef {
    /// Namespace of the referenced Secret. Empty for a flat local
    /// config, which has no namespaces.
    #[serde(default)]
    pub namespace: String,
    pub name: String,
    /// Data key inside that Secret.
    pub key: String,
}

impl SecretRef {
    pub fn new(
        namespace: impl Into<String>,
        name: impl Into<String>,
        key: impl Into<String>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
            key: key.into(),
        }
    }
}

impl fmt::Display for SecretRef {
    /// `namespace/name#key`, matching how a `SecretKey` prints with
    /// the data key appended.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}#{}", self.namespace, self.name, self.key)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TlsSecretError {
    #[error("no certificate found in PEM")]
    NoCertificate,
    #[error("no private key found in PEM")]
    NoPrivateKey,
    #[error("malformed PEM: {0}")]
    Malformed(String),
}

/// Why a secret arriving from the config stream could not be built.
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("secret type is unspecified")]
    UnspecifiedType,
    #[error("missing `{0}`")]
    MissingData(&'static str),
    #[error("`{0}` is not valid UTF-8")]
    NotUtf8(&'static str),
    #[error(transparent)]
    Tls(#[from] TlsSecretError),
}

/// Parse a PEM cert chain into DER. At least one certificate is
/// required — a secret with none names nothing the gateway can serve
/// or verify against.
fn parse_certs(cert_pem: &str) -> Result<Vec<CertificateDer<'static>>, TlsSecretError> {
    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsSecretError::Malformed(e.to_string()))?;
    if certs.is_empty() {
        return Err(TlsSecretError::NoCertificate);
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    // A throwaway self-signed EC P-256 cert + PKCS#8 key, generated
    // offline. Structurally valid for `rustls-pemfile`; reused by the
    // store / cp-client tests and (later) §14 handshake tests.
    pub(crate) const TEST_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBgjCCASmgAwIBAgIUW/OT9NoEgpMEra4i2ttY/oSsRe0wCgYIKoZIzj0EAwIw\n\
FzEVMBMGA1UEAwwMZ2F0ZXdheS10ZXN0MB4XDTI2MDYyNjEwNTEyOFoXDTM2MDYy\n\
MzEwNTEyOFowFzEVMBMGA1UEAwwMZ2F0ZXdheS10ZXN0MFkwEwYHKoZIzj0CAQYI\n\
KoZIzj0DAQcDQgAEZoF6gHnR0OJdILhqvT75ZE5oX/NkCobjCPRKQmQAvEFeN8ku\n\
f+C449e9U2Gq6S7C72DJWjcsr8gaxjiMRie0H6NTMFEwHQYDVR0OBBYEFKmMFFZT\n\
6oW/R893bFKGDqRaBuoRMB8GA1UdIwQYMBaAFKmMFFZT6oW/R893bFKGDqRaBuoR\n\
MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgEdjQ6EJUY9QMrNQy\n\
YhAYK89fjb5J6TE0AJY4QnmcFR0CIHo7A7WYP2hT7rr6orgxEqAVx7DGbd0aCCqe\n\
GkIpYyxV\n\
-----END CERTIFICATE-----\n";

    pub(crate) const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgcB/ubr8b5gfbp97H\n\
/hzgYBDdRqvQrz6jRyF1kz8TrcChRANCAARmgXqAedHQ4l0guGq9PvlkTmhf82QK\n\
huMI9EpCZAC8QV43yS5/4Ljj171TYarpLsLvYMlaNyyvyBrGOIxGJ7Qf\n\
-----END PRIVATE KEY-----\n";

    #[test]
    fn new_parses_valid_cert_and_key() {
        let s = TlsSecret::new("apps", "app-tls", TEST_CERT_PEM, TEST_KEY_PEM).expect("valid");
        assert_eq!(s.namespace, "apps");
        assert_eq!(s.name, "app-tls");
        assert_eq!(s.certs.len(), 1);
    }

    #[test]
    fn new_rejects_missing_certificate() {
        let err = TlsSecret::new("", "s", "not a cert", TEST_KEY_PEM).unwrap_err();
        assert!(matches!(err, TlsSecretError::NoCertificate));
    }

    #[test]
    fn new_rejects_missing_private_key() {
        let err = TlsSecret::new("", "s", TEST_CERT_PEM, "not a key").unwrap_err();
        assert!(matches!(err, TlsSecretError::NoPrivateKey));
    }

    #[test]
    fn ca_parses_certs_without_a_key() {
        let s = TlsSecret::ca("apps", "provider-ca", TEST_CERT_PEM).expect("valid");
        assert_eq!(s.certs.len(), 1);
        assert!(s.key.is_none());
    }

    #[test]
    fn ca_rejects_missing_certificate() {
        let err = TlsSecret::ca("", "provider-ca", "not a cert").unwrap_err();
        assert!(matches!(err, TlsSecretError::NoCertificate));
    }

    #[test]
    fn debug_redacts_key() {
        let s = TlsSecret::new("", "app-tls", TEST_CERT_PEM, TEST_KEY_PEM).unwrap();
        let out = format!("{s:?}");
        assert!(out.contains("app-tls"));
        assert!(out.contains("<redacted>"));
        // No private-key base64 leaks into Debug.
        assert!(!out.contains("MIGHAgEA"));
    }

    #[test]
    fn deserialize_parses_pem_from_yaml() {
        let yaml = format!(
            "name: app-tls\ncertPem: |\n{}\nkeyPem: |\n{}",
            indent(TEST_CERT_PEM),
            indent(TEST_KEY_PEM),
        );
        let secret: TlsSecret = serde_yaml::from_str(&yaml).expect("parses");
        assert_eq!(secret.name, "app-tls");
    }

    #[test]
    fn deserialize_without_key_pem_yields_a_ca_secret() {
        let yaml = format!("name: provider-ca\ncertPem: |\n{}", indent(TEST_CERT_PEM));
        let secret: TlsSecret = serde_yaml::from_str(&yaml).expect("parses");
        assert!(secret.key.is_none());
        // Nothing to redact, and nothing claimed to be there.
        assert!(format!("{secret:?}").contains("<none>"));
    }

    #[test]
    fn deserialize_rejects_malformed_pem() {
        let yaml = "name: bad\ncertPem: nope\nkeyPem: nope\n";
        let err = serde_yaml::from_str::<TlsSecret>(yaml).unwrap_err();
        assert!(err.to_string().contains("certificate") || err.to_string().contains("PEM"));
    }

    // ---- Secret, the shape-agnostic carrier ----

    /// Stands in for a credential; no test may print it.
    const SENSITIVE: &str = "sk-not-a-real-key";

    fn opaque(key: &str, value: &str) -> OpaqueSecret {
        OpaqueSecret::new(
            "apps",
            "provider-creds",
            BTreeMap::from([(key.to_string(), SecretValue::new(value))]),
        )
    }

    #[test]
    fn deserialize_dispatches_on_type() {
        let yaml = format!(
            "type: Tls\nname: app-tls\ncertPem: |\n{}\nkeyPem: |\n{}",
            indent(TEST_CERT_PEM),
            indent(TEST_KEY_PEM),
        );
        let secret: Secret = serde_yaml::from_str(&yaml).expect("parses");
        assert_eq!(secret.name(), "app-tls");
        assert!(secret.as_tls().is_some());
        assert!(secret.as_opaque().is_none());

        let yaml = format!("type: Opaque\nname: provider-creds\ndata:\n  apiKey: {SENSITIVE}\n");
        let secret: Secret = serde_yaml::from_str(&yaml).expect("parses");
        assert_eq!(secret.name(), "provider-creds");
        assert!(secret.as_tls().is_none());
        assert_eq!(
            secret
                .as_opaque()
                .expect("opaque")
                .get("apiKey")
                .and_then(SecretValue::expose_str),
            Some(SENSITIVE)
        );
    }

    #[test]
    fn opaque_reads_back_by_data_key() {
        let s = opaque("apiKey", SENSITIVE);
        assert_eq!(
            s.get("apiKey").map(SecretValue::expose),
            Some(SENSITIVE.as_bytes())
        );
        assert!(s.get("clientSecret").is_none());
        assert_eq!(s.keys().collect::<Vec<_>>(), vec!["apiKey"]);
    }

    #[test]
    fn opaque_debug_names_keys_and_redacts_values() {
        let s = Secret::from(opaque("apiKey", SENSITIVE));
        let out = format!("{s:?}");
        assert!(out.contains("provider-creds"), "{out}");
        assert!(out.contains("apiKey"), "data keys stay visible: {out}");
        assert!(!out.contains(SENSITIVE), "{out}");
    }

    #[test]
    fn secret_value_redacts_in_both_directions() {
        let v = SecretValue::new(SENSITIVE);
        assert_eq!(format!("{v:?}"), "<redacted>");
        assert_eq!(format!("{v}"), "<redacted>");
        // A struct holding one is safe to print whole.
        assert!(!format!("{:?}", vec![v]).contains(SENSITIVE));
    }

    #[test]
    fn secret_value_that_is_not_text_has_no_str() {
        let v = SecretValue::new(vec![0xff, 0xfe]);
        assert!(v.expose_str().is_none());
        assert!(!v.is_empty());
    }

    // ---- SecretRef ----

    #[test]
    fn secret_ref_carries_the_data_key() {
        let yaml = "namespace: apps\nname: provider-creds\nkey: apiKey\n";
        let r: SecretRef = serde_yaml::from_str(yaml).expect("parses");
        assert_eq!(r, SecretRef::new("apps", "provider-creds", "apiKey"));
        assert_eq!(r.to_string(), "apps/provider-creds#apiKey");
    }

    #[test]
    fn secret_ref_namespace_defaults_to_empty() {
        let r: SecretRef =
            serde_yaml::from_str("name: provider-creds\nkey: apiKey\n").expect("parses");
        assert!(r.namespace.is_empty(), "{:?}", r.namespace);
    }

    // Indent each line of a PEM block by 8 spaces for a YAML literal scalar.
    fn indent(pem: &str) -> String {
        pem.lines()
            .map(|l| format!("        {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

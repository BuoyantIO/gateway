use std::fmt;

use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Deserializer};

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
            .field("key", &self.key.as_ref().map_or("<none>", |_| "<redacted>"))
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

#[derive(Debug, thiserror::Error)]
pub enum TlsSecretError {
    #[error("no certificate found in PEM")]
    NoCertificate,
    #[error("no private key found in PEM")]
    NoPrivateKey,
    #[error("malformed PEM: {0}")]
    Malformed(String),
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

    // Indent each line of a PEM block by 8 spaces for a YAML literal scalar.
    fn indent(pem: &str) -> String {
        pem.lines()
            .map(|l| format!("        {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

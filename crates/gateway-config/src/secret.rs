use std::fmt;

use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Deserializer};

/// A TLS secret with its cert chain and private key already parsed
/// to DER.
pub struct TlsSecret {
    /// Kubernetes namespace of the Secret. Empty for a flat local
    /// config, which has no namespaces.
    pub namespace: String,
    pub name: String,
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

impl Clone for TlsSecret {
    fn clone(&self) -> Self {
        Self {
            namespace: self.namespace.clone(),
            name: self.name.clone(),
            certs: self.certs.clone(),
            key: self.key.clone_key(),
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
        let (certs, key) = parse_pem(cert_pem, key_pem)?;
        Ok(Self {
            namespace: namespace.into(),
            name: name.into(),
            certs,
            key,
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
            .field("key", &"<redacted>")
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
            key_pem: String,
        }
        let raw = Raw::deserialize(deserializer)?;
        let name = raw.name.clone();
        Self::new(raw.namespace, raw.name, &raw.cert_pem, &raw.key_pem)
            .map_err(|e| serde::de::Error::custom(format!("invalid secret `{name}`: {e}")))
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

/// Parse a PEM cert chain + private key into DER. Used by
/// [`TlsSecret::new`] and (later) by the data plane to build a rustls
/// `ServerConfig`.
fn parse_pem(
    cert_pem: &str,
    key_pem: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TlsSecretError> {
    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsSecretError::Malformed(e.to_string()))?;
    if certs.is_empty() {
        return Err(TlsSecretError::NoCertificate);
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| TlsSecretError::Malformed(e.to_string()))?
        .ok_or(TlsSecretError::NoPrivateKey)?;
    Ok((certs, key))
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

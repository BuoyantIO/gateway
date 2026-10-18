//! One JWT, parsed and validated: the header first, the signature
//! against the key its `kid` names, then the claims.
//!
//! Hand-rolled over `ring` rather than a JWT library, so the accepted
//! algorithm is decided here and nowhere else. The header must say
//! `RS256` exactly: `none`, every HMAC algorithm and every other
//! asymmetric one are refused before a key is looked up, which also
//! closes the classic confusion of an HS256 token "signed" with the
//! RSA public key. RSA keys under 2048 bits never verify.
//!
//! Claims are read only after the signature verifies, so nothing an
//! unauthenticated caller wrote is ever checked, logged or returned.
//! Every rejection is a fixed reason from [`Reject`], never text taken
//! from the token.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use serde::Deserialize;
use serde_json::{Map, Value};

/// Tolerance on `exp`, `nbf` and `iat`, for clocks that disagree.
pub(crate) const CLOCK_SKEW_SECS: f64 = 60.0;

/// The only algorithm accepted.
const RS256: &str = "RS256";

/// What a token is checked against, fixed at configure time.
pub(crate) struct Settings {
    pub(crate) issuer: String,
    pub(crate) audience: String,
    /// The claim the tenant is read from.
    pub(crate) tenant_claim: String,
    pub(crate) require_email_verified: bool,
}

/// An RSA public key from the issuer's key set.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RsaKey {
    /// Modulus and exponent, big-endian.
    pub(crate) n: Vec<u8>,
    pub(crate) e: Vec<u8>,
}

/// Why a token was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reject {
    Malformed,
    UnsupportedAlgorithm,
    UnknownKey,
    BadSignature,
    WrongIssuer,
    WrongAudience,
    Expired,
    NotYetValid,
    EmailNotVerified,
    /// A required claim is absent, or not the type it must be. The
    /// name is ours (a constant, or the configured tenant claim),
    /// never the token's.
    MissingClaim(String),
}

impl fmt::Display for Reject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("malformed token"),
            Self::UnsupportedAlgorithm => f.write_str("unsupported algorithm"),
            Self::UnknownKey => f.write_str("unknown signing key"),
            Self::BadSignature => f.write_str("bad signature"),
            Self::WrongIssuer => f.write_str("wrong issuer"),
            Self::WrongAudience => f.write_str("wrong audience"),
            Self::Expired => f.write_str("expired"),
            Self::NotYetValid => f.write_str("not yet valid"),
            Self::EmailNotVerified => f.write_str("email not verified"),
            Self::MissingClaim(claim) => write!(f, "missing {claim} claim"),
        }
    }
}

/// The parts of a JOSE header that matter here. Unknown fields are
/// ignored; a duplicated field fails the parse.
#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
    crit: Option<Value>,
}

/// A token whose header passed and whose signature is not yet checked.
/// Deliberately not `Debug`: it holds the token's bytes.
pub(crate) struct Unverified {
    kid: String,
    /// `header.payload`, the bytes the signature covers.
    signing_input: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

impl Unverified {
    /// Split and decode a compact JWS, and check its header.
    ///
    /// # Errors
    /// [`Reject::Malformed`] for anything that is not three base64url
    /// segments with a JSON header naming a `kid`, or that carries
    /// `crit`; [`Reject::UnsupportedAlgorithm`] for any `alg` but
    /// `RS256`.
    pub(crate) fn parse(token: &str) -> Result<Self, Reject> {
        let mut segments = token.split('.');
        let (Some(header), Some(payload), Some(signature), None) = (
            segments.next(),
            segments.next(),
            segments.next(),
            segments.next(),
        ) else {
            return Err(Reject::Malformed);
        };
        let decode = |segment: &str| {
            URL_SAFE_NO_PAD
                .decode(segment)
                .map_err(|_| Reject::Malformed)
        };
        let parsed: Header =
            serde_json::from_slice(&decode(header)?).map_err(|_| Reject::Malformed)?;
        if parsed.alg != RS256 {
            return Err(Reject::UnsupportedAlgorithm);
        }
        // No extension this verifier understands, so any is one it
        // must refuse (RFC 7515 §4.1.11).
        if parsed.crit.is_some() {
            return Err(Reject::Malformed);
        }
        let kid = parsed
            .kid
            .filter(|k| !k.is_empty())
            .ok_or(Reject::Malformed)?;
        Ok(Self {
            kid,
            signing_input: token.as_bytes()[..header.len() + 1 + payload.len()].to_vec(),
            payload: decode(payload)?,
            signature: decode(signature)?,
        })
    }

    /// The key the token says it was signed with. Untrusted until
    /// [`Unverified::verify`] succeeds.
    pub(crate) fn kid(&self) -> &str {
        &self.kid
    }

    /// Check the signature against `key`, and only then read the
    /// claims.
    ///
    /// # Errors
    /// [`Reject::BadSignature`] when the signature does not verify;
    /// [`Reject::Malformed`] when a verified payload is not a JSON
    /// object.
    pub(crate) fn verify(self, key: &RsaKey) -> Result<Claims, Reject> {
        RsaPublicKeyComponents {
            n: &key.n,
            e: &key.e,
        }
        .verify(
            &RSA_PKCS1_2048_8192_SHA256,
            &self.signing_input,
            &self.signature,
        )
        .map_err(|_| Reject::BadSignature)?;
        match serde_json::from_slice(&self.payload) {
            Ok(Value::Object(claims)) => Ok(Claims(claims)),
            _ => Err(Reject::Malformed),
        }
    }
}

/// The claims of a token whose signature verified.
pub(crate) struct Claims(Map<String, Value>);

/// What a validated token says about its caller.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Caller {
    pub(crate) tenant: String,
    pub(crate) subject: String,
}

impl Claims {
    /// A string claim, for logging a rejection.
    pub(crate) fn string(&self, name: &str) -> &str {
        self.0.get(name).and_then(Value::as_str).unwrap_or("")
    }

    /// Check the claims against `settings` at `now`, in seconds since
    /// the Unix epoch.
    ///
    /// # Errors
    /// The first claim that fails, in the order issuer, audience,
    /// expiry, not-before, issued-at, email verification, tenant.
    pub(crate) fn validate(&self, settings: &Settings, now: f64) -> Result<Caller, Reject> {
        if self.0.get("iss").and_then(Value::as_str) != Some(settings.issuer.as_str()) {
            return Err(Reject::WrongIssuer);
        }
        let audience_matches = match self.0.get("aud") {
            Some(Value::String(aud)) => *aud == settings.audience,
            Some(Value::Array(auds)) => auds
                .iter()
                .any(|a| a.as_str() == Some(settings.audience.as_str())),
            _ => false,
        };
        if !audience_matches {
            return Err(Reject::WrongAudience);
        }
        let exp = self.date("exp")?.ok_or_else(|| missing("exp"))?;
        if now >= exp + CLOCK_SKEW_SECS {
            return Err(Reject::Expired);
        }
        for claim in ["nbf", "iat"] {
            if self.date(claim)?.is_some_and(|t| t > now + CLOCK_SKEW_SECS) {
                return Err(Reject::NotYetValid);
            }
        }
        if settings.require_email_verified
            && self.0.get("email_verified").and_then(Value::as_bool) != Some(true)
        {
            return Err(Reject::EmailNotVerified);
        }
        let tenant = self
            .0
            .get(&settings.tenant_claim)
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .ok_or_else(|| missing(&settings.tenant_claim))?;
        Ok(Caller {
            tenant: tenant.to_owned(),
            subject: self.string("sub").to_owned(),
        })
    }

    /// A `NumericDate` claim: seconds since the epoch, integral or not.
    /// `Ok(None)` when absent; a present value of any other shape is a
    /// malformed token rather than a missing claim.
    fn date(&self, name: &str) -> Result<Option<f64>, Reject> {
        match self.0.get(name) {
            None => Ok(None),
            Some(v) => v
                .as_f64()
                .filter(|t| t.is_finite())
                .map(Some)
                .ok_or(Reject::Malformed),
        }
    }
}

fn missing(claim: &str) -> Reject {
    Reject::MissingClaim(claim.to_owned())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use base64::engine::general_purpose::STANDARD;
    use ring::rand::SystemRandom;
    use ring::rsa::{KeyPair, PublicKeyComponents};
    use serde_json::json;

    // Throwaway RSA-2048 keys generated for these tests alone; they
    // sign nothing outside this module's tests.
    const KEY_A: &str = include_str!("testdata/rsa-a.pk8.pem");
    const KEY_B: &str = include_str!("testdata/rsa-b.pk8.pem");

    pub(crate) const ISSUER: &str = "https://llm.example.com/dex";
    pub(crate) const AUDIENCE: &str = "inference-gateway";
    /// A fixed "now" for the claim tests: 2026-10-17T00:00:00Z.
    pub(crate) const NOW: f64 = 1_792_195_200.0;

    /// A test signing key and the `kid` it is published under.
    pub(crate) struct TestKey {
        pub(crate) kid: &'static str,
        pair: KeyPair,
    }

    impl TestKey {
        pub(crate) fn a() -> Self {
            Self::load("key-a", KEY_A)
        }

        pub(crate) fn b() -> Self {
            Self::load("key-b", KEY_B)
        }

        fn load(kid: &'static str, pem: &str) -> Self {
            let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
            let der = STANDARD.decode(body).expect("test key is base64");
            Self {
                kid,
                pair: KeyPair::from_pkcs8(&der).expect("test key is PKCS#8 RSA"),
            }
        }

        pub(crate) fn public(&self) -> RsaKey {
            let components = PublicKeyComponents::<Vec<u8>>::from(self.pair.public());
            RsaKey {
                n: components.n,
                e: components.e,
            }
        }

        /// The key as a JWKS entry, the shape an issuer publishes.
        pub(crate) fn jwk(&self) -> Value {
            let public = self.public();
            json!({
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": self.kid,
                "n": URL_SAFE_NO_PAD.encode(public.n),
                "e": URL_SAFE_NO_PAD.encode(public.e),
            })
        }

        /// An RS256 token over `claims`, under this key's `kid`.
        pub(crate) fn sign(&self, claims: &Value) -> String {
            self.sign_with_header(
                &json!({ "alg": "RS256", "typ": "JWT", "kid": self.kid }),
                claims,
            )
        }

        pub(crate) fn sign_with_header(&self, header: &Value, claims: &Value) -> String {
            let input = format!(
                "{}.{}",
                URL_SAFE_NO_PAD.encode(header.to_string()),
                URL_SAFE_NO_PAD.encode(claims.to_string())
            );
            let mut signature = vec![0; self.pair.public().modulus_len()];
            self.pair
                .sign(
                    &ring::signature::RSA_PKCS1_SHA256,
                    &SystemRandom::new(),
                    input.as_bytes(),
                    &mut signature,
                )
                .expect("sign");
            format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
        }
    }

    /// Claims Dex would issue for a verified user, valid at [`NOW`].
    pub(crate) fn good_claims() -> Value {
        json!({
            "iss": ISSUER,
            "sub": "CiQwOGE4Njg0Yi1kYjg4LTRiNzMtOTBhOS0zY2QxNjYxZjU0NjYSBWxvY2Fs",
            "aud": AUDIENCE,
            "exp": NOW + 3600.0,
            "iat": NOW - 10.0,
            "email": "alice@example.com",
            "email_verified": true,
            "name": "Alice",
        })
    }

    pub(crate) fn settings() -> Settings {
        Settings {
            issuer: ISSUER.into(),
            audience: AUDIENCE.into(),
            tenant_claim: "email".into(),
            require_email_verified: true,
        }
    }

    /// Run a token through every stage against `key`, at [`NOW`].
    fn check(token: &str, key: &RsaKey) -> Result<Caller, Reject> {
        Unverified::parse(token)?
            .verify(key)?
            .validate(&settings(), NOW)
    }

    fn with(claims: Value, field: &str, value: Value) -> Value {
        let mut claims = claims;
        claims[field] = value;
        claims
    }

    fn without(claims: Value, field: &str) -> Value {
        let mut claims = claims;
        claims.as_object_mut().unwrap().remove(field);
        claims
    }

    #[test]
    fn a_valid_token_yields_its_email_and_subject() {
        let key = TestKey::a();
        let caller = check(&key.sign(&good_claims()), &key.public()).expect("valid");
        assert_eq!(caller.tenant, "alice@example.com");
        assert!(caller.subject.starts_with("CiQ"), "{}", caller.subject);
    }

    #[test]
    fn each_bad_claim_has_its_reason() {
        let key = TestKey::a();
        for (claims, want) in [
            (
                with(good_claims(), "exp", json!(NOW - 3600.0)),
                Reject::Expired,
            ),
            (
                with(good_claims(), "iss", json!("https://evil.example.com/dex")),
                Reject::WrongIssuer,
            ),
            // The keys URL is in-cluster; the issuer is the public URL,
            // and only the exact public form is accepted.
            (
                with(good_claims(), "iss", json!("http://dex.dex.svc:5556/dex")),
                Reject::WrongIssuer,
            ),
            (
                with(good_claims(), "aud", json!("some-other-client")),
                Reject::WrongAudience,
            ),
            (
                with(good_claims(), "aud", json!(["a", "b"])),
                Reject::WrongAudience,
            ),
            (without(good_claims(), "aud"), Reject::WrongAudience),
            (
                with(good_claims(), "email_verified", json!(false)),
                Reject::EmailNotVerified,
            ),
            // A string is not a boolean.
            (
                with(good_claims(), "email_verified", json!("true")),
                Reject::EmailNotVerified,
            ),
            (
                without(good_claims(), "email_verified"),
                Reject::EmailNotVerified,
            ),
            (
                without(good_claims(), "email"),
                Reject::MissingClaim("email".into()),
            ),
            (
                with(good_claims(), "email", json!("")),
                Reject::MissingClaim("email".into()),
            ),
            (
                without(good_claims(), "exp"),
                Reject::MissingClaim("exp".into()),
            ),
            (
                with(good_claims(), "exp", json!("tomorrow")),
                Reject::Malformed,
            ),
            (
                with(good_claims(), "nbf", json!(NOW + 3600.0)),
                Reject::NotYetValid,
            ),
            (
                with(good_claims(), "iat", json!(NOW + 3600.0)),
                Reject::NotYetValid,
            ),
        ] {
            assert_eq!(
                check(&key.sign(&claims), &key.public()),
                Err(want.clone()),
                "{claims}"
            );
        }
    }

    #[test]
    fn an_audience_array_containing_ours_is_accepted() {
        let key = TestKey::a();
        let claims = with(good_claims(), "aud", json!(["other", AUDIENCE]));
        assert!(check(&key.sign(&claims), &key.public()).is_ok());
    }

    #[test]
    fn dates_allow_sixty_seconds_of_skew() {
        let key = TestKey::a();
        let at = |field: &str, t: f64| {
            check(
                &key.sign(&with(good_claims(), field, json!(t))),
                &key.public(),
            )
        };
        assert!(at("exp", NOW - 59.0).is_ok(), "59s past exp is within skew");
        assert_eq!(at("exp", NOW - 61.0), Err(Reject::Expired));
        assert!(at("nbf", NOW + 59.0).is_ok());
        assert_eq!(at("nbf", NOW + 61.0), Err(Reject::NotYetValid));
        assert!(at("iat", NOW + 59.0).is_ok());
        assert_eq!(at("iat", NOW + 61.0), Err(Reject::NotYetValid));
        // A fractional NumericDate is still a date.
        assert!(at("exp", NOW + 0.5).is_ok());
    }

    #[test]
    fn email_verification_can_be_waived() {
        let key = TestKey::a();
        let token = key.sign(&without(good_claims(), "email_verified"));
        let lenient = Settings {
            require_email_verified: false,
            ..settings()
        };
        let caller = Unverified::parse(&token)
            .unwrap()
            .verify(&key.public())
            .unwrap()
            .validate(&lenient, NOW);
        assert!(caller.is_ok());
    }

    #[test]
    fn a_tampered_payload_fails_the_signature() {
        let key = TestKey::a();
        let token = key.sign(&good_claims());
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = URL_SAFE_NO_PAD
            .encode(with(good_claims(), "email", json!("mallory@example.com")).to_string());
        parts[1] = &forged;
        assert_eq!(
            check(&parts.join("."), &key.public()),
            Err(Reject::BadSignature)
        );
    }

    #[test]
    fn a_token_signed_by_another_key_fails_the_signature() {
        let (a, b) = (TestKey::a(), TestKey::b());
        assert_eq!(
            check(&b.sign(&good_claims()), &a.public()),
            Err(Reject::BadSignature)
        );
    }

    #[test]
    fn alg_none_is_refused() {
        let header = URL_SAFE_NO_PAD.encode(json!({ "alg": "none", "kid": "key-a" }).to_string());
        let payload = URL_SAFE_NO_PAD.encode(good_claims().to_string());
        assert_eq!(
            Unverified::parse(&format!("{header}.{payload}.")).err(),
            Some(Reject::UnsupportedAlgorithm)
        );
    }

    /// The algorithm-confusion attack: an HMAC "signature" keyed with
    /// the RSA public key, which a verifier that trusts the header's
    /// `alg` would accept.
    #[test]
    fn an_hs256_token_keyed_with_the_public_key_is_refused() {
        let key = TestKey::a();
        let public = key.public();
        let header = URL_SAFE_NO_PAD.encode(json!({ "alg": "HS256", "kid": key.kid }).to_string());
        let payload = URL_SAFE_NO_PAD.encode(good_claims().to_string());
        let input = format!("{header}.{payload}");
        let hmac_key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &public.n);
        let tag = ring::hmac::sign(&hmac_key, input.as_bytes());
        let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(tag.as_ref()));
        assert_eq!(check(&token, &public), Err(Reject::UnsupportedAlgorithm));

        for alg in ["HS384", "HS512", "RS512", "ES256", "PS256", "rs256"] {
            let token =
                key.sign_with_header(&json!({ "alg": alg, "kid": key.kid }), &good_claims());
            assert_eq!(
                Unverified::parse(&token).err(),
                Some(Reject::UnsupportedAlgorithm),
                "{alg}"
            );
        }
    }

    #[test]
    fn malformed_tokens_are_refused() {
        let key = TestKey::a();
        let good = key.sign(&good_claims());
        let no_kid = key.sign_with_header(&json!({ "alg": "RS256" }), &good_claims());
        let crit = key.sign_with_header(
            &json!({ "alg": "RS256", "kid": key.kid, "crit": ["exp"] }),
            &good_claims(),
        );
        let dup_alg = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"none","alg":"RS256","kid":"key-a"}"#),
            good.split_once('.').unwrap().1
        );
        for token in [
            "",
            "not-a-jwt",
            "a.b",
            "a.b.c.d",
            "!!!.???.***",
            &format!("{good}.extra"),
            &no_kid,
            &crit,
            &dup_alg,
        ] {
            assert!(
                matches!(Unverified::parse(token).err(), Some(Reject::Malformed)),
                "{token}"
            );
        }
    }

    /// The reason strings are fixed text: nothing from the token can
    /// reach a log line or a response through them.
    #[test]
    fn reasons_are_fixed_text() {
        assert_eq!(Reject::Expired.to_string(), "expired");
        assert_eq!(Reject::BadSignature.to_string(), "bad signature");
        assert_eq!(
            Reject::MissingClaim("email".into()).to_string(),
            "missing email claim"
        );
    }
}

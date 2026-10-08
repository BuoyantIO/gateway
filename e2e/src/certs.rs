//! Certificate material for backends the gateway reaches over TLS it
//! originates itself.
//!
//! A locally generated CA and the leaf it signed, for `localhost` /
//! `api.test`, both valid for a century so no test run ever sees an
//! expired chain. The same pair `crates/gateway-runtime/tests/
//! tls_origination.rs` uses; e2e cannot borrow it from there, because
//! a test file is not a library.
//!
//! The leaf's names are why [`PROVIDER_SNI`] exists. A provider
//! deployed into a test namespace answers to
//! `{name}.{namespace}.svc.cluster.local`, and the namespace is
//! random per test, so no baked leaf can carry that name. The
//! `GatewayBackend`'s `tls.sni` overrides what is sent and verified,
//! which keeps the chain check real without generating a certificate
//! per run.

/// The CA to install as a `GatewayBackend`'s trust root.
pub const PROVIDER_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBsjCCAVmgAwIBAgIUAqZNnOsD0G5WuwUP/VAqg1pioKowCgYIKoZIzj0EAwIw\n\
JjEkMCIGA1UEAwwbZ2F0ZXdheS1vcmlnaW5hdGlvbi10ZXN0LWNhMCAXDTI2MDgy\n\
NzE0NDYzMVoYDzIxMjYwODAzMTQ0NjMxWjAmMSQwIgYDVQQDDBtnYXRld2F5LW9y\n\
aWdpbmF0aW9uLXRlc3QtY2EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATHgF+C\n\
6usYwYsp3HUehFK4Ru6DLVd++3/EQJM2XjDM2RNV8cXplEJpa4H7Agcaz3Dfq06O\n\
gOEf6xHpjE9bYRX6o2MwYTAdBgNVHQ4EFgQUmmXyVJdN4bk40OiR5xOwOQ7g018w\n\
HwYDVR0jBBgwFoAUmmXyVJdN4bk40OiR5xOwOQ7g018wDwYDVR0TAQH/BAUwAwEB\n\
/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwIDRwAwRAIgQjTSJ8Ka7Y8znUK2\n\
JmS1VOAC/qDna5hhngFX3Xo2HO4CIEwQcUUqHmydr7a881ReF9mfw2A2/ZZU4rjn\n\
8V48OIbq\n\
-----END CERTIFICATE-----\n";

/// The leaf a mock provider serves. Signed by [`PROVIDER_CA_PEM`],
/// with `localhost` and `api.test` in its SANs.
pub const PROVIDER_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIB1TCCAXugAwIBAgIUVLTPUUWjrU7KocTsDVnTRLzg++4wCgYIKoZIzj0EAwIw\n\
JjEkMCIGA1UEAwwbZ2F0ZXdheS1vcmlnaW5hdGlvbi10ZXN0LWNhMCAXDTI2MDgy\n\
NzE0NDYzMVoYDzIxMjYwODAzMTQ0NjMxWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3Qw\n\
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQUDCA32PJSGujpUsM+sLBoL/iKNNAc\n\
P771SzU047Y6/GT0Yd0NoYosJXYRWmwW7rbmuaQP+9Hv0OWOtDeTnW8Uo4GWMIGT\n\
MB4GA1UdEQQXMBWCCWxvY2FsaG9zdIIIYXBpLnRlc3QwDAYDVR0TAQH/BAIwADAO\n\
BgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwHQYDVR0OBBYEFFjh\n\
tqmJEwNoRYJXLOrsjgAWYR5yMB8GA1UdIwQYMBaAFJpl8lSXTeG5ONDokecTsDkO\n\
4NNfMAoGCCqGSM49BAMCA0gAMEUCIQD0Qxnf+dlFtUdXSW6S6du4Ha8N7g54I4j4\n\
0xXTenSg+gIgNuSajDRruKN+wcp5gPEbcZ1lzgOt28293yPj5DBqJ4M=\n\
-----END CERTIFICATE-----\n";

/// The leaf's private key.
pub const PROVIDER_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9E9CybOoAv5nunPY\n\
G+2BYNpApQ5oWbsrNL3i2TXPyn6hRANCAAQUDCA32PJSGujpUsM+sLBoL/iKNNAc\n\
P771SzU047Y6/GT0Yd0NoYosJXYRWmwW7rbmuaQP+9Hv0OWOtDeTnW8U\n\
-----END PRIVATE KEY-----\n";

/// The name to send as SNI and verify the leaf against, since the
/// provider's cluster DNS name is not in it.
pub const PROVIDER_SNI: &str = "api.test";

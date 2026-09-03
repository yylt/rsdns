//! TLS configuration helpers.
//!
//! Client side: [`default_tls_client_config`] (used by every upstream
//! protocol).  Server side: [`server_config`] builds the shared
//! `Arc<rustls::ServerConfig>` used by the DoT / DoH / DoH3 listeners —
//! either from the explicit `tls_cert` / `tls_key` PEM files or from an
//! in-memory ECDSA P-256 self-signed certificate generated at startup.

use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use std::io::BufReader;
use std::sync::Arc;

use crate::config::Config;

pub fn install_crypto_provider() {
    #[cfg(feature = "ring")]
    rustls::crypto::ring::default_provider().install_default().ok();

    #[cfg(feature = "aws-lc-rs")]
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();
}

pub fn default_tls_client_config() -> Arc<ClientConfig> {
    install_crypto_provider();

    let native_certs = rustls_native_certs::load_native_certs().expect("load native certs");

    let mut root_store = RootCertStore::empty();
    for cert in native_certs {
        root_store.add(cert).ok();
    }
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Arc::new(config)
}

/// Loads a server TLS config from PEM cert/key bytes.
///
/// `cert_pem` may contain the leaf certificate followed by intermediate
/// chain certificates.  `key_pem` is a PKCS#8 / PKCS#1 / SEC1 private key.
/// The private key must match the leaf certificate's public key.
pub fn load_server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<ServerConfig>, String> {
    install_crypto_provider();

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(cert_pem))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse certificate PEM: {e}"))?;
    if certs.is_empty() {
        return Err("no certificate found in tls_cert".into());
    }

    let key = rustls_pemfile::private_key(&mut BufReader::new(key_pem))
        .map_err(|e| format!("parse key PEM: {e}"))?
        .ok_or_else(|| String::from("no private key found in tls_key"))?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("certificate/private key mismatch or invalid: {e}"))?;

    // One shared ServerConfig serves DoT (RFC 7858 ALPN "dot"), DoH (h2 /
    // http/1.1 for ALPN) and DoH3 (h3 for QUIC).  Advertising all four lets
    // each listener negotiate its own protocol; clients that send no ALPN
    // (e.g. hickory's DoT client) still connect fine.
    config.alpn_protocols = vec![b"h3".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec(), b"dot".to_vec()];
    Ok(Arc::new(config))
}

/// Generates an ECDSA P-256 self-signed certificate (valid 1 year) covering
/// `localhost` and the common loopback/private IP SANs, returning
/// `(cert_pem, key_pem)`.
pub fn generate_self_signed() -> Result<(Vec<u8>, Vec<u8>), String> {
    use rcgen::generate_simple_self_signed;

    let sans = [
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect::<Vec<_>>();

    let certified = generate_simple_self_signed(sans).map_err(|e| format!("generate self-signed cert: {e}"))?;
    Ok((
        pem_encode("CERTIFICATE", certified.cert.der()),
        pem_encode("PRIVATE KEY", &certified.signing_key.serialize_der()),
    ))
}

/// Wraps DER bytes in a PEM block (base64, 64 columns), matching the
/// `--BEGIN/END <tag>--` format `rustls-pemfile` reads.
fn pem_encode(tag: &str, der: &[u8]) -> Vec<u8> {
    use data_encoding::BASE64;
    let mut out = Vec::with_capacity(der.len() * 2 + 64);
    out.extend_from_slice(format!("-----BEGIN {tag}-----\n").as_bytes());
    let b64 = BASE64.encode(der);
    for chunk in b64.as_bytes().chunks(64) {
        out.extend_from_slice(chunk);
        out.push(b'\n');
    }
    out.extend_from_slice(format!("-----END {tag}-----\n").as_bytes());
    out
}

/// Builds the shared server TLS config from `Config`:
///
/// - `tls_cert` + `tls_key` both set → load from those PEM files.
/// - both absent → generate an in-memory self-signed certificate.
/// - only one set → startup error.
pub fn server_config(config: &Config) -> Result<Arc<ServerConfig>, String> {
    match (&config.tls_cert, &config.tls_key) {
        (Some(cert), Some(key)) => {
            let cert_pem = std::fs::read(cert).map_err(|e| format!("read tls_cert {}: {e}", cert))?;
            let key_pem = std::fs::read(key).map_err(|e| format!("read tls_key {}: {e}", key))?;
            load_server_config(&cert_pem, &key_pem)
        }
        (None, None) => {
            let (cert_pem, key_pem) = generate_self_signed()?;
            load_server_config(&cert_pem, &key_pem)
        }
        (Some(_), None) => Err("tls_cert set but tls_key missing".into()),
        (None, Some(_)) => Err("tls_key set but tls_cert missing".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_self_signed_loads_as_server_config() {
        let (cert, key) = generate_self_signed().expect("generate");
        // The generated cert/key must produce a valid ServerConfig with the
        // shared ALPN set (h3 / h2 / http/1.1 / dot).
        let cfg = load_server_config(&cert, &key).expect("load");
        assert_eq!(
            cfg.alpn_protocols,
            vec![b"h3".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec(), b"dot".to_vec()]
        );
    }

    #[test]
    fn test_load_server_config_bad_pem() {
        assert!(load_server_config(b"not pem", b"not pem").is_err());
        assert!(
            load_server_config(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", b"nope").is_err()
        );
    }

    #[test]
    fn test_load_server_config_mismatched_key() {
        let (cert, _key) = generate_self_signed().expect("generate");
        let (_, other_key) = generate_self_signed().expect("generate other");
        // A key from a different self-signed pair must be rejected.
        assert!(load_server_config(&cert, &other_key).is_err());
    }

    #[test]
    fn test_server_config_partial_is_error() {
        let cfg = Config {
            tls_cert: Some("/tmp/x.crt".into()),
            tls_key: None,
            ..Config::default()
        };
        assert!(server_config(&cfg).is_err());
        let cfg = Config {
            tls_cert: None,
            tls_key: Some("/tmp/x.key".into()),
            ..Config::default()
        };
        assert!(server_config(&cfg).is_err());
    }

    #[test]
    fn test_server_config_missing_file_is_error() {
        let cfg = Config {
            tls_cert: Some("/nonexistent/server.crt".into()),
            tls_key: Some("/nonexistent/server.key".into()),
            ..Config::default()
        };
        assert!(server_config(&cfg).is_err());
    }

    #[test]
    fn test_server_config_self_signed_default() {
        let cfg = Config::default();
        let sc = server_config(&cfg).expect("self-signed default");
        assert_eq!(
            sc.alpn_protocols,
            vec![b"h3".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec(), b"dot".to_vec()]
        );
    }
}

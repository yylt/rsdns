//! TLS client configuration helpers (trimmed from the `xray-rs` common
//! module; only what `rsdns` uses is kept).

use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;

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

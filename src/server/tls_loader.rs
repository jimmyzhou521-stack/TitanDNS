use anyhow::{Result, Context};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

pub fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).context(format!("Failed to open cert file: {}", path))?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

pub fn load_keys(path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).context(format!("Failed to open key file: {}", path))?;
    let mut reader = BufReader::new(file);

    // rustls-pemfile 2.1 read_all
    for item in rustls_pemfile::read_all(&mut reader) {
        match item? {
            rustls_pemfile::Item::Pkcs8Key(key) => return Ok(PrivateKeyDer::Pkcs8(key)),
            rustls_pemfile::Item::Pkcs1Key(key) => return Ok(PrivateKeyDer::Pkcs1(key)),
            rustls_pemfile::Item::Sec1Key(key) => return Ok(PrivateKeyDer::Sec1(key)),
            _ => continue,
        }
    }
    
    Err(anyhow::anyhow!("No supported private key found (checked PKCS8/RSA/SEC1)"))
}

pub fn build_dot_config(cert_path: &str, key_path: &str) -> Result<Arc<rustls::ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_keys(key_path)?;

    // rustls 0.23: safe defaults are implicit if using ring/aws-lc-rs
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to build TLS config")?;
        
    let mut config = config;
    config.alpn_protocols = vec![b"dot".to_vec()];

    Ok(Arc::new(config))
}

pub fn build_doq_config(cert_path: &str, key_path: &str) -> Result<Arc<rustls::ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_keys(key_path)?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to build QUIC TLS config")?;
        
    let mut config = config;
    config.alpn_protocols = vec![b"doq".to_vec()];

    Ok(Arc::new(config))
}

pub fn build_doh_config(cert_path: &str, key_path: &str) -> Result<Arc<rustls::ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_keys(key_path)?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to build DoH TLS config")?;

    let mut config = config;
    // Support HTTP/2 and HTTP/1.1 for DoH
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

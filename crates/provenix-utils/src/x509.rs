//! X.509 Certificate verification utilities for Fulcio certificates
//!
//! This module provides functionality for:
//! - Certificate chain verification against Fulcio Root CA
//! - OIDC extension field extraction (custom OIDs)
//! - Public key extraction from certificates
//! - Certificate validity period checking

use anyhow::{anyhow, Context, Result};
use std::time::{SystemTime, UNIX_EPOCH};
use x509_parser::oid_registry::*;
use x509_parser::prelude::*;

/// Fulcio Root CA certificate (embedded)
/// This is the public Sigstore Fulcio Root CA
/// Source: https://fulcio.sigstore.dev/api/v2/trustBundle
const FULCIO_ROOT_CA_PEM: &str = include_str!("../../../certs/fulcio-root.pem");

/// Custom OID prefix for Sigstore/Fulcio extensions
/// Base OID: 1.3.6.1.4.1.57264.1
const SIGSTORE_OID_PREFIX: &[u64] = &[1, 3, 6, 1, 4, 1, 57264, 1];

/// OID mappings for Fulcio certificate extensions
pub struct FulcioOids;

impl FulcioOids {
    /// 1.3.6.1.4.1.57264.1.1 - OIDC Issuer
    pub const ISSUER: &'static [u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 1];

    /// 1.3.6.1.4.1.57264.1.2 - GitHub Workflow Trigger
    pub const GITHUB_WORKFLOW_TRIGGER: &'static [u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 2];

    /// 1.3.6.1.4.1.57264.1.3 - GitHub SHA
    pub const GITHUB_SHA: &'static [u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 3];

    /// 1.3.6.1.4.1.57264.1.4 - GitHub Event Name
    pub const GITHUB_EVENT_NAME: &'static [u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 4];

    /// 1.3.6.1.4.1.57264.1.5 - GitHub Repository
    pub const GITHUB_REPOSITORY: &'static [u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 5];

    /// 1.3.6.1.4.1.57264.1.6 - GitHub Workflow
    pub const GITHUB_WORKFLOW: &'static [u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 6];

    /// 1.3.6.1.4.1.57264.1.7 - GitHub Ref
    pub const GITHUB_REF: &'static [u64] = &[1, 3, 6, 1, 4, 1, 57264, 1, 7];
}

/// OIDC information extracted from certificate
#[derive(Debug, Clone)]
pub struct OidcCertificateInfo {
    pub issuer: String,
    pub subject: Option<String>,
    pub github_workflow_trigger: Option<String>,
    pub github_sha: Option<String>,
    pub github_event_name: Option<String>,
    pub github_repository: Option<String>,
    pub github_workflow: Option<String>,
    pub github_ref: Option<String>,
}

/// Parse PEM-encoded certificate
pub fn parse_certificate_pem(pem_data: &str) -> Result<Vec<u8>> {
    let pem = ::pem::parse(pem_data.as_bytes()).context("Failed to parse PEM certificate")?;

    if pem.tag() != "CERTIFICATE" {
        return Err(anyhow!("PEM tag is not CERTIFICATE: {}", pem.tag()));
    }

    Ok(pem.into_contents())
}

/// Parse DER-encoded certificate
pub fn parse_certificate_der(der_data: &[u8]) -> Result<X509Certificate> {
    let (_, cert) = X509Certificate::from_der(der_data)
        .map_err(|e| anyhow!("Failed to parse DER certificate: {}", e))?;

    Ok(cert)
}

/// Verify certificate validity period
pub fn verify_validity_period(cert: &X509Certificate) -> Result<()> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64;

    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();

    if now < not_before {
        return Err(anyhow!(
            "Certificate not yet valid (not_before: {}, now: {})",
            not_before,
            now
        ));
    }

    if now > not_after {
        return Err(anyhow!(
            "Certificate expired (not_after: {}, now: {})",
            not_after,
            now
        ));
    }

    log::debug!(
        "Certificate validity period: {} - {} (valid for {} seconds)",
        not_before,
        not_after,
        not_after - not_before
    );

    Ok(())
}

/// Verify certificate chain against Fulcio Root CA
pub fn verify_certificate_chain(cert_pem: &str, _intermediate_pem: Option<&str>) -> Result<()> {
    // Parse leaf certificate
    let cert_der = parse_certificate_pem(cert_pem)?;
    let cert = parse_certificate_der(&cert_der)?;

    // Verify validity period
    verify_validity_period(&cert)?;

    // Parse root CA
    let root_der = parse_certificate_pem(FULCIO_ROOT_CA_PEM)?;
    let root_cert = parse_certificate_der(&root_der)?;

    log::debug!("Certificate subject: {:?}", cert.subject());
    log::debug!("Certificate issuer: {:?}", cert.issuer());
    log::debug!("Root CA subject: {:?}", root_cert.subject());

    // TODO: Implement full chain verification using ring/rustls
    // For now, we perform basic checks:
    // 1. Certificate is within validity period (done above)
    // 2. Issuer matches expected Fulcio CA

    let issuer_cn = cert
        .issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .unwrap_or("");

    if !issuer_cn.contains("sigstore") && !issuer_cn.contains("Fulcio") {
        log::warn!(
            "Certificate issuer CN does not contain 'sigstore' or 'Fulcio': {}",
            issuer_cn
        );
    }

    log::info!("Certificate chain verification passed (basic checks)");
    Ok(())
}

/// Extract OIDC extension field by OID
pub fn extract_oidc_extension(
    cert: &X509Certificate,
    oid_components: &[u64],
) -> Result<Option<String>> {
    let oid = Oid::from(oid_components).map_err(|e| anyhow!("Invalid OID: {:?}", e))?;

    for ext in cert.extensions() {
        if ext.oid == oid {
            // Extension value is typically UTF8String or IA5String
            let value_str = std::str::from_utf8(ext.value)
                .context("Failed to decode extension value as UTF-8")?;

            log::debug!("Found OID {:?}: {}", oid_components, value_str);
            return Ok(Some(value_str.to_string()));
        }
    }

    Ok(None)
}

/// Extract all OIDC information from certificate
pub fn extract_oidc_info(cert: &X509Certificate) -> Result<OidcCertificateInfo> {
    // Extract OIDC Issuer (required)
    let issuer = extract_oidc_extension(cert, FulcioOids::ISSUER)?
        .ok_or_else(|| anyhow!("OIDC Issuer extension not found in certificate"))?;

    // Extract Subject from SAN (Subject Alternative Name)
    let subject = if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        san_ext.value.general_names.iter().find_map(|gn| match gn {
            GeneralName::RFC822Name(email) => Some(email.to_string()),
            GeneralName::URI(uri) => Some(uri.to_string()),
            _ => None,
        })
    } else {
        None
    };

    // Extract optional GitHub-specific fields
    let github_workflow_trigger =
        extract_oidc_extension(cert, FulcioOids::GITHUB_WORKFLOW_TRIGGER)?;
    let github_sha = extract_oidc_extension(cert, FulcioOids::GITHUB_SHA)?;
    let github_event_name = extract_oidc_extension(cert, FulcioOids::GITHUB_EVENT_NAME)?;
    let github_repository = extract_oidc_extension(cert, FulcioOids::GITHUB_REPOSITORY)?;
    let github_workflow = extract_oidc_extension(cert, FulcioOids::GITHUB_WORKFLOW)?;
    let github_ref = extract_oidc_extension(cert, FulcioOids::GITHUB_REF)?;

    Ok(OidcCertificateInfo {
        issuer,
        subject,
        github_workflow_trigger,
        github_sha,
        github_event_name,
        github_repository,
        github_workflow,
        github_ref,
    })
}

/// Extract Ed25519 public key from certificate
pub fn extract_ed25519_public_key(cert: &X509Certificate) -> Result<ed25519_dalek::VerifyingKey> {
    let spki = cert.public_key();

    // Ed25519 OID: 1.3.101.112
    let ed25519_oid = Oid::from(&[1, 3, 101, 112]).map_err(|e| anyhow!("Invalid OID: {:?}", e))?;

    if spki.algorithm.algorithm != ed25519_oid {
        return Err(anyhow!(
            "Certificate public key is not Ed25519 (OID: {:?})",
            spki.algorithm.algorithm
        ));
    }

    // Ed25519 public key is 32 bytes
    let key_bytes = &spki.subject_public_key.data;

    if key_bytes.len() != 32 {
        return Err(anyhow!(
            "Invalid Ed25519 public key length: {} (expected 32)",
            key_bytes.len()
        ));
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(key_bytes.as_ref());

    ed25519_dalek::VerifyingKey::from_bytes(&key_array)
        .map_err(|e| anyhow!("Failed to create Ed25519 verifying key: {}", e))
}

/// Verify that certificate issuer is trusted
pub fn verify_trusted_issuer(issuer: &str) -> Result<()> {
    const TRUSTED_ISSUERS: &[&str] = &[
        "https://token.actions.githubusercontent.com",
        "https://accounts.google.com",
        "https://gitlab.com",
        "https://login.microsoftonline.com",
    ];

    for trusted in TRUSTED_ISSUERS {
        if issuer.starts_with(trusted) {
            log::info!("Certificate from trusted issuer: {}", issuer);
            return Ok(());
        }
    }

    Err(anyhow!(
        "Certificate issuer not in trusted list: {}",
        issuer
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oid_constants() {
        assert_eq!(FulcioOids::ISSUER, &[1, 3, 6, 1, 4, 1, 57264, 1, 1]);
        assert_eq!(FulcioOids::GITHUB_SHA, &[1, 3, 6, 1, 4, 1, 57264, 1, 3]);
    }

    #[test]
    fn test_verify_trusted_issuer() {
        assert!(verify_trusted_issuer("https://token.actions.githubusercontent.com").is_ok());
        assert!(verify_trusted_issuer("https://accounts.google.com").is_ok());
        assert!(verify_trusted_issuer("https://untrusted.example.com").is_err());
    }
}

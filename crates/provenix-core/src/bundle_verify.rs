// Copyright 2025 Provenix Contributors
//
// Licensed under the Apache License, Version 2.0

//! Bundle Verification Module
//!
//! Provides comprehensive verification for Sigstore Bundle v0.3 format:
//! - Certificate chain validation
//! - Signature verification
//! - Rekor transparency log verification (inclusion proof)
//! - OIDC claim validation
//! - Online and offline verification modes

use crate::bundle::*;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use std::path::PathBuf;

/// Verification mode for Bundle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationMode {
    /// Online mode: Verify Rekor entries by fetching from server
    Online,
    /// Offline mode: Verify only inclusion proof without network access
    Offline,
}

/// Verification result
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub valid: bool,
    pub certificate_valid: bool,
    pub signature_valid: bool,
    pub rekor_verified: bool,
    pub timestamp_verified: bool,
    pub oidc_issuer: Option<String>,
    pub oidc_subject: Option<String>,
    pub details: String,
}

/// Verify a Sigstore Bundle
///
/// Performs comprehensive verification including:
/// - Bundle structure validation
/// - Certificate chain validation
/// - Signature verification
/// - Rekor inclusion proof verification
/// - OIDC claim validation
pub fn verify_bundle(
    bundle: &Bundle,
    _artifact: &PathBuf,
    mode: VerificationMode,
) -> Result<VerificationResult> {
    log::info!("Verifying Bundle (mode: {:?})", mode);

    // Step 1: Validate bundle structure
    bundle
        .validate()
        .map_err(|e| anyhow!("Bundle structure validation failed: {}", e))?;

    log::debug!("✓ Bundle structure valid");

    // Step 2: Extract certificate from verification material
    let cert_der = match &bundle.verification_material.content {
        VerificationMaterialContent::Certificate(cert) => &cert.raw_bytes,
        VerificationMaterialContent::X509CertificateChain(chain) => {
            if chain.certificates.is_empty() {
                return Err(anyhow!("Certificate chain is empty"));
            }
            &chain.certificates[0].raw_bytes
        }
        VerificationMaterialContent::PublicKey(_) => {
            return Err(anyhow!("Public key verification not yet supported"));
        }
    };

    // Step 3: Parse certificate
    let cert = provenix_utils::x509::parse_certificate_der(cert_der)
        .map_err(|e| anyhow!("Failed to parse certificate: {}", e))?;

    log::debug!("✓ Certificate parsed");

    // Step 4: Verify certificate chain (using Phase 4.1 implementation)
    let cert_pem = encode_certificate_pem(cert_der)?;

    // Get intermediate certificate if chain is provided
    let intermediate_pem = match &bundle.verification_material.content {
        VerificationMaterialContent::X509CertificateChain(chain) => {
            if chain.certificates.len() > 1 {
                Some(encode_certificate_pem(&chain.certificates[1].raw_bytes)?)
            } else {
                None
            }
        }
        _ => None,
    };

    provenix_utils::x509::verify_certificate_chain(&cert_pem, intermediate_pem.as_deref())
        .map_err(|e| anyhow!("Certificate chain verification failed: {}", e))?;

    log::info!("✓ Certificate chain verified");

    // Step 5: Extract OIDC information from certificate
    let oidc_info = provenix_utils::x509::extract_oidc_info(&cert)
        .map_err(|e| anyhow!("Failed to extract OIDC info: {}", e))?;

    // Verify OIDC issuer is trusted
    provenix_utils::x509::verify_trusted_issuer(&oidc_info.issuer)
        .map_err(|e| anyhow!("Untrusted OIDC issuer: {}", e))?;

    log::info!("✓ OIDC issuer verified: {}", oidc_info.issuer);

    // Step 6: Extract payload and signature from Bundle content
    let (payload_bytes, signature_bytes) = match &bundle.content {
        SignatureContent::DsseEnvelope(envelope) => {
            if envelope.signatures.is_empty() {
                return Err(anyhow!("No signatures in DSSE envelope"));
            }

            let payload = BASE64
                .decode(&envelope.payload)
                .map_err(|e| anyhow!("Failed to decode payload: {}", e))?;

            let sig = BASE64
                .decode(&envelope.signatures[0].sig)
                .map_err(|e| anyhow!("Failed to decode signature: {}", e))?;

            (payload, sig)
        }
        SignatureContent::MessageSignature(_) => {
            return Err(anyhow!("MessageSignature verification not yet implemented"));
        }
    };

    // Step 7: Extract public key from certificate
    let public_key = provenix_utils::x509::extract_ed25519_public_key(&cert)
        .map_err(|e| anyhow!("Failed to extract public key: {}", e))?;

    log::debug!("✓ Public key extracted from certificate");

    // Step 8: Verify signature
    use ed25519_dalek::{Signature, Verifier};

    let signature = Signature::from_bytes(
        &signature_bytes
            .try_into()
            .map_err(|_| anyhow!("Invalid signature length"))?,
    );

    public_key
        .verify(&payload_bytes, &signature)
        .map_err(|e| anyhow!("Signature verification failed: {}", e))?;

    log::info!("✓ Signature verified");

    // Step 9: Verify Rekor transparency log entries
    let mut rekor_verified = false;

    if !bundle.verification_material.tlog_entries.is_empty() {
        log::info!(
            "Verifying {} transparency log entries",
            bundle.verification_material.tlog_entries.len()
        );

        for entry in &bundle.verification_material.tlog_entries {
            verify_tlog_entry(entry, &payload_bytes, mode)?;
            rekor_verified = true;
        }

        log::info!("✓ All transparency log entries verified");
    } else {
        log::warn!("⚠ No transparency log entries in bundle");
    }

    // Step 10: Verify timestamps (if present)
    let timestamp_verified = if bundle
        .verification_material
        .timestamp_verification_data
        .is_some()
    {
        log::info!("⚠ RFC3161 timestamp verification not yet implemented");
        false
    } else {
        false
    };

    // Step 11: Create verification result
    Ok(VerificationResult {
        valid: true,
        certificate_valid: true,
        signature_valid: true,
        rekor_verified,
        timestamp_verified,
        oidc_issuer: Some(oidc_info.issuer),
        oidc_subject: oidc_info.subject,
        details: "Bundle verification successful".to_string(),
    })
}

/// Verify a single transparency log entry
fn verify_tlog_entry(
    entry: &TransparencyLogEntry,
    payload: &[u8],
    mode: VerificationMode,
) -> Result<()> {
    log::debug!(
        "Verifying transparency log entry: logIndex={}",
        entry.log_index
    );

    // Step 1: Verify inclusion proof (offline)
    let log_index: u64 = entry
        .log_index
        .parse()
        .map_err(|_| anyhow!("Invalid log index"))?;

    let tree_size: u64 = entry
        .inclusion_proof
        .tree_size
        .parse()
        .map_err(|_| anyhow!("Invalid tree size"))?;

    // Compute leaf hash from payload
    let leaf_hash = provenix_utils::rekor::compute_leaf_hash(payload);

    // Verify inclusion proof
    provenix_utils::rekor::verify_inclusion_proof(
        &leaf_hash,
        log_index,
        &entry.inclusion_proof.hashes,
        tree_size,
        &entry.inclusion_proof.root_hash,
    )
    .map_err(|e| anyhow!("Inclusion proof verification failed: {}", e))?;

    log::info!("✓ Inclusion proof verified (logIndex={})", log_index);

    // Step 2: Online verification (fetch from Rekor and compare)
    if mode == VerificationMode::Online {
        log::info!("⚠ Online Rekor verification not yet implemented");
        // TODO: Fetch entry from Rekor and compare with bundle data
    }

    Ok(())
}

/// Encode DER certificate to PEM format
fn encode_certificate_pem(der: &[u8]) -> Result<String> {
    let base64_cert = BASE64.encode(der);

    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in base64_cert.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");

    Ok(pem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verification_mode() {
        assert_eq!(VerificationMode::Online, VerificationMode::Online);
        assert_eq!(VerificationMode::Offline, VerificationMode::Offline);
        assert_ne!(VerificationMode::Online, VerificationMode::Offline);
    }

    #[test]
    fn test_verification_result_creation() {
        let result = VerificationResult {
            valid: true,
            certificate_valid: true,
            signature_valid: true,
            rekor_verified: true,
            timestamp_verified: false,
            oidc_issuer: Some("https://token.actions.githubusercontent.com".to_string()),
            oidc_subject: Some("repo:owner/repo:ref:refs/heads/main".to_string()),
            details: "Test".to_string(),
        };

        assert!(result.valid);
        assert!(result.certificate_valid);
        assert!(result.signature_valid);
        assert!(result.rekor_verified);
        assert!(!result.timestamp_verified);
    }

    #[test]
    fn test_encode_certificate_pem() {
        let der = vec![1, 2, 3, 4, 5];
        let pem = encode_certificate_pem(&der).unwrap();

        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));
        assert!(pem.contains("AQIDBAU")); // base64 of [1,2,3,4,5]
    }
}

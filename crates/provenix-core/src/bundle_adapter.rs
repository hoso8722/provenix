// Copyright 2025 Provenix Contributors
//
// Licensed under the Apache License, Version 2.0

//! Sigstore Bundle Format Adapter
//!
//! Converts between DSSE format and Sigstore Bundle format (v0.3).
//! Enables compatibility with Cosign and other Sigstore ecosystem tools.

use crate::bundle::*;
use crate::signature_format::{DsseEnvelope as SigDsseEnvelope, SignatureFormat};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::Value;

pub struct BundleAdapter;

impl SignatureFormat for BundleAdapter {
    fn name(&self) -> &str {
        "bundle"
    }

    fn from_dsse(&self, dsse: &SigDsseEnvelope) -> Result<Value> {
        // Extract DSSE components
        let payload_type = &dsse.payload_type;
        let payload = &dsse.payload;

        if dsse.signatures.len() != 1 {
            return Err(anyhow!(
                "Bundle format requires exactly one signature, found {}",
                dsse.signatures.len()
            ));
        }

        let sig_entry = &dsse.signatures[0];
        let sig = &sig_entry.sig;

        // Extract certificate if present
        let certificate_pem = sig_entry
            .certificate
            .as_ref()
            .ok_or_else(|| anyhow!("Bundle format requires certificate"))?;

        // Parse certificate to DER
        let cert_der = parse_certificate_pem(certificate_pem)
            .map_err(|e| anyhow!("Failed to parse certificate: {}", e))?;

        // Create verification material
        let verification_material = VerificationMaterial {
            content: VerificationMaterialContent::Certificate(X509Certificate {
                raw_bytes: cert_der,
            }),
            tlog_entries: vec![], // TODO: Extract from DSSE if present
            timestamp_verification_data: None,
        };

        // Create DSSE envelope for bundle
        let dsse_envelope = DsseEnvelope {
            payload_type: payload_type.to_string(),
            payload: payload.to_string(),
            signatures: vec![DsseSignature {
                keyid: None,
                sig: sig.to_string(),
            }],
        };

        // Create bundle
        let bundle = Bundle::new(
            verification_material,
            SignatureContent::DsseEnvelope(dsse_envelope),
        );

        // Serialize to JSON
        serde_json::to_value(bundle).map_err(|e| anyhow!("Failed to serialize bundle: {}", e))
    }

    fn to_dsse(&self, bundle_json: &Value) -> Result<SigDsseEnvelope> {
        // Deserialize bundle
        let bundle: Bundle = serde_json::from_value(bundle_json.clone())
            .map_err(|e| anyhow!("Invalid bundle format: {}", e))?;

        // Validate bundle
        bundle
            .validate()
            .map_err(|e| anyhow!("Bundle validation failed: {}", e))?;

        // Extract DSSE envelope
        let dsse_envelope = match bundle.content {
            SignatureContent::DsseEnvelope(envelope) => envelope,
            SignatureContent::MessageSignature(_) => {
                return Err(anyhow!("Cannot convert MessageSignature to DSSE"));
            }
        };

        // Extract certificate from verification material
        let certificate_pem = match bundle.verification_material.content {
            VerificationMaterialContent::Certificate(cert) => {
                encode_certificate_pem(&cert.raw_bytes)?
            }
            VerificationMaterialContent::X509CertificateChain(chain) => {
                if chain.certificates.is_empty() {
                    return Err(anyhow!("Certificate chain is empty"));
                }
                encode_certificate_pem(&chain.certificates[0].raw_bytes)?
            }
            VerificationMaterialContent::PublicKey(_) => {
                return Err(anyhow!(
                    "Public key identifier not supported in DSSE conversion"
                ));
            }
        };

        // Build DSSE structure with certificate
        use crate::signature_format::DsseSignature as SigDsseSignature;

        let sig_dsse_envelope = SigDsseEnvelope {
            payload_type: dsse_envelope.payload_type.clone(),
            payload: dsse_envelope.payload.clone(),
            signatures: dsse_envelope
                .signatures
                .iter()
                .map(|s| SigDsseSignature {
                    sig: s.sig.clone(),
                    public_key: None,
                    certificate: Some(certificate_pem.clone()),
                    chain: None,
                    oidc_issuer: None,
                    oidc_subject: None,
                })
                .collect(),
        };

        Ok(sig_dsse_envelope)
    }

    fn detect(&self, data: &Value) -> bool {
        // Check for bundle media type
        if let Some(media_type) = data.get("mediaType").and_then(|v| v.as_str()) {
            return media_type.starts_with("application/vnd.dev.sigstore.bundle");
        }

        // Check for verification material (unique to bundle format)
        data.get("verificationMaterial").is_some()
    }
}

/// Parse PEM certificate to DER bytes
fn parse_certificate_pem(pem: &str) -> Result<Vec<u8>> {
    // Remove PEM headers and decode base64
    let pem_content = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();

    BASE64
        .decode(pem_content.as_bytes())
        .map_err(|e| anyhow!("Failed to decode certificate PEM: {}", e))
}

/// Encode DER certificate to PEM format
fn encode_certificate_pem(der: &[u8]) -> Result<String> {
    let base64_cert = BASE64.encode(der);

    // Split into 64-character lines
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in base64_cert.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");

    Ok(pem)
}

// Register the adapter
#[ctor::ctor]
fn register_bundle_adapter() {
    use crate::signature_format::register_format;
    let _ = register_format("bundle", BundleAdapter);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_bundle_detection() {
        let adapter = BundleAdapter;

        // Valid bundle
        let bundle = json!({
            "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {}
        });
        assert!(adapter.detect(&bundle));

        // DSSE format
        let dsse = json!({
            "payloadType": "application/vnd.in-toto+json",
            "payload": "test",
            "signatures": []
        });
        assert!(!adapter.detect(&dsse));
    }

    #[test]
    fn test_pem_encoding() {
        let der = vec![1, 2, 3, 4, 5];
        let pem = encode_certificate_pem(&der).unwrap();

        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with("-----END CERTIFICATE-----\n"));

        // Decode back
        let decoded = parse_certificate_pem(&pem).unwrap();
        assert_eq!(decoded, der);
    }
}

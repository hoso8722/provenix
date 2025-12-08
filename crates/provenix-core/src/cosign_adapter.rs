/// Cosign signature format adapter
///
/// This module implements conversion between Provenix DSSE format and
/// Cosign SimpleSigning format for ecosystem interoperability.
///
/// References:
/// - Cosign SimpleSigning: https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md
/// - In-toto Statement: https://github.com/in-toto/attestation/blob/main/spec/README.md

use super::signature_format::{DsseEnvelope, DsseSignature, SignatureFormat};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::{json, Value};

/// Cosign signature format adapter
pub struct CosignAdapter;

impl SignatureFormat for CosignAdapter {
    fn name(&self) -> &str {
        "cosign"
    }

    /// Convert DSSE envelope to Cosign SimpleSigning format
    ///
    /// DSSE structure:
    /// ```json
    /// {
    ///   "payloadType": "application/vnd.in-toto+json",
    ///   "payload": "base64(...)",
    ///   "signatures": [{"sig": "...", "certificate": "..."}]
    /// }
    /// ```
    ///
    /// Cosign structure:
    /// ```json
    /// {
    ///   "critical": {
    ///     "identity": {"docker-reference": ""},
    ///     "image": {"docker-manifest-digest": "sha256:..."},
    ///     "type": "cosign container image signature"
    ///   },
    ///   "optional": {
    ///     "Signature": "...",
    ///     "Certificate": "...",
    ///     "Bundle": {...}
    ///   }
    /// }
    /// ```
    fn from_dsse(&self, dsse: &DsseEnvelope) -> Result<Value> {
        // Decode DSSE payload
        let payload_bytes = BASE64
            .decode(&dsse.payload)
            .map_err(|e| anyhow!("Failed to decode DSSE payload: {}", e))?;

        let attestation: Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| anyhow!("Failed to parse attestation JSON: {}", e))?;

        // Extract subject information (artifact hash)
        let subject = attestation
            .get("subject")
            .and_then(|s| s.get(0))
            .ok_or_else(|| anyhow!("Missing 'subject' in attestation"))?;

        let digest_sha256 = subject
            .get("digest")
            .and_then(|d| d.get("sha256"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'digest.sha256' in subject"))?;

        // Get signature entry
        let sig_entry = dsse
            .signatures
            .first()
            .ok_or_else(|| anyhow!("No signatures in DSSE envelope"))?;

        // Create Cosign SimpleSigning envelope
        let cosign_envelope = json!({
            "critical": {
                "identity": {
                    "docker-reference": ""
                },
                "image": {
                    "docker-manifest-digest": format!("sha256:{}", digest_sha256)
                },
                "type": "cosign container image signature"
            },
            "optional": {
                "Signature": sig_entry.sig,
                "Certificate": sig_entry.certificate,
                "Chain": sig_entry.chain,
                "Issuer": sig_entry.oidc_issuer,
                "Subject": sig_entry.oidc_subject
            }
        });

        log::debug!("Converted DSSE to Cosign format");
        Ok(cosign_envelope)
    }

    /// Convert Cosign SimpleSigning format to DSSE envelope
    fn to_dsse(&self, cosign_payload: &Value) -> Result<DsseEnvelope> {
        // Extract signature from optional section
        let optional = cosign_payload
            .get("optional")
            .and_then(|v| v.as_object())
            .ok_or_else(|| anyhow!("Missing 'optional' section in Cosign payload"))?;

        let signature = optional
            .get("Signature")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'Signature' in optional section"))?
            .to_string();

        // Extract optional fields
        let certificate = optional.get("Certificate").and_then(|v| v.as_str()).map(String::from);

        let chain = optional.get("Chain").and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(String::from)
                .collect()
        });

        let oidc_issuer = optional.get("Issuer").and_then(|v| v.as_str()).map(String::from);

        let oidc_subject = optional.get("Subject").and_then(|v| v.as_str()).map(String::from);

        // Extract critical section to reconstruct attestation
        let critical = cosign_payload
            .get("critical")
            .and_then(|v| v.as_object())
            .ok_or_else(|| anyhow!("Missing 'critical' section in Cosign payload"))?;

        let manifest_digest = critical
            .get("image")
            .and_then(|v| v.get("docker-manifest-digest"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("Missing 'docker-manifest-digest' in critical section"))?;

        // Remove "sha256:" prefix if present
        let digest = manifest_digest.strip_prefix("sha256:").unwrap_or(manifest_digest);

        // Reconstruct in-toto attestation
        let attestation = json!({
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "subject": [
                {
                    "name": "artifact",
                    "digest": {
                        "sha256": digest
                    }
                }
            ],
            "predicate": {
                "builder": {
                    "id": "provenix-cosign-adapter"
                },
                "buildType": "https://provenix.dev/cosign-import@v1",
                "metadata": {
                    "buildInvocationId": "cosign-import",
                    "completeness": {
                        "parameters": true,
                        "environment": false,
                        "materials": false
                    },
                    "reproducible": false
                }
            }
        });

        // Encode attestation as base64
        let payload_base64 = BASE64.encode(serde_json::to_vec(&attestation)?);

        // Create DSSE envelope
        let envelope = DsseEnvelope {
            payload_type: "application/vnd.in-toto+json".to_string(),
            payload: payload_base64,
            signatures: vec![DsseSignature {
                sig: signature,
                certificate,
                chain,
                oidc_issuer,
                oidc_subject,
            }],
        };

        log::debug!("Converted Cosign to DSSE format");
        Ok(envelope)
    }

    /// Detect if payload is in Cosign format
    fn detect(&self, payload: &Value) -> bool {
        if let Some(critical) = payload.get("critical") {
            if let Some(type_str) = critical.get("type").and_then(|v| v.as_str()) {
                return type_str == "cosign container image signature";
            }
        }
        false
    }
}

// Register Cosign format
#[ctor::ctor]
fn register_cosign_format() {
    let _ = super::signature_format::register_format("cosign", CosignAdapter);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cosign_detection() {
        let cosign_payload = json!({
            "critical": {
                "identity": {"docker-reference": ""},
                "image": {"docker-manifest-digest": "sha256:abc123"},
                "type": "cosign container image signature"
            },
            "optional": {
                "Signature": "sig_here"
            }
        });

        let adapter = CosignAdapter;
        assert!(adapter.detect(&cosign_payload));
    }

    #[test]
    fn test_not_cosign_format() {
        let dsse_payload = json!({
            "payloadType": "application/vnd.in-toto+json",
            "payload": "base64",
            "signatures": []
        });

        let adapter = CosignAdapter;
        assert!(!adapter.detect(&dsse_payload));
    }

    #[test]
    fn test_dsse_to_cosign_conversion() {
        let attestation = json!({
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "subject": [{
                "name": "test.txt",
                "digest": {
                    "sha256": "abc123def456"
                }
            }],
            "predicate": {}
        });

        let payload_base64 = BASE64.encode(serde_json::to_vec(&attestation).unwrap());

        let dsse = DsseEnvelope {
            payload_type: "application/vnd.in-toto+json".to_string(),
            payload: payload_base64,
            signatures: vec![DsseSignature {
                sig: "test_signature".to_string(),
                certificate: Some("cert_pem".to_string()),
                chain: None,
                oidc_issuer: Some("https://github.com".to_string()),
                oidc_subject: Some("user@example.com".to_string()),
            }],
        };

        let adapter = CosignAdapter;
        let cosign = adapter.from_dsse(&dsse).unwrap();

        // Verify Cosign structure
        assert_eq!(
            cosign["critical"]["type"],
            "cosign container image signature"
        );
        assert_eq!(
            cosign["critical"]["image"]["docker-manifest-digest"],
            "sha256:abc123def456"
        );
        assert_eq!(cosign["optional"]["Signature"], "test_signature");
        assert_eq!(cosign["optional"]["Certificate"], "cert_pem");
    }

    #[test]
    fn test_cosign_to_dsse_conversion() {
        let cosign_payload = json!({
            "critical": {
                "identity": {"docker-reference": ""},
                "image": {"docker-manifest-digest": "sha256:abc123def456"},
                "type": "cosign container image signature"
            },
            "optional": {
                "Signature": "test_signature",
                "Certificate": "cert_pem",
                "Issuer": "https://github.com",
                "Subject": "user@example.com"
            }
        });

        let adapter = CosignAdapter;
        let dsse = adapter.to_dsse(&cosign_payload).unwrap();

        // Verify DSSE structure
        assert_eq!(dsse.payload_type, "application/vnd.in-toto+json");
        assert_eq!(dsse.signatures[0].sig, "test_signature");
        assert_eq!(dsse.signatures[0].certificate, Some("cert_pem".to_string()));
        assert_eq!(
            dsse.signatures[0].oidc_issuer,
            Some("https://github.com".to_string())
        );

        // Decode and verify attestation
        let payload_bytes = BASE64.decode(&dsse.payload).unwrap();
        let attestation: Value = serde_json::from_slice(&payload_bytes).unwrap();

        assert_eq!(attestation["subject"][0]["digest"]["sha256"], "abc123def456");
    }
}

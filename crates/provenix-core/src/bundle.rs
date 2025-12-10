// Copyright 2025 Provenix Contributors
//
// Licensed under the Apache License, Version 2.0

//! Sigstore Bundle Format v0.3
//!
//! This module implements the Sigstore Bundle format as specified in:
//! https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto
//!
//! The Bundle format provides a self-contained verification artifact that includes:
//! - Signature data (MessageSignature or DSSE envelope)
//! - Verification material (certificate chain, public key)
//! - Transparency log entries (Rekor)
//! - Timestamp verification data
//!
//! This enables offline signature verification and interoperability with Cosign.

use serde::{Deserialize, Serialize};

/// Sigstore Bundle v0.3
///
/// A bundle contains all materials needed to verify a signature offline:
/// - The signature itself (MessageSignature or DSSE envelope)
/// - Certificate chain or public key for verification
/// - Rekor transparency log entries
/// - Optional RFC3161 timestamps
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bundle {
    /// Media type identifying the bundle version
    /// MUST be "application/vnd.dev.sigstore.bundle.v0.3+json" for v0.3
    pub media_type: String,

    /// Verification material (certificate, public key, transparency log)
    pub verification_material: VerificationMaterial,

    /// Signature content (either MessageSignature or DSSE envelope)
    #[serde(flatten)]
    pub content: SignatureContent,
}

/// Signature content - either a simple message signature or DSSE envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SignatureContent {
    /// Simple message signature (for non-DSSE payloads)
    MessageSignature(MessageSignature),
    
    /// DSSE envelope (for in-toto attestations)
    /// MUST contain exactly one signature
    DsseEnvelope(DsseEnvelope),
}

/// Simple message signature
///
/// Used for signing arbitrary messages (files, container images, etc.)
/// without the full DSSE envelope overhead.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageSignature {
    /// The message digest that was signed
    pub message_digest: MessageDigest,
    
    /// The signature bytes (base64-encoded)
    pub signature: String,
    
    /// Optional signature algorithm (defaults to ECDSA_SHA2_256_ASN1)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
}

/// Message digest
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MessageDigest {
    /// Digest algorithm (e.g., "sha256")
    pub algorithm: String,
    
    /// Digest value (hex or base64-encoded)
    pub digest: String,
}

/// DSSE envelope for in-toto attestations
///
/// Based on https://github.com/secure-systems-lab/dsse
/// When used in a Bundle, MUST contain exactly one signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseEnvelope {
    /// Payload type (e.g., "application/vnd.in-toto+json")
    pub payload_type: String,
    
    /// Base64-encoded payload
    pub payload: String,
    
    /// Signatures (MUST be exactly one in a Bundle)
    pub signatures: Vec<DsseSignature>,
}

/// DSSE signature
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsseSignature {
    /// Optional key identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyid: Option<String>,
    
    /// Signature bytes (base64-encoded)
    pub sig: String,
}

/// Verification material for signature validation
///
/// Contains everything needed to verify a signature:
/// - Public key or certificate chain
/// - Transparency log entries (Rekor)
/// - Optional timestamp verification data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMaterial {
    /// Key or certificate for signature verification
    #[serde(flatten)]
    pub content: VerificationMaterialContent,
    
    /// Transparency log entries from Rekor
    /// Multiple entries may be present if the signature was logged multiple times
    #[serde(default)]
    pub tlog_entries: Vec<TransparencyLogEntry>,
    
    /// Optional timestamp verification data (RFC3161)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_verification_data: Option<TimestampVerificationData>,
}

/// Key or certificate content in verification material
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VerificationMaterialContent {
    /// Public key identifier (for retrieving key from external keyring)
    /// MUST NOT be used with Fulcio keyless signing
    PublicKey(PublicKeyIdentifier),
    
    /// X.509 certificate chain (legacy format, used in v0.1 and v0.2)
    /// First certificate MUST be the leaf certificate
    /// Subsequent certificates SHOULD be in issuing order
    X509CertificateChain(X509CertificateChain),
    
    /// Single X.509 certificate (v0.3 format)
    /// MUST be the leaf certificate containing the signing key
    /// This is the preferred format for v0.3 bundles
    Certificate(X509Certificate),
}

/// Public key identifier
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyIdentifier {
    /// Key hint for retrieving the public key
    pub hint: String,
}

/// X.509 certificate chain (legacy format)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X509CertificateChain {
    /// Certificates in PEM or DER format
    /// First MUST be leaf, rest SHOULD be in issuing order
    pub certificates: Vec<X509Certificate>,
}

/// X.509 certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct X509Certificate {
    /// Certificate bytes (PEM or DER encoded)
    /// When serialized to JSON, this is base64-encoded
    #[serde(with = "base64_serde")]
    pub raw_bytes: Vec<u8>,
}

/// Transparency log entry from Rekor
///
/// Contains the log entry, inclusion proof, and optionally a signed timestamp
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransparencyLogEntry {
    /// Log index (position in the transparency log)
    pub log_index: String,
    
    /// Log ID (identifies which Rekor instance)
    pub log_id: LogId,
    
    /// Canonicalized JSON representation of the log entry
    pub canonicalized_body: String,
    
    /// Integrated time (Unix timestamp when entry was added)
    pub integrated_time: String,
    
    /// Inclusion proof (Merkle tree proof)
    pub inclusion_proof: InclusionProof,
    
    /// Optional inclusion promise (signed statement from Rekor)
    /// v0.1 bundles may contain only a promise, not a proof
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inclusion_promise: Option<InclusionPromise>,
    
    /// Signed Entry Timestamp (SET) from Rekor
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_entry_timestamp: Option<String>,
}

/// Log ID identifying a Rekor instance
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogId {
    /// Key identifier (SHA256 hash of the public key)
    #[serde(with = "base64_serde")]
    pub key_id: Vec<u8>,
}

/// Merkle tree inclusion proof
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionProof {
    /// Log index of this entry
    pub log_index: String,
    
    /// Root hash of the Merkle tree at this point
    #[serde(with = "base64_serde")]
    pub root_hash: Vec<u8>,
    
    /// Tree size when this entry was added
    pub tree_size: String,
    
    /// Merkle tree hashes for verification
    #[serde(with = "vec_base64_serde")]
    pub hashes: Vec<Vec<u8>>,
    
    /// Optional checkpoint (Signed Tree Head)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<Checkpoint>,
}

/// Rekor checkpoint (Signed Tree Head)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Checkpoint {
    /// Checkpoint body (tree size, root hash, etc.)
    pub envelope: String,
}

/// Inclusion promise (legacy, v0.1 bundles)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionPromise {
    /// Signed promise from Rekor
    #[serde(with = "base64_serde")]
    pub signed_entry_timestamp: Vec<u8>,
}

/// Timestamp verification data (RFC3161)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimestampVerificationData {
    /// RFC3161 timestamps
    pub rfc3161_timestamps: Vec<Rfc3161Timestamp>,
}

/// RFC3161 timestamp
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rfc3161Timestamp {
    /// Signed timestamp token
    #[serde(with = "base64_serde")]
    pub signed_timestamp: Vec<u8>,
}

// Helper serde modules for base64 encoding

mod base64_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    
    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use base64::{engine::general_purpose::STANDARD, Engine};
        serializer.serialize_str(&STANDARD.encode(bytes))
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

mod vec_base64_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    
    pub fn serialize<S>(vecs: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use base64::{engine::general_purpose::STANDARD, Engine};
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(vecs.len()))?;
        for vec in vecs {
            seq.serialize_element(&STANDARD.encode(vec))?;
        }
        seq.end()
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let strings: Vec<String> = Vec::deserialize(deserializer)?;
        strings
            .into_iter()
            .map(|s| STANDARD.decode(s).map_err(serde::de::Error::custom))
            .collect()
    }
}

impl Bundle {
    /// Creates a new Bundle v0.3
    pub fn new(verification_material: VerificationMaterial, content: SignatureContent) -> Self {
        Self {
            media_type: "application/vnd.dev.sigstore.bundle.v0.3+json".to_string(),
            verification_material,
            content,
        }
    }
    
    /// Validates the bundle structure
    pub fn validate(&self) -> Result<(), String> {
        // Check media type
        if !self.media_type.starts_with("application/vnd.dev.sigstore.bundle") {
            return Err(format!("Invalid media type: {}", self.media_type));
        }
        
        // If DSSE envelope, ensure exactly one signature
        if let SignatureContent::DsseEnvelope(ref envelope) = self.content {
            if envelope.signatures.len() != 1 {
                return Err(format!(
                    "DSSE envelope in bundle MUST have exactly one signature, found {}",
                    envelope.signatures.len()
                ));
            }
        }
        
        // Validate transparency log entries
        for entry in &self.verification_material.tlog_entries {
            if entry.log_index.is_empty() {
                return Err("Transparency log entry missing log_index".to_string());
            }
            if entry.integrated_time.is_empty() {
                return Err("Transparency log entry missing integrated_time".to_string());
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundle_validation() {
        let bundle = Bundle {
            media_type: "application/vnd.dev.sigstore.bundle.v0.3+json".to_string(),
            verification_material: VerificationMaterial {
                content: VerificationMaterialContent::Certificate(X509Certificate {
                    raw_bytes: vec![1, 2, 3],
                }),
                tlog_entries: vec![],
                timestamp_verification_data: None,
            },
            content: SignatureContent::MessageSignature(MessageSignature {
                message_digest: MessageDigest {
                    algorithm: "sha256".to_string(),
                    digest: "abc123".to_string(),
                },
                signature: "sig".to_string(),
                signature_algorithm: None,
            }),
        };
        
        assert!(bundle.validate().is_ok());
    }

    #[test]
    fn test_dsse_envelope_must_have_one_signature() {
        let bundle = Bundle {
            media_type: "application/vnd.dev.sigstore.bundle.v0.3+json".to_string(),
            verification_material: VerificationMaterial {
                content: VerificationMaterialContent::Certificate(X509Certificate {
                    raw_bytes: vec![1, 2, 3],
                }),
                tlog_entries: vec![],
                timestamp_verification_data: None,
            },
            content: SignatureContent::DsseEnvelope(DsseEnvelope {
                payload_type: "application/vnd.in-toto+json".to_string(),
                payload: "payload".to_string(),
                signatures: vec![
                    DsseSignature { keyid: None, sig: "sig1".to_string() },
                    DsseSignature { keyid: None, sig: "sig2".to_string() },
                ],
            }),
        };
        
        assert!(bundle.validate().is_err());
    }
    
    #[test]
    fn test_bundle_serialization() {
        let bundle = Bundle::new(
            VerificationMaterial {
                content: VerificationMaterialContent::Certificate(X509Certificate {
                    raw_bytes: vec![1, 2, 3, 4],
                }),
                tlog_entries: vec![],
                timestamp_verification_data: None,
            },
            SignatureContent::MessageSignature(MessageSignature {
                message_digest: MessageDigest {
                    algorithm: "sha256".to_string(),
                    digest: "abc123".to_string(),
                },
                signature: "test-signature".to_string(),
                signature_algorithm: Some("ECDSA_SHA2_256_ASN1".to_string()),
            }),
        );
        
        let json = serde_json::to_string_pretty(&bundle).unwrap();
        assert!(json.contains("application/vnd.dev.sigstore.bundle.v0.3+json"));
        
        let deserialized: Bundle = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.media_type, bundle.media_type);
    }
}

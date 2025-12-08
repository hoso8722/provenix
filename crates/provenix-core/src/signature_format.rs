/// Signature format abstraction for DSSE, Cosign, etc.
///
/// This module provides the SignatureFormat trait for signature format conversion
/// between different signature envelope formats (DSSE, Cosign SimpleSigning, etc.)

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Signature format trait for envelope conversions
pub trait SignatureFormat: Send + Sync {
    /// Format name (e.g., "dsse", "cosign")
    fn name(&self) -> &str;

    /// Convert from internal DSSE format to target format
    fn from_dsse(&self, dsse: &DsseEnvelope) -> Result<Value>;

    /// Convert from target format to internal DSSE format
    fn to_dsse(&self, payload: &Value) -> Result<DsseEnvelope>;

    /// Detect if payload is in this format
    fn detect(&self, payload: &Value) -> bool;
}

/// DSSE (Dead Simple Signing Envelope) structure
/// Reference: https://github.com/secure-systems-lab/dsse
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub payload: String, // base64-encoded
    pub signatures: Vec<DsseSignature>,
}

/// DSSE signature entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseSignature {
    pub sig: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_subject: Option<String>,
}

// Global signature format registry
lazy_static::lazy_static! {
    /// Global signature format registry
    static ref FORMAT_REGISTRY: Arc<RwLock<HashMap<String, Arc<dyn SignatureFormat>>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

/// Register a signature format
pub fn register_format(name: &str, format: impl SignatureFormat + 'static) -> Result<()> {
    let mut registry = FORMAT_REGISTRY
        .write()
        .map_err(|e| anyhow!("Failed to acquire registry lock: {}", e))?;

    registry.insert(name.to_string(), Arc::new(format));
    log::info!("Registered signature format: {}", name);
    Ok(())
}

/// Get signature format by name
pub fn get_format(name: &str) -> Result<Arc<dyn SignatureFormat>> {
    let registry = FORMAT_REGISTRY
        .read()
        .map_err(|e| anyhow!("Failed to acquire registry lock: {}", e))?;

    registry
        .get(name)
        .cloned()
        .ok_or_else(|| anyhow!("Signature format not found: {}", name))
}

/// Auto-detect signature format from payload
pub fn detect_format(payload: &Value) -> Result<Arc<dyn SignatureFormat>> {
    let registry = FORMAT_REGISTRY
        .read()
        .map_err(|e| anyhow!("Failed to acquire registry lock: {}", e))?;

    for format in registry.values() {
        if format.detect(payload) {
            return Ok(format.clone());
        }
    }

    Err(anyhow!("Unknown signature format"))
}

/// List all registered formats
pub fn list_formats() -> Result<Vec<String>> {
    let registry = FORMAT_REGISTRY
        .read()
        .map_err(|e| anyhow!("Failed to acquire registry lock: {}", e))?;

    Ok(registry.keys().cloned().collect())
}

// ===== Default DSSE Format Adapter =====

/// DSSE format adapter (identity transformation)
pub struct DsseAdapter;

impl SignatureFormat for DsseAdapter {
    fn name(&self) -> &str {
        "dsse"
    }

    fn from_dsse(&self, dsse: &DsseEnvelope) -> Result<Value> {
        Ok(serde_json::to_value(dsse)?)
    }

    fn to_dsse(&self, payload: &Value) -> Result<DsseEnvelope> {
        Ok(serde_json::from_value(payload.clone())?)
    }

    fn detect(&self, payload: &Value) -> bool {
        payload.get("payloadType").is_some() && payload.get("signatures").is_some()
    }
}

// Register default DSSE format
#[ctor::ctor]
fn register_default_dsse() {
    let _ = register_format("dsse", DsseAdapter);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dsse_format_registration() {
        let format = get_format("dsse").expect("DSSE format should be registered");
        assert_eq!(format.name(), "dsse");
    }

    #[test]
    fn test_dsse_detection() {
        let dsse_payload = serde_json::json!({
            "payloadType": "application/vnd.in-toto+json",
            "payload": "eyJzb21lIjogImRhdGEifQ==",
            "signatures": [
                {
                    "sig": "signature_here"
                }
            ]
        });

        let adapter = DsseAdapter;
        assert!(adapter.detect(&dsse_payload));
    }

    #[test]
    fn test_dsse_roundtrip() {
        let envelope = DsseEnvelope {
            payload_type: "application/vnd.in-toto+json".to_string(),
            payload: "eyJzb21lIjogImRhdGEifQ==".to_string(),
            signatures: vec![DsseSignature {
                sig: "signature_here".to_string(),
                certificate: None,
                chain: None,
                oidc_issuer: None,
                oidc_subject: None,
            }],
        };

        let adapter = DsseAdapter;
        let json = adapter.from_dsse(&envelope).unwrap();
        let back = adapter.to_dsse(&json).unwrap();

        assert_eq!(envelope.payload_type, back.payload_type);
        assert_eq!(envelope.payload, back.payload);
    }
}

use anyhow::Result;
use serde_json::Value;
use std::path::PathBuf;

pub type PluginResult = Result<Value>; // JSON-like result

/// SBOM provider
pub trait SbomProvider: Send + Sync {
    /// name identifier, e.g. "syft"
    fn name(&self) -> &str;

    /// generate SBOM for target and write to output path
    fn generate(&self, target: &str, output: &PathBuf) -> PluginResult;
}

/// Attestation provider
pub trait AttestProvider: Send + Sync {
    fn name(&self) -> &str;

    /// create attestation based on build metadata and sbom path
    fn attest(&self, sbom: &PathBuf, metadata: &Value, out: &PathBuf) -> PluginResult;
}

/// Sign provider
pub trait SignProvider: Send + Sync {
    fn name(&self) -> &str;

    /// sign an artifact (file path) and return signature bytes/base64 or store to out
    fn sign(&self, artifact: &PathBuf, key: &str, out: &PathBuf) -> PluginResult;
}

/// Verify provider
pub trait VerifyProvider: Send + Sync {
    fn name(&self) -> &str;

    /// verify artifact with signature and optional rekor check
    fn verify(&self, artifact: &PathBuf, signature: &PathBuf, rekor_url: Option<&str>) -> PluginResult;
}
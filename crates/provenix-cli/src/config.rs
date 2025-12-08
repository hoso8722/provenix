//! CLI Configuration module

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub sbom: SbomConfig,
    pub attest: AttestConfig,
    pub sign: SignConfig,
    pub verify: VerifyConfig,
    pub publish: PublishConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SbomConfig {
    pub provider: String,
    pub target: String,
    pub output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestConfig {
    pub provider: String,
    pub sbom_path: String,
    pub output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignConfig {
    pub provider: String,
    pub artifact_path: String,
    pub key_path: String,
    pub output: String,
    #[serde(default = "default_format")]
    pub format: String, // "dsse" or "cosign"
}

fn default_format() -> String {
    "dsse".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyConfig {
    pub provider: String,
    pub artifact_path: String,
    pub signature_path: String,
    #[serde(default = "default_verify_format")]
    pub format: String, // "dsse", "cosign", or "auto"
}

fn default_verify_format() -> String {
    "auto".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishConfig {
    pub registry_url: String,
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let content =
            std::fs::read_to_string(path.as_ref()).context("Failed to read config file")?;

        let config: Config =
            serde_json::from_str(&content).context("Failed to parse config file")?;

        Ok(config)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sbom: SbomConfig {
                provider: "syft".to_string(),
                target: ".".to_string(),
                output: "sbom.json".to_string(),
            },
            attest: AttestConfig {
                provider: "in-toto".to_string(),
                sbom_path: "sbom.json".to_string(),
                output: "attestation.json".to_string(),
            },
            sign: SignConfig {
                provider: "cosign".to_string(),
                artifact_path: "artifact".to_string(),
                key_path: "key.pem".to_string(),
                output: "signature.sig".to_string(),
                format: "dsse".to_string(),
            },
            verify: VerifyConfig {
                provider: "sigstore".to_string(),
                artifact_path: "artifact".to_string(),
                signature_path: "signature.sig".to_string(),
                format: "auto".to_string(),
            },
            publish: PublishConfig {
                registry_url: "https://registry.example.com".to_string(),
            },
        }
    }
}

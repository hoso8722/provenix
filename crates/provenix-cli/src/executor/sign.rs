//! Signing executor

use crate::config::Config;
use anyhow::Result;
use std::sync::Arc;
use std::path::PathBuf;
use std::fs;
use provenix_plugin::SignProvider;

pub fn run(config: &Config) -> Result<()> {
    log::info!("Signing artifact with provider: {}", config.sign.provider);
    log::info!("Output format: {}", config.sign.format);

    let provider: Arc<dyn SignProvider> = provenix_core::get_sign(&config.sign.provider)?;
    let artifact: PathBuf = PathBuf::from(&config.sign.artifact_path);
    let output: PathBuf = PathBuf::from(&config.sign.output);

    // Sign with provider (creates DSSE format internally)
    provider.sign(&artifact, &config.sign.key_path, &output)?;

    // If format is not "dsse", convert the signature
    if config.sign.format != "dsse" {
        log::info!("Converting signature to {} format", config.sign.format);
        
        // Read DSSE signature
        let dsse_content = fs::read_to_string(&output)?;
        let dsse_value: serde_json::Value = serde_json::from_str(&dsse_content)?;
        
        // Convert to target format using SignatureFormat trait
        let format_adapter = provenix_core::signature_format::get_format(&config.sign.format)?;
        let dsse_envelope: provenix_core::signature_format::DsseEnvelope = 
            serde_json::from_value(dsse_value)?;
        
        let converted = format_adapter.from_dsse(&dsse_envelope)?;
        
        // Write converted signature
        fs::write(&output, serde_json::to_string_pretty(&converted)?)?;
        
        log::info!("Signature converted to {} format", config.sign.format);
    }

    log::info!("Artifact signed successfully: {}", config.sign.output);
    Ok(())
}

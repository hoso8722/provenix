//! Attestation executor

use crate::config::Config;
use anyhow::Result;
use std::path::PathBuf;

pub fn run(config: &Config) -> Result<()> {
    log::info!("Creating attestation with provider: {}", config.attest.provider);
    
    let provider = provenix_core::get_attest(&config.attest.provider)?;
    let sbom_path = PathBuf::from(&config.attest.sbom_path);
    let output = PathBuf::from(&config.attest.output);
    let metadata = serde_json::json!({});
    
    provider.attest(&sbom_path, &metadata, &output)?;
    
    log::info!("Attestation created successfully: {}", config.attest.output);
    Ok(())
}

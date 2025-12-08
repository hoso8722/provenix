//! Verification executor

use crate::config::Config;
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use std::fs;
use provenix_plugin::VerifyProvider;

pub fn run(config: &Config) -> Result<()> {
    log::info!(
        "Verifying artifact with provider: {}",
        config.verify.provider
    );
    log::info!("Signature format: {}", config.verify.format);

    let provider: Arc<dyn VerifyProvider> = provenix_core::get_verify(&config.verify.provider)?;
    let artifact: PathBuf = PathBuf::from(&config.verify.artifact_path);
    let mut signature: PathBuf = PathBuf::from(&config.verify.signature_path);

    // If format is not "dsse", detect or convert the signature
    if config.verify.format != "dsse" {
        let sig_content = fs::read_to_string(&signature)?;
        let sig_value: serde_json::Value = serde_json::from_str(&sig_content)?;

        // Auto-detect or use specified format
        let format_adapter = if config.verify.format == "auto" {
            log::info!("Auto-detecting signature format...");
            provenix_core::signature_format::detect_format(&sig_value)?
        } else {
            provenix_core::signature_format::get_format(&config.verify.format)?
        };

        log::info!("Detected format: {}", format_adapter.name());

        // Convert to DSSE if needed
        if format_adapter.name() != "dsse" {
            log::info!("Converting {} format to DSSE for verification", format_adapter.name());
            
            let dsse_envelope = format_adapter.to_dsse(&sig_value)?;
            
            // Write temporary DSSE file
            let temp_path = signature.with_extension("dsse.tmp");
            fs::write(&temp_path, serde_json::to_string_pretty(&dsse_envelope)?)?;
            signature = temp_path;
        }
    }

    let result: serde_json::Value = provider.verify(&artifact, &signature, None)?;

    if result
        .get("valid")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        log::info!("Verification successful");
    } else {
        log::error!("Verification failed");
    }

    Ok(())
}

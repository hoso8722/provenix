//! Verification executor

use crate::config::Config;
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use provenix_plugin::VerifyProvider;

pub fn run(config: &Config) -> Result<()> {
    log::info!(
        "Verifying artifact with provider: {}",
        config.verify.provider
    );

    let provider: Arc<dyn VerifyProvider> = provenix_core::get_verify(&config.verify.provider)?;
    let artifact: PathBuf = PathBuf::from(&config.verify.artifact_path);
    let signature: PathBuf = PathBuf::from(&config.verify.signature_path);

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

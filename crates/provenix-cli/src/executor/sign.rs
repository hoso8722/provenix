//! Signing executor

use crate::config::Config;
use anyhow::Result;
use std::sync::Arc;
use std::path::PathBuf;
use provenix_plugin::SignProvider;

pub fn run(config: &Config) -> Result<()> {
    log::info!("Signing artifact with provider: {}", config.sign.provider);

    let provider: Arc<dyn SignProvider> = provenix_core::get_sign(&config.sign.provider)?;
    let artifact: PathBuf = PathBuf::from(&config.sign.artifact_path);
    let output: PathBuf = PathBuf::from(&config.sign.output);

    provider.sign(&artifact, &config.sign.key_path, &output)?;

    log::info!("Artifact signed successfully: {}", config.sign.output);
    Ok(())
}

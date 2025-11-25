//! SBOM generation executor

use crate::config::Config;
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use provenix_plugin::SbomProvider;

pub fn run(config: &Config) -> Result<()> {
    log::info!("Generating SBOM with provider: {}", config.sbom.provider);

    let provider: Arc<dyn SbomProvider> = provenix_core::get_sbom(&config.sbom.provider)?;
    let output: PathBuf = PathBuf::from(&config.sbom.output);
    
    provider.generate(&config.sbom.target, &output)?;
    
    log::info!("SBOM generated successfully: {}", config.sbom.output);
    Ok(())
}

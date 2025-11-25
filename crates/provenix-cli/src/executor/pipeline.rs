//! Pipeline executor - runs all steps in sequence

use crate::config::Config;
use anyhow::Result;

pub fn run_all(config: &Config) -> Result<()> {
    log::info!("Running full Provenix pipeline");
    
    // Step 1: Generate SBOM
    super::sbom::run(config)?;
    
    // Step 2: Create attestation
    super::attest::run(config)?;
    
    // Step 3: Sign artifacts
    super::sign::run(config)?;
    
    // Step 4: Verify
    super::verify::run(config)?;
    
    // Step 5: Publish
    super::publish::run(config)?;
    
    log::info!("Pipeline completed successfully");
    Ok(())
}

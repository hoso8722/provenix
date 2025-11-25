//! Configuration management module

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use anyhow::{Result, Context};

/// Main configuration structure for Provenix
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Default SBOM provider to use
    pub sbom_provider: Option<String>,
    
    /// Default attestation provider
    pub attest_provider: Option<String>,
    
    /// Default signing provider
    pub sign_provider: Option<String>,
    
    /// Default verification provider
    pub verify_provider: Option<String>,
    
    /// Output directory for generated artifacts
    pub output_dir: PathBuf,
    
    /// Enable verbose logging
    pub verbose: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sbom_provider: None,
            attest_provider: None,
            sign_provider: None,
            verify_provider: None,
            output_dir: PathBuf::from("./output"),
            verbose: false,
        }
    }
}

impl Config {
    /// Load configuration from a file
    pub fn from_file(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let contents = std::fs::read_to_string(path.as_ref())
            .context("Failed to read config file")?;
        
        let config: Config = serde_json::from_str(&contents)
            .context("Failed to parse config file")?;
        
        Ok(config)
    }
    
    /// Save configuration to a file
    pub fn save_to_file(&self, path: impl AsRef<std::path::Path>) -> Result<()> {
        let contents = serde_json::to_string_pretty(self)
            .context("Failed to serialize config")?;
        
        std::fs::write(path.as_ref(), contents)
            .context("Failed to write config file")?;
        
        Ok(())
    }
    
    /// Create a new config with default values
    pub fn new() -> Self {
        Self::default()
    }
}

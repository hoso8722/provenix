//! Error types for provenix-core

use thiserror::Error;

/// Core error types for Provenix operations
#[derive(Debug, Error)]
pub enum ProvenixError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("Provider error: {0}")]
    Provider(String),
    
    #[error("Pipeline error: {0}")]
    Pipeline(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, ProvenixError>;

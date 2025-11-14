use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProvenixError {
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Authorization failed: {0}")]
    AuthorizationFailed(String),
    
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    
    #[error("Configuration error: {0}")]
    ConfigError(#[from] config::ConfigError),
    
    #[error("Policy evaluation error: {0}")]
    PolicyError(String),
    
    #[error("SBOM validation error: {0}")]
    SbomValidationError(String),
    
    #[error("Attestation error: {0}")]
    AttestationError(String),
    
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Unknown error: {0}")]
    Unknown(String),
}

pub type Result<T> = std::result::Result<T, ProvenixError>;

impl ProvenixError {
    pub fn error_code(&self) -> &'static str {
        match self {
            ProvenixError::AuthenticationFailed(_) => "AUTH_001",
            ProvenixError::AuthorizationFailed(_) => "AUTH_002", 
            ProvenixError::DatabaseError(_) => "DB_001",
            ProvenixError::ConfigError(_) => "CONFIG_001",
            ProvenixError::PolicyError(_) => "POLICY_001",
            ProvenixError::SbomValidationError(_) => "SBOM_001",
            ProvenixError::AttestationError(_) => "ATTEST_001",
            ProvenixError::NetworkError(_) => "NET_001",
            ProvenixError::SerializationError(_) => "SER_001",
            ProvenixError::IoError(_) => "IO_001",
            ProvenixError::Unknown(_) => "UNK_001",
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(self, ProvenixError::NetworkError(_) | ProvenixError::DatabaseError(_))
    }
}
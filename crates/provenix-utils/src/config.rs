use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
    pub security: SecurityConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: Option<u32>,
    pub timeout: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub oidc_issuer_url: String,
    pub oidc_client_id: String,
    pub oidc_client_secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub opa_url: String,
    pub enable_policy_enforcement: bool,
    pub cors_origins: Vec<String>,
    pub rate_limit_per_minute: u32,
}

impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let environment = std::env::var("PROVENIX_ENV").unwrap_or_else(|_| "dev".to_string());
        
        let mut config_builder = Config::builder()
            .add_source(File::with_name("server/config/default"))
            .add_source(File::with_name(&format!("server/config/{}", environment)).required(false))
            .add_source(Environment::with_prefix("PROVENIX").separator("__"));

        // Allow local override
        if Path::new("server/config/local.toml").exists() {
            config_builder = config_builder.add_source(File::with_name("server/config/local"));
        }

        let config = config_builder.build()?;
        config.try_deserialize()
    }

    pub fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.auth.jwt_secret.len() < 32 {
            return Err("JWT secret must be at least 32 characters".into());
        }

        if self.server.port == 0 {
            return Err("Server port must be specified".into());
        }

        // Add more validation as needed
        Ok(())
    }
}
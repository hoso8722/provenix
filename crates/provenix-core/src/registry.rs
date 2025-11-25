use std::collections::HashMap;
use std::sync::{Arc, RwLock, PoisonError};
use once_cell::sync::Lazy;
use anyhow::{Result, bail};

// Import plugin traits from provenix-plugin crate
use provenix_plugin::{SbomProvider, AttestProvider, SignProvider, VerifyProvider};

/// Registry error types
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("Lock poisoned: {0}")]
    LockPoisoned(String),
    
    #[error("Provider '{0}' not found")]
    ProviderNotFound(String),
    
    #[error("Provider '{0}' already registered")]
    ProviderAlreadyExists(String),
}

impl<T> From<PoisonError<T>> for RegistryError {
    fn from(err: PoisonError<T>) -> Self {
        RegistryError::LockPoisoned(err.to_string())
    }
}

/// Thread-safe clonable provider trait
pub trait ClonableProvider: Send + Sync {
    fn clone_box(&self) -> Box<dyn ClonableProvider>;
}

/// Wrapper for SBOM providers with Arc for efficient cloning
type SbomProviderMap = HashMap<String, Arc<dyn SbomProvider>>;
type AttestProviderMap = HashMap<String, Arc<dyn AttestProvider>>;
type SignProviderMap = HashMap<String, Arc<dyn SignProvider>>;
type VerifyProviderMap = HashMap<String, Arc<dyn VerifyProvider>>;

pub static SBOM_REGISTRY: Lazy<RwLock<SbomProviderMap>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

pub static ATTEST_REGISTRY: Lazy<RwLock<AttestProviderMap>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

pub static SIGN_REGISTRY: Lazy<RwLock<SignProviderMap>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

pub static VERIFY_REGISTRY: Lazy<RwLock<VerifyProviderMap>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

// ==================== SBOM Registry ====================

/// Register an SBOM provider with error handling
/// Returns an error if the provider name already exists
pub fn register_sbom<P: SbomProvider + 'static>(name: impl Into<String>, provider: P) -> Result<()> {
    let name = name.into();
    let mut registry = SBOM_REGISTRY
        .write()
        .map_err(|e| RegistryError::from(e))?;
    
    if registry.contains_key(&name) {
        bail!(RegistryError::ProviderAlreadyExists(name));
    }
    
    registry.insert(name, Arc::new(provider));
    Ok(())
}

/// Get an SBOM provider by name with proper error handling
pub fn get_sbom(name: &str) -> Result<Arc<dyn SbomProvider>> {
    let registry = SBOM_REGISTRY
        .read()
        .map_err(|e| RegistryError::from(e))?;
    
    registry
        .get(name)
        .cloned()
        .ok_or_else(|| RegistryError::ProviderNotFound(name.to_string()).into())
}

/// List all registered SBOM provider names
pub fn list_sbom_providers() -> Result<Vec<String>> {
    let registry = SBOM_REGISTRY
        .read()
        .map_err(|e| RegistryError::from(e))?;
    
    Ok(registry.keys().cloned().collect())
}

/// Check if an SBOM provider is registered
pub fn has_sbom_provider(name: &str) -> Result<bool> {
    let registry = SBOM_REGISTRY
        .read()
        .map_err(|e| RegistryError::from(e))?;
    
    Ok(registry.contains_key(name))
}

// ==================== Attest Registry ====================

pub fn register_attest<P: AttestProvider + 'static>(name: impl Into<String>, provider: P) -> Result<()> {
    let name = name.into();
    let mut registry = ATTEST_REGISTRY
        .write()
        .map_err(|e| RegistryError::from(e))?;
    
    if registry.contains_key(&name) {
        bail!(RegistryError::ProviderAlreadyExists(name));
    }
    
    registry.insert(name, Arc::new(provider));
    Ok(())
}

pub fn get_attest(name: &str) -> Result<Arc<dyn AttestProvider>> {
    let registry = ATTEST_REGISTRY
        .read()
        .map_err(|e| RegistryError::from(e))?;
    
    registry
        .get(name)
        .cloned()
        .ok_or_else(|| RegistryError::ProviderNotFound(name.to_string()).into())
}

pub fn list_attest_providers() -> Result<Vec<String>> {
    let registry = ATTEST_REGISTRY
        .read()
        .map_err(|e| RegistryError::from(e))?;
    
    Ok(registry.keys().cloned().collect())
}

// ==================== Sign Registry ====================

pub fn register_sign<P: SignProvider + 'static>(name: impl Into<String>, provider: P) -> Result<()> {
    let name = name.into();
    let mut registry = SIGN_REGISTRY
        .write()
        .map_err(|e| RegistryError::from(e))?;
    
    if registry.contains_key(&name) {
        bail!(RegistryError::ProviderAlreadyExists(name));
    }
    
    registry.insert(name, Arc::new(provider));
    Ok(())
}

pub fn get_sign(name: &str) -> Result<Arc<dyn SignProvider>> {
    let registry = SIGN_REGISTRY
        .read()
        .map_err(|e| RegistryError::from(e))?;
    
    registry
        .get(name)
        .cloned()
        .ok_or_else(|| RegistryError::ProviderNotFound(name.to_string()).into())
}

pub fn list_sign_providers() -> Result<Vec<String>> {
    let registry = SIGN_REGISTRY
        .read()
        .map_err(|e| RegistryError::from(e))?;
    
    Ok(registry.keys().cloned().collect())
}

// ==================== Verify Registry ====================

pub fn register_verify<P: VerifyProvider + 'static>(name: impl Into<String>, provider: P) -> Result<()> {
    let name = name.into();
    let mut registry = VERIFY_REGISTRY
        .write()
        .map_err(|e| RegistryError::from(e))?;
    
    if registry.contains_key(&name) {
        bail!(RegistryError::ProviderAlreadyExists(name));
    }
    
    registry.insert(name, Arc::new(provider));
    Ok(())
}

pub fn get_verify(name: &str) -> Result<Arc<dyn VerifyProvider>> {
    let registry = VERIFY_REGISTRY
        .read()
        .map_err(|e| RegistryError::from(e))?;
    
    registry
        .get(name)
        .cloned()
        .ok_or_else(|| RegistryError::ProviderNotFound(name.to_string()).into())
}

pub fn list_verify_providers() -> Result<Vec<String>> {
    let registry = VERIFY_REGISTRY
        .read()
        .map_err(|e| RegistryError::from(e))?;
    
    Ok(registry.keys().cloned().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use serde_json::Value;
    
    struct MockSbomProvider;
    
    impl SbomProvider for MockSbomProvider {
        fn name(&self) -> &str {
            "mock"
        }
        
        fn generate(&self, _target: &str, _output: &PathBuf) -> anyhow::Result<Value> {
            Ok(serde_json::json!({"mock": "sbom"}))
        }
    }
    
    #[test]
    fn test_register_and_get() {
        let result = register_sbom("test_provider", MockSbomProvider);
        assert!(result.is_ok());
        
        let provider = get_sbom("test_provider");
        assert!(provider.is_ok());
        assert_eq!(provider.unwrap().name(), "mock");
    }
    
    #[test]
    fn test_duplicate_registration() {
        let _ = register_sbom("dup_test", MockSbomProvider);
        let result = register_sbom("dup_test", MockSbomProvider);
        assert!(result.is_err());
    }
    
    #[test]
    fn test_provider_not_found() {
        let result = get_sbom("nonexistent");
        assert!(result.is_err());
    }
    
    #[test]
    fn test_list_providers() {
        let _ = register_sbom("list_test_1", MockSbomProvider);
        let _ = register_sbom("list_test_2", MockSbomProvider);
        
        let providers = list_sbom_providers().unwrap();
        assert!(providers.contains(&"list_test_1".to_string()));
        assert!(providers.contains(&"list_test_2".to_string()));
    }
}
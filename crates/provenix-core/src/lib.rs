pub mod config;
pub mod cosign_adapter;
pub mod errors;
pub mod pipeline;
pub mod registry;
pub mod signature_format;

// re-export commonly used types
pub use config::Config;

pub use registry::{
    get_attest, get_sbom, get_sign, get_verify, has_sbom_provider, list_attest_providers,
    list_sbom_providers, list_sign_providers, list_verify_providers, register_attest,
    register_sbom, register_sign, register_verify, RegistryError,
};

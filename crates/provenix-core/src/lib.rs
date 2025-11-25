pub mod pipeline;
pub mod config;
pub mod errors;
pub mod registry;

// re-export commonly used types
pub use config::Config;


pub use registry::{
    register_sbom, get_sbom, list_sbom_providers, has_sbom_provider,
    register_attest, get_attest, list_attest_providers,
    register_sign, get_sign, list_sign_providers,
    register_verify, get_verify, list_verify_providers,
    RegistryError,
};
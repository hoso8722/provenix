use provenix_plugin::SbomProvider;
use serde_json::json;
use std::path::PathBuf;

pub struct SyftProvider;

impl SbomProvider for SyftProvider {
    fn name(&self) -> &str {
        "syft"
    }

    fn generate(&self, _target: &str, output: &PathBuf) -> anyhow::Result<serde_json::Value> {
        // call system syft; write file to output; return metadata
        // ...
        Ok(json!({"sbom":"ok","path": output.to_string_lossy()}))
    }
}

#[ctor::ctor]
fn register() {
    let _ = provenix_core::registry::register_sbom("syft", SyftProvider);
}

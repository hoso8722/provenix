use provenix_plugin::AttestProvider;
use serde_json::{json, Value};
use std::path::PathBuf;

pub struct InTotoProvider;

impl AttestProvider for InTotoProvider {
    fn name(&self) -> &str {
        "in-toto"
    }

    fn attest(
        &self,
        _sbom: &PathBuf,
        _metadata: &Value,
        output: &PathBuf,
    ) -> anyhow::Result<Value> {
        // TODO: Implement actual in-toto attestation
        Ok(json!({"attestation": "ok", "path": output.to_string_lossy()}))
    }
}

#[ctor::ctor]
fn register() {
    let _ = provenix_core::registry::register_attest("in-toto", InTotoProvider);
}

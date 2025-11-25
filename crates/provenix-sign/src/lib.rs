use provenix_plugin::SignProvider;
use serde_json::{json, Value};
use std::path::PathBuf;

pub struct CosignProvider;

impl SignProvider for CosignProvider {
    fn name(&self) -> &str {
        "cosign"
    }

    fn sign(&self, _artifact: &PathBuf, _key: &str, output: &PathBuf) -> anyhow::Result<Value> {
        // TODO: Implement actual cosign signing
        Ok(json!({"signature": "ok", "path": output.to_string_lossy()}))
    }
}

#[ctor::ctor]
fn register() {
    let _ = provenix_core::registry::register_sign("cosign", CosignProvider);
}

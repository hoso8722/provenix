use provenix_plugin::VerifyProvider;
use serde_json::{json, Value};
use std::path::PathBuf;

pub struct SigstoreProvider;

impl VerifyProvider for SigstoreProvider {
    fn name(&self) -> &str {
        "sigstore"
    }

    fn verify(
        &self,
        _artifact: &PathBuf,
        _signature: &PathBuf,
        _rekor_url: Option<&str>,
    ) -> anyhow::Result<Value> {
        // TODO: Implement actual sigstore verification
        Ok(json!({"valid": true, "verifier": "sigstore"}))
    }
}

#[ctor::ctor]
fn register() {
    let _ = provenix_core::registry::register_verify("sigstore", SigstoreProvider);
}

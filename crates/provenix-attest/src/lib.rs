use chrono::Utc;
use provenix_plugin::AttestProvider;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::PathBuf;

// ===== Built-in Provider: in-toto/SLSA Attestation =====

pub struct InTotoProvider;

impl AttestProvider for InTotoProvider {
    fn name(&self) -> &str {
        "in-toto"
    }

    fn attest(&self, sbom: &PathBuf, metadata: &Value, output: &PathBuf) -> anyhow::Result<Value> {
        log::info!("Creating in-toto attestation for SBOM: {:?}", sbom);

        // Phase 1 Security: Compute SBOM hash
        let sbom_hash = compute_file_hash(sbom)
            .map_err(|e| anyhow::anyhow!("Failed to compute SBOM hash: {}", e))?;

        log::debug!("SBOM SHA256: {}", sbom_hash);

        // Read SBOM content
        let sbom_content = fs::read_to_string(sbom)
            .map_err(|e| anyhow::anyhow!("Failed to read SBOM file: {}", e))?;

        let sbom_json: Value = serde_json::from_str(&sbom_content)
            .map_err(|e| anyhow::anyhow!("Failed to parse SBOM JSON: {}", e))?;

        // Phase 1 Security: Add timestamp
        let timestamp = Utc::now().to_rfc3339();
        log::debug!("Attestation timestamp: {}", timestamp);

        // Create in-toto attestation envelope (SLSA Provenance v0.2 format)
        let attestation =
            create_intoto_attestation(sbom, &sbom_hash, &sbom_json, metadata, &timestamp)?;

        // Ensure output directory exists
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }

        // Write attestation to file
        let attestation_json = serde_json::to_string_pretty(&attestation)?;
        fs::write(output, attestation_json)?;

        log::info!("Attestation created successfully at: {:?}", output);

        Ok(json!({
            "provider": "in-toto",
            "format": "slsa-provenance-v0.2",
            "output": output.to_string_lossy(),
            "sbom": sbom.to_string_lossy(),
            "sbom_hash": sbom_hash,
            "timestamp": timestamp,
        }))
    }
}

/// Create in-toto attestation in SLSA Provenance v0.2 format
fn create_intoto_attestation(
    sbom_path: &PathBuf,
    sbom_hash: &str,
    sbom_content: &Value,
    metadata: &Value,
    timestamp: &str,
) -> anyhow::Result<Value> {
    let sbom_filename = sbom_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("sbom.json");

    Ok(json!({
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{
            "name": sbom_filename,
            "digest": {
                "sha256": sbom_hash  // Phase 1: Hash embedded for verification
            }
        }],
        "predicateType": "https://slsa.dev/provenance/v0.2",
        "predicate": {
            "builder": {
                "id": "https://github.com/hoso8722/provenix",
                "version": env!("CARGO_PKG_VERSION")
            },
            "buildType": "https://provenix.dev/attestation/v1",
            "invocation": {
                "configSource": metadata.get("config").cloned().unwrap_or(json!({})),
                "parameters": metadata.get("parameters").cloned().unwrap_or(json!({})),
                "environment": {
                    "timestamp": timestamp,  // Phase 1: Timestamp for chronological proof
                    "platform": std::env::consts::OS,
                    "arch": std::env::consts::ARCH,
                }
            },
            "metadata": {
                "buildStartedOn": timestamp,
                "buildFinishedOn": timestamp,
                "completeness": {
                    "parameters": true,
                    "environment": true,
                    "materials": true
                },
                "reproducible": false
            },
            "materials": [{
                "uri": format!("file://{}", sbom_path.display()),
                "digest": {
                    "sha256": sbom_hash  // Phase 1: Duplicate hash for materials tracking
                },
                "content": sbom_content
            }]
        }
    }))
}

/// Compute SHA256 hash of a file
/// Phase 1 Security: Critical for tamper detection
fn compute_file_hash(path: &PathBuf) -> anyhow::Result<String> {
    let mut file = fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("Failed to open file for hashing: {}", e))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|e| anyhow::anyhow!("Failed to read file for hashing: {}", e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

#[ctor::ctor]
fn register() {
    let _ = provenix_core::registry::register_attest("in-toto", InTotoProvider);
}

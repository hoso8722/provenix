use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use provenix_plugin::VerifyProvider;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

// ===== Phase 2: Ed25519 Verification Provider =====

pub struct Ed25519Provider;

impl VerifyProvider for Ed25519Provider {
    fn name(&self) -> &str {
        "ed25519"
    }

    fn verify(
        &self,
        artifact: &PathBuf,       // SBOM file
        signature: &PathBuf,      // Signed envelope file
        _rekor_url: Option<&str>, // Phase 3: Rekor transparency log
    ) -> anyhow::Result<Value> {
        log::info!("Verifying signature with Ed25519");
        log::info!("  Artifact:  {:?}", artifact);
        log::info!("  Signature: {:?}", signature);

        // 1. Read signed envelope (DSSE format)
        let envelope_content = fs::read_to_string(signature)
            .map_err(|e| anyhow::anyhow!("Failed to read signature file: {}", e))?;

        let envelope: Value = serde_json::from_str(&envelope_content)
            .map_err(|e| anyhow::anyhow!("Failed to parse signature envelope: {}", e))?;

        // 2. Extract components from DSSE envelope
        let payload_base64 = envelope["payload"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'payload' in signature envelope"))?;

        let signatures = envelope["signatures"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("Missing 'signatures' in envelope"))?;

        if signatures.is_empty() {
            return Err(anyhow::anyhow!("No signatures found in envelope"));
        }

        let sig_entry = &signatures[0];
        let sig_base64 = sig_entry["sig"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'sig' in signature entry"))?;

        let public_key_base64 = sig_entry["publicKey"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'publicKey' in signature entry"))?;

        // 3. Decode payload and signature
        let payload_bytes = BASE64
            .decode(payload_base64)
            .map_err(|e| anyhow::anyhow!("Failed to decode payload: {}", e))?;

        let sig_bytes = BASE64
            .decode(sig_base64)
            .map_err(|e| anyhow::anyhow!("Failed to decode signature: {}", e))?;

        // 4. Parse attestation from payload
        let attestation: Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse attestation from payload: {}", e))?;

        // 5. Verify attestation hash chain (Phase 1 integration)
        let hash_valid = verify_hash_chain(artifact, &attestation)?;
        if !hash_valid {
            return Err(anyhow::anyhow!(
                "Hash chain verification failed: SBOM has been tampered!"
            ));
        }
        log::info!("✅ Hash chain verification passed");

        // 6. Load public key from DSSE envelope
        let public_key_bytes = BASE64
            .decode(public_key_base64)
            .map_err(|e| anyhow::anyhow!("Failed to decode public key: {}", e))?;

        if public_key_bytes.len() != 32 {
            return Err(anyhow::anyhow!(
                "Invalid public key size: expected 32 bytes, got {}",
                public_key_bytes.len()
            ));
        }

        let key_array: [u8; 32] = public_key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert public key bytes"))?;

        let public_key = VerifyingKey::from_bytes(&key_array)
            .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?;

        let signature_obj = Signature::from_bytes(
            &sig_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid signature length"))?,
        );

        public_key
            .verify(&payload_bytes, &signature_obj)
            .map_err(|e| anyhow::anyhow!("Signature verification failed: {}", e))?;

        log::info!("✅ Ed25519 signature verification passed");

        // 7. Extract verification metadata
        let subject_name = attestation["subject"][0]["name"]
            .as_str()
            .unwrap_or("unknown");
        let sbom_hash = attestation["subject"][0]["digest"]["sha256"]
            .as_str()
            .unwrap_or("unknown");
        let timestamp = attestation["predicate"]["invocation"]["environment"]["timestamp"]
            .as_str()
            .unwrap_or("unknown");

        Ok(json!({
            "valid": true,
            "provider": "ed25519",
            "algorithm": "Ed25519",
            "hash_chain_valid": hash_valid,
            "signature_valid": true,
            "subject": subject_name,
            "sbom_hash": sbom_hash,
            "timestamp": timestamp,
        }))
    }
}

/// Verify hash chain: SBOM hash must match attestation
/// Phase 1 Security: Critical tamper detection
fn verify_hash_chain(sbom_path: &PathBuf, attestation: &Value) -> anyhow::Result<bool> {
    // 1. Get expected hash from attestation
    let expected_hash = attestation["subject"][0]["digest"]["sha256"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("Missing SBOM hash in attestation"))?;

    // 2. Compute actual SBOM hash
    let actual_hash = compute_file_hash(sbom_path)?;

    // 3. Compare
    let valid = expected_hash == actual_hash;

    if !valid {
        log::error!("Hash mismatch detected!");
        log::error!("  Expected: {}", expected_hash);
        log::error!("  Actual:   {}", actual_hash);
    }

    Ok(valid)
}

/// Compute SHA-256 hash of a file
/// Reused from attestation module for consistency
fn compute_file_hash(path: &PathBuf) -> anyhow::Result<String> {
    let mut file = fs::File::open(path)
        .map_err(|e| anyhow::anyhow!("Failed to open file for hashing: {}", e))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    use std::io::Read;
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

/// Load public key from attestation or from file
fn load_public_key_from_attestation(attestation: &Value) -> anyhow::Result<VerifyingKey> {
    // Try to extract from builder metadata (if embedded)
    if let Some(public_key_base64) = attestation["predicate"]["builder"]["public_key"].as_str() {
        let key_bytes = BASE64
            .decode(public_key_base64)
            .map_err(|e| anyhow::anyhow!("Failed to decode public key: {}", e))?;

        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid public key length"))?;

        return VerifyingKey::from_bytes(&key_array)
            .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e));
    }

    // Fallback: Load from config (Phase 2.5: better key management)
    load_public_key_from_file("keys/public.key")
}

/// Load public key from file
fn load_public_key_from_file(key_path: &str) -> anyhow::Result<VerifyingKey> {
    let path = PathBuf::from(key_path);

    if !path.exists() {
        return Err(anyhow::anyhow!(
            "Public key not found: {}\n\nProvide public key or embed in attestation",
            key_path
        ));
    }

    log::info!("Loading public key from: {}", key_path);
    let key_bytes =
        fs::read(&path).map_err(|e| anyhow::anyhow!("Failed to read key file: {}", e))?;

    // Decode base64
    let key_bytes = BASE64
        .decode(&key_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to decode base64 key: {}", e))?;

    if key_bytes.len() != 32 {
        return Err(anyhow::anyhow!(
            "Invalid public key size: expected 32 bytes, got {}",
            key_bytes.len()
        ));
    }

    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Failed to convert key bytes to array"))?;

    VerifyingKey::from_bytes(&key_array).map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))
}

#[ctor::ctor]
fn register() {
    let _ = provenix_core::registry::register_verify("ed25519", Ed25519Provider);
}

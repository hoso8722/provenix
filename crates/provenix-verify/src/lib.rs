use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use provenix_plugin::VerifyProvider;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

// ===== Phase 2: Ed25519 Verification Provider =====
// ===== Phase 3: Rekor Transparency Log Integration =====

pub struct Ed25519Provider {
    pub check_rekor: bool,
}

impl Ed25519Provider {
    pub fn new(check_rekor: bool) -> Self {
        Self { check_rekor }
    }
}

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

        // 6. Load public key - try publicKey field first, then certificate
        let public_key = if let Some(public_key_base64) = sig_entry["publicKey"].as_str() {
            // Standard DSSE format with embedded public key
            log::debug!("Using public key from 'publicKey' field");
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

            VerifyingKey::from_bytes(&key_array)
                .map_err(|e| anyhow::anyhow!("Invalid public key: {}", e))?
        } else if let Some(cert_pem) = sig_entry["certificate"].as_str() {
            // Cosign/Fulcio format with certificate
            log::debug!("Extracting public key from certificate");
            
            #[cfg(feature = "x509")]
            {
                use provenix_utils::x509;
                let cert_der = x509::parse_certificate_pem(cert_pem)
                    .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {}", e))?;
                let cert = x509::parse_certificate_der(&cert_der)
                    .map_err(|e| anyhow::anyhow!("Failed to parse certificate DER: {}", e))?;
                x509::extract_ed25519_public_key(&cert)
                    .map_err(|e| anyhow::anyhow!("Failed to extract public key from certificate: {}", e))?
            }
            #[cfg(not(feature = "x509"))]
            {
                return Err(anyhow::anyhow!(
                    "Certificate-based verification requires 'x509' feature. \
                    Signature is missing 'publicKey' field and contains certificate instead."
                ));
            }
        } else {
            return Err(anyhow::anyhow!(
                "Missing both 'publicKey' and 'certificate' in signature entry. \
                Cannot verify signature without public key."
            ));
        };

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

        // 8. Verify Rekor transparency log (Phase 3)
        let mut rekor_verified = false;
        let mut rekor_metadata = json!(null);

        if self.check_rekor {
            if let Some(rekor_url) = _rekor_url {
                log::info!("Checking Rekor transparency log: {}", rekor_url);

                match verify_rekor_entry(rekor_url, &envelope, sbom_hash) {
                    Ok(metadata) => {
                        log::info!("✅ Rekor transparency log verification passed");
                        rekor_verified = true;
                        rekor_metadata = metadata;
                    }
                    Err(e) => {
                        log::warn!("Rekor verification failed (continuing): {}", e);
                    }
                }
            } else {
                log::debug!("Rekor check requested but no URL provided");
            }
        } else {
            log::debug!("Rekor verification disabled");
        }

        Ok(json!({
            "valid": true,
            "provider": "ed25519",
            "algorithm": "Ed25519",
            "hash_chain_valid": hash_valid,
            "signature_valid": true,
            "rekor_verified": rekor_verified,
            "rekor": rekor_metadata,
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

/// Verify entry exists in Rekor transparency log
/// Phase 3: Rekor Integration
fn verify_rekor_entry(
    rekor_url: &str,
    _envelope: &Value,
    sbom_hash: &str,
) -> anyhow::Result<Value> {
    use provenix_utils::rekor::RekorClient;

    // Create async runtime for Rekor API calls
    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| anyhow::anyhow!("Failed to create async runtime: {}", e))?;

    runtime.block_on(async {
        let client = RekorClient::new(Some(rekor_url));

        // Try to search by artifact hash
        let entries = client
            .search_by_hash(sbom_hash)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to search Rekor: {}", e))?;

        if entries.is_empty() {
            return Err(anyhow::anyhow!(
                "No Rekor entry found for artifact hash: {}",
                sbom_hash
            ));
        }

        // Get the first matching entry
        let uuid = &entries[0];
        let entry = client
            .get_entry(uuid)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to fetch Rekor entry: {}", e))?;

        log::info!(
            "Found Rekor entry: UUID={}, logIndex={}",
            entry.uuid,
            entry.log_index
        );

        Ok(json!({
            "uuid": entry.uuid,
            "log_index": entry.log_index,
            "integrated_time": entry.integrated_time,
            "location": format!("{}/api/v1/log/entries/{}", rekor_url, entry.uuid),
        }))
    })
}

#[ctor::ctor]
fn register() {
    // Register Ed25519 provider with default configuration (no Rekor check)
    let _ = provenix_core::registry::register_verify("ed25519", Ed25519Provider::new(false));
}

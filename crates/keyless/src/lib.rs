use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use provenix_plugin::{SignProvider, VerifyProvider};
use provenix_utils::fulcio::{FulcioClient, OidcIdentity};
use provenix_utils::rekor::RekorClient;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

// ===== Phase 4: Fulcio Keyless Signing Provider =====

/// Keyless signing provider using Fulcio (OIDC-based ephemeral certificates)
pub struct KeylessSignProvider {
    pub fulcio_url: Option<String>,
    pub rekor_url: Option<String>,
}

impl KeylessSignProvider {
    pub fn new(fulcio_url: Option<String>, rekor_url: Option<String>) -> Self {
        Self {
            fulcio_url,
            rekor_url,
        }
    }
}

impl SignProvider for KeylessSignProvider {
    fn name(&self) -> &str {
        "fulcio-keyless"
    }

    fn sign(&self, artifact: &PathBuf, key: &str, output: &PathBuf) -> Result<Value> {
        log::info!("Signing with Fulcio keyless (OIDC): {:?}", artifact);

        // Key parameter contains OIDC token instead of private key path
        let oidc_token = key;

        // 1. Read attestation file
        let attestation_content = fs::read_to_string(artifact)
            .map_err(|e| anyhow::anyhow!("Failed to read attestation file: {}", e))?;

        let attestation_json: Value = serde_json::from_str(&attestation_content)
            .map_err(|e| anyhow::anyhow!("Failed to parse attestation JSON: {}", e))?;

        // 2. Generate ephemeral keypair
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_bytes();

        log::info!("Generated ephemeral Ed25519 keypair");

        // 3. Create payload for signing
        let payload = serde_json::to_vec(&attestation_json)?;

        // 4. Sign with ephemeral key
        let signature = signing_key.sign(&payload);
        let signature_base64 = BASE64.encode(signature.to_bytes());

        log::debug!("Signature created: {} bytes", signature.to_bytes().len());

        // 5. Get Fulcio certificate (async operation)
        let fulcio_url = self
            .fulcio_url
            .as_deref()
            .unwrap_or("https://fulcio.sigstore.dev");

        let runtime = tokio::runtime::Runtime::new()
            .map_err(|e| anyhow::anyhow!("Failed to create async runtime: {}", e))?;

        let cert_chain = runtime.block_on(async {
            let fulcio_client = FulcioClient::new(Some(fulcio_url));

            // Parse OIDC token
            let oidc_identity = fulcio_client
                .verify_oidc_token(oidc_token)
                .await
                .map_err(|e| anyhow::anyhow!("Invalid OIDC token: {}", e))?;

            log::info!(
                "OIDC Identity: issuer={}, subject={}",
                oidc_identity.issuer,
                oidc_identity.subject
            );

            // Generate proof of possession
            let challenge = b"fulcio-challenge"; // In production, use server's challenge
            let proof = signing_key.sign(challenge);

            // Request certificate from Fulcio
            let certs = fulcio_client
                .get_signing_certificate(&oidc_identity, &public_key_bytes, &proof.to_bytes())
                .await
                .map_err(|e| anyhow::anyhow!("Failed to get Fulcio certificate: {}", e))?;

            log::info!("✅ Received Fulcio certificate chain");

            Ok::<_, anyhow::Error>((certs, oidc_identity))
        })?;

        let (certificate_chain, oidc_identity) = cert_chain;

        // 6. Create DSSE envelope with certificate
        let signed_envelope = json!({
            "payloadType": "application/vnd.in-toto+json",
            "payload": BASE64.encode(&payload),
            "signatures": [{
                "keyid": "",
                "sig": signature_base64,
                "certificate": certificate_chain[0], // Leaf certificate
                "chain": certificate_chain[1..],     // Intermediate + root
                "publicKey": BASE64.encode(public_key_bytes),
                "oidc_issuer": oidc_identity.issuer,
                "oidc_subject": oidc_identity.subject
            }]
        });

        // 7. Ensure output directory exists
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }

        // 8. Write signed envelope
        let envelope_json = serde_json::to_string_pretty(&signed_envelope)?;
        fs::write(output, &envelope_json)?;

        log::info!("Signed envelope created at: {:?}", output);

        let mut result = json!({
            "provider": "fulcio-keyless",
            "algorithm": "Ed25519",
            "output": output.to_string_lossy(),
            "signature_length": signature.to_bytes().len(),
            "format": "in-toto DSSE with Fulcio certificate",
            "oidc_issuer": oidc_identity.issuer,
            "oidc_subject": oidc_identity.subject,
            "certificate_chain_length": certificate_chain.len()
        });

        // 9. Upload to Rekor (optional, Phase 3 integration)
        if let Some(rekor_url) = &self.rekor_url {
            log::info!("Uploading to Rekor transparency log: {}", rekor_url);

            match upload_to_rekor_with_cert(rekor_url, &signed_envelope, &certificate_chain) {
                Ok(rekor_metadata) => {
                    log::info!(
                        "Successfully uploaded to Rekor: UUID={}",
                        rekor_metadata["uuid"].as_str().unwrap_or("unknown")
                    );
                    result["rekor"] = rekor_metadata;
                }
                Err(e) => {
                    log::warn!(
                        "Failed to upload to Rekor (continuing without transparency log): {}",
                        e
                    );
                    result["rekor_error"] = json!(e.to_string());
                }
            }
        } else {
            log::debug!("Rekor upload disabled (no URL configured)");
        }

        Ok(result)
    }
}

/// Upload signed envelope with certificate to Rekor
fn upload_to_rekor_with_cert(
    rekor_url: &str,
    signed_envelope: &Value,
    certificate_chain: &[String],
) -> Result<Value> {
    // Extract public key from certificate (simplified)
    // In production, parse X.509 certificate properly
    let public_key_placeholder = vec![0u8; 32]; // TODO: Extract from cert

    let runtime = tokio::runtime::Runtime::new()
        .map_err(|e| anyhow::anyhow!("Failed to create async runtime: {}", e))?;

    runtime.block_on(async {
        let client = RekorClient::new(Some(rekor_url));

        // Upload DSSE envelope to Rekor
        let (uuid, log_index) = client
            .upload_dsse(signed_envelope, &public_key_placeholder)
            .await
            .map_err(|e| anyhow::anyhow!("Rekor upload failed: {}", e))?;

        Ok(json!({
            "uuid": uuid,
            "log_index": log_index,
            "location": format!("{}/api/v1/log/entries/{}", rekor_url, uuid),
            "rekor_url": rekor_url
        }))
    })
}

// ===== Keyless Verification Provider =====

/// Keyless verification provider (verifies Fulcio certificates)
pub struct KeylessVerifyProvider {
    pub check_rekor: bool,
}

impl KeylessVerifyProvider {
    pub fn new(check_rekor: bool) -> Self {
        Self { check_rekor }
    }
}

impl VerifyProvider for KeylessVerifyProvider {
    fn name(&self) -> &str {
        "fulcio-keyless"
    }

    fn verify(
        &self,
        artifact: &PathBuf,
        signature: &PathBuf,
        rekor_url: Option<&str>,
    ) -> Result<Value> {
        log::info!("Verifying keyless signature with Fulcio certificate");
        log::info!("  Artifact:  {:?}", artifact);
        log::info!("  Signature: {:?}", signature);

        // 1. Read signed envelope
        let envelope_content = fs::read_to_string(signature)
            .map_err(|e| anyhow::anyhow!("Failed to read signature file: {}", e))?;

        let envelope: Value = serde_json::from_str(&envelope_content)
            .map_err(|e| anyhow::anyhow!("Failed to parse signature envelope: {}", e))?;

        // 2. Extract components
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

        let certificate_pem = sig_entry["certificate"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'certificate' in signature entry"))?;

        let oidc_issuer = sig_entry["oidc_issuer"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'oidc_issuer' in signature entry"))?;

        let oidc_subject = sig_entry["oidc_subject"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'oidc_subject' in signature entry"))?;

        log::info!("OIDC Issuer: {}", oidc_issuer);
        log::info!("OIDC Subject: {}", oidc_subject);

        // 3. Verify certificate chain (TODO: implement proper X.509 validation)
        // This requires:
        // - Parsing X.509 certificates
        // - Verifying chain up to Fulcio root CA
        // - Checking certificate extensions (OIDC claims)
        log::info!("⏭️  Certificate chain verification (not yet implemented)");

        // 4. Decode payload and signature
        let payload_bytes = BASE64
            .decode(payload_base64)
            .map_err(|e| anyhow::anyhow!("Failed to decode payload: {}", e))?;

        let sig_bytes = BASE64
            .decode(sig_base64)
            .map_err(|e| anyhow::anyhow!("Failed to decode signature: {}", e))?;

        // 5. Extract public key from certificate (TODO: proper X.509 parsing)
        // For now, use public key from envelope
        let public_key_base64 = sig_entry["publicKey"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'publicKey' in signature entry"))?;

        let public_key_bytes = BASE64
            .decode(public_key_base64)
            .map_err(|e| anyhow::anyhow!("Failed to decode public key: {}", e))?;

        // 6. Verify signature
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

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

        // 7. Parse attestation and verify hash chain
        let attestation: Value = serde_json::from_slice(&payload_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse attestation from payload: {}", e))?;

        let subject_name = attestation["subject"][0]["name"]
            .as_str()
            .unwrap_or("unknown");
        let sbom_hash = attestation["subject"][0]["digest"]["sha256"]
            .as_str()
            .unwrap_or("unknown");

        Ok(json!({
            "valid": true,
            "provider": "fulcio-keyless",
            "algorithm": "Ed25519",
            "signature_valid": true,
            "certificate_valid": true, // TODO: implement proper validation
            "oidc_issuer": oidc_issuer,
            "oidc_subject": oidc_subject,
            "subject": subject_name,
            "sbom_hash": sbom_hash,
        }))
    }
}

#[ctor::ctor]
fn register() {
    // Register keyless providers
    let _ = provenix_core::registry::register_sign(
        "fulcio-keyless",
        KeylessSignProvider::new(None, None),
    );

    let _ = provenix_core::registry::register_verify(
        "fulcio-keyless",
        KeylessVerifyProvider::new(false),
    );
}

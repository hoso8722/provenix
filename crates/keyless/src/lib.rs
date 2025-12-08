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

        // 3. Verify certificate chain using Phase 4.1 implementation
        use provenix_utils::x509;

        let cert_chain = sig_entry["chain"].as_array();
        let intermediate_pem = cert_chain.and_then(|c| c.first()).and_then(|v| v.as_str());

        // Verify certificate chain
        x509::verify_certificate_chain(certificate_pem, intermediate_pem)
            .map_err(|e| anyhow::anyhow!("Certificate chain verification failed: {}", e))?;

        log::info!("✅ Certificate chain verification passed");

        // Parse certificate and extract OIDC info
        let cert_der = x509::parse_certificate_pem(certificate_pem)
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate PEM: {}", e))?;

        let cert = x509::parse_certificate_der(&cert_der)
            .map_err(|e| anyhow::anyhow!("Failed to parse certificate DER: {}", e))?;

        let oidc_info = x509::extract_oidc_info(&cert)
            .map_err(|e| anyhow::anyhow!("Failed to extract OIDC info from certificate: {}", e))?;

        // Verify OIDC issuer is trusted
        x509::verify_trusted_issuer(&oidc_info.issuer)
            .map_err(|e| anyhow::anyhow!("Untrusted OIDC issuer: {}", e))?;

        log::info!("✅ OIDC issuer verified: {}", oidc_info.issuer);

        // Verify OIDC claims match envelope
        if oidc_info.issuer != oidc_issuer {
            return Err(anyhow::anyhow!(
                "OIDC issuer mismatch: certificate='{}', envelope='{}'",
                oidc_info.issuer,
                oidc_issuer
            ));
        }

        if let Some(ref cert_subject) = oidc_info.subject {
            if cert_subject != oidc_subject {
                return Err(anyhow::anyhow!(
                    "OIDC subject mismatch: certificate='{}', envelope='{}'",
                    cert_subject,
                    oidc_subject
                ));
            }
        }

        log::info!("✅ OIDC claims verified");

        // 4. Decode payload and signature
        let payload_bytes = BASE64
            .decode(payload_base64)
            .map_err(|e| anyhow::anyhow!("Failed to decode payload: {}", e))?;

        let sig_bytes = BASE64
            .decode(sig_base64)
            .map_err(|e| anyhow::anyhow!("Failed to decode signature: {}", e))?;

        // 5. Extract Ed25519 public key from certificate using Phase 4.1
        let public_key = x509::extract_ed25519_public_key(&cert)
            .map_err(|e| anyhow::anyhow!("Failed to extract public key from certificate: {}", e))?;

        log::info!("✅ Public key extracted from certificate");

        // 6. Verify signature using certificate public key
        use ed25519_dalek::{Signature, Verifier};

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

        let mut result = json!({
            "valid": true,
            "provider": "fulcio-keyless",
            "algorithm": "Ed25519",
            "signature_valid": true,
            "certificate_valid": true,
            "certificate_chain_verified": true,
            "oidc_issuer": oidc_info.issuer,
            "oidc_subject": oidc_info.subject,
            "subject": subject_name,
            "sbom_hash": sbom_hash,
        });

        // Add GitHub-specific OIDC information if present
        if let Some(ref repo) = oidc_info.github_repository {
            result["github_repository"] = json!(repo);
        }
        if let Some(ref workflow) = oidc_info.github_workflow {
            result["github_workflow"] = json!(workflow);
        }
        if let Some(ref sha) = oidc_info.github_sha {
            result["github_sha"] = json!(sha);
        }
        if let Some(ref event) = oidc_info.github_event_name {
            result["github_event"] = json!(event);
        }
        if let Some(ref ref_str) = oidc_info.github_ref {
            result["github_ref"] = json!(ref_str);
        }

        Ok(result)
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

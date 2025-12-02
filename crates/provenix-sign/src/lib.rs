use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey};
use provenix_plugin::SignProvider;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

// ===== Phase 2: Ed25519 Signing Provider =====

pub struct Ed25519Provider;

impl SignProvider for Ed25519Provider {
    fn name(&self) -> &str {
        "ed25519"
    }

    fn sign(&self, artifact: &PathBuf, key: &str, output: &PathBuf) -> anyhow::Result<Value> {
        log::info!("Signing artifact with Ed25519: {:?}", artifact);

        // 1. Read attestation file
        let attestation_content = fs::read_to_string(artifact)
            .map_err(|e| anyhow::anyhow!("Failed to read attestation file: {}", e))?;

        let attestation_json: Value = serde_json::from_str(&attestation_content)
            .map_err(|e| anyhow::anyhow!("Failed to parse attestation JSON: {}", e))?;

        // 2. Load private key
        let signing_key = load_private_key(key)?;
        log::debug!("Private key loaded successfully");

        // 3. Create canonical payload (for signing)
        let payload = serde_json::to_vec(&attestation_json)?;

        // 4. Sign with Ed25519
        let signature: Signature = signing_key.sign(&payload);
        let signature_base64 = BASE64.encode(signature.to_bytes());

        log::debug!("Signature created: {} bytes", signature.to_bytes().len());

        // 5. Create in-toto DSSE (Dead Simple Signing Envelope) format
        let signed_envelope = create_dsse_envelope(&payload, &signature_base64, &signing_key)?;

        // 6. Ensure output directory exists
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }

        // 7. Write signed envelope
        let envelope_json = serde_json::to_string_pretty(&signed_envelope)?;
        fs::write(output, envelope_json)?;

        log::info!("Signed envelope created at: {:?}", output);

        Ok(json!({
            "provider": "ed25519",
            "algorithm": "Ed25519",
            "output": output.to_string_lossy(),
            "signature_length": signature.to_bytes().len(),
            "format": "in-toto DSSE"
        }))
    }
}

/// Load private key from file or generate new one
fn load_private_key(key_path: &str) -> anyhow::Result<SigningKey> {
    let path = PathBuf::from(key_path);

    if path.exists() {
        // Load existing key
        log::info!("Loading private key from: {}", key_path);
        let key_bytes =
            fs::read(&path).map_err(|e| anyhow::anyhow!("Failed to read key file: {}", e))?;

        // Decode base64 if needed
        let key_bytes = if key_bytes.starts_with(b"-----BEGIN") {
            // PEM format (not supported yet)
            return Err(anyhow::anyhow!(
                "PEM format not supported. Use raw bytes or base64."
            ));
        } else if key_bytes.len() == 64 {
            // Already raw bytes (base64 decoded)
            key_bytes
        } else {
            // Try base64 decode
            BASE64
                .decode(&key_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to decode base64 key: {}", e))?
        };

        if key_bytes.len() != 64 {
            return Err(anyhow::anyhow!(
                "Invalid key size: expected 64 bytes, got {}",
                key_bytes.len()
            ));
        }

        let key_array: [u8; 64] = key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Failed to convert key bytes to array"))?;

        Ok(SigningKey::from_keypair_bytes(&key_array)?)
    } else {
        Err(anyhow::anyhow!(
            "Private key not found: {}\n\nGenerate a key pair with:\n  provenix-cli keygen -o {}",
            key_path,
            key_path
        ))
    }
}

/// Create in-toto DSSE (Dead Simple Signing Envelope)
/// Spec: https://github.com/secure-systems-lab/dsse
fn create_dsse_envelope(
    payload: &[u8],
    signature_base64: &str,
    signing_key: &SigningKey,
) -> anyhow::Result<Value> {
    // Get public key for keyid and embedding
    let public_key = signing_key.verifying_key();
    let public_key_bytes = public_key.to_bytes();
    let keyid = format!("ed25519:{}", BASE64.encode(&public_key_bytes[..8])); // Use first 8 bytes as keyid
    let public_key_base64 = BASE64.encode(&public_key_bytes);

    Ok(json!({
        "payload": BASE64.encode(payload),
        "payloadType": "application/vnd.in-toto+json",
        "signatures": [{
            "keyid": keyid,
            "sig": signature_base64,
            "publicKey": public_key_base64  // Embed public key for verification
        }]
    }))
}

/// Generate new Ed25519 keypair
pub fn generate_keypair() -> anyhow::Result<(SigningKey, Vec<u8>, Vec<u8>)> {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    // Export as base64-encoded bytes for easy storage
    let private_key_bytes = signing_key.to_keypair_bytes().to_vec();
    let public_key_bytes = verifying_key.to_bytes().to_vec();

    Ok((signing_key, private_key_bytes, public_key_bytes))
}

/// Save keypair to files
pub fn save_keypair(
    private_key: &[u8],
    public_key: &[u8],
    private_path: &PathBuf,
    public_path: &PathBuf,
) -> anyhow::Result<()> {
    // Ensure directories exist
    if let Some(parent) = private_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = public_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Write keys (base64 encoded for readability)
    fs::write(private_path, BASE64.encode(private_key))?;
    fs::write(public_path, BASE64.encode(public_key))?;

    // Set restrictive permissions on private key (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(private_path)?.permissions();
        perms.set_mode(0o600); // rw------- (owner only)
        fs::set_permissions(private_path, perms)?;
    }

    log::info!("Keypair saved:");
    log::info!("  Private: {:?}", private_path);
    log::info!("  Public:  {:?}", public_path);

    Ok(())
}

#[ctor::ctor]
fn register() {
    let _ = provenix_core::registry::register_sign("ed25519", Ed25519Provider);
}

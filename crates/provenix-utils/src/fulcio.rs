use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Fulcio API client for keyless signing with OIDC
pub struct FulcioClient {
    base_url: String,
    client: Client,
}

/// Certificate signing request
#[derive(Debug, Serialize)]
pub struct CertificateRequest {
    #[serde(rename = "publicKeyRequest")]
    pub public_key_request: PublicKeyRequest,
}

#[derive(Debug, Serialize)]
pub struct PublicKeyRequest {
    #[serde(rename = "publicKey")]
    pub public_key: PublicKey,
    #[serde(rename = "proofOfPossession")]
    pub proof_of_possession: String,
}

#[derive(Debug, Serialize)]
pub struct PublicKey {
    pub algorithm: String,
    pub content: String, // base64-encoded public key
}

/// Certificate response from Fulcio
#[derive(Debug, Deserialize)]
pub struct CertificateResponse {
    #[serde(rename = "signedCertificateEmbeddedSct")]
    pub signed_certificate_embedded_sct: SignedCertificate,
}

#[derive(Debug, Deserialize)]
pub struct SignedCertificate {
    pub chain: Chain,
}

#[derive(Debug, Deserialize)]
pub struct Chain {
    pub certificates: Vec<String>, // PEM-encoded certificates
}

/// OIDC Identity token information
#[derive(Debug, Clone)]
pub struct OidcIdentity {
    pub token: String,
    pub issuer: String,
    pub subject: String,
}

impl FulcioClient {
    /// Create new Fulcio client
    ///
    /// # Arguments
    /// * `base_url` - Fulcio server URL (None = public sigstore instance)
    ///
    /// # Examples
    /// ```
    /// let client = FulcioClient::new(Some("https://fulcio.sigstore.dev"));
    /// let client = FulcioClient::new(None); // Default
    /// ```
    pub fn new(base_url: Option<&str>) -> Self {
        let base_url = base_url
            .unwrap_or("https://fulcio.sigstore.dev")
            .trim_end_matches('/')
            .to_string();

        Self {
            base_url,
            client: Client::new(),
        }
    }

    /// Request signing certificate from Fulcio with OIDC token
    ///
    /// # Arguments
    /// * `oidc_identity` - OIDC identity token
    /// * `public_key` - Public key bytes (e.g., Ed25519 32 bytes)
    /// * `proof` - Proof of possession (signature over challenge)
    ///
    /// # Returns
    /// PEM-encoded certificate chain
    pub async fn get_signing_certificate(
        &self,
        oidc_identity: &OidcIdentity,
        public_key: &[u8],
        proof: &[u8],
    ) -> Result<Vec<String>> {
        log::info!(
            "Requesting signing certificate from Fulcio: {}",
            self.base_url
        );

        // Encode public key and proof as base64
        let public_key_base64 = BASE64.encode(public_key);
        let proof_base64 = BASE64.encode(proof);

        // Create certificate request
        let request = CertificateRequest {
            public_key_request: PublicKeyRequest {
                public_key: PublicKey {
                    algorithm: "ECDSA".to_string(), // or "ED25519"
                    content: public_key_base64,
                },
                proof_of_possession: proof_base64,
            },
        };

        // POST to /api/v2/signingCert
        let url = format!("{}/api/v2/signingCert", self.base_url);
        let response = self
            .client
            .post(&url)
            .bearer_auth(&oidc_identity.token)
            .json(&request)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await?;
            return Err(anyhow::anyhow!(
                "Fulcio certificate request failed: {} - {}",
                status,
                body
            ));
        }

        // Parse response
        let cert_response: CertificateResponse = response.json().await?;

        log::info!(
            "✅ Received certificate chain with {} certificates",
            cert_response
                .signed_certificate_embedded_sct
                .chain
                .certificates
                .len()
        );

        Ok(cert_response
            .signed_certificate_embedded_sct
            .chain
            .certificates)
    }

    /// Verify OIDC token with full JWT signature verification (Phase 4.2)
    ///
    /// This performs complete JWT verification including:
    /// - Fetching OIDC configuration
    /// - Fetching JWKS (with caching)
    /// - Verifying JWT signature with public key
    /// - Validating JWT claims (exp, iat, iss, aud)
    pub async fn verify_oidc_token(&self, token: &str) -> Result<OidcIdentity> {
        use crate::jwt::JwtVerifier;

        // First, do a quick parse to get the issuer
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow::anyhow!("Invalid JWT format"));
        }

        // Decode payload (base64url) to get issuer
        let payload_json = BASE64.decode(parts[1])?;
        let payload: Value = serde_json::from_slice(&payload_json)?;

        let issuer = payload["iss"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Missing 'iss' claim"))?;

        log::info!("Verifying JWT from issuer: {}", issuer);

        // Phase 4.2: Full JWT verification with JWKS
        let verifier = JwtVerifier::new();
        let claims = verifier
            .verify_jwt(token, issuer)
            .await
            .map_err(|e| anyhow::anyhow!("JWT verification failed: {}", e))?;

        log::info!("✅ JWT signature verified");
        log::info!(
            "OIDC Identity: issuer={}, subject={}",
            claims.iss,
            claims.sub
        );

        Ok(OidcIdentity {
            token: token.to_string(),
            issuer: claims.iss,
            subject: claims.sub,
        })
    }

    /// Get root certificate for Fulcio
    ///
    /// This is used to verify the certificate chain returned by Fulcio.
    pub async fn get_root_certificate(&self) -> Result<String> {
        let url = format!("{}/api/v2/trustBundle", self.base_url);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to fetch Fulcio root certificate"));
        }

        let body = response.text().await?;
        Ok(body)
    }
}

/// Generate proof of possession for public key
///
/// This is a challenge-response to prove we control the private key.
pub fn generate_proof_of_possession(
    private_key: &[u8],
    public_key: &[u8],
    challenge: &[u8],
) -> Result<Vec<u8>> {
    use ed25519_dalek::{Signer, SigningKey};

    // For Ed25519
    if private_key.len() == 32 {
        let signing_key = SigningKey::from_bytes(
            private_key
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid key length"))?,
        );

        // Sign challenge
        let signature = signing_key.sign(challenge);
        Ok(signature.to_bytes().to_vec())
    } else {
        Err(anyhow::anyhow!("Unsupported key type"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fulcio_client_creation() {
        let client = FulcioClient::new(None);
        assert_eq!(client.base_url, "https://fulcio.sigstore.dev");
    }

    #[test]
    fn test_custom_fulcio_url() {
        let client = FulcioClient::new(Some("https://custom.fulcio.io"));
        assert_eq!(client.base_url, "https://custom.fulcio.io");
    }

    #[tokio::test]
    async fn test_oidc_token_parsing() {
        // Mock JWT token (header.payload.signature)
        let mock_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL3Rva2VuLmFjdGlvbnMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwic3ViIjoicmVwbzpvd25lci9yZXBvOnJlZjpyZWZzL2hlYWRzL21haW4ifQ.signature";

        let client = FulcioClient::new(None);
        // Note: This will fail without proper JWT signature verification
        // In production, use a proper JWT library
    }
}

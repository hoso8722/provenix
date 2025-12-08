//! JWT (JSON Web Token) verification utilities for OIDC tokens
//!
//! This module provides functionality for:
//! - OIDC discovery (.well-known/openid-configuration)
//! - JWKS (JSON Web Key Set) fetching and caching
//! - JWT signature verification
//! - JWT claims validation

use anyhow::{anyhow, Context, Result};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

/// OIDC Provider configuration from .well-known/openid-configuration
#[derive(Debug, Clone, Deserialize)]
pub struct OidcConfiguration {
    pub issuer: String,
    pub jwks_uri: String,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub userinfo_endpoint: Option<String>,
}

/// JSON Web Key Set
#[derive(Debug, Clone, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// JSON Web Key
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,         // Key Type (e.g., "RSA", "EC")
    pub kid: Option<String>, // Key ID
    pub alg: Option<String>, // Algorithm (e.g., "RS256", "ES256")
    pub n: Option<String>,   // RSA modulus
    pub e: Option<String>,   // RSA exponent
    pub x: Option<String>,   // EC x coordinate
    pub y: Option<String>,   // EC y coordinate
    pub crv: Option<String>, // EC curve (e.g., "P-256")
}

impl Jwks {
    /// Find JWK by Key ID
    pub fn find_key(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }
}

/// JWT Claims for OIDC tokens
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcClaims {
    pub iss: String,            // Issuer
    pub sub: String,            // Subject (user identifier)
    pub aud: serde_json::Value, // Audience (can be string or array)
    pub exp: i64,               // Expiration time (Unix timestamp)
    pub iat: i64,               // Issued at (Unix timestamp)
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>, // Additional claims
}

/// JWKS cache entry with TTL
#[derive(Debug, Clone)]
struct JwksCacheEntry {
    jwks: Jwks,
    fetched_at: SystemTime,
    ttl: Duration,
}

impl JwksCacheEntry {
    fn is_expired(&self) -> bool {
        SystemTime::now()
            .duration_since(self.fetched_at)
            .map(|d| d > self.ttl)
            .unwrap_or(true)
    }
}

/// JWKS cache (thread-safe)
pub struct JwksCache {
    cache: Arc<RwLock<HashMap<String, JwksCacheEntry>>>,
    default_ttl: Duration,
}

impl JwksCache {
    /// Create new JWKS cache with default TTL (1 hour)
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            default_ttl: Duration::from_secs(3600), // 1 hour
        }
    }

    /// Create new JWKS cache with custom TTL
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            default_ttl: ttl,
        }
    }

    /// Get JWKS from cache if valid
    pub fn get(&self, jwks_uri: &str) -> Option<Jwks> {
        let cache = self.cache.read().ok()?;
        let entry = cache.get(jwks_uri)?;

        if entry.is_expired() {
            None
        } else {
            Some(entry.jwks.clone())
        }
    }

    /// Store JWKS in cache
    pub fn set(&self, jwks_uri: String, jwks: Jwks) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(
                jwks_uri,
                JwksCacheEntry {
                    jwks,
                    fetched_at: SystemTime::now(),
                    ttl: self.default_ttl,
                },
            );
        }
    }

    /// Clear expired entries
    pub fn cleanup(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.retain(|_, entry| !entry.is_expired());
        }
    }
}

impl Default for JwksCache {
    fn default() -> Self {
        Self::new()
    }
}

/// JWT verifier with JWKS caching
pub struct JwtVerifier {
    cache: JwksCache,
    client: reqwest::Client,
}

impl JwtVerifier {
    /// Create new JWT verifier
    pub fn new() -> Self {
        Self {
            cache: JwksCache::new(),
            client: reqwest::Client::new(),
        }
    }

    /// Create new JWT verifier with custom cache TTL
    pub fn with_cache_ttl(ttl: Duration) -> Self {
        Self {
            cache: JwksCache::with_ttl(ttl),
            client: reqwest::Client::new(),
        }
    }

    /// Fetch OIDC configuration from .well-known endpoint
    pub async fn fetch_oidc_configuration(&self, issuer: &str) -> Result<OidcConfiguration> {
        let well_known_url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );

        log::debug!("Fetching OIDC configuration from: {}", well_known_url);

        let response = self
            .client
            .get(&well_known_url)
            .send()
            .await
            .context("Failed to fetch OIDC configuration")?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "OIDC configuration request failed: {}",
                response.status()
            ));
        }

        let config: OidcConfiguration = response
            .json()
            .await
            .context("Failed to parse OIDC configuration")?;

        log::info!("OIDC configuration fetched: issuer={}", config.issuer);
        Ok(config)
    }

    /// Fetch JWKS from URI (with caching)
    pub async fn fetch_jwks(&self, jwks_uri: &str) -> Result<Jwks> {
        // Check cache first
        if let Some(jwks) = self.cache.get(jwks_uri) {
            log::debug!("JWKS cache hit: {}", jwks_uri);
            return Ok(jwks);
        }

        log::debug!("Fetching JWKS from: {}", jwks_uri);

        let response = self
            .client
            .get(jwks_uri)
            .send()
            .await
            .context("Failed to fetch JWKS")?;

        if !response.status().is_success() {
            return Err(anyhow!("JWKS request failed: {}", response.status()));
        }

        let jwks: Jwks = response.json().await.context("Failed to parse JWKS")?;

        log::info!("JWKS fetched: {} keys", jwks.keys.len());

        // Cache the JWKS
        self.cache.set(jwks_uri.to_string(), jwks.clone());

        Ok(jwks)
    }

    /// Verify JWT signature and claims
    pub async fn verify_jwt(&self, token: &str, expected_issuer: &str) -> Result<OidcClaims> {
        // Decode header to get kid and algorithm
        let header = decode_header(token).context("Failed to decode JWT header")?;

        let kid = header
            .kid
            .ok_or_else(|| anyhow!("JWT header missing 'kid' (Key ID)"))?;

        log::debug!("JWT kid: {}, alg: {:?}", kid, header.alg);

        // Fetch OIDC configuration
        let oidc_config = self
            .fetch_oidc_configuration(expected_issuer)
            .await
            .context("Failed to fetch OIDC configuration")?;

        // Verify issuer matches
        if oidc_config.issuer != expected_issuer {
            return Err(anyhow!(
                "OIDC issuer mismatch: expected '{}', got '{}'",
                expected_issuer,
                oidc_config.issuer
            ));
        }

        // Fetch JWKS
        let jwks = self
            .fetch_jwks(&oidc_config.jwks_uri)
            .await
            .context("Failed to fetch JWKS")?;

        // Find matching JWK
        let jwk = jwks
            .find_key(&kid)
            .ok_or_else(|| anyhow!("JWK not found for kid: {}", kid))?;

        // Create DecodingKey from JWK
        let decoding_key = jwk_to_decoding_key(jwk)?;

        // Set up validation
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[expected_issuer]);
        validation.set_audience(&["sigstore"]); // Fulcio expects "sigstore" audience

        // Decode and verify JWT
        let token_data = decode::<OidcClaims>(token, &decoding_key, &validation)
            .context("JWT verification failed")?;

        log::info!(
            "✅ JWT verified: iss={}, sub={}",
            token_data.claims.iss,
            token_data.claims.sub
        );

        // Additional claims validation
        validate_claims(&token_data.claims)?;

        Ok(token_data.claims)
    }

    /// Cleanup expired cache entries
    pub fn cleanup_cache(&self) {
        self.cache.cleanup();
    }
}

impl Default for JwtVerifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert JWK to jsonwebtoken DecodingKey
fn jwk_to_decoding_key(jwk: &Jwk) -> Result<DecodingKey> {
    match jwk.kty.as_str() {
        "RSA" => {
            let n = jwk
                .n
                .as_ref()
                .ok_or_else(|| anyhow!("RSA JWK missing 'n' (modulus)"))?;
            let e = jwk
                .e
                .as_ref()
                .ok_or_else(|| anyhow!("RSA JWK missing 'e' (exponent)"))?;

            DecodingKey::from_rsa_components(n, e)
                .map_err(|e| anyhow!("Failed to create RSA decoding key: {}", e))
        }
        "EC" => {
            // EC keys require different handling
            // For now, return error as jsonwebtoken doesn't directly support EC from components
            Err(anyhow!(
                "EC key type not yet fully supported in jwk_to_decoding_key"
            ))
        }
        other => Err(anyhow!("Unsupported JWK key type: {}", other)),
    }
}

/// Validate JWT claims
fn validate_claims(claims: &OidcClaims) -> Result<()> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs() as i64;

    // Check expiration
    if claims.exp < now {
        return Err(anyhow!("JWT expired: exp={}, now={}", claims.exp, now));
    }

    // Check issued at (not in the future)
    if claims.iat > now + 60 {
        // Allow 60 seconds clock skew
        return Err(anyhow!(
            "JWT issued in the future: iat={}, now={}",
            claims.iat,
            now
        ));
    }

    // Check audience
    let audience_valid = match &claims.aud {
        serde_json::Value::String(s) => s == "sigstore",
        serde_json::Value::Array(arr) => arr.iter().any(|v| v.as_str() == Some("sigstore")),
        _ => false,
    };

    if !audience_valid {
        return Err(anyhow!(
            "JWT audience validation failed: expected 'sigstore', got {:?}",
            claims.aud
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwks_cache() {
        let cache = JwksCache::new();
        let jwks = Jwks { keys: vec![] };

        cache.set("https://example.com/jwks".to_string(), jwks.clone());
        assert!(cache.get("https://example.com/jwks").is_some());
    }

    #[test]
    fn test_jwks_find_key() {
        let jwks = Jwks {
            keys: vec![
                Jwk {
                    kty: "RSA".to_string(),
                    kid: Some("key1".to_string()),
                    alg: Some("RS256".to_string()),
                    n: None,
                    e: None,
                    x: None,
                    y: None,
                    crv: None,
                },
                Jwk {
                    kty: "RSA".to_string(),
                    kid: Some("key2".to_string()),
                    alg: Some("RS256".to_string()),
                    n: None,
                    e: None,
                    x: None,
                    y: None,
                    crv: None,
                },
            ],
        };

        assert!(jwks.find_key("key1").is_some());
        assert!(jwks.find_key("key3").is_none());
    }
}

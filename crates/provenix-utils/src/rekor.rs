use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// Rekor API client for transparency log operations
pub struct RekorClient {
    base_url: String,
    client: Client,
}

/// Rekor log entry response
#[derive(Debug, Serialize, Deserialize)]
pub struct RekorEntry {
    pub uuid: String,
    pub log_index: u64,
    pub body: String,
    pub integrated_time: i64,
}

/// Rekor upload response
#[derive(Debug, Serialize, Deserialize)]
pub struct RekorUploadResponse {
    pub uuid: String,
    pub log_index: u64,
    pub body: String,
}

impl RekorClient {
    /// Create new Rekor client
    pub fn new(base_url: Option<&str>) -> Self {
        let base_url: String = base_url
            .unwrap_or("https://rekor.sigstore.dev")
            .trim_end_matches('/')
            .to_string();

        Self {
            base_url,
            client: Client::new(),
        }
    }

    /// Upload DSSE envelope to Rekor
    /// Returns (UUID, log_index)
    pub async fn upload_dsse(
        &self,
        dsse_envelope: &Value,
        public_key: &[u8],
    ) -> Result<(String, u64)> {
        log::info!("Uploading to Rekor: {}", self.base_url);

        // Prepare Rekor entry
        let entry = self.create_rekor_entry(dsse_envelope, public_key)?;

        // POST to /api/v1/log/entries
        let url = format!("{}/api/v1/log/entries", self.base_url);
        let response = self.client.post(&url).json(&entry).send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await?;
            return Err(anyhow::anyhow!(
                "Rekor upload failed: {} - {}",
                status,
                body
            ));
        }

        // Parse response
        let response_json: Value = response.json().await?;

        // Rekor returns a map with UUID as key
        let (uuid, entry_data) = response_json
            .as_object()
            .and_then(|obj| obj.iter().next())
            .ok_or_else(|| anyhow::anyhow!("Invalid Rekor response"))?;

        let log_index = entry_data["logIndex"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("Missing logIndex in response"))?;

        log::info!(
            "✅ Uploaded to Rekor: UUID={}, logIndex={}",
            uuid,
            log_index
        );

        Ok((uuid.clone(), log_index))
    }

    /// Get entry from Rekor by UUID
    pub async fn get_entry(&self, uuid: &str) -> Result<RekorEntry> {
        log::info!("Fetching Rekor entry: {}", uuid);

        let url = format!("{}/api/v1/log/entries/{}", self.base_url, uuid);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Rekor entry not found: {}",
                response.status()
            ));
        }

        let response_json: Value = response.json().await?;

        // Parse entry
        let entry_data = response_json
            .as_object()
            .and_then(|obj| obj.values().next())
            .ok_or_else(|| anyhow::anyhow!("Invalid entry response"))?;

        Ok(RekorEntry {
            uuid: uuid.to_string(),
            log_index: entry_data["logIndex"].as_u64().unwrap_or(0),
            body: entry_data["body"].as_str().unwrap_or("").to_string(),
            integrated_time: entry_data["integratedTime"].as_i64().unwrap_or(0),
        })
    }

    /// Verify entry exists in Rekor
    pub async fn verify_entry_exists(&self, uuid: &str) -> Result<bool> {
        match self.get_entry(uuid).await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Search Rekor by artifact hash
    pub async fn search_by_hash(&self, hash: &str) -> Result<Vec<String>> {
        log::debug!("Searching Rekor by hash: {}", hash);

        let url = format!("{}/api/v1/index/retrieve", self.base_url);
        let body = json!({
            "hash": format!("sha256:{}", hash)
        });

        let response = self.client.post(&url).json(&body).send().await?;

        if !response.status().is_success() {
            return Ok(vec![]);
        }

        let uuids: Vec<String> = response.json().await?;
        Ok(uuids)
    }

    /// Create Rekor entry in hashedrekord format
    fn create_rekor_entry(&self, dsse_envelope: &Value, public_key: &[u8]) -> Result<Value> {
        // Compute hash of DSSE envelope
        let envelope_bytes = serde_json::to_vec(dsse_envelope)?;
        let mut hasher = Sha256::new();
        hasher.update(&envelope_bytes);
        let hash = format!("{:x}", hasher.finalize());

        // Create hashedrekord entry
        let entry = json!({
            "kind": "hashedrekord",
            "apiVersion": "0.0.1",
            "spec": {
                "signature": {
                    "content": BASE64.encode(&envelope_bytes),
                    "publicKey": {
                        "content": BASE64.encode(public_key)
                    }
                },
                "data": {
                    "hash": {
                        "algorithm": "sha256",
                        "value": hash
                    }
                }
            }
        });

        Ok(entry)
    }

    /// Get public Rekor instance URL
    pub fn public_instance() -> &'static str {
        "https://rekor.sigstore.dev"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = RekorClient::new(None);
        assert_eq!(client.base_url, "https://rekor.sigstore.dev");

        let client = RekorClient::new(Some("https://custom.rekor.io"));
        assert_eq!(client.base_url, "https://custom.rekor.io");
    }

    #[test]
    fn test_public_instance() {
        assert_eq!(RekorClient::public_instance(), "https://rekor.sigstore.dev");
    }
}

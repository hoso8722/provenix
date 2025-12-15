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
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RekorEntry {
    pub uuid: String,
    pub log_index: u64,
    pub body: String,
    pub integrated_time: i64,
    pub log_id: Option<String>,
    pub verification: Option<RekorVerification>,
}

/// Rekor verification data (inclusion proof, SET, etc.)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RekorVerification {
    #[serde(rename = "inclusionProof")]
    pub inclusion_proof: Option<InclusionProof>,
    #[serde(rename = "signedEntryTimestamp")]
    pub signed_entry_timestamp: Option<String>,
}

/// Merkle tree inclusion proof
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct InclusionProof {
    #[serde(rename = "logIndex")]
    pub log_index: u64,
    #[serde(rename = "rootHash")]
    pub root_hash: String,
    #[serde(rename = "treeSize")]
    pub tree_size: u64,
    pub hashes: Vec<String>,
    pub checkpoint: Option<Checkpoint>,
}

/// Rekor checkpoint (Signed Tree Head)
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Checkpoint {
    pub envelope: String,
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

        // Parse verification data (inclusion proof, SET)
        let verification = entry_data.get("verification").and_then(|v| {
            let inclusion_proof = v.get("inclusionProof").and_then(|ip| {
                Some(InclusionProof {
                    log_index: ip["logIndex"].as_u64()?,
                    root_hash: ip["rootHash"].as_str()?.to_string(),
                    tree_size: ip["treeSize"].as_u64()?,
                    hashes: ip["hashes"]
                        .as_array()?
                        .iter()
                        .filter_map(|h| h.as_str().map(|s| s.to_string()))
                        .collect(),
                    checkpoint: ip.get("checkpoint").and_then(|c| {
                        Some(Checkpoint {
                            envelope: c["envelope"].as_str()?.to_string(),
                        })
                    }),
                })
            });

            let signed_entry_timestamp = v
                .get("signedEntryTimestamp")
                .and_then(|s| s.as_str())
                .map(|s| s.to_string());

            Some(RekorVerification {
                inclusion_proof,
                signed_entry_timestamp,
            })
        });

        Ok(RekorEntry {
            uuid: uuid.to_string(),
            log_index: entry_data["logIndex"].as_u64().unwrap_or(0),
            body: entry_data["body"].as_str().unwrap_or("").to_string(),
            integrated_time: entry_data["integratedTime"].as_i64().unwrap_or(0),
            log_id: entry_data["logID"].as_str().map(|s| s.to_string()),
            verification,
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

// ===== Merkle Tree Inclusion Proof Verification (RFC 6962) =====

/// Verify Merkle tree inclusion proof
///
/// Implements RFC 6962 Certificate Transparency verification logic.
/// Verifies that a leaf hash is included in the Merkle tree at the specified index.
pub fn verify_inclusion_proof(
    leaf_hash: &[u8],
    log_index: u64,
    proof_hashes: &[Vec<u8>],
    tree_size: u64,
    root_hash: &[u8],
) -> Result<bool> {
    if log_index >= tree_size {
        return Err(anyhow::anyhow!(
            "Log index {} >= tree size {}",
            log_index,
            tree_size
        ));
    }

    // Compute root hash from leaf and proof
    let computed_root = compute_root_from_inclusion_proof(leaf_hash, log_index, proof_hashes, tree_size)?;

    // Compare with expected root hash
    Ok(computed_root == root_hash)
}

/// Compute Merkle tree root from inclusion proof
fn compute_root_from_inclusion_proof(
    leaf_hash: &[u8],
    mut index: u64,
    proof_hashes: &[Vec<u8>],
    _tree_size: u64,
) -> Result<Vec<u8>> {
    let mut current_hash = leaf_hash.to_vec();
    let mut last_node = index;

    for proof_hash in proof_hashes {
        let (left, right) = if last_node % 2 == 0 {
            // Current node is left child
            (&current_hash[..], &proof_hash[..])
        } else {
            // Current node is right child
            (&proof_hash[..], &current_hash[..])
        };

        // Hash(left || right)
        current_hash = hash_children(left, right);
        
        last_node /= 2;
        index /= 2;
    }

    // Verify we've reached the root level
    if last_node != 0 {
        return Err(anyhow::anyhow!(
            "Inclusion proof verification failed: did not reach root (last_node={})",
            last_node
        ));
    }

    Ok(current_hash)
}

/// Hash two child nodes to create parent node
/// RFC 6962: MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
fn hash_children(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&[0x01]); // Node prefix (0x01 for internal nodes)
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

/// Compute leaf hash for Rekor entry
/// RFC 6962: MTH({d(0)}) = SHA-256(0x00 || d(0))
pub fn compute_leaf_hash(entry_data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(&[0x00]); // Leaf prefix (0x00 for leaf nodes)
    hasher.update(entry_data);
    hasher.finalize().to_vec()
}

/// Helper: Decode base64 hash string to bytes
pub fn decode_hash(hash_str: &str) -> Result<Vec<u8>> {
    BASE64
        .decode(hash_str)
        .map_err(|e| anyhow::anyhow!("Failed to decode hash: {}", e))
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

    #[test]
    fn test_compute_leaf_hash() {
        let data = b"test data";
        let leaf_hash = compute_leaf_hash(data);
        
        // Leaf hash should be SHA256(0x00 || data)
        let mut hasher = Sha256::new();
        hasher.update(&[0x00]);
        hasher.update(data);
        let expected = hasher.finalize().to_vec();
        
        assert_eq!(leaf_hash, expected);
    }

    #[test]
    fn test_hash_children() {
        let left = vec![1, 2, 3, 4];
        let right = vec![5, 6, 7, 8];
        
        let parent = hash_children(&left, &right);
        
        // Parent should be SHA256(0x01 || left || right)
        let mut hasher = Sha256::new();
        hasher.update(&[0x01]);
        hasher.update(&left);
        hasher.update(&right);
        let expected = hasher.finalize().to_vec();
        
        assert_eq!(parent, expected);
    }

    #[test]
    fn test_inclusion_proof_simple() {
        // Simple tree with 4 leaves: [A, B, C, D]
        // Tree structure:
        //        Root
        //       /    \
        //     H(AB)  H(CD)
        //     / \    / \
        //    A   B  C   D
        
        let leaf_a = compute_leaf_hash(b"A");
        let leaf_b = compute_leaf_hash(b"B");
        let leaf_c = compute_leaf_hash(b"C");
        let leaf_d = compute_leaf_hash(b"D");
        
        let h_ab = hash_children(&leaf_a, &leaf_b);
        let h_cd = hash_children(&leaf_c, &leaf_d);
        let root = hash_children(&h_ab, &h_cd);
        
        // Prove leaf_a is at index 0
        // Proof path: [B, H(CD)]
        let proof = vec![leaf_b.clone(), h_cd.clone()];
        let result = verify_inclusion_proof(&leaf_a, 0, &proof, 4, &root);
        
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_inclusion_proof_invalid_index() {
        let leaf = compute_leaf_hash(b"test");
        let proof = vec![];
        let root = vec![0; 32];
        
        let result = verify_inclusion_proof(&leaf, 10, &proof, 5, &root);
        assert!(result.is_err());
    }
}

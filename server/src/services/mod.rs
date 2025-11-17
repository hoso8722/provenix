#![allow(dead_code)]

use crate::storage::{SbomRecord, AttestationRecord, DatabaseManager};
use uuid::Uuid;
use chrono::Utc;
use anyhow::Result;
use sha2::{Sha256, Digest};

pub struct SbomService {
    db: DatabaseManager,
}

impl SbomService {
    pub fn new(db: DatabaseManager) -> Self {
        Self { db }
    }

    pub async fn create_sbom(
        &self,
        project: String,
        version: String,
        format: String,
        data: serde_json::Value,
        created_by: String,
    ) -> Result<Uuid> {
        let sbom_id = Uuid::new_v4();
        let data_str = serde_json::to_string(&data)?;
        let mut hasher = Sha256::new();
        hasher.update(&data_str);
        let hash = format!("sha256:{:x}", hasher.finalize());

        let sbom = SbomRecord {
            id: sbom_id,
            project,
            version,
            format,
            data,
            hash,
            created_at: Utc::now(),
            created_by,
        };

        self.db.store_sbom(&sbom).await?;
        Ok(sbom_id)
    }

    pub async fn get_sbom(&self, id: Uuid) -> Result<Option<SbomRecord>> {
        let sbom = self.db.get_sbom(id).await?;
        Ok(sbom)
    }

    pub async fn list_sboms(
        &self,
        project: Option<String>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SbomRecord>> {
        let sboms = self.db.list_sboms(project, limit, offset).await?;
        Ok(sboms)
    }
}

pub struct AttestationService {
    db: DatabaseManager,
}

impl AttestationService {
    pub fn new(db: DatabaseManager) -> Self {
        Self { db }
    }

    pub async fn create_attestation(
        &self,
        subject_id: Uuid,
        attestation_type: String,
        signature: String,
        certificate: String,
        verifier: String,
    ) -> Result<Uuid> {
        let attestation_id = Uuid::new_v4();

        let attestation = AttestationRecord {
            id: attestation_id,
            subject_id,
            attestation_type,
            signature,
            certificate,
            timestamp: Utc::now(),
            verifier,
        };

        self.db.store_attestation(&attestation).await?;
        Ok(attestation_id)
    }

    pub async fn get_attestations_for_subject(
        &self,
        subject_id: Uuid,
    ) -> Result<Vec<AttestationRecord>> {
        let attestations = self.db.get_attestations_for_subject(subject_id).await?;
        Ok(attestations)
    }

    pub async fn verify_attestation(&self, _attestation_id: Uuid, _public_key: &str) -> Result<bool> {
        // TODO: Implement cryptographic verification
        // This is a placeholder implementation
        Ok(true)
    }
}
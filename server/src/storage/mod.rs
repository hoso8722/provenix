#![allow(dead_code)]

use sqlx::{PgPool};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone)]
pub struct DatabaseManager {
    pool: PgPool,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct SbomRecord {
    pub id: Uuid,
    pub project: String,
    pub version: String,
    pub format: String,
    pub data: serde_json::Value,
    pub hash: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct AttestationRecord {
    pub id: Uuid,
    pub subject_id: Uuid,
    pub attestation_type: String,
    pub signature: String,
    pub certificate: String,
    pub timestamp: DateTime<Utc>,
    pub verifier: String,
}

impl DatabaseManager {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(20)
            .connect(database_url)
            .await?;

        Ok(Self { pool })
    }

    pub async fn migrate(&self) -> Result<(), sqlx::Error> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }

    // SBOM operations
    pub async fn store_sbom(&self, sbom: &SbomRecord) -> Result<Uuid, sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO sboms (id, project, version, format, data, hash, created_at, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#
        )
        .bind(&sbom.id)
        .bind(&sbom.project)
        .bind(&sbom.version)
        .bind(&sbom.format)
        .bind(&sbom.data)
        .bind(&sbom.hash)
        .bind(&sbom.created_at)
        .bind(&sbom.created_by)
        .execute(&self.pool)
        .await?;

        Ok(sbom.id)
    }

    pub async fn get_sbom(&self, id: Uuid) -> Result<Option<SbomRecord>, sqlx::Error> {
        let record = sqlx::query_as::<_, SbomRecord>(
            "SELECT id, project, version, format, data, hash, created_at, created_by FROM sboms WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(record)
    }

    pub async fn list_sboms(&self, project: Option<String>, limit: i64, offset: i64) -> Result<Vec<SbomRecord>, sqlx::Error> {
        let records = if let Some(project) = project {
            sqlx::query_as::<_, SbomRecord>(
                "SELECT id, project, version, format, data, hash, created_at, created_by FROM sboms WHERE project = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
            )
            .bind(project)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, SbomRecord>(
                "SELECT id, project, version, format, data, hash, created_at, created_by FROM sboms ORDER BY created_at DESC LIMIT $1 OFFSET $2"
            )
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?
        };

        Ok(records)
    }

    // Attestation operations
    pub async fn store_attestation(&self, attestation: &AttestationRecord) -> Result<Uuid, sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO attestations (id, subject_id, attestation_type, signature, certificate, timestamp, verifier)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#
        )
        .bind(&attestation.id)
        .bind(&attestation.subject_id)
        .bind(&attestation.attestation_type)
        .bind(&attestation.signature)
        .bind(&attestation.certificate)
        .bind(&attestation.timestamp)
        .bind(&attestation.verifier)
        .execute(&self.pool)
        .await?;

        Ok(attestation.id)
    }

    pub async fn get_attestations_for_subject(&self, subject_id: Uuid) -> Result<Vec<AttestationRecord>, sqlx::Error> {
        let records = sqlx::query_as::<_, AttestationRecord>(
            "SELECT id, subject_id, attestation_type, signature, certificate, timestamp, verifier FROM attestations WHERE subject_id = $1 ORDER BY timestamp DESC"
        )
        .bind(subject_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(records)
    }
}
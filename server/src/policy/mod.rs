#![allow(dead_code)]

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyRequest {
    pub subject: String,
    pub action: String,
    pub resource: String,
    pub context: Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyResponse {
    pub allow: bool,
    pub reason: String,
    pub obligations: Vec<String>,
}

pub struct OpaClient {
    pub base_url: String,
    pub client: reqwest::Client,
}

impl OpaClient {
    pub fn new() -> Self {
        Self {
            base_url: std::env::var("OPA_URL")
                .unwrap_or_else(|_| "http://localhost:8181".to_string()),
            client: reqwest::Client::new(),
        }
    }

    pub async fn evaluate_policy(
        &self,
        request: PolicyRequest,
    ) -> Result<PolicyResponse, Box<dyn std::error::Error>> {
        let url = format!("{}/v1/data/provenix/authz/allow", self.base_url);
        
        let opa_input = json!({
            "input": {
                "subject": request.subject,
                "action": request.action,
                "resource": request.resource,
                "context": request.context
            }
        });

        let response = self
            .client
            .post(&url)
            .json(&opa_input)
            .send()
            .await?;

        if response.status().is_success() {
            let opa_response: Value = response.json().await?;
            
            let allow = opa_response
                .pointer("/result")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            Ok(PolicyResponse {
                allow,
                reason: if allow {
                    "Policy evaluation passed".to_string()
                } else {
                    "Policy evaluation failed".to_string()
                },
                obligations: Vec::new(),
            })
        } else {
            Ok(PolicyResponse {
                allow: false,
                reason: "OPA evaluation failed".to_string(),
                obligations: Vec::new(),
            })
        }
    }
}

pub async fn policy_enforcement_middleware(
    State(_app_state): State<crate::AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract claims from request (set by auth middleware)
    let claims = req
        .extensions()
        .get::<crate::auth::Claims>()
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Create policy request
    let policy_request = PolicyRequest {
        subject: claims.sub.clone(),
        action: req.method().to_string(),
        resource: req.uri().path().to_string(),
        context: json!({
            "roles": claims.roles,
            "permissions": claims.permissions,
            "timestamp": chrono::Utc::now().timestamp()
        }),
    };

    // Evaluate policy with OPA
    let opa_client = OpaClient::new();
    let policy_response = opa_client
        .evaluate_policy(policy_request)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    if !policy_response.allow {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(req).await)
}
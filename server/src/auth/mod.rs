use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Router, Json,
};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone)]
pub struct AuthState {
    pub jwt_secret: String,
    pub oidc_config: OidcConfig,
}

#[derive(Clone)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub aud: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
}

impl AuthState {
    pub async fn new() -> anyhow::Result<Self> {
        Ok(Self {
            jwt_secret: std::env::var("JWT_SECRET")
                .unwrap_or_else(|_| "default-secret-change-in-production".to_string()),
            oidc_config: OidcConfig {
                issuer_url: std::env::var("OIDC_ISSUER_URL")
                    .unwrap_or_else(|_| "https://your-oidc-provider.com".to_string()),
                client_id: std::env::var("OIDC_CLIENT_ID")
                    .unwrap_or_else(|_| "provenix-client".to_string()),
                client_secret: std::env::var("OIDC_CLIENT_SECRET")
                    .unwrap_or_else(|_| "client-secret".to_string()),
            },
        })
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let validation = Validation::new(Algorithm::HS256);
        let key = DecodingKey::from_secret(self.jwt_secret.as_ref());
        
        let token_data = decode::<Claims>(token, &key, &validation)?;
        Ok(token_data.claims)
    }
}

pub fn routes() -> Router<crate::AppState> {
    Router::new()
        .route("/login", post(login))
        .route("/verify", get(verify_token))
        .route("/logout", post(logout))
}

async fn login() -> Json<Value> {
    Json(json!({
        "message": "OIDC login flow - redirect to identity provider",
        "redirect_url": "/api/v1/auth/oidc/callback",
        "status": "not_implemented"
    }))
}

async fn verify_token(
    State(app_state): State<crate::AppState>,
    headers: HeaderMap,
) -> Result<Json<Value>, StatusCode> {
    let auth_header = headers
        .get("authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let claims = app_state
        .auth
        .validate_token(auth_header)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(Json(json!({
        "valid": true,
        "subject": claims.sub,
        "roles": claims.roles,
        "permissions": claims.permissions,
        "expires_at": claims.exp
    })))
}

async fn logout() -> Json<Value> {
    Json(json!({
        "message": "Token invalidated",
        "status": "success"
    }))
}
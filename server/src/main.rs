use axum::{
    response::Json,
    routing::get,
    Router,
};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
};
use tracing::{info, Level};
use tracing_subscriber;

mod auth;
mod policy;
mod routes;
mod services;
mod storage;

use crate::auth::AuthState;

#[derive(Clone)]
pub struct AppState {
    pub auth: AuthState,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .json()
        .init();

    info!("Starting Provenix Server (pxs) with Zero-Trust Security");

    // Initialize authentication state
    let auth_state = AuthState::new().await?;
    
    let app_state = AppState {
        auth: auth_state,
    };

    // Build our application with routes
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1", get(api_info))
        .nest("/api/v1/auth", auth::routes())
        .nest("/api/v1/sbom", routes::sbom::routes())
        .nest("/api/v1/attest", routes::attest::routes())
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CorsLayer::permissive())
        )
        .with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    info!("Server listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "healthy",
        "service": "provenix-server",
        "version": env!("CARGO_PKG_VERSION"),
        "security_model": "zero-trust"
    }))
}

async fn api_info() -> Json<Value> {
    Json(json!({
        "service": "Provenix API Server",
        "version": "v1",
        "description": "Zero-trust software supply chain security platform",
        "endpoints": {
            "auth": "/api/v1/auth",
            "sbom": "/api/v1/sbom", 
            "attestation": "/api/v1/attest"
        }
    }))
}
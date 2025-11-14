use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::time::sleep;

const BASE_URL: &str = "http://localhost:8080";

#[tokio::test]
async fn test_health_endpoint() {
    let client = Client::new();
    
    let response = client
        .get(&format!("{}/health", BASE_URL))
        .send()
        .await
        .expect("Failed to send request");
    
    assert_eq!(response.status(), 200);
    
    let body: Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["status"], "healthy");
    assert_eq!(body["service"], "provenix-server");
    assert_eq!(body["security_model"], "zero-trust");
}

#[tokio::test]
async fn test_api_info_endpoint() {
    let client = Client::new();
    
    let response = client
        .get(&format!("{}/api/v1", BASE_URL))
        .send()
        .await
        .expect("Failed to send request");
    
    assert_eq!(response.status(), 200);
    
    let body: Value = response.json().await.expect("Failed to parse JSON");
    assert_eq!(body["service"], "Provenix API Server");
    assert_eq!(body["version"], "v1");
    assert!(body["endpoints"].is_object());
}

#[tokio::test]
async fn test_authentication_required() {
    let client = Client::new();
    
    // Test without authentication token
    let response = client
        .get(&format!("{}/api/v1/sbom", BASE_URL))
        .send()
        .await
        .expect("Failed to send request");
    
    // Should return 401 Unauthorized
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn test_cors_headers() {
    let client = Client::new();
    
    let response = client
        .options(&format!("{}/api/v1", BASE_URL))
        .header("Origin", "http://localhost:3000")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .expect("Failed to send request");
    
    assert_eq!(response.status(), 200);
    
    let headers = response.headers();
    assert!(headers.contains_key("access-control-allow-origin"));
}

#[tokio::test]
async fn test_server_startup_time() {
    let start = std::time::Instant::now();
    
    let client = Client::new();
    let mut attempts = 0;
    const MAX_ATTEMPTS: u32 = 30; // 30 seconds timeout
    
    loop {
        if attempts >= MAX_ATTEMPTS {
            panic!("Server did not start within 30 seconds");
        }
        
        match client.get(&format!("{}/health", BASE_URL)).send().await {
            Ok(response) if response.status().is_success() => break,
            _ => {
                attempts += 1;
                sleep(Duration::from_secs(1)).await;
            }
        }
    }
    
    let startup_time = start.elapsed();
    assert!(startup_time < Duration::from_secs(30), "Server took too long to start");
}
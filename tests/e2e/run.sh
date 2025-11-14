#!/bin/bash

# E2E Test Runner for Provenix
# Tests the complete workflow from development to deployment

set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[E2E]${NC} $1"
}

error() {
    echo -e "${RED}[E2E ERROR]${NC} $1"
    exit 1
}

warn() {
    echo -e "${YELLOW}[E2E WARN]${NC} $1"
}

# Test configuration
TEST_PROJECT="e2e-test-project"
TEST_VERSION="1.0.0-e2e"
TEMP_DIR=$(mktemp -d)
CLEANUP_ON_EXIT=true

cleanup() {
    if [[ "$CLEANUP_ON_EXIT" == "true" ]]; then
        log "Cleaning up test environment..."
        rm -rf "$TEMP_DIR"
        docker-compose -f infra/docker/compose.yaml down -v 2>/dev/null || true
    fi
}

trap cleanup EXIT

setup_test_environment() {
    log "Setting up E2E test environment..."
    
    # Start infrastructure services
    docker-compose -f infra/docker/compose.yaml up -d
    
    # Wait for services to be ready
    log "Waiting for services to be ready..."
    sleep 30
    
    # Verify services are running
    for service in postgres opa provenix-server; do
        if ! docker-compose -f infra/docker/compose.yaml ps | grep -q "$service.*Up"; then
            error "Service $service is not running"
        fi
    done
    
    log "Test environment ready"
}

test_sbom_generation() {
    log "Testing SBOM generation workflow..."
    
    # Create test project
    mkdir -p "$TEMP_DIR/$TEST_PROJECT"
    cd "$TEMP_DIR/$TEST_PROJECT"
    
    # Initialize a simple Rust project
    cat > Cargo.toml << EOF
[package]
name = "$TEST_PROJECT"
version = "$TEST_VERSION"
edition = "2021"

[dependencies]
serde = "1.0"
EOF
    
    mkdir src
    echo 'fn main() { println!("Hello, world!"); }' > src/main.rs
    
    # Generate SBOM
    ../../target/release/pxb generate \
        --format spdx \
        --output sbom.json \
        --project "$TEST_PROJECT" \
        --version "$TEST_VERSION"
    
    # Verify SBOM was created
    if [[ ! -f "sbom.json" ]]; then
        error "SBOM generation failed"
    fi
    
    # Validate SBOM content
    if ! grep -q "$TEST_PROJECT" sbom.json; then
        error "SBOM does not contain project name"
    fi
    
    if ! grep -q "$TEST_VERSION" sbom.json; then
        error "SBOM does not contain project version"
    fi
    
    log "SBOM generation test passed"
}

test_attestation_workflow() {
    log "Testing attestation workflow..."
    
    cd "$TEMP_DIR/$TEST_PROJECT"
    
    # Generate test signing key
    ../../target/release/pxa keygen \
        --output test-key.pem \
        --algorithm ed25519
    
    # Sign the SBOM
    ../../target/release/pxa sign \
        --input sbom.json \
        --key test-key.pem \
        --output sbom.signed.json
    
    # Verify signature
    ../../target/release/pxa verify \
        --input sbom.signed.json \
        --key test-key.pem
    
    # Verify signed SBOM exists
    if [[ ! -f "sbom.signed.json" ]]; then
        error "SBOM signing failed"
    fi
    
    log "Attestation workflow test passed"
}

test_api_integration() {
    log "Testing API integration..."
    
    cd "$TEMP_DIR/$TEST_PROJECT"
    
    # Test server health
    response=$(curl -s -w "%{http_code}" http://localhost:8080/health -o /dev/null)
    if [[ "$response" != "200" ]]; then
        error "Server health check failed (HTTP $response)"
    fi
    
    # Upload SBOM to server
    upload_response=$(curl -s -w "%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -d @sbom.json \
        http://localhost:8080/api/v1/sbom \
        -o upload_response.json)
    
    if [[ "$upload_response" != "200" ]]; then
        warn "SBOM upload returned HTTP $upload_response (authentication may be required)"
    fi
    
    # Test API endpoints
    api_response=$(curl -s -w "%{http_code}" http://localhost:8080/api/v1 -o /dev/null)
    if [[ "$api_response" != "200" ]]; then
        error "API info endpoint failed (HTTP $api_response)"
    fi
    
    log "API integration test passed"
}

test_cli_integration() {
    log "Testing CLI integration..."
    
    cd "$TEMP_DIR/$TEST_PROJECT"
    
    # Test px command
    if ! ../../target/release/px --version | grep -q "0.1.0"; then
        error "px command version check failed"
    fi
    
    # Test integrated workflow
    ../../target/release/px workflow \
        --generate-sbom \
        --format spdx \
        --sign \
        --key test-key.pem \
        --output workflow-result.json \
        --dry-run
    
    log "CLI integration test passed"
}

test_security_policies() {
    log "Testing security policy enforcement..."
    
    # Test OPA policy evaluation
    policy_response=$(curl -s \
        -X POST \
        -H "Content-Type: application/json" \
        -d '{
            "input": {
                "user": "test@example.com",
                "action": "read",
                "resource": "/api/v1/sbom"
            }
        }' \
        http://localhost:8181/v1/data/provenix/authz/allow)
    
    if [[ -z "$policy_response" ]]; then
        error "OPA policy evaluation failed"
    fi
    
    log "Security policy test passed"
}

test_performance() {
    log "Testing performance characteristics..."
    
    cd "$TEMP_DIR/$TEST_PROJECT"
    
    # Measure SBOM generation time
    start_time=$(date +%s%N)
    ../../target/release/pxb generate \
        --format spdx \
        --output perf-sbom.json \
        --project "perf-test" \
        --version "1.0.0"
    end_time=$(date +%s%N)
    
    generation_time=$((($end_time - $start_time) / 1000000)) # Convert to milliseconds
    
    if [[ $generation_time -gt 5000 ]]; then # 5 seconds threshold
        warn "SBOM generation took ${generation_time}ms (threshold: 5000ms)"
    fi
    
    # Test concurrent operations
    for i in {1..5}; do
        ../../target/release/pxb generate \
            --format spdx \
            --output "concurrent-sbom-$i.json" \
            --project "concurrent-test-$i" \
            --version "1.0.0" &
    done
    
    wait
    
    # Verify all concurrent operations completed
    for i in {1..5}; do
        if [[ ! -f "concurrent-sbom-$i.json" ]]; then
            error "Concurrent SBOM generation failed for iteration $i"
        fi
    done
    
    log "Performance test passed"
}

test_error_handling() {
    log "Testing error handling..."
    
    cd "$TEMP_DIR/$TEST_PROJECT"
    
    # Test invalid input handling
    if ../../target/release/pxb generate --format invalid 2>/dev/null; then
        error "Invalid format should have failed"
    fi
    
    # Test missing file handling
    if ../../target/release/pxa sign --input nonexistent.json --key test-key.pem 2>/dev/null; then
        error "Missing input file should have failed"
    fi
    
    # Test invalid API calls
    error_response=$(curl -s -w "%{http_code}" \
        -X POST \
        -H "Content-Type: application/json" \
        -d '{"invalid": "data"}' \
        http://localhost:8080/api/v1/invalid-endpoint \
        -o /dev/null)
    
    if [[ "$error_response" == "200" ]]; then
        error "Invalid API endpoint should not return 200"
    fi
    
    log "Error handling test passed"
}

main() {
    log "Starting Provenix E2E test suite..."
    
    # Build release versions if not already built
    if [[ ! -f "target/release/px" ]]; then
        log "Building release binaries..."
        cargo build --release
    fi
    
    setup_test_environment
    
    test_sbom_generation
    test_attestation_workflow
    test_api_integration
    test_cli_integration
    test_security_policies
    test_performance
    test_error_handling
    
    log "All E2E tests passed successfully!"
    log "Test artifacts available in: $TEMP_DIR"
    
    # Optionally keep test artifacts for debugging
    if [[ "${KEEP_ARTIFACTS:-false}" == "true" ]]; then
        CLEANUP_ON_EXIT=false
        log "Test artifacts preserved: $TEMP_DIR"
    fi
}

case "${1:-run}" in
    "run")
        main
        ;;
    "setup")
        setup_test_environment
        log "E2E environment setup complete"
        CLEANUP_ON_EXIT=false
        ;;
    "teardown")
        cleanup
        log "E2E environment cleaned up"
        ;;
    *)
        error "Usage: $0 [run|setup|teardown]"
        ;;
esac
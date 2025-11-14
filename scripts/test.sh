#!/bin/bash

# Provenix Test Suite
# Comprehensive testing for zero-trust security model

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
PROJECT_NAME="provenix"
TEST_DB="provenix_test"
TEST_ENV_FILE=".env.test"

log() {
    echo -e "${GREEN}[TEST]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

setup_test_env() {
    log "Setting up test environment..."
    
    # Create test environment file
    cat > $TEST_ENV_FILE << EOF
PROVENIX_ENV=test
PROVENIX__DATABASE__URL=postgresql://provenix:testpassword@localhost:5432/${TEST_DB}
PROVENIX__AUTH__JWT_SECRET=test-secret-key-for-testing-only-32-chars
PROVENIX__SECURITY__OPA_URL=http://localhost:8181
PROVENIX__SECURITY__ENABLE_POLICY_ENFORCEMENT=false
RUST_LOG=debug
EOF

    log "Test environment configured"
}

setup_test_database() {
    log "Setting up test database..."
    
    if ! command -v psql &> /dev/null; then
        warn "PostgreSQL client not found. Skipping database setup."
        warn "Some tests may fail without proper database setup."
        return
    fi
    
    # Create test database
    createdb ${TEST_DB} 2>/dev/null || true
    
    log "Test database ready"
}

run_unit_tests() {
    log "Running unit tests..."
    
    # Set test environment
    export $(cat $TEST_ENV_FILE | xargs)
    
    # Run tests for each crate
    cargo test --workspace --lib
    
    log "Unit tests completed"
}

run_integration_tests() {
    log "Running integration tests..."
    
    export $(cat $TEST_ENV_FILE | xargs)
    
    # Run integration tests
    cargo test --workspace --test '*' --bins
    
    log "Integration tests completed"
}

run_api_tests() {
    if [ ! -d "tests/api" ]; then
        warn "API test directory not found. Skipping API tests."
        return
    fi
    
    log "Running API tests..."
    
    # Start test server in background
    cargo build --bin pxs
    ./target/debug/pxs &
    SERVER_PID=$!
    
    # Wait for server to start
    sleep 5
    
    # Run API tests with Newman/Postman or custom scripts
    if command -v newman &> /dev/null && [ -f "tests/api/provenix.postman_collection.json" ]; then
        newman run tests/api/provenix.postman_collection.json \
               --env-var base_url=http://localhost:8080
    else
        warn "Newman not found or collection missing. Skipping API tests."
    fi
    
    # Stop test server
    kill $SERVER_PID 2>/dev/null || true
    
    log "API tests completed"
}

run_security_tests() {
    log "Running security tests..."
    
    # SAST (Static Application Security Testing)
    if command -v cargo-audit &> /dev/null; then
        cargo audit
    else
        warn "cargo-audit not installed. Install with: cargo install cargo-audit"
    fi
    
    # Check for common security issues
    if command -v semgrep &> /dev/null; then
        semgrep --config=auto .
    else
        warn "semgrep not installed. Install with: pip install semgrep"
    fi
    
    # License compliance
    if command -v cargo-deny &> /dev/null; then
        cargo deny check
    else
        warn "cargo-deny not installed. Install with: cargo install cargo-deny"
    fi
    
    log "Security tests completed"
}

run_performance_tests() {
    log "Running performance tests..."
    
    # Build release version for performance testing
    cargo build --release --bin pxs
    
    # Start server
    ./target/release/pxs &
    SERVER_PID=$!
    sleep 5
    
    # Basic load testing with curl or wrk if available
    if command -v wrk &> /dev/null; then
        info "Running load test with wrk..."
        wrk -t4 -c40 -d10s http://localhost:8080/health
    elif command -v ab &> /dev/null; then
        info "Running load test with Apache Bench..."
        ab -n 1000 -c 10 http://localhost:8080/health
    else
        warn "No load testing tools available (wrk, ab). Skipping performance tests."
    fi
    
    # Stop server
    kill $SERVER_PID 2>/dev/null || true
    
    log "Performance tests completed"
}

run_e2e_tests() {
    if [ ! -d "tests/e2e" ]; then
        warn "E2E test directory not found. Skipping E2E tests."
        return
    fi
    
    log "Running E2E tests..."
    
    # Start full environment with docker-compose
    if command -v docker-compose &> /dev/null; then
        docker-compose -f infra/docker/compose.yaml up -d
        sleep 30  # Wait for services to be ready
        
        # Run E2E tests (could be Cypress, Playwright, or custom scripts)
        if [ -f "tests/e2e/run.sh" ]; then
            ./tests/e2e/run.sh
        else
            warn "No E2E test runner found"
        fi
        
        # Clean up
        docker-compose -f infra/docker/compose.yaml down
    else
        warn "Docker Compose not available. Skipping E2E tests."
    fi
    
    log "E2E tests completed"
}

generate_coverage() {
    log "Generating test coverage report..."
    
    if command -v cargo-tarpaulin &> /dev/null; then
        cargo tarpaulin --workspace --out html --output-dir coverage
        info "Coverage report generated in: coverage/tarpaulin-report.html"
    else
        warn "cargo-tarpaulin not installed. Install with: cargo install cargo-tarpaulin"
    fi
}

cleanup() {
    log "Cleaning up test environment..."
    
    # Remove test files
    rm -f $TEST_ENV_FILE
    
    # Drop test database
    dropdb ${TEST_DB} 2>/dev/null || true
    
    log "Cleanup completed"
}

main() {
    log "Starting Provenix test suite..."
    
    setup_test_env
    setup_test_database
    
    case "${1:-all}" in
        "unit")
            run_unit_tests
            ;;
        "integration")
            run_integration_tests
            ;;
        "api")
            run_api_tests
            ;;
        "security")
            run_security_tests
            ;;
        "performance")
            run_performance_tests
            ;;
        "e2e")
            run_e2e_tests
            ;;
        "coverage")
            generate_coverage
            ;;
        "all")
            run_unit_tests
            run_integration_tests
            run_api_tests
            run_security_tests
            generate_coverage
            ;;
        "ci")
            # CI-specific test suite (without performance/e2e)
            run_unit_tests
            run_integration_tests
            run_security_tests
            ;;
        *)
            error "Unknown test type: $1. Use: unit, integration, api, security, performance, e2e, coverage, all, ci"
            ;;
    esac
    
    cleanup
    
    log "Test suite completed successfully!"
}

# Trap cleanup on script exit
trap cleanup EXIT

main "$@"
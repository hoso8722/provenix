#!/bin/bash

# Provenix Build Script
# Builds all components with proper zero-trust security configurations

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="provenix"
BUILD_DIR="target"
RELEASE_MODE=${RELEASE_MODE:-false}

log() {
    echo -e "${GREEN}[BUILD]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

check_prerequisites() {
    log "Checking prerequisites..."
    
    if ! command -v cargo &> /dev/null; then
        error "Rust/Cargo not found. Please install Rust: https://rustup.rs/"
    fi
    
    if ! command -v docker &> /dev/null; then
        warn "Docker not found. Container builds will be skipped."
    fi
    
    log "Prerequisites check completed"
}

clean_build() {
    log "Cleaning previous build artifacts..."
    cargo clean
    rm -rf ${BUILD_DIR}/release/${PROJECT_NAME}-*
}

build_crates() {
    log "Building Rust crates..."
    
    local cargo_flags=""
    if [ "$RELEASE_MODE" = "true" ]; then
        cargo_flags="--release"
        log "Building in release mode"
    else
        log "Building in debug mode"
    fi
    
    # Build all workspace members
    cargo build ${cargo_flags}
    
    # Build specific binaries
    log "Building CLI tools..."
    cargo build ${cargo_flags} --bin px
    cargo build ${cargo_flags} --bin pxb  
    cargo build ${cargo_flags} --bin pxa
    
    log "Building server..."
    cargo build ${cargo_flags} --bin pxs
    
    log "Rust build completed successfully"
}

run_tests() {
    log "Running tests..."
    cargo test --workspace
    log "Tests completed successfully"
}

security_scan() {
    log "Running security scans..."
    
    # Audit dependencies
    if command -v cargo-audit &> /dev/null; then
        cargo audit
    else
        warn "cargo-audit not installed. Skipping dependency audit."
        warn "Install with: cargo install cargo-audit"
    fi
    
    # Check for vulnerabilities
    if command -v cargo-deny &> /dev/null; then
        cargo deny check
    else
        warn "cargo-deny not installed. Skipping license/vulnerability checks."
        warn "Install with: cargo install cargo-deny"
    fi
    
    log "Security scan completed"
}

build_containers() {
    if ! command -v docker &> /dev/null; then
        warn "Docker not available. Skipping container builds."
        return
    fi
    
    log "Building Docker containers..."
    
    # Build server container
    docker build -f infra/docker/server.Dockerfile -t ${PROJECT_NAME}-server:latest .
    
    # Build CLI container  
    docker build -f infra/docker/cli.Dockerfile -t ${PROJECT_NAME}-cli:latest .
    
    log "Container builds completed"
}

generate_sbom() {
    log "Generating Software Bill of Materials..."
    
    if command -v cargo-cyclonedx &> /dev/null; then
        cargo cyclonedx --format json --output-file sbom.json
        log "SBOM generated: sbom.json"
    else
        warn "cargo-cyclonedx not installed. Skipping SBOM generation."
        warn "Install with: cargo install cargo-cyclonedx"
    fi
}

main() {
    log "Starting Provenix build process..."
    log "Project: ${PROJECT_NAME}"
    log "Release mode: ${RELEASE_MODE}"
    
    check_prerequisites
    
    if [ "${1:-}" = "clean" ]; then
        clean_build
        return
    fi
    
    build_crates
    run_tests
    security_scan
    generate_sbom
    
    if [ "${BUILD_CONTAINERS:-false}" = "true" ]; then
        build_containers
    fi
    
    log "Build process completed successfully!"
    log "Binaries available in: ${BUILD_DIR}/"
    
    if [ "$RELEASE_MODE" = "true" ]; then
        log "Release binaries:"
        ls -la ${BUILD_DIR}/release/px* ${BUILD_DIR}/release/pxs 2>/dev/null || true
    fi
}

# Handle script arguments
case "${1:-}" in
    "clean")
        main clean
        ;;
    "release") 
        RELEASE_MODE=true
        BUILD_CONTAINERS=true
        main
        ;;
    "containers")
        BUILD_CONTAINERS=true
        main
        ;;
    *)
        main
        ;;
esac
#!/bin/bash

# Provenix Release Script
# Handles versioning, building, and releasing with security attestation

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
PROJECT_NAME="provenix"
RELEASE_DIR="release"
REGISTRY=${REGISTRY:-"ghcr.io/your-org"}

log() {
    echo -e "${GREEN}[RELEASE]${NC} $1"
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

check_prerequisites() {
    log "Checking release prerequisites..."
    
    # Check if we're on main/master branch
    current_branch=$(git branch --show-current)
    if [[ "$current_branch" != "main" && "$current_branch" != "master" ]]; then
        error "Release must be performed from main/master branch. Current: $current_branch"
    fi
    
    # Check for uncommitted changes
    if ! git diff --quiet; then
        error "Uncommitted changes detected. Please commit or stash changes before release."
    fi
    
    # Check required tools
    for tool in git cargo docker; do
        if ! command -v $tool &> /dev/null; then
            error "$tool is required for release process"
        fi
    done
    
    log "Prerequisites check passed"
}

get_current_version() {
    grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/'
}

bump_version() {
    local bump_type=$1
    local current_version=$(get_current_version)
    
    log "Current version: $current_version"
    
    # Parse version components
    IFS='.' read -ra VERSION_PARTS <<< "$current_version"
    local major=${VERSION_PARTS[0]}
    local minor=${VERSION_PARTS[1]}
    local patch=${VERSION_PARTS[2]}
    
    # Bump based on type
    case $bump_type in
        "major")
            major=$((major + 1))
            minor=0
            patch=0
            ;;
        "minor")
            minor=$((minor + 1))
            patch=0
            ;;
        "patch")
            patch=$((patch + 1))
            ;;
        *)
            error "Invalid bump type: $bump_type. Use: major, minor, patch"
            ;;
    esac
    
    local new_version="${major}.${minor}.${patch}"
    log "New version: $new_version"
    
    # Update version in workspace Cargo.toml
    sed -i "s/^version = \".*\"/version = \"$new_version\"/" Cargo.toml
    
    # Update version in all crate Cargo.toml files
    find crates/ server/ -name Cargo.toml -exec sed -i "s/^version = \".*\"/version = \"$new_version\"/" {} \;
    
    echo $new_version
}

run_comprehensive_tests() {
    log "Running comprehensive test suite..."
    ./scripts/test.sh ci
    log "All tests passed"
}

build_release() {
    log "Building release artifacts..."
    
    # Clean and build
    cargo clean
    RELEASE_MODE=true BUILD_CONTAINERS=true ./scripts/build.sh
    
    # Create release directory
    mkdir -p $RELEASE_DIR
    
    # Copy binaries
    cp target/release/px* target/release/pxs $RELEASE_DIR/
    
    # Generate checksums
    cd $RELEASE_DIR
    sha256sum * > checksums.sha256
    cd ..
    
    log "Release artifacts built"
}

generate_attestation() {
    local version=$1
    
    log "Generating release attestation..."
    
    # Generate SBOM
    if command -v cargo-cyclonedx &> /dev/null; then
        cargo cyclonedx --format json --output-file $RELEASE_DIR/sbom-${version}.json
    fi
    
    # Generate attestation using in-tree pxa tool
    if [ -f "target/release/pxa" ]; then
        ./target/release/pxa attest \
            --input $RELEASE_DIR/ \
            --output $RELEASE_DIR/attestation-${version}.json \
            --type release
    fi
    
    log "Attestation generated"
}

create_git_tag() {
    local version=$1
    
    log "Creating Git tag..."
    
    # Commit version changes
    git add -A
    git commit -m "Release version $version"
    
    # Create signed tag
    git tag -s "v$version" -m "Release version $version"
    
    log "Git tag v$version created"
}

build_and_push_containers() {
    local version=$1
    
    log "Building and pushing container images..."
    
    # Build containers with version tags
    docker build -f infra/docker/server.Dockerfile -t ${REGISTRY}/${PROJECT_NAME}-server:${version} -t ${REGISTRY}/${PROJECT_NAME}-server:latest .
    docker build -f infra/docker/cli.Dockerfile -t ${REGISTRY}/${PROJECT_NAME}-cli:${version} -t ${REGISTRY}/${PROJECT_NAME}-cli:latest .
    
    # Push to registry
    if [[ "${PUSH_CONTAINERS:-true}" == "true" ]]; then
        docker push ${REGISTRY}/${PROJECT_NAME}-server:${version}
        docker push ${REGISTRY}/${PROJECT_NAME}-server:latest
        docker push ${REGISTRY}/${PROJECT_NAME}-cli:${version}
        docker push ${REGISTRY}/${PROJECT_NAME}-cli:latest
        log "Container images pushed to registry"
    else
        info "Container push skipped (PUSH_CONTAINERS=false)"
    fi
}

create_github_release() {
    local version=$1
    
    if ! command -v gh &> /dev/null; then
        warn "GitHub CLI not found. Please create release manually."
        return
    fi
    
    log "Creating GitHub release..."
    
    # Generate release notes
    local release_notes="Release notes for version $version"
    if [ -f "CHANGELOG.md" ]; then
        # Extract release notes from CHANGELOG
        release_notes=$(sed -n "/## \[${version}\]/,/## \[/p" CHANGELOG.md | head -n -1)
    fi
    
    # Create release
    gh release create "v$version" \
        --title "Release $version" \
        --notes "$release_notes" \
        $RELEASE_DIR/*
    
    log "GitHub release created"
}

publish_crates() {
    local version=$1
    
    log "Publishing crates to crates.io..."
    
    # Publish in dependency order
    cargo publish -p provenix-utils --dry-run
    cargo publish -p provenix-corelib --dry-run
    cargo publish -p provenix-bom --dry-run
    cargo publish -p provenix-attest --dry-run
    cargo publish -p provenix-cli --dry-run
    cargo publish -p provenix-server --dry-run
    
    if [[ "${DRY_RUN:-true}" != "true" ]]; then
        read -p "Proceed with actual publish? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            cargo publish -p provenix-utils
            cargo publish -p provenix-corelib
            cargo publish -p provenix-bom
            cargo publish -p provenix-attest
            cargo publish -p provenix-cli
            cargo publish -p provenix-server
            log "Crates published to crates.io"
        fi
    else
        info "Dry run mode - crates not published"
    fi
}

main() {
    local bump_type=${1:-patch}
    
    log "Starting release process..."
    log "Bump type: $bump_type"
    
    check_prerequisites
    
    # Bump version
    local new_version=$(bump_version $bump_type)
    
    # Run tests
    run_comprehensive_tests
    
    # Build release
    build_release
    
    # Generate security attestation
    generate_attestation $new_version
    
    # Create git tag
    create_git_tag $new_version
    
    # Build and push containers
    build_and_push_containers $new_version
    
    # Create GitHub release
    create_github_release $new_version
    
    # Publish to crates.io
    if [[ "${PUBLISH_CRATES:-false}" == "true" ]]; then
        publish_crates $new_version
    fi
    
    log "Release $new_version completed successfully!"
    info "Next steps:"
    info "  - Push the tag: git push origin v$new_version"
    info "  - Push the commits: git push origin main"
    info "  - Verify the release: https://github.com/your-org/${PROJECT_NAME}/releases/tag/v$new_version"
}

# Handle dry run
if [[ "${DRY_RUN:-false}" == "true" ]]; then
    warn "DRY RUN MODE - No actual changes will be made"
fi

case "${1:-patch}" in
    "major"|"minor"|"patch")
        main "$1"
        ;;
    "--help"|"-h")
        echo "Usage: $0 [major|minor|patch]"
        echo ""
        echo "Environment variables:"
        echo "  DRY_RUN=true          - Run without making changes"
        echo "  PUSH_CONTAINERS=false - Skip container push"
        echo "  PUBLISH_CRATES=true   - Publish to crates.io"
        echo "  REGISTRY=...          - Container registry"
        ;;
    *)
        error "Invalid argument: $1. Use: major, minor, patch, or --help"
        ;;
esac
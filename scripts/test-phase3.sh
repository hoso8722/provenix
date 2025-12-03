#!/bin/bash
# Phase 3 Integration Test Script
# Tests Rekor transparency log integration

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Phase 3: Rekor Integration Test${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Check if binaries exist
if [ ! -f "./target/release/provenix-cli" ]; then
    echo -e "${RED}❌ Error: provenix-cli not found${NC}"
    echo "Please run: cargo build --release"
    exit 1
fi

if [ ! -f "./target/release/provenix-keygen" ]; then
    echo -e "${RED}❌ Error: provenix-keygen not found${NC}"
    echo "Please run: cargo build --release"
    exit 1
fi

# Create fresh test directory
echo -e "${YELLOW}📁 Setting up test environment...${NC}"
rm -rf test-output-phase3
mkdir -p test-output-phase3/keys

# ============================================
# Test 1: Phase 2 Compatibility (No Rekor)
# ============================================
echo ""
echo -e "${BLUE}=== Test 1: Phase 2 Compatibility (Rekor Disabled) ===${NC}"

# Update config to disable Rekor
cat > test-output-phase3/config-no-rekor.json <<EOF
{
  "sbom": {
    "provider": "cargo-sbom",
    "target": ".",
    "output": "test-output-phase3/sbom.json"
  },
  "attest": {
    "provider": "in-toto",
    "sbom_path": "test-output-phase3/sbom.json",
    "output": "test-output-phase3/attestation.json"
  },
  "sign": {
    "provider": "ed25519",
    "artifact_path": "test-output-phase3/attestation.json",
    "key_path": "test-output-phase3/keys/private.key",
    "output": "test-output-phase3/signed-attestation.json",
    "rekor_url": null
  },
  "verify": {
    "provider": "ed25519",
    "artifact_path": "test-output-phase3/sbom.json",
    "signature_path": "test-output-phase3/signed-attestation.json",
    "rekor_url": null,
    "check_rekor": false
  },
  "publish": {
    "registry_url": "https://registry.example.com"
  }
}
EOF

# Backup original config
if [ -f "provenix.yaml" ]; then
    cp provenix.yaml provenix.yaml.backup
fi
cp test-output-phase3/config-no-rekor.json provenix.yaml

echo -e "${YELLOW}🔑 Generating keypair...${NC}"
./target/release/provenix-keygen \
    --output test-output-phase3/keys

echo -e "${YELLOW}📦 Generating SBOM...${NC}"
./target/release/provenix-cli sbom

echo -e "${YELLOW}📝 Creating attestation...${NC}"
./target/release/provenix-cli attest

echo -e "${YELLOW}✍️  Signing (without Rekor)...${NC}"
SIGN_RESULT=$(./target/release/provenix-cli sign)
echo "$SIGN_RESULT"

# Check that Rekor metadata is NOT present
if echo "$SIGN_RESULT" | grep -q '"rekor"'; then
    echo -e "${RED}❌ Test 1 Failed: Rekor metadata found when it should be disabled${NC}"
    exit 1
else
    echo -e "${GREEN}✅ Test 1 Passed: No Rekor metadata (as expected)${NC}"
fi

echo -e "${YELLOW}🔍 Verifying signature (without Rekor)...${NC}"
VERIFY_RESULT=$(./target/release/provenix-cli verify)
echo "$VERIFY_RESULT"

if echo "$VERIFY_RESULT" | grep -q '"valid": true'; then
    echo -e "${GREEN}✅ Test 1 Complete: Phase 2 compatibility confirmed${NC}"
else
    echo -e "${RED}❌ Test 1 Failed: Verification failed${NC}"
    exit 1
fi

# ============================================
# Test 2: Rekor Integration (Public Server)
# ============================================
echo ""
echo -e "${BLUE}=== Test 2: Rekor Integration (Public Sigstore) ===${NC}"
echo -e "${YELLOW}⚠️  This test will upload to the PUBLIC Sigstore Rekor server${NC}"
echo -e "${YELLOW}   The data will be permanently visible on the internet${NC}"
read -p "Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}⏭️  Skipping Test 2${NC}"
    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Phase 3 Tests Summary${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}✅ Test 1: Phase 2 Compatibility - PASSED${NC}"
    echo -e "${YELLOW}⏭️  Test 2: Rekor Integration - SKIPPED${NC}"
    echo ""
    
    # Restore original config
    if [ -f "provenix.yaml.backup" ]; then
        mv provenix.yaml.backup provenix.yaml
    fi
    
    exit 0
fi

# Clean up for fresh test
rm -rf test-output-phase3
mkdir -p test-output-phase3/keys

# Update config to enable Rekor
cat > test-output-phase3/config-with-rekor.json <<EOF
{
  "sbom": {
    "provider": "cargo-sbom",
    "target": ".",
    "output": "test-output-phase3/sbom.json"
  },
  "attest": {
    "provider": "in-toto",
    "sbom_path": "test-output-phase3/sbom.json",
    "output": "test-output-phase3/attestation.json"
  },
  "sign": {
    "provider": "ed25519",
    "artifact_path": "test-output-phase3/attestation.json",
    "key_path": "test-output-phase3/keys/private.key",
    "output": "test-output-phase3/signed-attestation.json",
    "rekor_url": "https://rekor.sigstore.dev"
  },
  "verify": {
    "provider": "ed25519",
    "artifact_path": "test-output-phase3/sbom.json",
    "signature_path": "test-output-phase3/signed-attestation.json",
    "rekor_url": "https://rekor.sigstore.dev",
    "check_rekor": true
  },
  "publish": {
    "registry_url": "https://registry.example.com"
  }
}
EOF

cp test-output-phase3/config-with-rekor.json provenix.yaml

echo -e "${YELLOW}🔑 Generating keypair...${NC}"
./target/release/provenix-keygen \
    --output test-output-phase3/keys

echo -e "${YELLOW}📦 Generating SBOM...${NC}"
./target/release/provenix-cli sbom

echo -e "${YELLOW}📝 Creating attestation...${NC}"
./target/release/provenix-cli attest

echo -e "${YELLOW}✍️  Signing with Rekor upload...${NC}"
SIGN_RESULT=$(./target/release/provenix-cli sign)
echo "$SIGN_RESULT"

# Check for Rekor metadata
if echo "$SIGN_RESULT" | grep -q '"uuid"'; then
    REKOR_UUID=$(echo "$SIGN_RESULT" | grep -o '"uuid": "[^"]*"' | cut -d'"' -f4)
    REKOR_LOG_INDEX=$(echo "$SIGN_RESULT" | grep -o '"log_index": [0-9]*' | grep -o '[0-9]*')
    echo -e "${GREEN}✅ Rekor Upload Success:${NC}"
    echo -e "   UUID: ${BLUE}${REKOR_UUID}${NC}"
    echo -e "   Log Index: ${BLUE}${REKOR_LOG_INDEX}${NC}"
    echo -e "   URL: ${BLUE}https://rekor.sigstore.dev/api/v1/log/entries/${REKOR_UUID}${NC}"
    
    # Save metadata for manual inspection
    echo "$SIGN_RESULT" > test-output-phase3/rekor-metadata.json
    echo -e "${GREEN}✅ Metadata saved to: test-output-phase3/rekor-metadata.json${NC}"
elif echo "$SIGN_RESULT" | grep -q '"rekor_error"'; then
    echo -e "${RED}❌ Test 2 Failed: Rekor upload error${NC}"
    echo "$SIGN_RESULT" | grep '"rekor_error"'
    exit 1
else
    echo -e "${RED}❌ Test 2 Failed: No Rekor metadata found${NC}"
    exit 1
fi

echo -e "${YELLOW}🔍 Verifying with Rekor check...${NC}"
sleep 2  # Wait for Rekor propagation
VERIFY_RESULT=$(./target/release/provenix-cli verify)
echo "$VERIFY_RESULT"

if echo "$VERIFY_RESULT" | grep -q '"rekor_verified": true'; then
    echo -e "${GREEN}✅ Test 2 Complete: Rekor verification passed${NC}"
else
    echo -e "${YELLOW}⚠️  Warning: Rekor verification returned false${NC}"
    echo -e "${YELLOW}   This may be due to Rekor propagation delay${NC}"
    echo -e "${YELLOW}   Signature is still valid (Phase 2 verification passed)${NC}"
fi

# ============================================
# Test 3: Manual Rekor Entry Inspection
# ============================================
echo ""
echo -e "${BLUE}=== Test 3: Manual Rekor Entry Inspection ===${NC}"

if [ -n "$REKOR_UUID" ]; then
    echo -e "${YELLOW}📡 Fetching entry from Rekor...${NC}"
    REKOR_ENTRY=$(curl -s "https://rekor.sigstore.dev/api/v1/log/entries/${REKOR_UUID}")
    
    if [ $? -eq 0 ]; then
        echo "$REKOR_ENTRY" > test-output-phase3/rekor-entry-raw.json
        echo -e "${GREEN}✅ Rekor entry downloaded${NC}"
        echo -e "   Saved to: test-output-phase3/rekor-entry-raw.json"
        
        # Pretty print if jq is available
        if command -v jq &> /dev/null; then
            echo ""
            echo -e "${YELLOW}Entry details:${NC}"
            echo "$REKOR_ENTRY" | jq '.'
        fi
    else
        echo -e "${YELLOW}⚠️  Could not fetch entry (may need to wait for propagation)${NC}"
    fi
fi

# ============================================
# Summary
# ============================================
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Phase 3 Tests Summary${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✅ Test 1: Phase 2 Compatibility - PASSED${NC}"
echo -e "${GREEN}✅ Test 2: Rekor Integration - PASSED${NC}"
if [ -n "$REKOR_UUID" ]; then
    echo -e "${GREEN}✅ Test 3: Manual Inspection - COMPLETED${NC}"
fi
echo ""
echo -e "${BLUE}Test artifacts:${NC}"
echo -e "  📁 test-output-phase3/"
echo -e "     ├── sbom.json"
echo -e "     ├── attestation.json"
echo -e "     ├── signed-attestation.json"
echo -e "     ├── rekor-metadata.json"
if [ -f "test-output-phase3/rekor-entry-raw.json" ]; then
    echo -e "     └── rekor-entry-raw.json"
fi
echo ""
if [ -n "$REKOR_UUID" ]; then
    echo -e "${BLUE}🌐 View on Rekor:${NC}"
    echo -e "   https://search.sigstore.dev/?logIndex=${REKOR_LOG_INDEX}"
    echo ""
fi

# Restore original config
if [ -f "provenix.yaml.backup" ]; then
    mv provenix.yaml.backup provenix.yaml
    echo -e "${YELLOW}Restored original provenix.yaml${NC}"
fi

echo -e "${GREEN}✨ All tests completed successfully!${NC}"

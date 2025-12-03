#!/bin/bash
# Quick Test: Phase 2 互換性テスト（Rekorなし）
# Dockerや外部サービス不要で即座にテスト可能

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  Quick Test: Phase 2 Compatibility${NC}"
echo -e "${BLUE}  (No Rekor, No Internet Required)${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Clean test directory
echo -e "${YELLOW}🧹 Cleaning test directory...${NC}"
rm -rf test-output-quick
mkdir -p test-output-quick/keys

# Create config (Rekor disabled)
cat > provenix-quick.yaml <<EOF
{
  "sbom": {
    "provider": "cargo-sbom",
    "target": ".",
    "output": "test-output-quick/sbom.json"
  },
  "attest": {
    "provider": "in-toto",
    "sbom_path": "test-output-quick/sbom.json",
    "output": "test-output-quick/attestation.json"
  },
  "sign": {
    "provider": "ed25519",
    "artifact_path": "test-output-quick/attestation.json",
    "key_path": "test-output-quick/keys/private.key",
    "output": "test-output-quick/signed-attestation.json",
    "rekor_url": null
  },
  "verify": {
    "provider": "ed25519",
    "artifact_path": "test-output-quick/sbom.json",
    "signature_path": "test-output-quick/signed-attestation.json",
    "rekor_url": null,
    "check_rekor": false
  },
  "publish": {
    "registry_url": "https://registry.example.com"
  }
}
EOF

# Backup and use test config
if [ -f "provenix.yaml" ]; then
    cp provenix.yaml provenix.yaml.backup-quick
fi
cp provenix-quick.yaml provenix.yaml

echo -e "${YELLOW}🔑 Step 1/5: Generating keypair...${NC}"
./target/release/provenix-keygen \
    --output test-output-quick/keys
echo -e "${GREEN}✅ Keypair generated${NC}"

echo ""
echo -e "${YELLOW}📦 Step 2/5: Generating SBOM...${NC}"
./target/release/provenix-cli sbom
SBOM_SIZE=$(wc -c < test-output-quick/sbom.json | tr -d ' ')
echo -e "${GREEN}✅ SBOM generated (${SBOM_SIZE} bytes)${NC}"

echo ""
echo -e "${YELLOW}📝 Step 3/5: Creating attestation...${NC}"
./target/release/provenix-cli attest
ATTEST_SIZE=$(wc -c < test-output-quick/attestation.json | tr -d ' ')
echo -e "${GREEN}✅ Attestation created (${ATTEST_SIZE} bytes)${NC}"

echo ""
echo -e "${YELLOW}✍️  Step 4/5: Signing...${NC}"
SIGN_OUTPUT=$(./target/release/provenix-cli sign)
echo "$SIGN_OUTPUT"

# Verify no Rekor metadata
if echo "$SIGN_OUTPUT" | grep -q '"rekor"'; then
    echo -e "${YELLOW}⚠️  Warning: Rekor metadata found (should be null)${NC}"
fi

SIGNED_SIZE=$(wc -c < test-output-quick/signed-attestation.json | tr -d ' ')
echo -e "${GREEN}✅ Signed (${SIGNED_SIZE} bytes)${NC}"

echo ""
echo -e "${YELLOW}🔍 Step 5/5: Verifying...${NC}"
VERIFY_LOG=$(RUST_LOG=info ./target/release/provenix-cli verify 2>&1)
if echo "$VERIFY_LOG" | grep -q "Verification successful"; then
    echo -e "${GREEN}✅ Verification PASSED${NC}"
else
    echo -e "\033[0;31m❌ Verification FAILED${NC}"
    echo "$VERIFY_LOG"
    exit 1
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  ✨ Quick Test: SUCCESS${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${BLUE}Results:${NC}"
echo -e "  📦 SBOM: ${SBOM_SIZE} bytes"
echo -e "  📝 Attestation: ${ATTEST_SIZE} bytes"
echo -e "  ✍️  Signature: ${SIGNED_SIZE} bytes"
echo ""
echo -e "${BLUE}Files:${NC}"
echo -e "  test-output-quick/"
echo -e "  ├── keys/"
echo -e "  │   ├── private.key"
echo -e "  │   └── public.key"
echo -e "  ├── sbom.json"
echo -e "  ├── attestation.json"
echo -e "  └── signed-attestation.json"
echo ""

# Restore config
if [ -f "provenix.yaml.backup-quick" ]; then
    mv provenix.yaml.backup-quick provenix.yaml
fi
rm -f provenix-quick.yaml

echo -e "${GREEN}Phase 3 implementation is backward compatible! ✅${NC}"

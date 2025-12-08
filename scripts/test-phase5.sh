#!/bin/bash
# Phase 5: Cosign Format Compatibility Test

set -e

echo "========================================"
echo "  Phase 5: Cosign Format Test"
echo "========================================"
echo ""

OUTPUT_DIR="test-output-cosign"

# Clean up
echo "🧹 Cleaning test directory..."
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/keys"

# Step 1: Generate keypair
echo "🔑 Step 1/6: Generating keypair..."
cargo run --bin provenix-keygen -- -o "$OUTPUT_DIR/keys" > /dev/null 2>&1
echo "✅ Keypair generated"

# Step 2: Generate SBOM
echo "📦 Step 2/6: Generating SBOM..."
cargo run --bin provenix-cli -- sbom > /dev/null 2>&1
cp test-output-quick/sbom.json "$OUTPUT_DIR/sbom.json"
echo "✅ SBOM generated"

# Step 3: Create attestation
echo "📝 Step 3/6: Creating attestation..."
cargo run --bin provenix-cli -- attest > /dev/null 2>&1
cp test-output-quick/attestation.json "$OUTPUT_DIR/attestation.json"
echo "✅ Attestation created"

# Step 4: Update config for Cosign format signing
echo "✍️  Step 4/6: Signing with Cosign format..."
cat > provenix-cosign.yaml <<EOF
{
  "sbom": {
    "provider": "cargo-sbom",
    "target": ".",
    "output": "$OUTPUT_DIR/sbom.json"
  },
  "attest": {
    "provider": "in-toto",
    "sbom_path": "$OUTPUT_DIR/sbom.json",
    "output": "$OUTPUT_DIR/attestation.json"
  },
  "sign": {
    "provider": "ed25519",
    "artifact_path": "$OUTPUT_DIR/attestation.json",
    "key_path": "$OUTPUT_DIR/keys/private.key",
    "output": "$OUTPUT_DIR/signed-attestation.cosign",
    "format": "cosign",
    "rekor_url": null
  },
  "verify": {
    "provider": "ed25519",
    "artifact_path": "$OUTPUT_DIR/sbom.json",
    "signature_path": "$OUTPUT_DIR/signed-attestation.cosign",
    "format": "cosign",
    "rekor_url": null,
    "check_rekor": false
  },
  "publish": {
    "registry_url": "https://registry.example.com"
  }
}
EOF

# Sign with Cosign format
PROVENIX_CONFIG=provenix-cosign.yaml cargo run --bin provenix-cli -- sign > /dev/null 2>&1
if [ ! -f "$OUTPUT_DIR/signed-attestation.cosign" ]; then
    echo "❌ Cosign format signature not created"
    exit 1
fi
echo "✅ Signed with Cosign format ($(wc -c < $OUTPUT_DIR/signed-attestation.cosign) bytes)"

# Step 5: Verify Cosign format signature structure
echo "🔍 Step 5/6: Verifying Cosign format structure..."
if ! grep -q '"critical"' "$OUTPUT_DIR/signed-attestation.cosign"; then
    echo "❌ Missing 'critical' section in Cosign signature"
    exit 1
fi
if ! grep -q '"optional"' "$OUTPUT_DIR/signed-attestation.cosign"; then
    echo "❌ Missing 'optional' section in Cosign signature"
    exit 1
fi
if ! grep -q '"type": "cosign container image signature"' "$OUTPUT_DIR/signed-attestation.cosign"; then
    echo "❌ Incorrect signature type"
    exit 1
fi
echo "✅ Cosign format structure verified"

# Step 6: Verify with auto-detection
echo "🔍 Step 6/6: Verifying with auto-detection..."
cat > provenix-verify-auto.yaml <<EOF
{
  "sbom": {
    "provider": "cargo-sbom",
    "target": ".",
    "output": "$OUTPUT_DIR/sbom.json"
  },
  "attest": {
    "provider": "in-toto",
    "sbom_path": "$OUTPUT_DIR/sbom.json",
    "output": "$OUTPUT_DIR/attestation.json"
  },
  "sign": {
    "provider": "ed25519",
    "artifact_path": "$OUTPUT_DIR/attestation.json",
    "key_path": "$OUTPUT_DIR/keys/private.key",
    "output": "$OUTPUT_DIR/signed-attestation.cosign",
    "format": "cosign",
    "rekor_url": null
  },
  "verify": {
    "provider": "ed25519",
    "artifact_path": "$OUTPUT_DIR/sbom.json",
    "signature_path": "$OUTPUT_DIR/signed-attestation.cosign",
    "format": "auto",
    "rekor_url": null,
    "check_rekor": false
  },
  "publish": {
    "registry_url": "https://registry.example.com"
  }
}
EOF

PROVENIX_CONFIG=provenix-verify-auto.yaml cargo run --bin provenix-cli -- verify > /dev/null 2>&1
echo "✅ Auto-detection and verification PASSED"

# Clean up temporary configs
rm -f provenix-cosign.yaml provenix-verify-auto.yaml

echo ""
echo "========================================"
echo "  ✨ Phase 5 Test: SUCCESS"
echo "========================================"
echo ""
echo "Results:"
echo "  📦 SBOM: $(wc -c < $OUTPUT_DIR/sbom.json) bytes"
echo "  📝 Attestation: $(wc -c < $OUTPUT_DIR/attestation.json) bytes"
echo "  ✍️  Cosign Signature: $(wc -c < $OUTPUT_DIR/signed-attestation.cosign) bytes"
echo ""
echo "Files:"
echo "  $OUTPUT_DIR/"
echo "  ├── keys/"
echo "  │   ├── private.key"
echo "  │   └── public.key"
echo "  ├── sbom.json"
echo "  ├── attestation.json"
echo "  └── signed-attestation.cosign"
echo ""
echo "✅ Cosign format compatibility verified!"
echo ""

# Display sample of Cosign signature
echo "📋 Cosign Signature Sample:"
head -20 "$OUTPUT_DIR/signed-attestation.cosign"
echo ""

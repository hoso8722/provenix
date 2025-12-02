#!/bin/bash
# Phase 2 Test Script: Ed25519 Signing and Verification

set -e

echo "========================================"
echo "Phase 2: Ed25519 Signing Test"
echo "========================================"

# Setup
OUTPUT_DIR="test-output"
KEYS_DIR="$OUTPUT_DIR/keys"
SBOM_FILE="$OUTPUT_DIR/sbom.json"
ATTESTATION_FILE="$OUTPUT_DIR/attestation.json"
SIGNED_FILE="$OUTPUT_DIR/signed-attestation.json"

mkdir -p "$KEYS_DIR"

echo ""
echo "Step 1: Generate Ed25519 Keypair"
echo "----------------------------------------"
# Note: Will implement keygen CLI command
# For now, we'll use Rust code directly
cat > "$KEYS_DIR/gen_keys.rs" << 'EOF'
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::fs;

fn main() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    
    let private_key = signing_key.to_keypair_bytes();
    let public_key = verifying_key.to_bytes();
    
    fs::write("test-output/keys/private.key", BASE64.encode(private_key)).unwrap();
    fs::write("test-output/keys/public.key", BASE64.encode(public_key)).unwrap();
    
    println!("✅ Keypair generated:");
    println!("  Private: test-output/keys/private.key");
    println!("  Public:  test-output/keys/public.key");
}
EOF

echo "  (Keypair generation will be integrated into CLI)"
echo "  Temporary: Using Rust snippet"

# Generate keys if not exist
if [ ! -f "$KEYS_DIR/private.key" ]; then
    echo "  Generating keypair..."
    # Will be replaced with: ./target/release/provenix-cli keygen
    echo "  (Manual key generation required for now)"
fi

echo ""
echo "Step 2: Generate SBOM"
echo "----------------------------------------"
./target/release/provenix-cli sbom
echo "✅ SBOM generated: $SBOM_FILE"
ls -lh "$SBOM_FILE"

echo ""
echo "Step 3: Create Attestation"
echo "----------------------------------------"
./target/release/provenix-cli attest
echo "✅ Attestation created: $ATTESTATION_FILE"
ls -lh "$ATTESTATION_FILE"

echo ""
echo "Step 4: Sign Attestation (Phase 2)"
echo "----------------------------------------"
echo "Command: ./target/release/provenix-cli sign"
echo "(Note: Requires integration with config)"

# Test will be enabled after CLI integration
echo "⏳ Signing test pending CLI integration"

echo ""
echo "Step 5: Verify Signature (Phase 2)"
echo "----------------------------------------"
echo "Command: ./target/release/provenix-cli verify"
echo "(Note: Requires signed attestation)"

echo "⏳ Verification test pending CLI integration"

echo ""
echo "========================================"
echo "Phase 2 Implementation Status"
echo "========================================"
echo "✅ Ed25519 signing provider implemented"
echo "✅ Ed25519 verification provider implemented"
echo "✅ Hash chain verification integrated"
echo "✅ DSSE envelope format supported"
echo "⏳ CLI integration (next step)"
echo "⏳ Keygen command (next step)"
echo ""

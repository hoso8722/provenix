# Security Implementation Plan for Provenix

## Overview

This document outlines security risks in the software supply chain attestation process and provides implementation priorities for Provenix to mitigate these risks.

---

## Current Process Flow

```
1. SBOM Generation
   cargo-sbom → sbom.json (local file)

2. Attestation Creation
   InTotoProvider::attest(sbom.json) → attestation.json (local file)

3. Signing
   SignProvider::sign(attestation.json) → signature.sig (local file)

4. Verification
   VerifyProvider::verify(attestation.json, signature.sig)
```

---

## Security Risk Analysis

### Risk 1: Local File Tampering 🔴 **CRITICAL**

**Attack Scenario:**

```
1. User generates SBOM → sbom.json
2. Attacker modifies sbom.json (hides malicious dependencies)
3. User attests the tampered sbom.json
4. Signature is created for the tampered file
→ Result: Tampered SBOM is legitimately signed
```

**Concrete Example:**

```bash
# Generate SBOM (contains malware-lib)
provenix sbom  # → sbom.json

# Attacker intervenes (removes malware-lib from file)
# Edit sbom.json...

# Sign tampered file
provenix attest  # → attests tampered sbom.json
provenix sign    # → signs tampered attestation
```

**Risk Level:** 🔴 **CRITICAL**

- **Timing:** Between SBOM generation and Attestation creation
- **Impact:** Entire supply chain trust is compromised

---

### Risk 2: Private Key Management 🔴 **CRITICAL**

**Attack Scenario:**

```
1. Private key stored in local filesystem
2. Malware or attacker steals key file
3. Attacker can sign arbitrary files
```

**Current Implementation Issue:**

```rust
// Key path in config file
{
  "sign": {
    "key_path": "key.pem"  // ← Local file
  }
}
```

**Risk Level:** 🔴 **CRITICAL**

---

### Risk 3: Insufficient Attestation Content Validation 🟡 **MEDIUM**

**Attack Scenario:**

```
1. Attestation doesn't include SBOM hash
2. Same attestation can be used after SBOM changes
3. Unclear which SBOM this attestation is for
```

**Current Implementation:**

```rust
// TODO state - no hash verification
fn attest(&self, sbom: &PathBuf, ...) {
    // Not computing SBOM hash
    // Not embedding in attestation
}
```

**Risk Level:** 🟡 **MEDIUM to HIGH**

---

### Risk 4: Missing Timestamps 🟡 **MEDIUM**

**Attack Scenario:**

```
1. Vulnerability discovered
2. Attacker forges attestation with past date
3. Claims "created before vulnerability was known"
```

**Risk Level:** 🟡 **MEDIUM**

---

### Risk 5: Chain Discontinuity 🟡 **MEDIUM**

**Attack Scenario:**

```
SBOM → Attestation → Signature steps are independent
→ Any step can be replaced
```

```bash
# Legitimate flow
sbom-v1.json → attestation-v1.json → signature-v1.sig

# Attacker intervention
sbom-v2.json (tampered) + attestation-v1.json + signature-v1.sig
→ sbom-v2 may be used during verification
```

**Risk Level:** 🟡 **MEDIUM**

---

## Mitigation Strategies

### Strategy 1: In-Memory Chain ✅ **Recommended**

```rust
// Complete in memory without writing to files
pub fn generate_and_attest_and_sign() -> Result<SignedAttestation> {
    // 1. Generate SBOM (in memory)
    let sbom = generate_sbom_in_memory()?;
    let sbom_hash = hash(&sbom);

    // 2. Create Attestation (includes SBOM hash)
    let attestation = create_attestation(&sbom, sbom_hash)?;
    let attestation_hash = hash(&attestation);

    // 3. Sign (against attestation hash)
    let signature = sign(&attestation_hash, key)?;

    // 4. Save all atomically
    save_all_atomically(sbom, attestation, signature)?;

    Ok(SignedAttestation { sbom, attestation, signature })
}
```

**Benefits:**

- Reduces opportunities for file tampering
- Guarantees hash chain integrity

---

### Strategy 2: Embed SBOM Hash ✅ **Required**

```rust
// Attestation must always include SBOM hash
{
  "subject": [{
    "name": "sbom.json",
    "digest": {
      "sha256": "abc123..."  // ← Actual SBOM hash
    }
  }],
  "predicate": {
    "materials": [{
      "uri": "file://sbom.json",
      "digest": {
        "sha256": "abc123..."  // ← Same hash
      }
    }]
  }
}
```

**During Verification:**

```rust
// 1. Read SBOM from file
let sbom = read_file("sbom.json")?;
let actual_hash = compute_hash(&sbom);

// 2. Get expected hash from attestation
let expected_hash = attestation.subject[0].digest.sha256;

// 3. Compare
if actual_hash != expected_hash {
    bail!("SBOM has been tampered!");
}
```

---

### Strategy 3: Improved Key Management ✅ **Recommended**

#### **Option A: Hardware Security Module (HSM)**

```rust
// Use hardware token like YubiKey
use yubikey::YubiKey;

pub fn sign_with_yubikey(data: &[u8]) -> Result<Signature> {
    let yubikey = YubiKey::open()?;
    yubikey.sign_with_pin(data, "123456")
}
```

#### **Option B: System Keychain**

```rust
// macOS Keychain, Windows Credential Manager, etc.
#[cfg(target_os = "macos")]
pub fn get_key_from_keychain() -> Result<SecretKey> {
    // Retrieve via Security Framework
}
```

#### **Option C: Ephemeral Key + Remote Signing**

```rust
// Generate locally, destroy immediately
pub fn sign_with_ephemeral_key(data: &[u8]) -> Result<SignedData> {
    let (private_key, public_key) = generate_keypair();
    let signature = sign(data, &private_key);

    // Destroy private key immediately
    drop(private_key);

    // Submit to trusted service
    submit_to_transparency_log(public_key, data, signature)?;

    Ok(SignedData { signature, public_key })
}
```

---

### Strategy 4: Timestamp Service ✅ **Recommended**

```rust
// RFC3161 compliant timestamp
pub fn add_timestamp(signature: &Signature) -> Result<TimestampedSignature> {
    let tsa_url = "http://timestamp.digicert.com";
    let response = reqwest::blocking::Client::new()
        .post(tsa_url)
        .body(signature.as_bytes())
        .send()?;

    let timestamp = parse_tsa_response(response)?;

    Ok(TimestampedSignature {
        signature: signature.clone(),
        timestamp,
        tsa_cert: timestamp.signer_cert,
    })
}
```

---

### Strategy 5: Transparency Log (Rekor) ✅ **Best Practice**

```rust
// Record in Sigstore Rekor
pub fn publish_to_rekor(attestation: &Attestation, signature: &Signature) -> Result<RekorEntry> {
    let client = RekorClient::new("https://rekor.sigstore.dev");

    let entry = client.create_entry(json!({
        "kind": "intoto",
        "apiVersion": "0.0.1",
        "spec": {
            "content": {
                "envelope": attestation,
                "signature": signature,
            }
        }
    }))?;

    // Get immutable log index from Rekor
    log::info!("Published to Rekor: index={}, uuid={}",
               entry.log_index, entry.uuid);

    Ok(entry)
}
```

**Benefits:**

- **Immutable**: Once recorded, cannot be changed
- **Auditable**: Anyone can verify the log
- **Chronological proof**: Entry order is guaranteed

---

### Strategy 6: File Integrity Verification ✅ **Implementation Required**

```rust
// Verify all file integrity during verification
pub fn verify_chain(
    sbom_path: &Path,
    attestation_path: &Path,
    signature_path: &Path,
) -> Result<()> {
    // 1. Read files
    let sbom = fs::read(sbom_path)?;
    let attestation: Attestation = serde_json::from_slice(&fs::read(attestation_path)?)?;
    let signature = fs::read(signature_path)?;

    // 2. Verify SBOM hash
    let sbom_hash = compute_sha256(&sbom);
    if sbom_hash != attestation.subject[0].digest.sha256 {
        bail!("SBOM hash mismatch! File has been tampered.");
    }

    // 3. Verify attestation signature
    let attestation_bytes = serde_json::to_vec(&attestation)?;
    let attestation_hash = compute_sha256(&attestation_bytes);
    verify_signature(&attestation_hash, &signature, &public_key)?;

    // 4. Verify Rekor log (optional)
    if let Some(rekor_uuid) = attestation.metadata.rekor_uuid {
        verify_rekor_entry(&rekor_uuid, &attestation)?;
    }

    Ok(())
}
```

---

## Risk Matrix

| Risk                     | Severity    | Without Mitigation         | With Mitigation      | Recommended Strategy             |
| ------------------------ | ----------- | -------------------------- | -------------------- | -------------------------------- |
| **Local File Tampering** | 🔴 CRITICAL | Easy to tamper             | Detectable           | Hash embedding + In-memory chain |
| **Private Key Leak**     | 🔴 CRITICAL | Signature forgery possible | Impact limited       | HSM/Keychain + Ephemeral keys    |
| **Hash Mismatch**        | 🟡 MEDIUM   | Undetectable               | Immediately detected | SHA256 embedding (required)      |
| **Timestamp Forgery**    | 🟡 MEDIUM   | Forgeable                  | RFC3161 prevents     | TSA usage                        |
| **Chain Discontinuity**  | 🟡 MEDIUM   | Replaceable                | Integrity guaranteed | Atomic save + Rekor              |

---

## Implementation Priority for Provenix

### **Phase 1: Basic Tampering Detection (Immediate)** ✅

```rust
1. Embed SBOM hash in Attestation
2. Verify hash match during verification
3. Add timestamp (chrono)
```

**Dependencies:**

- `sha2` crate for SHA-256 hashing
- `chrono` crate for timestamps
- No external services required

**Estimated Effort:** 1-2 days

---

### **Phase 2: Secure Key Management (Early)** 🔐

```rust
1. System keychain integration
2. Read keys from environment variables
3. Warn about key file permissions
```

**Dependencies:**

- `keyring` crate for system keychain
- `dirs` crate for standard directories

**Estimated Effort:** 3-5 days

---

### **Phase 3: Transparency Log Integration (Mid-term)** 📜

```rust
1. Implement Rekor API client
2. Auto-upload functionality
3. Rekor verification during validation
```

**Dependencies:**

- `reqwest` for HTTP client
- Rekor API understanding
- Network connectivity required

**Estimated Effort:** 1-2 weeks

---

### **Phase 4: Enterprise Features (Long-term)** 🏢

```rust
1. HSM support
2. Custom CA integration
3. Policy engine
```

**Dependencies:**

- Hardware tokens (YubiKey, etc.)
- Enterprise PKI infrastructure
- Advanced cryptography libraries

**Estimated Effort:** 1-2 months

---

## Recommended: Minimal Secure Implementation

```rust
// Minimum set to implement immediately
pub fn secure_attest_flow(
    target: &str,
    output_dir: &Path,
) -> Result<AttestationBundle> {
    // 1. Generate SBOM
    let sbom = generate_sbom(target)?;
    let sbom_hash = compute_sha256(&sbom);

    // 2. Create Attestation (with hash)
    let attestation = create_attestation_with_hash(
        &sbom,
        sbom_hash,
        Utc::now(),  // Timestamp
    )?;

    // 3. Secure key retrieval
    let key = load_key_securely()?;  // Keychain/env var

    // 4. Sign
    let signature = sign(&attestation, &key)?;

    // 5. Atomic save (all succeed or all fail)
    save_bundle_atomically(output_dir, AttestationBundle {
        sbom,
        sbom_hash,
        attestation,
        signature,
    })?;

    Ok(bundle)
}
```

---

## Required Dependencies

### Phase 1 (Immediate)

```toml
[dependencies]
sha2 = "0.10"           # SHA-256 hashing
chrono = "0.4"          # Timestamps
serde = "1.0"           # Serialization
serde_json = "1.0"      # JSON handling
anyhow = "1.0"          # Error handling
```

### Phase 2 (Early)

```toml
keyring = "2.0"         # System keychain
dirs = "5.0"            # Standard directories
```

### Phase 3 (Mid-term)

```toml
reqwest = { version = "0.11", features = ["json", "blocking"] }
base64 = "0.21"         # Base64 encoding
```

---

## Testing Strategy

### Unit Tests

```rust
#[test]
fn test_hash_embedding() {
    let sbom = generate_test_sbom();
    let attestation = create_attestation(&sbom);
    assert_eq!(
        compute_hash(&sbom),
        attestation.subject[0].digest.sha256
    );
}

#[test]
fn test_tampering_detection() {
    let mut sbom = generate_test_sbom();
    let attestation = create_attestation(&sbom);

    // Tamper with SBOM
    sbom.push_str("malicious");

    // Verification should fail
    assert!(verify_chain(&sbom, &attestation).is_err());
}
```

### Integration Tests

```rust
#[test]
fn test_end_to_end_flow() {
    // Generate → Attest → Sign → Verify
    let bundle = secure_attest_flow(".", temp_dir())?;
    assert!(verify_bundle(&bundle).is_ok());
}
```

---

## Security Checklist

Before deploying to production:

- [ ] SBOM hash is embedded in attestation
- [ ] Hash verification is performed during validation
- [ ] Timestamps are included (RFC 3339 format)
- [ ] Keys are not stored in plaintext files
- [ ] Atomic file operations are used
- [ ] Error messages don't leak sensitive information
- [ ] Cryptographic libraries are up to date
- [ ] Test coverage includes tampering scenarios
- [ ] Documentation includes security warnings
- [ ] Threat model is documented

---

## CI/CD Environment Considerations

### Challenge: Local File Handling in CI/CD

CI/CD pipelines present unique security challenges because:

1. **Ephemeral Runners**: Build agents are temporary and destroyed after each job
2. **No Persistent Storage**: Files between steps may not persist
3. **Shared Infrastructure**: Multiple builds may run on same hardware
4. **Limited Secrets Management**: Keys must be injected securely
5. **Artifact Storage**: Files need to be uploaded to external storage

---

### CI/CD Attack Vectors

#### Attack 1: Artifact Substitution
```yaml
# GitHub Actions example
steps:
  - name: Generate SBOM
    run: provenix sbom
    # → sbom.json created
  
  # ⚠️ RISK: Another step or malicious action could modify sbom.json here
  
  - name: Attest SBOM
    run: provenix attest
    # → attests potentially tampered sbom.json
```

#### Attack 2: Cache Poisoning
```yaml
# Cached artifacts from previous runs
- uses: actions/cache@v3
  with:
    path: ~/.cargo/registry
    key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
    
# ⚠️ RISK: Malicious package in cache affects SBOM
```

#### Attack 3: Secrets Exposure
```yaml
# Secrets stored in CI/CD variables
env:
  SIGNING_KEY: ${{ secrets.SIGNING_KEY }}
  
# ⚠️ RISK: Key logged in output or stored in temp files
```

---

### Solution 1: Immutable Artifact Strategy ✅ **Recommended**

**Approach:** Treat each CI/CD run as producing immutable artifacts that are immediately uploaded.

#### GitHub Actions Example

```yaml
name: Secure SBOM Pipeline

on:
  push:
    branches: [main]
  release:
    types: [created]

jobs:
  generate-and-attest:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write  # For OIDC token
      
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        
      - name: Setup Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          
      - name: Install Provenix
        run: cargo install provenix-cli
        
      # CRITICAL: Generate everything in one atomic step
      - name: Generate SBOM + Attestation + Signature
        id: attest
        run: |
          # Use single command that does all steps in memory
          provenix bundle \
            --target . \
            --output-dir ./artifacts \
            --format json \
            --atomic
          
          # Immediately compute hashes
          cd artifacts
          sha256sum * > checksums.txt
          
        env:
          # Use GitHub's OIDC token instead of long-lived keys
          GITHUB_TOKEN: ${{ github.token }}
          
      # Upload immediately (no tampering window)
      - name: Upload Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: attestation-bundle
          path: artifacts/
          retention-days: 90
          if-no-files-found: error
          
      # Publish to Rekor for transparency
      - name: Publish to Rekor
        run: |
          provenix publish \
            --rekor-url https://rekor.sigstore.dev \
            --bundle ./artifacts/bundle.json
```

---

### Solution 2: Keyless Signing with OIDC ✅ **Best Practice**

**Approach:** Use ephemeral certificates tied to CI/CD identity, no long-lived keys.

```rust
// Implementation using Sigstore's Fulcio
pub fn sign_with_oidc(
    attestation: &Attestation,
    oidc_token: &str,
) -> Result<SignedAttestation> {
    // 1. Request ephemeral certificate from Fulcio
    let fulcio_url = "https://fulcio.sigstore.dev";
    let cert_response = reqwest::blocking::Client::new()
        .post(format!("{}/api/v2/signingCert", fulcio_url))
        .bearer_auth(oidc_token)
        .json(&json!({
            "publicKeyRequest": {
                "publicKey": {
                    "algorithm": "ECDSA",
                    "content": base64::encode(&public_key)
                },
                "proofOfPossession": base64::encode(&proof)
            }
        }))
        .send()?;
    
    let cert = parse_certificate(cert_response)?;
    
    // 2. Sign with ephemeral key
    let signature = sign_with_certificate(attestation, &cert)?;
    
    // 3. Certificate contains identity claims:
    //    - GitHub repo: octo-org/octo-repo
    //    - Workflow: .github/workflows/release.yml
    //    - Commit SHA: abc123...
    
    // 4. Destroy private key immediately
    // (ephemeral key only exists in this function)
    
    Ok(SignedAttestation {
        attestation,
        signature,
        certificate: cert,
    })
}
```

**Benefits:**
- No secrets to manage in CI/CD
- Certificate proves "built by GitHub Actions for repo X"
- Short-lived certificates (valid for minutes)
- Automatic revocation when workflow ends

---

### Solution 3: Artifact Attestation Service ✅ **GitHub Native**

**GitHub Attestations** (native feature):

```yaml
steps:
  - name: Generate SBOM
    run: provenix sbom --output sbom.json
    
  # Use GitHub's built-in attestation
  - name: Attest SBOM
    uses: actions/attest-sbom@v1
    with:
      subject-path: sbom.json
      sbom-path: sbom.json
      push-to-registry: true
```

**How it works:**
1. GitHub generates attestation using its own keys
2. Attestation includes:
   - Repository identity
   - Workflow name and path
   - Commit SHA
   - Runner environment
3. Published to GitHub's attestation registry
4. Can be verified with `gh attestation verify`

---

### Solution 4: Workspace Isolation ✅ **Defense in Depth**

```yaml
jobs:
  sbom:
    runs-on: ubuntu-latest
    container:
      image: rust:1.70
      options: --read-only --tmpfs /tmp
    
    steps:
      - name: Generate SBOM (isolated)
        run: |
          # Run in read-only container
          provenix sbom --output /tmp/sbom.json
          
      - name: Upload immediately
        uses: actions/upload-artifact@v4
        with:
          name: sbom
          path: /tmp/sbom.json
  
  attest:
    needs: sbom
    runs-on: ubuntu-latest
    container:
      image: rust:1.70
      options: --read-only --tmpfs /tmp
      
    steps:
      - name: Download SBOM
        uses: actions/download-artifact@v4
        with:
          name: sbom
          path: /tmp
          
      - name: Verify SBOM hash before attesting
        run: |
          EXPECTED_HASH="${{ needs.sbom.outputs.sbom-hash }}"
          ACTUAL_HASH=$(sha256sum /tmp/sbom.json | cut -d' ' -f1)
          
          if [ "$EXPECTED_HASH" != "$ACTUAL_HASH" ]; then
            echo "SBOM hash mismatch! Artifact tampered."
            exit 1
          fi
          
      - name: Create Attestation
        run: provenix attest --sbom /tmp/sbom.json
```

---

### Solution 5: Provenance from CI/CD Metadata ✅ **SLSA Level 3**

**Approach:** Include CI/CD context in attestation to prove build environment.

```rust
pub fn create_attestation_with_ci_context(
    sbom: &Sbom,
    ci_env: &CiEnvironment,
) -> Result<Attestation> {
    Ok(json!({
        "_type": "https://in-toto.io/Statement/v0.1",
        "subject": [{
            "name": "sbom.json",
            "digest": {
                "sha256": compute_hash(&sbom)
            }
        }],
        "predicateType": "https://slsa.dev/provenance/v1.0",
        "predicate": {
            "buildDefinition": {
                "buildType": ci_env.build_type,  // "https://github.com/actions/workflow/v1"
                "externalParameters": {
                    "repository": ci_env.repository,  // "octo-org/octo-repo"
                    "ref": ci_env.git_ref,            // "refs/heads/main"
                    "workflow": ci_env.workflow_path   // ".github/workflows/release.yml"
                },
                "resolvedDependencies": ci_env.dependencies
            },
            "runDetails": {
                "builder": {
                    "id": ci_env.runner_id,           // "GitHub Actions"
                    "version": ci_env.runner_version
                },
                "metadata": {
                    "invocationId": ci_env.run_id,    // Unique run ID
                    "startedOn": ci_env.started_at,
                    "finishedOn": Utc::now()
                }
            }
        }
    }))
}

// Populate from environment variables
impl CiEnvironment {
    pub fn from_github_actions() -> Result<Self> {
        Ok(Self {
            build_type: "https://github.com/actions/workflow/v1".to_string(),
            repository: env::var("GITHUB_REPOSITORY")?,
            git_ref: env::var("GITHUB_REF")?,
            workflow_path: env::var("GITHUB_WORKFLOW")?,
            runner_id: env::var("RUNNER_NAME")?,
            runner_version: env::var("RUNNER_VERSION")?,
            run_id: env::var("GITHUB_RUN_ID")?,
            started_at: env::var("GITHUB_RUN_STARTED_AT")?,
        })
    }
    
    pub fn from_gitlab_ci() -> Result<Self> {
        Ok(Self {
            build_type: "https://gitlab.com/ci/v1".to_string(),
            repository: env::var("CI_PROJECT_PATH")?,
            git_ref: env::var("CI_COMMIT_REF_NAME")?,
            workflow_path: env::var("CI_CONFIG_PATH")?,
            runner_id: env::var("CI_RUNNER_DESCRIPTION")?,
            runner_version: env::var("CI_RUNNER_VERSION")?,
            run_id: env::var("CI_PIPELINE_ID")?,
            started_at: env::var("CI_PIPELINE_CREATED_AT")?,
        })
    }
}
```

---

### Solution 6: Hash Chain with Job Outputs ✅ **Verification**

```yaml
jobs:
  sbom:
    outputs:
      sbom-hash: ${{ steps.generate.outputs.hash }}
    steps:
      - id: generate
        run: |
          provenix sbom --output sbom.json
          HASH=$(sha256sum sbom.json | cut -d' ' -f1)
          echo "hash=$HASH" >> $GITHUB_OUTPUT
          
  attest:
    needs: sbom
    steps:
      - name: Download SBOM
        uses: actions/download-artifact@v4
        
      - name: Verify chain
        run: |
          # Hash from previous job (trusted)
          EXPECTED="${{ needs.sbom.outputs.sbom-hash }}"
          
          # Hash of downloaded artifact (verify no tampering)
          ACTUAL=$(sha256sum sbom.json | cut -d' ' -f1)
          
          if [ "$EXPECTED" != "$ACTUAL" ]; then
            echo "ERROR: SBOM tampered between jobs!"
            exit 1
          fi
          
      - name: Create attestation with verified hash
        run: |
          provenix attest \
            --sbom sbom.json \
            --expected-hash ${{ needs.sbom.outputs.sbom-hash }}
```

---

### Comparison: CI/CD Strategies

| Strategy | Security | Complexity | Key Management | SLSA Level |
|----------|----------|------------|----------------|------------|
| **Atomic Bundle** | High | Low | Required | L2 |
| **OIDC Signing** | Very High | Medium | None | L3 |
| **GitHub Attestations** | High | Very Low | None | L3 |
| **Container Isolation** | Medium | Medium | Required | L2 |
| **CI Provenance** | High | Medium | Required | L3+ |
| **Hash Chain** | Medium | Low | Required | L2 |

---

### Recommended CI/CD Implementation

**For GitHub Actions:**

```yaml
name: Secure Build with Attestation

on:
  push:
    branches: [main]
  release:
    types: [published]

permissions:
  contents: read
  id-token: write  # OIDC token
  packages: write  # Attestation storage
  attestations: write

jobs:
  build-and-attest:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Rust
        uses: actions-rs/toolchain@v1
        
      # Single atomic operation
      - name: Build and Generate Attestation Bundle
        run: |
          # Install provenix
          cargo install provenix-cli
          
          # Generate everything atomically
          provenix bundle \
            --target . \
            --output artifacts/ \
            --ci-mode github-actions \
            --oidc-token "${{ github.token }}" \
            --atomic
            
      # Native GitHub attestation (recommended)
      - name: Attest Build Provenance
        uses: actions/attest-build-provenance@v1
        with:
          subject-path: 'artifacts/*'
          
      # Upload for external verification
      - name: Upload Bundle
        uses: actions/upload-artifact@v4
        with:
          name: attestation-bundle
          path: artifacts/
          
      # Publish to Rekor (transparency log)
      - name: Publish to Transparency Log
        run: |
          provenix publish \
            --rekor-url https://rekor.sigstore.dev \
            --bundle artifacts/bundle.json
```

**Key Features:**
1. ✅ No long-lived secrets
2. ✅ OIDC for identity
3. ✅ Atomic generation
4. ✅ Native GitHub attestation
5. ✅ Transparency log
6. ✅ Verifiable by anyone

---

### Verification in CI/CD

**Downstream job or deployment:**

```yaml
jobs:
  verify-and-deploy:
    runs-on: ubuntu-latest
    
    steps:
      - name: Download Attestation Bundle
        uses: actions/download-artifact@v4
        with:
          name: attestation-bundle
          
      - name: Verify Bundle
        run: |
          # Verify attestation signature
          provenix verify \
            --bundle bundle.json \
            --rekor-url https://rekor.sigstore.dev
            
          # Verify it was built from correct repo
          REPO=$(provenix inspect bundle.json --field repository)
          if [ "$REPO" != "octo-org/octo-repo" ]; then
            echo "ERROR: Built from wrong repository!"
            exit 1
          fi
          
          # Verify workflow
          WORKFLOW=$(provenix inspect bundle.json --field workflow)
          if [ "$WORKFLOW" != ".github/workflows/release.yml" ]; then
            echo "ERROR: Built from wrong workflow!"
            exit 1
          fi
          
      - name: Deploy (only if verified)
        run: ./deploy.sh
```

---

## References

- [in-toto Specification](https://github.com/in-toto/docs/blob/master/in-toto-spec.md)
- [SLSA Framework](https://slsa.dev/)
- [Sigstore](https://www.sigstore.dev/)
- [RFC 3161 - Time-Stamp Protocol](https://www.rfc-editor.org/rfc/rfc3161)
- [Supply Chain Security Best Practices](https://github.com/ossf/wg-best-practices-os-developers)
- [GitHub Attestations](https://docs.github.com/en/actions/security-guides/using-artifact-attestations)
- [Sigstore Fulcio](https://docs.sigstore.dev/fulcio/overview/)
- [SLSA Build Levels](https://slsa.dev/spec/v1.0/levels)

---

## Conclusion

Implementing these security measures in phases will significantly improve Provenix's resilience against supply chain attacks. Start with Phase 1 for immediate protection, then progressively add layers of security as the project matures.

**Key Principle:** Defense in depth - multiple layers of security ensure that if one layer fails, others still provide protection.

# CLI Usage Examples

## Provenix Command Line Interface

The Provenix CLI provides both short (`px`) and full (`provenix`) command names.

### Basic Usage

```bash
# Show help
px --help
provenix --help

# Check version
px --version
provenix --version
```

### SBOM Operations (pxb integration)

```bash
# Generate SBOM for current project
px bom generate --format spdx --output sbom.json

# Analyze dependencies
px bom analyze --input sbom.json --check-vulnerabilities

# Convert between formats
px bom convert --input sbom.spdx --output sbom.cyclonedx --format cyclonedx
```

### Attestation Operations (pxa integration)

```bash
# Sign an SBOM
px attest sign --input sbom.json --key private.pem --output sbom.signed.json

# Verify signature
px attest verify --input sbom.signed.json --key public.pem

# Generate remote attestation
px attest remote --target-url https://api.example.com --output attestation.json
```

### Server Operations (pxs integration)

```bash
# Start local server
px server start --port 8080 --data-dir ./provenix-data

# Upload SBOM to server
px server upload --input sbom.json --endpoint https://provenix.example.com

# Query server for artifacts
px server query --artifact-id sha256:abc123... --format json
```

### Integrated Workflows

```bash
# Complete provenance workflow
px workflow run \
  --generate-sbom \
  --sign-artifacts \
  --upload-server https://provenix.example.com \
  --notify-webhook https://ci.example.com/webhook

# Batch processing
px batch process --input-dir ./artifacts --output-dir ./processed --config workflow.yaml
```

### Configuration

```bash
# Initialize configuration
px config init

# Set default server
px config set server.default-url https://provenix.example.com

# Configure signing key
px config set attest.default-key ~/.provenix/signing-key.pem
```
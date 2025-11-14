# REST API Specification

## Provenix Server API (pxs)

Base URL: `https://your-provenix-server.com/api/v1`

### Authentication

All API endpoints require authentication via Bearer token:

```
Authorization: Bearer <your-api-token>
```

### Endpoints

#### SBOM Management

##### Upload SBOM
```http
POST /sboms
Content-Type: application/json

{
  "format": "spdx|cyclonedx|provenix",
  "data": { /* SBOM content */ },
  "metadata": {
    "project": "example-project",
    "version": "1.0.0",
    "timestamp": "2024-01-01T00:00:00Z"
  }
}
```

##### Get SBOM
```http
GET /sboms/{id}
Accept: application/json

Response:
{
  "id": "sbom-12345",
  "format": "spdx",
  "data": { /* SBOM content */ },
  "metadata": { /* metadata */ },
  "created_at": "2024-01-01T00:00:00Z"
}
```

##### List SBOMs
```http
GET /sboms?project=example&limit=50&offset=0
```

#### Attestation Management

##### Upload Attestation
```http
POST /attestations
Content-Type: application/json

{
  "type": "signature|remote-attestation",
  "subject": "sbom-12345",
  "signature": "base64-encoded-signature",
  "certificate": "base64-encoded-cert",
  "timestamp": "2024-01-01T00:00:00Z"
}
```

##### Verify Attestation
```http
POST /attestations/verify
Content-Type: application/json

{
  "attestation_id": "att-67890",
  "public_key": "base64-encoded-public-key"
}

Response:
{
  "valid": true,
  "verified_at": "2024-01-01T00:00:00Z",
  "details": {
    "signature_valid": true,
    "certificate_valid": true,
    "timestamp_valid": true
  }
}
```

#### Artifact Tracking

##### Register Artifact
```http
POST /artifacts
Content-Type: application/json

{
  "name": "my-app",
  "version": "1.0.0",
  "hash": "sha256:abc123...",
  "type": "container|binary|library",
  "sbom_id": "sbom-12345",
  "attestations": ["att-67890"]
}
```

##### Get Artifact Provenance
```http
GET /artifacts/{hash}/provenance

Response:
{
  "artifact": { /* artifact info */ },
  "sbom": { /* SBOM data */ },
  "attestations": [ /* attestation list */ ],
  "provenance_chain": [ /* full chain */ ]
}
```

#### Search and Query

##### Search Artifacts
```http
GET /search/artifacts?q=vulnerability:CVE-2024-1234
GET /search/artifacts?component=openssl&version=1.1.1
```

##### Vulnerability Query
```http
GET /vulnerabilities/{cve-id}/affected-artifacts
```

### WebSocket Events

Real-time updates via WebSocket at `/ws`:

```json
{
  "type": "sbom.uploaded|attestation.created|vulnerability.detected",
  "data": { /* event-specific data */ },
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Error Responses

```json
{
  "error": "invalid_request",
  "message": "Detailed error message",
  "code": 400,
  "timestamp": "2024-01-01T00:00:00Z"
}
```

### Rate Limiting

- 1000 requests per hour per API key
- Burst limit: 100 requests per minute
- Headers: `X-RateLimit-Remaining`, `X-RateLimit-Reset`
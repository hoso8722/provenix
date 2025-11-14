# Provenix

Zero-trust software supply chain security and provenance platform.

## Overview

Provenix implements a comprehensive zero-trust security model for software supply chain protection, providing end-to-end visibility and security through:

- **Software Bill of Materials (SBOM)** generation with cryptographic integrity
- **Digital attestation** and remote attestation with hardware security
- **Zero-trust policy enforcement** using Open Policy Agent (OPA)
- **Provenance tracking** with immutable audit trails
- **Vulnerability assessment** and compliance reporting
- **Enterprise-grade API and Web UI** with OIDC authentication

## Zero-Trust Security Features

🔒 **Identity-Centric Security**: Multi-factor authentication and continuous verification  
🛡️ **Policy-Based Access Control**: Dynamic authorization with context-aware policies  
🔐 **Cryptographic Attestation**: Hardware-backed signing and verification  
📊 **Continuous Monitoring**: Real-time security monitoring and audit logging  
🏗️ **Secure by Design**: Security controls embedded in every component

## Tools

### Core CLI Commands

- **`px`** / **`provenix`** - Main CLI interface with zero-trust authentication
- **`pxb`** - SBOM generation and analysis tool with vulnerability scanning
- **`pxa`** - Cryptographic attestation and signing with HSM support
- **`pxs`** - Enterprise API server with OIDC and policy enforcement

### Quick Start

```bash
# Build from source
git clone https://github.com/your-org/provenix.git
cd provenix
./scripts/build.sh

# Initialize configuration
./target/release/px config init

# Generate SBOM with vulnerability scanning
./target/release/px bom generate --format spdx --scan-vulns

# Sign with hardware attestation
./target/release/px attest sign --input sbom.json --hsm

# Start zero-trust server
./target/release/px server start --config production
```

## Architecture

Provenix implements a zero-trust architecture with the following components:

### Core Libraries (`crates/`)
- **`provenix-corelib`** - Domain-driven design core with security primitives
- **`provenix-utils`** - Secure utilities for logging, config, and error handling
- **`provenix-bom`** - SBOM generation with supply chain analysis
- **`provenix-attest`** - Cryptographic attestation and verification
- **`provenix-cli`** - Zero-trust CLI with secure credential management

### Enterprise Server (`server/`)
- **Authentication**: OIDC integration with MFA enforcement
- **Authorization**: Policy engine with OPA for dynamic access control
- **Storage**: Encrypted data with immutable audit trails
- **Services**: Business logic with security-first design
- **API**: RESTful and gRPC APIs with comprehensive security

### Infrastructure (`infra/`)
- **Docker**: Multi-stage builds with security scanning
- **Kubernetes**: Production-ready deployments with network policies
- **Terraform**: Infrastructure as Code with security baselines

### Security Features
```
┌─────────────────────────────────────────────────────────────┐
│                    Zero-Trust Security                      │
├─────────────────────────────────────────────────────────────┤
│ Identity │ Network │ Device │ Application │ Data │ Workload │
│ Verify   │ Segment │ Attest │ Authorize   │Encrypt│ Isolate  │
└─────────────────────────────────────────────────────────────┘
```

## Documentation

- [🏗️ Architecture Overview](docs/ARCHITECTURE.md) - Zero-trust system design
- [🛡️ Security Model](docs/SECURITY_MODEL.md) - Comprehensive security framework  
- [🚀 Deployment Guide](docs/DEPLOYMENT_GUIDE.md) - Production deployment strategies
- [📖 CLI Usage Guide](docs/cli.md) - Command-line interface documentation
- [🔌 API Reference](docs/api.md) - REST API specifications
- [📋 Project Guide](docs/PROJECT_GUIDE.md) - Development and contribution guide

## Development

### Quick Build

```bash
# Automated build with security scanning
./scripts/build.sh

# Run comprehensive test suite
./scripts/test.sh

# Create production release
./scripts/release.sh minor
```

### Manual Build

```bash
# Clone the repository
git clone https://github.com/your-org/provenix.git
cd provenix

# Build all workspace components
cargo build --release --workspace

# Run tests with security checks
cargo test --workspace
cargo audit
```

### Development Environment

```bash
# Start local development environment
docker-compose -f infra/docker/compose.yaml up -d

# Run in development mode
PROVENIX_ENV=dev cargo run --bin pxs
```

### Project Structure

```
provenix/
├── crates/                   # Rust libraries
│   ├── corelib/             # Domain core (DDD)
│   ├── utils/               # Common utilities 
│   ├── bom/                 # SBOM generation (pxb)
│   ├── attest/              # Attestation tools (pxa)
│   └── cli/                 # Main CLI (px)
│
├── server/                  # Enterprise API server (pxs)
│   ├── src/                 # Server implementation
│   │   ├── auth/           # Authentication & OIDC
│   │   ├── policy/         # OPA policy engine
│   │   ├── routes/         # API endpoints
│   │   ├── services/       # Business logic
│   │   └── storage/        # Data layer
│   └── config/             # Configuration files
│
├── frontend/               # Web UI (React/TypeScript)
├── infra/                  # Infrastructure as Code
│   ├── docker/             # Container definitions
│   └── terraform/          # Cloud infrastructure
│
├── scripts/                # Automation scripts
│   ├── build.sh           # Build automation
│   ├── test.sh            # Test suite
│   └── release.sh         # Release management
│
├── tests/                  # Test suites
│   ├── api/               # API integration tests
│   ├── cli/               # CLI tests
│   └── e2e/               # End-to-end tests
│
└── docs/                   # Documentation
    ├── ARCHITECTURE.md     # System architecture
    ├── SECURITY_MODEL.md   # Security framework
    └── DEPLOYMENT_GUIDE.md # Deployment guide
```

## Security & Compliance

### Security Features
- **Zero Trust Network Architecture (ZTNA)**
- **Hardware Security Module (HSM) integration**
- **Multi-factor authentication (MFA)**
- **Policy-as-Code with Open Policy Agent**
- **End-to-end encryption with TLS 1.3+**
- **Immutable audit trails**
- **Vulnerability scanning and SBOM analysis**
- **Container image signing and verification**

### Compliance Standards
- **SOC 2 Type II** controls implementation
- **NIST Cybersecurity Framework** alignment
- **SLSA (Supply-chain Levels for Software Artifacts)** compliance
- **GDPR/CCPA** privacy controls
- **FIPS 140-2** cryptographic standards (where applicable)

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Security Contributions
For security-related contributions:
1. Follow responsible disclosure practices
2. Submit security issues via private channels
3. Include proof-of-concept only after fixes are available

## Support & Community

- 📖 **Documentation**: [docs/](docs/)
- 🐛 **Issues**: [GitHub Issues](https://github.com/your-org/provenix/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/your-org/provenix/discussions)
- 📧 **Security**: security@provenix.dev

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Security Notice

For security vulnerabilities, please email security@provenix.dev rather than filing a public issue. We follow responsible disclosure practices and will acknowledge receipt within 24 hours.
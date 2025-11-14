# Provenix Project Specification & Roadmap

## 1. Overview

**Project Name:** Provenix  
**Type:** OSS (Open Source Software)  
**Language Stack:**  
- Backend: Rust  
- Frontend: React (Router v7, Vite)  
- CLI: Rust (Cargo-based multi-crate)  
- Infra: Docker / IaC (Terraform or Ansible予定)  
- Security: Zero Trust (Optional, pluggable design)

**Goal:**  
Provide a verifiable, secure, and modular foundation for software transparency and trust management.  
Modules A–D cover BOM tracking, attestation, CLI tooling, and server coordination.  
LLM-assisted development ensures structured evolution and consistency.

---

## 2. Project Modules

### 2.1 Core Libraries (`corelib`)
- **Purpose:** Common utilities, domain entities, error handling, logging, and shared traits.
- **Architecture:** Onion architecture (Domain-Driven Design)
- **Key Features:**
  - Strongly typed domain models
  - Pluggable persistence
  - Reusable domain logic

### 2.2 BOM Management (`bom`)
- **Purpose:** Manage, track, and verify Software Bill of Materials (SBOM)
- **Structure:** Onion + Hexagonal
- **Features:**
  - SBOM parsing (CycloneDX, SPDX)
  - Dependency trust scoring
  - Versioned audit trail
  - Integration hooks for CI/CD

### 2.3 Attestation (`attest`)
- **Purpose:** Handle software attestation and signature verification
- **Features:**
  - Digital signing & verification
  - Key management abstraction
  - Policy-based validation

### 2.4 CLI Tool (`cli`)
- **Purpose:** Unified command-line interface for Provenix modules
- **Design:**
  - Modular subcommands: `provenix bom`, `provenix attest`, etc.
  - Optional standalone installation: `bom-cli`, `attest-cli`
  - TUI (Text UI) planned for v2
- **Future:** AI-assisted command recommendations

### 2.5 Server (`server`)
- **Purpose:** Provide REST/GraphQL API to expose Provenix services
- **Backend:** Axum / Actix (Rust)
- **Features:**
  - AuthN/AuthZ (JWT or OAuth)
  - Multi-tenant storage layer
  - Secure API gateway
  - Optional Zero Trust enforcement layer

### 2.6 Frontend (`frontend`)
- **Purpose:** UI portal for Provenix features
- **Tech:** React + Router v7 + TypeScript + Vite
- **Features:**
  - Interactive dashboard for BOM and attestation
  - Integration with Provenix server APIs
  - Authentication and role-based views

---

## 3. Security and Zero Trust (Optional Extension)

| Layer | Description | Implementation |
|--------|--------------|----------------|
| Identity | Service-to-service auth | OIDC + SPIFFE/SPIRE |
| Network | Access segmentation | Envoy + mTLS |
| Storage | Data integrity | Signed records |
| Endpoint | CLI signing | Provenix attest |
| LLM Ops | Controlled context | Secure prompt gateway |

All Zero Trust components are **optional** and can be **self-hosted or community-provided**.

---

## 4. Repository Layout

provenix/
├── Cargo.toml
├── README.md
├── LICENSE
├── crates/
│ ├── corelib/
│ ├── bom/
│ ├── attest/
│ └── cli/
├── server/
│ └── src/
├── frontend/
│ ├── src/
│ ├── public/
│ └── vite.config.ts
├── infra/
│ └── docker-compose.yml (planned)
├── docs/
│ ├── PROJECT_GUIDE.md
│ ├── architecture.md
│ ├── api.md
│ └── roadmap.md
└── scripts/

---

## 5. Development Plan

| Phase | Description | Milestones | Target |
|-------|--------------|-------------|--------|
| **Phase 1** | Core setup | `corelib`, `bom`, initial CLI | Q1 |
| **Phase 2** | Server + API | Rust Axum + REST API | Q2 |
| **Phase 3** | Frontend UI | React portal | Q3 |
| **Phase 4** | Zero Trust | SPIRE integration, signed attestations | Q4 |
| **Phase 5** | LLM Agent Integration | AI-assisted CLI and codegen | Q1 (next year) |

---

## 6. Governance and OSS Policy

- License: MIT / Apache-2.0 Dual License  
- Governance model: Meritocratic (open governance)  
- Contributions:
  - PR review with CODEOWNERS
  - CLA optional (for organizational contributors)
  - Security disclosures via `security@provenix.org` (planned)

---

## 7. LLM Integration Strategy

- Use LLM to:
  - Generate module scaffolds
  - Review architecture changes
  - Propose dependency updates
  - Assist with documentation and testing

LLM prompt discipline is critical — context must include `docs/PROJECT_GUIDE.md`.

---

## 8. Long-term Roadmap

| Goal | Description | Target Version |
|------|--------------|----------------|
| Provenix Cloud | Managed SaaS version with zero trust integration | v2.0 |
| Provenix Agent | Local agent for on-device verification | v2.2 |
| Provenix Connect | Federation across instances | v3.0 |
| Provenix Audit | Immutable audit trail (blockchain optional) | v3.5 |

---

## 9. Documentation Plan

- `docs/architecture.md` → Onion + Hexagonal hybrid design  
- `docs/api.md` → REST endpoints (OpenAPI format)  
- `docs/cli.md` → CLI usage and subcommand structure  
- `docs/security.md` → Zero Trust architecture  
- `docs/roadmap.md` → Ongoing progress and milestones  

---

## 10. Contact and Coordination

- **Website:** https://provenix.org (planned)  
- **GitHub:** https://github.com/provenix  
- **Community:** Discord / Matrix (TBD)  
- **Maintainers:** Core maintainers + community maintainers

---

_Last updated: 2025-11-10_
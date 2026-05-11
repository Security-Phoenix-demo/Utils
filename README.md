# Phoenix Security Utilities

A collection of utilities for integrating with the Phoenix Security platform — covering vulnerability ingestion, asset inventory, CI/CD gating, SBOM management, and risk reporting.

## Available Utilities

### Loading_Script_V5_PUB — Multi-Scanner Import (Production)
Location: `/Loading_Script_V5_PUB`

Production-ready solution for automated security scanner data ingestion into Phoenix. Ships two integrated components:

- **Phoenix Scanner Service** — Docker-based microservice with REST API and WebSocket support for background worker processing
- **Phoenix Scanner Client** — Python CLI tool for file uploads, CI/CD integration, and batch processing

Supports a wide range of scanners (Trivy, SonarQube, and others). See `START_HERE.md` to get up and running in ~5 minutes.

---

### container scan — SBOM Generation & Container Vulnerability Scanning
Location: `/container scan`

Enterprise-grade GitHub Actions workflows and Python scripts for multi-SBOM generation, container vulnerability scanning, and secure Phoenix API integration. Key features:

- One SBOM per manifest file (build files, dependency files)
- Command injection prevention and path traversal protection
- Docker sandboxing and security controls
- JWT-validated Phoenix API integration with audit logging
- 47-test security test suite

---

### Gating — CI/CD Policy Gating
Location: `/Gating`

Enforces vulnerability and risk thresholds as a pipeline gate. Configurable pass/fail logic via two modes:

- **ALL mode** — every defined threshold must pass
- **REQUIRED mode** — only specified thresholds must pass

Evaluates Phoenix Security posture data against policy to gate software releases.

API endpoints used:
- `POST /v1/components/posture`
- `POST /v1/applications/posture`

---

### sbom-single-repo — Single-Repository SBOM Importer
Location: `/sbom-single-repo`

Imports CycloneDX JSON SBOMs for a single repository into Phoenix. Creates BUILD asset identities using `repo/file:branch` format (e.g. `acme/payments/package-lock.json:main`).

- Auto-detects Bitbucket Pipeline environment variables (`--from-bitbucket-env`)
- Dry-run and payload preview modes for validation before upload
- Preserves source context via tags (repository, sourceFile, branch, commit, CI build number/URL)

---

### Generic_to_csv_translator — Vulnerability Format Converter
Location: `/Generic_to_csv_translator`

Zero-dependency converter that normalises vulnerability data from multiple formats into Phoenix-compatible CSV. Supported input formats:

- Infrastructure
- Cloud
- Web application
- Software (including **Prowler OCSF JSON** with severity-to-risk mapping: Critical→10, High→8, Medium→5, Low→3, Informational→1)

Handles CVE extraction, date normalisation (DD-MM-YYYY HH:MM:SS), and tag formatting as JSON objects.

---

### vulnerability translator — JSON to CSV/Excel Converter
Location: `/vulnerability translator`

Converts Phoenix JSON vulnerability exports to CSV or Excel. Features:

- Interactive file selection or command-line mode
- Nested structure flattening (`stats.risk` → `stats_risk`, array indexing like `referenceIds_0_id`)
- Companion summary file (`*_summary.txt`) with column metadata, data coverage percentages, and sample values

---

### asset-count-scripts — Cloud & Git Asset Inventory
Location: `/asset-count-scripts`

Read-only scripts that count and inventory assets across cloud platforms and source code repositories. No data is modified. Supported platforms:

- **Cloud**: AWS, Azure, GCP
- **Source control**: GitHub, GitLab
- **Cloud security**: Wiz

Output: JSON/CSV reports with asset counts by type, region, and account.

---

### Team-exporter — Risk Reporting & Time-Series Analysis
Location: `/Team-exporter`

Generates risk assessment reports across teams with historical trend analysis. Output formats:

- **Weekly CSV** — issued/solved vulnerabilities, open criticals, zero-critical teams
- **PDF** — risk distribution charts, team performance trends, summary statistics (requires matplotlib/seaborn/pandas/numpy)

Performance tiers: Very High Risk (≥40,000) → Very Low Risk (<5,000).

---

### Jenkins Integration — SonarQube Pipeline Integration
Location: `/Jenkins Integration`

Groovy Jenkins pipeline scripts that orchestrate the full SonarQube → Phoenix Security workflow:

1. Run SonarQube scan
2. Upload results to Phoenix via API

Requires: SonarQube Scanner, Credentials, and Pipeline Jenkins plugins.

---

### LEGACY_Loading_Script_V2_PUB — Legacy Import Script
Location: `/LEGACY_Loading_Script_V2_PUB`

Previous-generation import script for uploading scanner results to Phoenix. Retained for backward compatibility. For new integrations use `Loading_Script_V5_PUB`.

Features: fuzzy scanner-type validation, configurable polling/timeout, access token generation, and import status monitoring.

---

## Environment Setup

### Prerequisites

- Python 3.x
- Docker (for `Loading_Script_V5_PUB` and `container scan`)
- Phoenix Security API credentials (Client ID + Client Secret)

### Authentication

All utilities authenticate against:
```
POST /v1/auth/access_token
```
using Basic Auth (Client ID : Client Secret) to obtain a Bearer token.

### Base URLs

| Environment | URL |
|-------------|-----|
| Production  | `https://api.securityphoenix.cloud` |
| Demo        | `https://api.demo.appsecphx.io` |
| PoC         | `https://api.poc1.appsecphx.io` |

### Environment Variables

```bash
export CLIENT_ID="your-client-id"
export CLIENT_SECRET="your-client-secret"
export BASE_URL="https://api.securityphoenix.cloud"   # or demo/poc
```

---

## Getting Started

1. Clone the repository:
```bash
git clone <repository-url>
cd Utils-PUB-NEW-2
```

2. Set your credentials:
```bash
export CLIENT_ID="your-client-id"
export CLIENT_SECRET="your-client-secret"
```

3. Navigate to the relevant utility and follow its README or `START_HERE.md`.

For the most common use case (scanner ingestion), start with `Loading_Script_V5_PUB/START_HERE.md`.

---

## Directory Structure

```
.
├── README.md
├── Loading_Script_V5_PUB/          # Production multi-scanner import (service + CLI)
├── container scan/                  # SBOM generation & container vulnerability scanning
├── Gating/                          # CI/CD policy gating
├── sbom-single-repo/                # Single-repo CycloneDX SBOM importer
├── Generic_to_csv_translator/       # Vulnerability format → Phoenix CSV converter
├── vulnerability translator/        # Phoenix JSON export → CSV/Excel converter
├── asset-count-scripts/             # Cloud & Git asset inventory (read-only)
├── Team-exporter/                   # Risk reporting & time-series analysis
├── Jenkins Integration/             # SonarQube → Phoenix Jenkins pipeline
└── LEGACY_Loading_Script_V2_PUB/   # Legacy import script (v2)
```

---

## License

This project is licensed under the Apache 2.0 License — see the [LICENSE](LICENSE) file for details.

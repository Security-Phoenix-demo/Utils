# Phoenix Upload Architecture Guide

This document explains two supported upload patterns for scanner data:

1. **Client + Scanner Service (recommended default)**
2. **Direct upload from CI/CD into Phoenix API**

It also includes when to use each option, trade-offs, and practical CI/CD use cases.

---

## 1) Two Upload Patterns

### Pattern A: Client + Scanner Service

**Flow**

Scanner output -> CI/CD runner -> `phoenix-scanner-client` -> `phoenix-scanner-service` -> Phoenix API

**Main components**

- Client CLI scripts:
  - `phoenix-scanner-client/actions/upload_single.py`
  - `phoenix-scanner-client/actions/upload_batch.py`
  - `phoenix-scanner-client/actions/upload_folder.py`
- Service API:
  - `phoenix-scanner-service/` (FastAPI + Redis + Celery worker)
- Core importer engine used by worker:
  - `phoenix_multi_scanner_enhanced.py`

**Best for**

- Standard enterprise CI/CD pipelines
- Asynchronous/background processing
- Centralized retry, logging, and job status tracking
- Multiple teams sharing the same upload service

---

### Pattern B: Direct CI/CD Upload to Phoenix

**Flow**

Scanner output -> CI/CD runner -> `phoenix_multi_scanner_enhanced.py` -> Phoenix API

**Main component**

- Direct importer script:
  - `phoenix_multi_scanner_enhanced.py`

**Best for**

- Simpler environments without running a service stack
- One-off or low-volume integrations
- Air-gapped or controlled runners where service hosting is not desired
- Teams that want one script and fewer moving parts

---

## 2) Requirements for Both Approaches

### A) Client + Scanner Service

**Runtime prerequisites**

- Docker 20.10+
- Docker Compose 2.0+
- Python 3.8+ (for client scripts)

**Required components**

- `phoenix-scanner-service/` (FastAPI API, Redis queue, Celery worker)
- `phoenix-scanner-client/` (CLI uploader scripts)

**Python dependencies**

- `phoenix-scanner-service/requirements.txt`
- `phoenix-scanner-client/requirements.txt`

**Required credentials and configuration**

- Service/API auth:
  - `API_KEY`
  - `SECRET_KEY`
- Phoenix credentials:
  - `PHOENIX_CLIENT_ID`
  - `PHOENIX_CLIENT_SECRET`
  - `PHOENIX_API_URL`
- Client endpoint auth:
  - `PHOENIX_SCANNER_API_URL`
  - `PHOENIX_SCANNER_API_KEY`

**Network requirements**

- CI runner must reach scanner service URL (for example, `http://localhost:8000` or internal service URL)
- Scanner service/worker must reach Phoenix API URL

### B) Direct CI/CD Upload to Phoenix

**Runtime prerequisites**

- Python 3.8+

**Required components**

- `phoenix_multi_scanner_enhanced.py` (direct importer script)

**Python dependencies**

- `requirements.txt` (from `Loading_Script_V5_PUB`)

**Required credentials and configuration**

- Phoenix API credentials in config/env:
  - `client_id`
  - `client_secret`
  - `api_base_url`

**Network requirements**

- CI runner must have direct network access to Phoenix API

### Quick Requirements Checklist

| Requirement Area | Client + Service | Direct CI/CD |
|---|---|---|
| Docker/Compose | Required | Not required |
| Python | Required | Required |
| Additional service stack | Required (API + Redis + worker) | Not required |
| Script runtime deps | Client + service requirement files | Root requirement file |
| Phoenix credentials | Required | Required |
| Service API key management | Required | Not required |
| Direct Phoenix network from runner | Optional | Required |

---

## 3) Decision Matrix

| Decision Factor | Client + Service | Direct CI/CD |
|---|---|---|
| Operational complexity | Medium (service to run) | Low |
| Scalability for many uploads | High | Medium |
| Retry and queue management | Strong (worker queue) | Script-level |
| Real-time job tracking | Strong | Basic/script logs |
| Setup speed | Medium | Fast |
| Team-level standardization | Strong | Moderate |
| Best default for production | Yes | Use case dependent |

---

## 4) Recommended Choice

Use **Client + Service** as the default architecture for production programs, especially when:

- you process frequent scans,
- you need reliable queue-based processing,
- you want shared operational visibility for multiple teams.

Use **Direct CI/CD** when:

- you need fast deployment with minimal infrastructure,
- your upload volume is moderate,
- your platform team prefers script-only operations.

---

## 5) CI/CD Use Cases

### Use Case 1: Daily multi-team scheduled ingestion

- **Recommended:** Client + Service
- Why:
  - centralized queue
  - better handling of bursts
  - easier shared monitoring and troubleshooting

### Use Case 2: Single product team with one nightly scan

- **Recommended:** Direct CI/CD (or Client + Service if already available)
- Why:
  - minimal setup
  - simple operational model

### Use Case 3: Regulated environment, strict audit requirements

- **Recommended:** Client + Service
- Why:
  - centralized logs and job lifecycle
  - better operational controls and consistency

### Use Case 4: Temporary migration or pilot rollout

- **Recommended:** Direct CI/CD first, then move to Client + Service
- Why:
  - start quickly
  - evolve later as volume and teams increase

---

## 6) Pipeline Examples

## A) Client + Service in CI/CD

### Jenkins stage (client calling service)

```groovy
stage('Upload to Phoenix Scanner Service') {
  steps {
    sh '''
      cd phoenix-scanner-client
      python3 actions/upload_single.py \
        --file scan-results.json \
        --scanner-type auto \
        --import-type delta \
        --wait \
        --report upload-report.txt
    '''
  }
}
```

### GitHub Actions step (client calling service)

```yaml
- name: Upload scan via scanner service
  run: |
    python phoenix-scanner-client/actions/upload_single.py \
      --file scan-results.json \
      --scanner-type auto \
      --import-type delta \
      --wait
  env:
    PHOENIX_SCANNER_API_URL: ${{ secrets.PHOENIX_SCANNER_API_URL }}
    PHOENIX_SCANNER_API_KEY: ${{ secrets.PHOENIX_SCANNER_API_KEY }}
```

## B) Direct CI/CD to Phoenix API

### Generic shell step (direct script)

```bash
python3 phoenix_multi_scanner_enhanced.py \
  --file scan-results.json \
  --scanner auto \
  --assessment "CI-Upload-${BUILD_ID}" \
  --import-type delta \
  --fix-data \
  --enable-batching \
  --verify-import
```

> Note: For direct mode, ensure the script configuration file has valid Phoenix credentials and API base URL.

---

## 7) Import-Type Guidance (Critical)

- `new`: replace-style import; can close vulnerabilities not present in current payload.
- `merge`: combine/update, but can still close missing vulnerabilities depending on data completeness.
- `delta` (**safest default**): add/update without unintended closure from partial scan data.

**CI/CD safe default:** `--import-type delta` unless you explicitly require replace behavior.

---

## 8) Security and Secrets

- Never hardcode credentials in pipeline files.
- Use CI secret stores for:
  - API keys
  - client ID
  - client secret
  - API URLs
- Keep config templates in repo, but inject real values at runtime.

---

## 9) Quick Recommendation Summary

- **If you need reliability and scale:** choose **Client + Service**.
- **If you need speed and simplicity:** choose **Direct CI/CD**.
- **If unsure:** start with **Client + Service** and use `import-type=delta`.


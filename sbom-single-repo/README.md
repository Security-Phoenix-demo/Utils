# sbom-single-repo

Single-repo SCA utility for importing CycloneDX SBOM findings into Phoenix.

## Purpose

This utility is designed for teams that want to import **one repository SBOM at a time**
into Phoenix with a stable build-oriented identity.

It specifically:

- Reads one CycloneDX JSON SBOM file
- Builds one Phoenix `BUILD` asset identity using `repo/file:branch`
- Imports vulnerabilities and component metadata through Phoenix asset import APIs
- Preserves source context (repository, file path, branch, and CI metadata) using tags

Use this when your pipeline produces a per-repo SBOM (GitHub, Bitbucket Cloud, or Bitbucket
on-prem CI) and you want predictable mapping between SBOM source and Phoenix `BUILD` assets.

This utility creates one `BUILD` asset using an asset identity format:

- `repo/file:branch`

Example:

- `acme/payments/package-lock.json:main`

It can also auto-read Bitbucket Pipeline metadata with `--from-bitbucket-env`.

## Why this utility

Phoenix currently supports `BUILD` imports through `buildFile` and related metadata.  
If your preferred source identity model (`repo/file:branch`) is not natively modeled yet, this utility encodes it into:

- `attributes.buildFile`
- tags (`repository`, `sourceFile`, `branch`, `assetKeyMode`)

This keeps imports usable now while preserving your desired identity convention.

## What it imports

- CycloneDX JSON SBOM (`bomFormat: CycloneDX`)
- Vulnerabilities as Phoenix findings
- Components as `installedSoftware`

## Files

- `sbom_sca_single_repo_to_phoenix.py` - main importer
- `config.ini.template` - config template
- `requirements.txt` - Python dependencies
- `QUICK_START.md` - fast setup/run

## Quick commands

```bash
# from repo root
cd Utils/sca-pipeline/sbom-single-repo
python3 -m pip install -r requirements.txt

# import one SBOM
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --repo acme/payments \
  --file-path package-lock.json \
  --branch main \
  --import-type merge

# preview payload only (no upload)
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --repo acme/payments \
  --file-path package-lock.json \
  --branch main \
  --dry-run \
  --payload-out payload-preview.json
```

## Security

- Do not hardcode credentials in source files
- Use environment variables or local `config.ini` (not committed)
- Auth flow follows Phoenix API v1.25:
  - `GET /v1/auth/access_token` with Basic Auth (`client_id:client_secret`)
  - `POST /v1/import/assets` with Bearer token

## Example command

```bash
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --repo acme/payments \
  --file-path package-lock.json \
  --branch main \
  --config config.ini
```

## Bitbucket Pipeline mode

Use Bitbucket environment variables for repository and branch:

```bash
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --file-path package-lock.json \
  --from-bitbucket-env \
  --import-type merge
```

The script reads:

- `BITBUCKET_REPO_FULL_NAME` -> `repository`
- `BITBUCKET_BRANCH` -> `branch`
- `BITBUCKET_COMMIT` -> extra tag `commit`
- `BITBUCKET_BUILD_NUMBER` -> extra tag `ciBuildNumber`
- `BITBUCKET_WORKSPACE` + `BITBUCKET_REPO_SLUG` + build number -> extra tag `ciPipelineUrl`

## Utils repository map (top-level folders and purpose)

This utility is part of the broader `Utils/` ecosystem. Use this map as a quick index when you need related tooling.

| Subfolder | Purpose |
| --- | --- |
| `Backstage Translator/` | Convert Backstage/ServiceNow catalog data into Phoenix-compatible YAML/config structures |
| `Config_File_autogen/` | Auto-generate Phoenix configuration files from repository or metadata inputs |
| `Gating/` | CI/CD policy gating (pass/fail) based on vulnerability and risk thresholds |
| `Jenkins Integration/` | Jenkins pipeline integration templates/scripts for Phoenix workflows |
| `Loading Script_V2/` | Legacy scanner import implementation (deprecated generation) |
| `Loading_Script_V2_Pub/` | Public/portable legacy V2 import scripts (deprecated generation) |
| `Loading_Script_V5/` | Internal advanced scanner-import stack (test assets, service, lambda, synthetic tooling) |
| `Loading_Script_V5_PUB/` | Production public scanner import utility for multi-scanner ingestion |
| `Nucleus/` | Legacy Nucleus integration scripts |
| `Nucleustophoenix/` | Migration tooling from Nucleus into Phoenix |
| `Shodan conversion/` | Convert Shodan outputs into Phoenix-consumable formats |
| `Test/` | Utility-level test assets/scratch validation content |
| `asset-count-scripts/` | Asset counting/inventory scripts for cloud, git, and Wiz sources |
| `asset-translator/` | Normalize and transform asset files into Phoenix-ready structures |
| `client scripts/` | Client-specific translators/automation (for example Q2 and Okta workflows) |
| `container scan/` | Container scan-related helper scripts/data transformations |
| `container3rp/` | Third-party container report processing and Phoenix import support |
| `csv_translator/` | Convert CSV/JSON vulnerability exports and upload to Phoenix |
| `docs/` | Shared Utils architecture, operations, and development documentation |
| `logos/` | Branding/media assets for Utils documentation and reporting |
| `pentest-import/` | Import penetration-test findings from CSV-like sources |
| `prowler extractor/` | Parse/reshape Prowler output for downstream ingestion/reporting |
| `report-Team_dashboard_report/` | Team-focused dashboard report generation |
| `report-asset_and_vulnerability_report/` | Combined asset + vulnerability report generation |
| `report-dashboard/` | Executive dashboard/report generation (PDF/Excel) |
| `report-vulnerability_report/` | Vulnerability-centric report generator |
| `sca-pipeline/` | SCA-focused pipeline utilities (includes this `sbom-single-repo` tool) |
| `technology-determination/` | Technology stack detection/classification using NVD/CPE mappings |

## Linked documentation (start here)

- Utils system map: `../../CLAUDE.md`
- Utils docs router: `../../DOC_INDEX.md`
- Utility selection guide: `../../UTILS_MASTER_INDEX.md`
- SCA quick runbook: `./QUICK_START.md`

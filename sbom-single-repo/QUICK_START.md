# sbom-single-repo — Quick Start

## 1) Move to utility folder and install dependencies

```bash
# from repository root
cd Utils/sca-pipeline/sbom-single-repo
python3 -m pip install -r requirements.txt
```

## 2) Configure Phoenix credentials

Option A - environment variables:

```bash
export PHOENIX_CLIENT_ID="<your-client-id>"
export PHOENIX_CLIENT_SECRET="<your-client-secret>"
export PHOENIX_API_BASE_URL="https://api.securityphoenix.cloud"
```

Option B - local config file:

```bash
cp config.ini.template config.ini
# edit config.ini with your values
```

## 3) Run import

```bash
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --repo acme/payments \
  --file-path package-lock.json \
  --branch main \
  --import-type merge
```

## 4) Dry-run and payload preview (recommended first run)

```bash
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --repo acme/payments \
  --file-path package-lock.json \
  --branch main \
  --dry-run \
  --payload-out payload-preview.json
```

## 5) Bitbucket Pipelines mode

If running in Bitbucket Pipelines, use:

```bash
python3 sbom_sca_single_repo_to_phoenix.py \
  --sbom-file sbom.cdx.json \
  --file-path package-lock.json \
  --from-bitbucket-env \
  --import-type merge
```

You can still override any value manually (for example `--repo` or `--branch`).

## 6) Quick repo navigation commands

```bash
# return to Utils root
cd ../..

# inspect top-level utilities
/bin/ls -a

# open ecosystem map
open CLAUDE.md

# open docs router
open DOC_INDEX.md
```

## 7) Utils subfolder purpose map

Use this as a quick "what is where" reference when navigating `Utils/`.

| Subfolder | Purpose |
| --- | --- |
| `Backstage Translator/` | Backstage/ServiceNow catalog translation into Phoenix data models |
| `Config_File_autogen/` | Automated Phoenix configuration generation |
| `Gating/` | Security policy gate execution in CI/CD |
| `Jenkins Integration/` | Jenkins integration helpers |
| `Loading Script_V2/` | Legacy import scripts |
| `Loading_Script_V2_Pub/` | Legacy public import scripts |
| `Loading_Script_V5/` | Internal V5 scanner import framework |
| `Loading_Script_V5_PUB/` | Public production scanner import framework |
| `Nucleus/` | Legacy Nucleus integration |
| `Nucleustophoenix/` | Nucleus-to-Phoenix migration utility |
| `Shodan conversion/` | Shodan data conversion scripts |
| `Test/` | Utility tests/scratch datasets |
| `asset-count-scripts/` | Cloud/git/Wiz asset inventory counters |
| `asset-translator/` | Asset normalization/translation scripts |
| `client scripts/` | Client-specific translators and workflows |
| `container scan/` | Container scan helper tools |
| `container3rp/` | Third-party container report ingestion |
| `csv_translator/` | CSV/JSON vulnerability conversion + upload |
| `docs/` | Shared Utils documentation |
| `logos/` | Branding assets |
| `pentest-import/` | Pentest findings import |
| `prowler extractor/` | Prowler output extraction/transform |
| `report-Team_dashboard_report/` | Team dashboard reporting |
| `report-asset_and_vulnerability_report/` | Asset and vulnerability reporting |
| `report-dashboard/` | Executive dashboard reporting |
| `report-vulnerability_report/` | Vulnerability-focused reporting |
| `sca-pipeline/` | SCA pipeline utilities, including this utility |
| `technology-determination/` | Technology detection/classification |

## 8) Linked docs (authoritative)

- `../../CLAUDE.md` - Utils system map and architecture overview
- `../../DOC_INDEX.md` - docs router (best first stop)
- `../../UTILS_MASTER_INDEX.md` - utility selection + shared config model

## Notes

- Asset identity is sent as `buildFile=repo/file:branch`
- Findings are imported from CycloneDX `vulnerabilities[]`
- Components are attached as `installedSoftware[]`

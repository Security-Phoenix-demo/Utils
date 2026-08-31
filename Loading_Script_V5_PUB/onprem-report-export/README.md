# On-Prem Scanner Report Export for Phoenix Loading Script V5

This folder contains generic helper scripts for exporting reports from on-premise scanner appliances and loading those reports into Phoenix with the V5 loading script (`phoenix_multi_scanner_enhanced.py`) that lives in the parent folder.

Supported sources:

- JFrog X-Ray vulnerability reports.
- Sonatype Nexus IQ application reports.

The workflow is push-only from the customer's environment:

1. Export scanner reports from internal appliances.
2. Store the reports locally in `./reports` or another approved staging folder.
3. Load the reports into Phoenix over outbound HTTPS using the V5 loading script.

## Files

| File | Purpose |
|---|---|
| `config.env.example` | Template for Phoenix, JFrog X-Ray, and Sonatype Nexus IQ runtime configuration. |
| `export_xray.sh` | Exports a JFrog X-Ray vulnerabilities report to JSON. |
| `export_sonatype.sh` | Exports and normalizes one Sonatype Nexus IQ application report to JSON. |
| `run_all.sh` | Runs export and Phoenix upload for the configured scanner scope. |
| `lib_phoenix.sh` | Writes the V5 Phoenix config file and invokes `phoenix_multi_scanner_enhanced.py`. |
| `scanner_field_mappings.yaml` | **Required.** Field mappings for both exporters. Replaces (does not merge with) the bundled toolkit mapping while `run_all.sh` runs — see note below. |

## Prerequisites

- `bash`
- `curl`
- `jq`
- `python3`
- Phoenix Loading Script V5 in the parent folder.
- A JFrog X-Ray service token with access to generate/read reports.
- A Sonatype Nexus IQ user token or service account with access to application reports.
- Phoenix API credentials for the target tenant.

## Configure

```bash
cp config.env.example config.env
chmod 600 config.env
```

Edit `config.env` and set the scanner URLs, credentials, initial scope, Phoenix API URL, and Phoenix API credentials.

## Export Reports Only

```bash
set -a
source config.env
set +a

./export_xray.sh
./export_sonatype.sh "<sonatype-application-public-id>"
```

Each export script prints the generated report path on the last line of output.

## Export And Upload To Phoenix

```bash
./run_all.sh
```

`run_all.sh` exports the configured scanner reports, then calls the V5 loading script with:

```bash
python3 ../phoenix_multi_scanner_enhanced.py \
  --file reports/<scanner-report>.json \
  --scanner <scanner-token> \
  --assessment "<assessment-name>" \
  --import-type merge \
  --config ./config.ini \
  --verify-import
```

Recommended scanner tokens:

- `jfrog_xray_unified`
- `sonatype`

Use `PHOENIX_IMPORT_TYPE=merge` for repeated scheduled runs.

## How Field Mapping Resolves

`FieldMapper` in `scanner_field_mapper.py` loads `scanner_field_mappings.yaml`
relative to the **current working directory**. `run_all.sh` does
`cd "$(dirname "$0")"`, so the copy in this folder is what gets loaded — the
toolkit's bundled 200-scanner mapping is not read during these runs, and the two
files are never merged.

That is deliberate: both exporters emit their own normalized JSON shape, and
pinning the mapping beside them keeps this workflow stable regardless of changes
to the bundled file. Two rules follow:

- Any scanner loaded from this folder must be defined in this file.
- Keep `file_patterns` narrow. A bare `*.json` pattern will also match the other
  exporter's output, and the report will be silently mis-mapped to the wrong
  scanner and imported with zero findings.

## Security Notes

- Do not commit `config.env`, `config.ini`, generated reports, logs, debug files, or scanner credentials.
- Use service accounts with the minimum required scanner permissions.
- Treat exported scanner reports as sensitive security data.
- Keep the first run small: one JFrog project/repository and one Sonatype application.

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

> **If you upload these files yourself, run the loader from this folder.**
> `python3 ../phoenix_multi_scanner_enhanced.py` invoked from the V5 parent
> directory reads the *bundled* `scanner_field_mappings.yaml` instead of the one
> here, under which the X-Ray export is detected as `gitleaks` and the Sonatype
> export as `twistlock` — both import zero findings and zero asset attributes
> without raising an error. See [How Field Mapping Resolves](#how-field-mapping-resolves).
> `run_all.sh` and `phoenix_load_v5` guard against this; a hand-rolled command
> does not.

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

Scanner tokens — do not change these:

- `jfrog_xray_unified`
- `sonatype`

`XRAY_V5_SCANNER` and `SONATYPE_V5_SCANNER` exist only so the token can track a
rename of the corresponding key in `scanner_field_mappings.yaml`. Both scripts
refuse to run if the configured token is not defined in that file, because a
token that resolves to a hard-coded translator instead — `jfrog`, for example —
is handed a shape that translator rejects, and the import completes with zero
findings and no error.

Use `PHOENIX_IMPORT_TYPE=merge` for repeated scheduled runs.

## How Field Mapping Resolves

`FieldMapper` in `scanner_field_mapper.py` loads `scanner_field_mappings.yaml`
relative to the **current working directory** — not relative to the loader.
`run_all.sh` does `cd "$(dirname "$0")"`, so the copy in this folder is what gets
loaded. The bundled mapping is not read during these runs, and the two files are
never merged.

**This folder's mapping is not an optimisation, it is a prerequisite.** The
toolkit's bundled `scanner_field_mappings.yaml` opens `scanners:` at line 44 and
closes it at line 1470; the ~167 scanner blocks appended after
`asset_type_detection:` (line 1492) are parsed as children of *that* key
instead. `yaml.safe_load` therefore exposes only 36 of the advertised 200
scanners, and both `jfrog_xray_unified` (line 3598) and `sonatype` (line 5211)
are among the unreachable ones:

```
scanners loaded:                  36
scanner keys present in text:    200
'jfrog_xray_unified' in scanners: False
'sonatype' in scanners:           False
```

So there is no bundled definition for either scanner to fall back to. Loading
one of these reports against the bundled file does not fail — it scores the
remaining 36 entries and picks the best match, which is `gitleaks` (CODE) for
the X-Ray export and `twistlock` (CONTAINER) for the Sonatype export, each
yielding zero findings and zero asset attributes.

Two rules follow:

- **Always invoke the loader with this folder as the working directory.**
  `phoenix_load_v5` enforces it; a hand-rolled `python3 ../…` command does not.
- Any scanner loaded from this folder must be defined in this file, and
  `file_patterns` must stay narrow. A bare `*.json` pattern would also match the
  other exporter's output and silently mis-map it.

The bundled-mapping nesting bug is a pre-existing toolkit issue and is
deliberately not fixed here — it costs the V5 loader 164 of its 200 scanners and
should be tracked separately.

## Asset Model

Both exporters normalize to a shape that produces **one Phoenix asset per
report**, keyed on the configured scope (the X-Ray project/repository) or the
Nexus IQ application public id. Repeated runs therefore update one stable asset
rather than creating new ones.

For X-Ray this is a deliberate trade-off against the toolkit's own
`JFrogXRayTranslator`, which handles the raw Reports API output natively and
groups findings by `impacted_artifact` into one BUILD asset *per artifact*, with
`package_type` retained. That granularity is lost here. If per-artifact assets
are wanted instead, drop the `rows[]` flattening in `export_xray.sh` and write
the raw X-Ray rows unchanged: `_is_unified_format` keys off
`rows[0].provider == "JFrog"` plus `vulnerable_component`/`issue_id`, which the
current flattening strips, and the file would then route to the native
translator without needing a mapping entry at all.

## Security Notes

- Do not commit `config.env`, `config.ini`, generated reports, logs, debug files, or scanner credentials.
- The generated `config.ini` holds no credentials. Both config readers in the V5
  loader seed `PhoenixConfig` from `PHOENIX_CLIENT_ID` / `PHOENIX_CLIENT_SECRET` /
  `PHOENIX_API_BASE_URL` before falling back to the ini, and `phoenix_load_v5`
  exports all three, so the client secret never needs a second copy on disk.
  `config.env` remains the only file holding secrets — keep it `chmod 600`.
- Use service accounts with the minimum required scanner permissions.
- Treat exported scanner reports as sensitive security data.
- Keep the first run small: one JFrog project/repository and one Sonatype application.

#!/usr/bin/env bash
# =============================================================================
# lib_phoenix.sh - Phoenix auth/config helpers and V5 loading wrapper.
#
# Requires: bash, curl, jq, python3, and Loading Script V5.
# Source this file; do not execute it directly.
# =============================================================================

# Resolve the V5 entrypoint. Honours an explicit V5_SCRIPT, otherwise tries the
# known layouts: this folder ships inside the V5 tree, one level below
# phoenix_multi_scanner_enhanced.py.
phoenix_resolve_v5_script() {
  local here candidate
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

  if [[ -n "${V5_SCRIPT:-}" && -f "${V5_SCRIPT}" ]]; then
    printf '%s' "$V5_SCRIPT"
    return 0
  fi

  for candidate in \
    "${here}/../phoenix_multi_scanner_enhanced.py" \
    "${here}/../../Loading_Script_V5/phoenix_multi_scanner_enhanced.py" \
    "${here}/../../Loading_Script_V5_PUB/phoenix_multi_scanner_enhanced.py"
  do
    if [[ -f "$candidate" ]]; then
      printf '%s' "$candidate"
      return 0
    fi
  done

  echo "ERROR: could not locate phoenix_multi_scanner_enhanced.py. Set V5_SCRIPT in config.env." >&2
  return 1
}

phoenix_get_token() {
  local base resp token
  # Strip a trailing slash: the export scripts already do this for their own
  # base URLs, and "https://host//v1/auth/..." 404s in a way that looks like a
  # credential problem.
  base="${PHOENIX_API_BASE_URL%/}"
  resp="$(curl -fsS -u "${PHOENIX_CLIENT_ID}:${PHOENIX_CLIENT_SECRET}" \
                "${base}/v1/auth/access_token")" \
    || { echo "ERROR: Phoenix auth failed (check client_id/secret/base_url)" >&2; return 1; }
  token="$(jq -er '.token' <<<"$resp")" \
    || { echo "ERROR: no token in Phoenix auth response" >&2; return 1; }
  printf '%s' "$token"
}

# configparser uses BasicInterpolation, so a literal '%' in any value raises
# InterpolationSyntaxError when the loader reads the section. Escape as '%%'.
_phoenix_ini_escape() {
  printf '%s' "${1//%/%%}"
}

phoenix_write_v5_config() {
  local path="${1:-./config.ini}"

  # Credentials are deliberately NOT written here. Both config readers in the V5
  # loader (_load_configuration_safe in phoenix_multi_scanner_enhanced.py and
  # load_configuration in phoenix_import_refactored.py) seed PhoenixConfig from
  # PHOENIX_CLIENT_ID / PHOENIX_CLIENT_SECRET / PHOENIX_API_BASE_URL first and
  # only fall back to the ini when those are empty. phoenix_load_v5 exports all
  # three, so writing the client secret to disk buys nothing and just creates a
  # second copy of it to protect.
  #
  # umask only applies to files being created, so a config.ini left over from an
  # earlier run would keep its old (possibly world-readable) mode. chmod
  # explicitly, and scope the umask to a subshell so it does not leak.
  ( umask 077
    cat > "$path" <<INI
[phoenix]
# client_id / client_secret / api_base_url come from the environment.
assessment_name = $(_phoenix_ini_escape "${PHOENIX_ASSESSMENT}")
import_type = $(_phoenix_ini_escape "${IMPORT_TYPE:-${PHOENIX_IMPORT_TYPE:-merge}}")
auto_import = true
wait_for_completion = true
INI
  )
  chmod 600 "$path"
  echo "$path"
}

# The V5 FieldMapper loads "scanner_field_mappings.yaml" relative to the process
# CWD, so the loader must be invoked from this folder. Guard it rather than let
# the run silently pick up the toolkit's bundled mapping, under which both
# exports mis-detect as unrelated scanners and import zero findings.
phoenix_assert_local_mapping() {
  local scanner="$1" mapping="scanner_field_mappings.yaml"

  if [[ ! -f "$mapping" ]]; then
    echo "ERROR: $mapping not found in $(pwd)." >&2
    echo "       The V5 loader resolves the scanner mapping relative to the current" >&2
    echo "       working directory. Run this from the onprem-report-export folder." >&2
    return 1
  fi

  # Resolve the key with the same parser FieldMapper uses, so this check sees
  # exactly what the loader will see. A key that is present in the text but
  # nested under the wrong parent - the failure mode in the toolkit's own bundled
  # mapping, where ~167 scanner blocks sit under 'asset_type_detection:' and are
  # invisible to yaml.safe_load - is correctly reported as missing.
  local available
  if ! available="$("${PYTHON_BIN:-python3}" -c '
import sys, yaml
try:
    with open(sys.argv[1]) as fh:
        cfg = yaml.safe_load(fh) or {}
except Exception as exc:
    sys.stderr.write("could not parse mapping: %s\n" % exc)
    raise SystemExit(2)
print(" ".join(sorted((cfg.get("scanners") or {}))))
' "$mapping" 2>&1)"; then
    echo "ERROR: could not read scanners from $mapping: $available" >&2
    return 1
  fi

  case " $available " in
    *" $scanner "*) return 0 ;;
  esac

  echo "ERROR: scanner '$scanner' is not defined under 'scanners:' in $mapping." >&2
  echo "       Defined here: ${available:-<none>}" >&2
  echo "       Do not point XRAY_V5_SCANNER / SONATYPE_V5_SCANNER at a token the" >&2
  echo "       toolkit resolves to a hard-coded translator (e.g. 'jfrog'): it will" >&2
  echo "       reject this normalized shape and import zero findings without error." >&2
  return 1
}

phoenix_load_v5() {
  local file="$1" scanner="$2" asset_name="${3:-}" script import_type
  [[ -s "$file" ]] || { echo "ERROR: report file empty/missing: $file" >&2; return 1; }

  phoenix_assert_local_mapping "$scanner" || return 1

  script="$(phoenix_resolve_v5_script)" || return 1

  # IMPORT_TYPE is only exported by run_all.sh; fall back so that sourcing this
  # file directly (as the header invites) does not trip set -u.
  import_type="${IMPORT_TYPE:-${PHOENIX_IMPORT_TYPE:-merge}}"

  # --asset-name is required, not cosmetic: phoenix_multi_scanner_enhanced.py
  # opens an interactive "ASSET NAME CONFIGURATION" stdin prompt for every
  # --file import that does not pass one, which hangs any scheduled run.
  # </dev/null is a second line of defence.
  [[ -n "$asset_name" ]] || asset_name="$PHOENIX_ASSESSMENT"

  export PHOENIX_CLIENT_ID PHOENIX_CLIENT_SECRET PHOENIX_API_BASE_URL

  # Note on --scanner: neither 'jfrog_xray_unified' nor 'sonatype' resolves to a
  # hard-coded translator (_find_translator_by_name has no entry for either, and
  # its substring fallback does not survive the underscores), so the loader logs
  # "no hard-coded translator found ... using YAML fallback" and picks the format
  # by content detection against scanner_field_mappings.yaml. The flag is passed
  # for provenance in the logs; the mapping is what actually selects the format.
  # phoenix_assert_local_mapping above enforces that the two stay consistent.
  "${PYTHON_BIN:-python3}" "$script" \
    --file "$file" \
    --scanner "$scanner" \
    --assessment "$PHOENIX_ASSESSMENT" \
    --asset-name "$asset_name" \
    --import-type "$import_type" \
    --config "${V5_CONFIG:-./config.ini}" \
    --verify-import </dev/null
}

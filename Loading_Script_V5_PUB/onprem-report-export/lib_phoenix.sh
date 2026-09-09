#!/usr/bin/env bash
# =============================================================================
# lib_phoenix.sh - Phoenix auth/config helpers and V5 loading wrapper.
#
# Requires: bash, curl, jq, python3, and Loading Script V5.
# Source this file; do not execute it directly.
# =============================================================================

# Resolve the V5 entrypoint. Honours an explicit V5_SCRIPT, otherwise tries the
# known layouts: this folder lives inside the V5 tree, which is published to the
# public repo as Loading_Script_V5_PUB.
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

phoenix_write_v5_config() {
  local path="${1:-./config.ini}"

  # umask only applies to files being created, so a config.ini left over from an
  # earlier run would keep its old (possibly world-readable) mode while holding
  # the Phoenix client secret. chmod explicitly, and scope the umask to a
  # subshell so it does not leak into the caller.
  ( umask 077
    cat > "$path" <<INI
[phoenix]
client_id = ${PHOENIX_CLIENT_ID}
client_secret = ${PHOENIX_CLIENT_SECRET}
api_base_url = ${PHOENIX_API_BASE_URL%/}
assessment_name = ${PHOENIX_ASSESSMENT}
import_type = ${IMPORT_TYPE:-${PHOENIX_IMPORT_TYPE:-merge}}
auto_import = true
wait_for_completion = true
INI
  )
  chmod 600 "$path"
  echo "$path"
}

phoenix_load_v5() {
  local file="$1" scanner="$2" asset_name="${3:-}" script import_type
  [[ -s "$file" ]] || { echo "ERROR: report file empty/missing: $file" >&2; return 1; }

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

  "${PYTHON_BIN:-python3}" "$script" \
    --file "$file" \
    --scanner "$scanner" \
    --assessment "$PHOENIX_ASSESSMENT" \
    --asset-name "$asset_name" \
    --import-type "$import_type" \
    --config "${V5_CONFIG:-./config.ini}" \
    --verify-import </dev/null
}

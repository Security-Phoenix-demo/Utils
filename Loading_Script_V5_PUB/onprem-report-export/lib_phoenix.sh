#!/usr/bin/env bash
# =============================================================================
# lib_phoenix.sh - Phoenix auth/config helpers and V5 loading wrapper.
#
# Requires: bash, curl, jq, python3, and Loading Script V5 PUB.
# Source this file; do not execute it directly.
# =============================================================================

phoenix_get_token() {
  local resp token
  resp="$(curl -fsS -u "${PHOENIX_CLIENT_ID}:${PHOENIX_CLIENT_SECRET}" \
                "${PHOENIX_API_BASE_URL}/v1/auth/access_token")" \
    || { echo "ERROR: Phoenix auth failed (check client_id/secret/base_url)" >&2; return 1; }
  token="$(jq -er '.token' <<<"$resp")" \
    || { echo "ERROR: no token in Phoenix auth response" >&2; return 1; }
  printf '%s' "$token"
}

phoenix_write_v5_config() {
  local path="${1:-./config.ini}"
  umask 077
  cat > "$path" <<INI
[phoenix]
client_id = ${PHOENIX_CLIENT_ID}
client_secret = ${PHOENIX_CLIENT_SECRET}
api_base_url = ${PHOENIX_API_BASE_URL}
assessment_name = ${PHOENIX_ASSESSMENT}
import_type = ${PHOENIX_IMPORT_TYPE}
auto_import = true
wait_for_completion = true
INI
  echo "$path"
}

phoenix_load_v5() {
  local file="$1" scanner="$2"
  [[ -s "$file" ]] || { echo "ERROR: report file empty/missing: $file" >&2; return 1; }
  [[ -f "$V5_SCRIPT" ]] || { echo "ERROR: V5 script not found at '$V5_SCRIPT'" >&2; return 1; }

  export PHOENIX_CLIENT_ID PHOENIX_CLIENT_SECRET PHOENIX_API_BASE_URL

  "$PYTHON_BIN" "$V5_SCRIPT" \
    --file "$file" \
    --scanner "$scanner" \
    --assessment "$PHOENIX_ASSESSMENT" \
    --import-type "$IMPORT_TYPE" \
    --config "${V5_CONFIG:-./config.ini}" \
    --verify-import
}

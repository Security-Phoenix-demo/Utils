#!/usr/bin/env bash
# =============================================================================
# run_all.sh - export on-prem scanner reports and load them into Phoenix using
# Loading Script V5 PUB.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

if [[ -f config.env ]]; then
  set -a
  source config.env
  set +a
else
  echo "ERROR: config.env not found. Copy config.env.example and fill it in." >&2
  exit 1
fi

source ./lib_phoenix.sh

: "${PHOENIX_ASSESSMENT:?set PHOENIX_ASSESSMENT}"
: "${PHOENIX_API_BASE_URL:?set PHOENIX_API_BASE_URL}"
: "${V5_SCRIPT:?set V5_SCRIPT}"

IMPORT_TYPE="${PHOENIX_IMPORT_TYPE:-merge}"
export IMPORT_TYPE
export OUT_DIR="${OUT_DIR:-./reports}"
export PYTHON_BIN="${PYTHON_BIN:-python3}"

for bin in curl jq "$PYTHON_BIN"; do
  command -v "$bin" >/dev/null || { echo "missing dependency: $bin" >&2; exit 1; }
done

echo "== Phoenix on-prem scanner export =="
echo "   assessment : $PHOENIX_ASSESSMENT"
echo "   importType : $IMPORT_TYPE"
echo "   api base   : $PHOENIX_API_BASE_URL"
echo "   v5 script  : $V5_SCRIPT"

phoenix_get_token >/dev/null && echo "   auth       : ok"

V5_CONFIG="$(phoenix_write_v5_config ./config.ini)"
export V5_CONFIG
echo "   v5 config  : $V5_CONFIG"

rc=0

echo
echo "-- JFrog X-Ray --"
if xray_file="$(bash ./export_xray.sh)"; then
  phoenix_load_v5 "$xray_file" "${XRAY_V5_SCANNER:-jfrog_xray_unified}" || rc=1
else
  echo "!! X-Ray export failed, skipping load" >&2
  rc=1
fi

echo
echo "-- Sonatype Nexus IQ --"
IFS=',' read -ra APPS <<<"${SONATYPE_APP_PUBLIC_IDS:-}"
for raw in "${APPS[@]}"; do
  app="$(echo "$raw" | xargs)"
  [[ -z "$app" ]] && continue
  echo "   app: $app"
  if son_file="$(bash ./export_sonatype.sh "$app")"; then
    phoenix_load_v5 "$son_file" "${SONATYPE_V5_SCANNER:-sonatype}" || rc=1
  else
    echo "!! Sonatype export failed for $app, skipping load" >&2
    rc=1
  fi
done

echo
echo "== done (exit $rc) =="
exit "$rc"

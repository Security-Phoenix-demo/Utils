#!/usr/bin/env bash
# =============================================================================
# run_all.sh - export on-prem scanner reports and load them into Phoenix using
# Loading Script V5.
#
# Each scanner is optional: X-Ray runs when JFROG_URL is set, Sonatype Nexus IQ
# runs when SONATYPE_APP_PUBLIC_IDS is set.
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"

if [[ -f config.env ]]; then
  set -a
  # shellcheck disable=SC1091
  source config.env
  set +a
else
  echo "ERROR: config.env not found. Copy config.env.example and fill it in." >&2
  exit 1
fi

# shellcheck disable=SC1091
source ./lib_phoenix.sh

: "${PHOENIX_ASSESSMENT:?set PHOENIX_ASSESSMENT}"
: "${PHOENIX_API_BASE_URL:?set PHOENIX_API_BASE_URL}"
: "${PHOENIX_CLIENT_ID:?set PHOENIX_CLIENT_ID}"
: "${PHOENIX_CLIENT_SECRET:?set PHOENIX_CLIENT_SECRET}"

IMPORT_TYPE="${PHOENIX_IMPORT_TYPE:-merge}"
export IMPORT_TYPE
export OUT_DIR="${OUT_DIR:-./reports}"
export PYTHON_BIN="${PYTHON_BIN:-python3}"

for bin in curl jq "$PYTHON_BIN"; do
  command -v "$bin" >/dev/null || { echo "missing dependency: $bin" >&2; exit 1; }
done

# Resolved rather than required: this folder ships inside the V5 tree.
V5_SCRIPT="$(phoenix_resolve_v5_script)"
export V5_SCRIPT

# Trim surrounding whitespace without invoking xargs, which also applies shell
# quote/backslash processing and would mangle (or, on an unmatched quote, fail
# on) ids containing those characters.
trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

# Decide what is in scope before doing any work.
run_xray=false
run_sonatype=false
[[ -n "$(trim "${JFROG_URL:-}")" ]] && run_xray=true
[[ -n "$(trim "${SONATYPE_APP_PUBLIC_IDS:-}")" ]] && run_sonatype=true

if [[ "$run_xray" == false && "$run_sonatype" == false ]]; then
  echo "ERROR: nothing to do. Set JFROG_URL and/or SONATYPE_APP_PUBLIC_IDS in config.env." >&2
  exit 1
fi

echo "== Phoenix on-prem scanner export =="
echo "   assessment : $PHOENIX_ASSESSMENT"
echo "   importType : $IMPORT_TYPE"
echo "   api base   : ${PHOENIX_API_BASE_URL%/}"
echo "   v5 script  : $V5_SCRIPT"
echo "   x-ray      : $run_xray"
echo "   sonatype   : $run_sonatype"

# Fail fast on bad credentials. `cmd && echo ok` is exempt from set -e, so an
# auth failure there printed an error and carried on exporting regardless.
if ! phoenix_get_token >/dev/null; then
  echo "ERROR: aborting before export - Phoenix credentials were rejected." >&2
  exit 1
fi
echo "   auth       : ok"

V5_CONFIG="$(phoenix_write_v5_config ./config.ini)"
export V5_CONFIG
echo "   v5 config  : $V5_CONFIG"

rc=0

if [[ "$run_xray" == true ]]; then
  echo
  echo "-- JFrog X-Ray --"
  if xray_file="$(bash ./export_xray.sh)"; then
    phoenix_load_v5 "$xray_file" "${XRAY_V5_SCANNER:-jfrog_xray_unified}" \
      "${XRAY_ASSET_NAME:-${XRAY_PROJECT_KEY:-${XRAY_REPOSITORIES:-jfrog-xray}}}" || rc=1
  else
    echo "!! X-Ray export failed, skipping load" >&2
    rc=1
  fi
fi

if [[ "$run_sonatype" == true ]]; then
  echo
  echo "-- Sonatype Nexus IQ --"
  # Note: "${ARR[@]}" on an empty array is an unbound-variable error under
  # set -u on bash 3.2 (still the default /bin/bash on macOS), hence the
  # explicit length guard and the ${ARR[@]+...} expansion below.
  IFS=',' read -ra APPS <<<"${SONATYPE_APP_PUBLIC_IDS}"
  if (( ${#APPS[@]} == 0 )); then
    echo "!! SONATYPE_APP_PUBLIC_IDS is set but contains no application ids" >&2
    rc=1
  fi
  for raw in ${APPS[@]+"${APPS[@]}"}; do
    app="$(trim "$raw")"
    [[ -z "$app" ]] && continue
    echo "   app: $app"
    if son_file="$(bash ./export_sonatype.sh "$app")"; then
      # Asset name is the application public id, so repeated runs update one
      # stable asset per application.
      phoenix_load_v5 "$son_file" "${SONATYPE_V5_SCANNER:-sonatype}" "$app" || rc=1
    else
      echo "!! Sonatype export failed for $app, skipping load" >&2
      rc=1
    fi
  done
fi

echo
echo "== done (exit $rc) =="
exit "$rc"

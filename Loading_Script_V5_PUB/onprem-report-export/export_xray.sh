#!/usr/bin/env bash
# =============================================================================
# export_xray.sh - export a JFrog X-Ray vulnerabilities report to JSON.
#
# X-Ray Reports API flow:
#   1) POST /xray/api/v1/reports/vulnerabilities
#   2) POST /xray/api/v1/reports/vulnerabilities/{id}
#
# Requires: bash, curl, jq.
# Reads config from the environment. Prints the written report path on the last
# line of stdout.
# =============================================================================
set -euo pipefail

: "${JFROG_URL:?set JFROG_URL}"
: "${JFROG_TOKEN:?set JFROG_TOKEN}"

OUT_DIR="${OUT_DIR:-./reports}"
mkdir -p "$OUT_DIR"

API="${JFROG_URL%/}/xray/api/v1"
AUTH=(-H "Authorization: Bearer ${JFROG_TOKEN}")
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_FILE="${OUT_DIR}/xray_vulnerabilities_${TS}.json"

resources='{}'
if [[ -n "${XRAY_REPOSITORIES:-}" ]]; then
  repos_json="$(jq -R 'split(",") | map({name: (. | gsub("^ +| +$";""))})' <<<"$XRAY_REPOSITORIES")"
  resources="$(jq -n --argjson r "$repos_json" '{repositories: $r}')"
fi

filters='{}'
if [[ -n "${XRAY_SEVERITIES:-}" ]]; then
  sev_json="$(jq -R 'split(",") | map(gsub("^ +| +$";""))' <<<"$XRAY_SEVERITIES")"
  filters="$(jq -n --argjson s "$sev_json" '{severities: $s}')"
fi

body="$(jq -n --arg name "phoenix-export-${TS}" \
              --argjson resources "$resources" \
              --argjson filters "$filters" \
              '{name:$name, resources:$resources, filters:$filters}')"

gen_url="${API}/reports/vulnerabilities"
[[ -n "${XRAY_PROJECT_KEY:-}" ]] && gen_url="${gen_url}?projectKey=${XRAY_PROJECT_KEY}"

echo ">> Generating X-Ray vulnerabilities report..." >&2
report_id="$(curl -fsS -X POST "$gen_url" "${AUTH[@]}" \
                  -H 'Content-Type: application/json' -d "$body" \
             | jq -er '.report_id')"
echo "   report_id: $report_id" >&2

content_url="${API}/reports/vulnerabilities/${report_id}?num_of_rows=100&page_num="
page=1
tries=0
max_tries=60
tmp="$(mktemp)"
echo '[]' >"$tmp"

while :; do
  resp="$(curl -fsS -X POST "${content_url}${page}" "${AUTH[@]}" \
                -H 'Content-Type: application/json' -d '{"filters":{}}')" || true
  status="$(jq -r '.status // "ready"' <<<"$resp" 2>/dev/null || echo waiting)"
  if [[ "$status" != "ready" && "$status" != "completed" ]]; then
    tries=$((tries + 1))
    if (( tries > max_tries )); then
      echo "timed out generating report" >&2
      rm -f "$tmp"
      exit 1
    fi
    echo "   report not ready ($status), waiting... ($tries/$max_tries)" >&2
    sleep 5
    continue
  fi

  rows="$(jq -c '.rows // []' <<<"$resp")"
  n="$(jq 'length' <<<"$rows")"
  jq -c --argjson add "$rows" '. + $add' "$tmp" >"${tmp}.n" && mv "${tmp}.n" "$tmp"
  total="$(jq -r '.total_rows // 0' <<<"$resp")"
  echo "   page $page: +$n rows (total reported: $total)" >&2
  (( n < 100 )) && break
  page=$((page + 1))
done

jq -n --argjson rows "$(cat "$tmp")" '{total_rows: ($rows|length), rows: $rows}' >"$OUT_FILE"
rm -f "$tmp"

echo ">> Wrote $(jq '.total_rows' "$OUT_FILE") findings -> $OUT_FILE" >&2
echo "$OUT_FILE"

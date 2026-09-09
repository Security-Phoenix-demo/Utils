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

# Refuse to run unscoped: an empty `resources` asks X-Ray to report across the
# whole platform, contradicting the "keep the first run small" guidance.
if [[ -z "${XRAY_REPOSITORIES:-}" && -z "${XRAY_PROJECT_KEY:-}" ]]; then
  echo "ERROR: no X-Ray scope configured. Set XRAY_REPOSITORIES or XRAY_PROJECT_KEY in config.env." >&2
  exit 1
fi

resources='{}'
if [[ -n "${XRAY_REPOSITORIES:-}" ]]; then
  repos_json="$(jq -R 'split(",") | map(gsub("^ +| +$";"")) | map(select(. != "")) | map({name: .})' \
                <<<"$XRAY_REPOSITORIES")"
  resources="$(jq -n --argjson r "$repos_json" '{repositories: $r}')"
fi

filters='{}'
if [[ -n "${XRAY_SEVERITIES:-}" ]]; then
  sev_json="$(jq -R 'split(",") | map(gsub("^ +| +$";"")) | map(select(. != ""))' <<<"$XRAY_SEVERITIES")"
  filters="$(jq -n --argjson s "$sev_json" '{severities: $s}')"
fi

body="$(jq -n --arg name "phoenix-export-${TS}" \
              --argjson resources "$resources" \
              --argjson filters "$filters" \
              '{name:$name, resources:$resources, filters:$filters}')"

gen_url="${API}/reports/vulnerabilities"
if [[ -n "${XRAY_PROJECT_KEY:-}" ]]; then
  # URL-encode: project keys may contain characters that are unsafe in a query string.
  project_key_enc="$(jq -rn --arg v "$XRAY_PROJECT_KEY" '$v|@uri')"
  gen_url="${gen_url}?projectKey=${project_key_enc}"
fi

echo ">> Generating X-Ray vulnerabilities report..." >&2
report_id="$(curl -fsS -X POST "$gen_url" "${AUTH[@]}" \
                  -H 'Content-Type: application/json' -d "$body" \
             | jq -er '.report_id')"
echo "   report_id: $report_id" >&2

PAGE_SIZE=100
content_url="${API}/reports/vulnerabilities/${report_id}?num_of_rows=${PAGE_SIZE}&page_num="
page=1
tries=0
max_tries=60
tmp="$(mktemp)"
trap 'rm -f "$tmp" "${tmp}.n"' EXIT
echo '[]' >"$tmp"

while :; do
  # Distinguish a transport/auth failure from "the report is still generating".
  # With `|| true` a 401 looked identical to "not ready" and burned all 60
  # retries before reporting a misleading timeout.
  if ! resp="$(curl -fsS -X POST "${content_url}${page}" "${AUTH[@]}" \
                    -H 'Content-Type: application/json' -d '{"filters":{}}')"; then
    echo "ERROR: X-Ray report request failed (page $page). Check JFROG_URL, JFROG_TOKEN and token permissions." >&2
    exit 1
  fi

  status="$(jq -r '.status // "ready"' <<<"$resp")"
  if [[ "$status" != "ready" && "$status" != "completed" ]]; then
    tries=$((tries + 1))
    if (( tries > max_tries )); then
      echo "ERROR: timed out after $(( max_tries * 5 ))s waiting for report $report_id (last status: $status)" >&2
      exit 1
    fi
    echo "   report not ready ($status), waiting... ($tries/$max_tries)" >&2
    sleep 5
    continue
  fi

  rows="$(jq -c '.rows // []' <<<"$resp")"
  n="$(jq 'length' <<<"$rows")"
  jq -c --argjson add "$rows" '. + $add' "$tmp" >"${tmp}.n"
  mv "${tmp}.n" "$tmp"
  total="$(jq -r '.total_rows // 0' <<<"$resp")"
  echo "   page $page: +$n rows (total reported: $total)" >&2
  (( n < PAGE_SIZE )) && break
  page=$((page + 1))
done

# X-Ray report rows use the Reports API schema (cves[], summary,
# impacted_artifact*, fixed_versions, issue_id). The Phoenix mapping expects
# flat rows[].{vuln,cve,severity,package,description,fix}, so normalize here.
# Field names vary across X-Ray versions, hence the `//` fallback chains.
# Read the accumulator as jq's input rather than passing it via --argjson: a
# realistic export is megabytes of JSON and would exceed ARG_MAX ("Argument list
# too long") only after every page had already been fetched.
jq --arg scope "${XRAY_PROJECT_KEY:-${XRAY_REPOSITORIES:-jfrog-xray}}" '
  def first_cve:
    ( (.cves // [])
      | map(if type == "object" then (.cve // .cve_id // empty) else . end)
      | map(select(. != null and . != ""))
      | .[0] ) // .cve // .cve_id // "";
  def artifact:
    ( .impacted_artifact
      // .impacted_artifact_name
      // .vulnerable_component
      // .impacted_artifact_path
      // .component
      // "unknown-artifact" );
  def score:
    ( (.cves // [])
      | map(if type == "object" then (.cvss_v3_score // .cvss_v3 // .cvss_v2_score // .cvss_v2 // empty) else empty end)
      | map(select(. != null and . != ""))
      | .[0] );
  . as $rows
  | {
    # Stable asset identity for the import: the configured scope, not
    # rows[0].package, which changes with whatever finding happens to sort first.
    scope: $scope,
    total_rows: ($rows | length),
    rows: ($rows | map(
      . as $r
      | ($r | first_cve) as $cve
      | ($r | artifact)  as $art
      | ($r | score)     as $sc
      | {
          vuln: (if $cve != "" then $cve else ($r.issue_id // $r.summary // "xray-issue") end),
          cve: $cve,
          severity: (if $sc != null then ($sc | tostring) else ($r.severity // "Medium") end),
          package: $art,
          description: ($r.summary // $r.description // ("X-Ray issue " + ($r.issue_id // "unknown") + " in " + $art)),
          fix: (
            ($r.fixed_versions // [])
            | map(select(. != null and . != ""))
            | if length > 0 then "Upgrade to: " + join(", ") else "No fixed version published by JFrog X-Ray" end
          )
        }
    ))
  }' "$tmp" >"$OUT_FILE"

found="$(jq -r '.total_rows' "$OUT_FILE")"
if [[ "$found" == "0" ]]; then
  echo "   WARNING: report is empty - check XRAY_REPOSITORIES / XRAY_SEVERITIES scope." >&2
fi
echo ">> Wrote $found findings -> $OUT_FILE" >&2
echo "$OUT_FILE"

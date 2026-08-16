#!/usr/bin/env bash
# =============================================================================
# export_sonatype.sh - export the latest Sonatype Nexus IQ application report.
#
# Nexus IQ API flow:
#   1) GET /api/v2/applications?publicId=<public-id>
#   2) GET /api/v2/reports/applications/<application-id>
#   3) GET <reportDataUrl>/raw
#
# Requires: bash, curl, jq.
# Usage: export_sonatype.sh <application-public-id>
# Prints the written report path on the last line of stdout.
# =============================================================================
set -euo pipefail

APP_PUBLIC_ID="${1:?usage: export_sonatype.sh <application-public-id>}"
: "${SONATYPE_URL:?set SONATYPE_URL}"
: "${SONATYPE_USER:?set SONATYPE_USER}"
: "${SONATYPE_TOKEN:?set SONATYPE_TOKEN}"

STAGE="${SONATYPE_STAGE:-release}"
OUT_DIR="${OUT_DIR:-./reports}"
mkdir -p "$OUT_DIR"

BASE="${SONATYPE_URL%/}"
AUTH=(-u "${SONATYPE_USER}:${SONATYPE_TOKEN}")
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_FILE="${OUT_DIR}/sonatype_${APP_PUBLIC_ID}_${STAGE}_${TS}.json"

echo ">> Resolving internal id for app '$APP_PUBLIC_ID'..." >&2
app_id="$(curl -fsS "${AUTH[@]}" "${BASE}/api/v2/applications?publicId=${APP_PUBLIC_ID}" \
          | jq -er '.applications[0].id')"
echo "   internal id: $app_id" >&2

echo ">> Finding latest '$STAGE' report..." >&2
data_url="$(curl -fsS "${AUTH[@]}" "${BASE}/api/v2/reports/applications/${app_id}" \
            | jq -er --arg s "$STAGE" '(map(select(.stage==$s)) | .[0].reportDataUrl) // empty')"
[[ -n "$data_url" ]] || { echo "ERROR: no '$STAGE' report for $APP_PUBLIC_ID" >&2; exit 1; }
echo "   reportDataUrl: $data_url" >&2

echo ">> Downloading raw report..." >&2
curl -fsS "${AUTH[@]}" "${BASE}/${data_url#/}/raw" -o "$OUT_FILE"

# Nexus IQ raw reports can place issues under
# components[].securityData.securityIssues[]. The Phoenix V5 Sonatype mapping
# expects components[].vulnerabilities[], so this preserves the original data
# and adds the normalized shape.
jq '
  .matchSummary //= {totalComponentCount: ((.components // []) | length), knownComponentCount: ((.components // []) | length)}
  | .components = ((.components // []) | map(
      if (.vulnerabilities? | type) == "array" then
        .
      else
        .vulnerabilities = ((.securityData.securityIssues // []) | map({
          vuln: (.reference // .id // .threatCategory // "sonatype-issue"),
          cve: (.reference // ""),
          severity: (
            if (.severity | type) == "number" then
              (if .severity >= 9 then "Critical"
               elif .severity >= 7 then "High"
               elif .severity >= 4 then "Medium"
               elif .severity > 0 then "Low"
               else "Negligible" end)
            else
              (.severity // "Medium")
            end
          ),
          package: (.packageUrl // .componentIdentifier.packageUrl // ""),
          description: (.reference // .id // .threatCategory // "Sonatype security issue"),
          fix: (.status // .remediation // "Review in Sonatype Nexus IQ")
        }))
      end
    ))
' "$OUT_FILE" >"${OUT_FILE}.normalized" && mv "${OUT_FILE}.normalized" "$OUT_FILE"

comps="$(jq -r '(.components | length) // "?"' "$OUT_FILE" 2>/dev/null || echo '?')"
echo ">> Wrote report ($comps components) -> $OUT_FILE" >&2
echo "$OUT_FILE"

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

# reportDataUrl is already the raw data path and normally ends in /raw. Only add
# the suffix when it is genuinely missing, otherwise the request 404s on /raw/raw.
raw_url="${BASE}/${data_url#/}"
[[ "$raw_url" == */raw ]] || raw_url="${raw_url%/}/raw"

echo ">> Downloading raw report..." >&2
curl -fsS "${AUTH[@]}" "$raw_url" -o "$OUT_FILE"

jq -e 'type == "object"' "$OUT_FILE" >/dev/null \
  || { echo "ERROR: Nexus IQ did not return a JSON report object ($raw_url)" >&2; exit 1; }

# Nexus IQ raw reports can place issues under
# components[].securityData.securityIssues[]. The Phoenix V5 Sonatype mapping
# expects components[].vulnerabilities[], so this preserves the original data
# and adds the normalized shape.
#
# NOTE: `$pkg` is bound from the enclosing component before mapping the issue
# list. Inside `map()` over securityIssues, `.packageUrl` would refer to the
# issue object (which has no such field), leaving Phoenix's required `location`
# field empty.
jq --arg app "$APP_PUBLIC_ID" --arg stage "$STAGE" '
  .matchSummary //= {totalComponentCount: ((.components // []) | length), knownComponentCount: ((.components // []) | length)}
  # Stable per-application asset identity. Keying the asset on a component (e.g.
  # components[0].packageUrl) both drifts between scans and collides across
  # applications that happen to share a first component, merging separate
  # Nexus IQ applications into one Phoenix asset.
  | .applicationId = $app
  | .components = ((.components // []) | map(
      if (.vulnerabilities? | type) == "array" then
        .
      else
        . as $c
        | ([ $c.packageUrl,
             $c.componentIdentifier.packageUrl,
             # npm/pypi/nuget coordinates use packageId/name rather than
             # groupId/artifactId; without those the fallback collapsed to a
             # bare version string like "4.17.11".
             ( ($c.componentIdentifier.coordinates // {})
               | [ .groupId, .artifactId, .packageId, .name, .version ]
               | map(select(. != null and . != ""))
               | if length > 0 then join(":") else null end ),
             $c.hash,
             $c.displayName
           ]
           | map(select(. != null and . != ""))
           | (.[0] // "unknown-component")) as $pkg
        | .vulnerabilities = (($c.securityData.securityIssues // []) | map({
          vuln: (.reference // .id // .threatCategory // "sonatype-issue"),
          cve: (if ((.reference // "") | test("^CVE-")) then .reference else "" end),
          severity: (
            if (.severity | type) == "number" then
              (.severity | tostring)
            else
              (.severity // "Medium")
            end
          ),
          package: $pkg,
          description: ((.threatCategory // "security") + " issue "
                        + (.reference // .id // "unknown")
                        + " in " + $pkg),
          # `.status` is deliberately absent from this chain: Nexus IQ
          # securityIssues carry no `remediation` field and `.status` is the
          # issue workflow state ("Open"), so including it rendered every
          # Phoenix remedy as the literal string "Open".
          fix: ("Review " + (.reference // .id // "this issue")
                + " for " + $pkg + " in Sonatype Nexus IQ"
                + " (application " + $app + ", stage " + $stage + ")")
        }))
      end
    ))
' "$OUT_FILE" >"${OUT_FILE}.normalized"
# Deliberately not `jq ... && mv`: an && list is exempt from set -e, so a failed
# normalization would skip the mv and still exit 0, uploading the raw report.
mv "${OUT_FILE}.normalized" "$OUT_FILE"

comps="$(jq -r '(.components | length) // 0' "$OUT_FILE")"
vulns="$(jq -r '[.components[]?.vulnerabilities[]?] | length' "$OUT_FILE")"
if [[ "$vulns" == "0" ]]; then
  echo "   WARNING: report contains no security issues - nothing will be imported." >&2
fi
echo ">> Wrote report ($comps components, $vulns findings) -> $OUT_FILE" >&2
echo "$OUT_FILE"

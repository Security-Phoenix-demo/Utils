"""
CycloneDX parsing and Phoenix payload construction.

Reads a CycloneDX JSON SBOM (Trivy, dep-scan VDR, cdxgen, Grype, or a vendor SBOM), maps its
components and vulnerabilities onto the Phoenix asset-import shape, and normalises severity.
"""

import json
import re
import urllib.parse
import os
from typing import Dict, List, Optional, Tuple


def read_sbom(path: str) -> Dict:
    if not os.path.exists(path):
        raise ValueError(
            f"SBOM file not found: {path}. Check that the scan stage ran and wrote its output "
            f"to this path."
        )
    if os.path.getsize(path) == 0:
        raise ValueError(
            f"SBOM file is empty: {path}. The scanner exited without writing a report - check "
            f"the scan stage logs."
        )

    with open(path, "r", encoding="utf-8") as handle:
        try:
            data = json.load(handle)
        except json.JSONDecodeError as exc:
            raise ValueError(f"SBOM file is not valid JSON ({path}): {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"SBOM file must contain a JSON object, got {type(data).__name__} ({path})")

    bom_format = data.get("bomFormat")
    # Compared case-insensitively. The spec says "CycloneDX" and every generator used here emits
    # exactly that, but some in-house scanners emit other casings and rejecting those is a
    # pointless failure - the document is still CycloneDX.
    if str(bom_format or "").lower() != "cyclonedx":
        hint = ""
        if "runs" in data:
            hint = " This looks like SARIF."
        elif "Results" in data or "SchemaVersion" in data:
            hint = " This looks like Trivy's native JSON - re-run with '--format cyclonedx'."
        elif "spdxVersion" in data:
            hint = " This looks like SPDX - re-generate the SBOM in CycloneDX format."
        raise ValueError(
            f"Input is not a CycloneDX JSON SBOM (bomFormat={bom_format!r}).{hint}"
        )
    return data


def build_component_maps(sbom: Dict) -> Tuple[Dict[str, str], List[Dict[str, str]]]:
    ref_to_name: Dict[str, str] = {}
    installed_software: List[Dict[str, str]] = []

    for comp in sbom.get("components", []):
        name = comp.get("name", "unknown")
        version = comp.get("version", "")
        bom_ref = comp.get("bom-ref", "")
        purl = comp.get("purl", "")
        publisher = comp.get("publisher", "") or comp.get("author", "")

        display = f"{name}@{version}" if version else name
        if bom_ref:
            ref_to_name[bom_ref] = display

        sw_entry = {"vendor": publisher or "unknown", "name": name, "version": version or "unknown"}
        if purl:
            sw_entry["cpe"] = purl
        installed_software.append(sw_entry)

    return ref_to_name, installed_software


# effected.sub_component is varchar(1024); anything longer fails the import outright.
LOCATION_MAX_LENGTH = 1024
# Affected component refs shown inline in `location`; the rest are summarised as "(+N more)".
LOCATION_MAX_REFS = 5

SEVERITY_TEXT_MAP = {
    "critical": "10.0",
    "high": "8.0",
    "medium": "5.0",
    "moderate": "5.0",
    "low": "2.0",
    "info": "1.0",
    "informational": "1.0",
    "none": "1.0",
}


def score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "10.0"
    if score >= 7.0:
        return "8.0"
    if score >= 4.0:
        return "5.0"
    if score > 0.0:
        return "2.0"
    return "1.0"


def normalize_severity(vuln: Dict) -> str:
    """
    Map CycloneDX ratings onto a Phoenix severity score.

    CycloneDX carries one rating per advisory source (ghsa, nvd, redhat, ...) in no
    guaranteed order, so the highest rating across every source is used rather than
    the first one encountered. A vulnerability with no usable rating at all falls back to
    5.0 (MEDIUM) rather than 0 or 1: dropping it under-reports, and LOW hides it beneath
    most tenants' default threshold, so MEDIUM keeps it visible for triage.
    Scanners such as Trivy derive their own headline
    severity the same way, which keeps imported severities aligned with the scan report.
    """
    ratings = vuln.get("ratings", [])
    best_score: Optional[float] = None
    text_severity: Optional[str] = None

    for rating in ratings:
        raw_score = rating.get("score")
        if raw_score is not None:
            try:
                candidate = float(raw_score)
            except (TypeError, ValueError):
                candidate = None
            if candidate is not None and (best_score is None or candidate > best_score):
                best_score = candidate

        raw_text = rating.get("severity")
        if raw_text:
            mapped = SEVERITY_TEXT_MAP.get(str(raw_text).strip().lower())
            if mapped and (text_severity is None or float(mapped) > float(text_severity)):
                text_severity = mapped

    candidates: List[str] = []
    if best_score is not None:
        candidates.append(score_to_severity(best_score))
    if text_severity:
        candidates.append(text_severity)
    if not candidates:
        return "5.0"
    return max(candidates, key=float)


def parse_reference_ids(vuln: Dict) -> List[str]:
    out: List[str] = []
    vuln_id = vuln.get("id", "")
    if vuln_id:
        out.append(vuln_id)

    for ref in vuln.get("references", []):
        if isinstance(ref, dict) and ref.get("id"):
            out.append(str(ref["id"]))
    # unique, preserve order
    unique: List[str] = []
    seen = set()
    for item in out:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def parse_cwes(vuln: Dict) -> List[str]:
    cwes = []
    for cwe in vuln.get("cwes", []):
        cwe_str = str(cwe)
        if cwe_str.startswith("CWE-"):
            cwes.append(cwe_str)
        else:
            cwes.append(f"CWE-{cwe_str}")
    return cwes


def _format_location(affected_components: List[str], fallback: str) -> str:
    """
    Render a finding's `location` without ever losing the "(+N more)" suffix.

    location lands in effected.sub_component, a varchar(1024): Postgres raises 22001
    instead of truncating, so the value has to be capped here. Capping the joined string
    afterwards cut the suffix off mid-word, which hid the fact that the list was partial
    and left the last component severed at an arbitrary character. Room for the suffix is
    reserved before joining instead, and the count covers every component the field does
    not name - those dropped for readability and those dropped for length alike. The
    complete list always stays in details.affected_components.
    """
    if not affected_components:
        return fallback[:LOCATION_MAX_LENGTH]

    total = len(affected_components)
    for count in range(min(LOCATION_MAX_REFS, total), 0, -1):
        omitted = total - count
        suffix = f" (+{omitted} more)" if omitted else ""
        body = ", ".join(affected_components[:count])
        if len(body) + len(suffix) <= LOCATION_MAX_LENGTH:
            return body + suffix

    # One name on its own already exceeds the column: truncate that name, and keep the
    # counter honest about the rest rather than reporting them as shown.
    omitted = total - 1
    suffix = f" (+{omitted} more)" if omitted else ""
    return affected_components[0][: max(0, LOCATION_MAX_LENGTH - len(suffix))] + suffix


def build_findings(sbom: Dict, ref_to_name: Dict[str, str], asset_key: str) -> List[Dict]:
    findings: List[Dict] = []
    for vuln in sbom.get("vulnerabilities", []):
        vuln_id = vuln.get("id", "UNKNOWN")
        affects = vuln.get("affects", [])
        affected_components: List[str] = []
        for affect in affects:
            if not isinstance(affect, dict):
                continue
            ref = affect.get("ref", "")
            if ref:
                affected_components.append(ref_to_name.get(ref, ref))
        location = _format_location(affected_components, asset_key)

        description = vuln.get("description") or f"Vulnerability {vuln_id} detected from CycloneDX SBOM"
        # recommendation, then workaround, then a generic string. A vulnerability carrying a
        # workaround but no recommendation would otherwise be reported with generic text in
        # place of real remediation advice. Trivy emits neither field, but other generators
        # (dep-scan VDRs) do. The fallback string is shared with the backend's server-side
        # translation path so the same vulnerability reads identically whichever route it
        # was imported by - keep the two in step if either changes.
        remedy = (
            vuln.get("recommendation")
            or vuln.get("workaround")
            or "See vulnerability advisory and update the affected package"
        )

        # Field limits follow the Phoenix schema rather than a round number.
        # vulnerability.description and vulnerability.remedy are Postgres `text` - unbounded -
        # so truncating them only discarded advisory content. The varchar(1024) limit on
        # effected.sub_component is load-bearing and is applied by _format_location, which
        # caps the value without severing the "(+N more)" suffix.
        finding = {
            "name": vuln_id,
            "description": description,
            "remedy": remedy,
            "severity": normalize_severity(vuln),
            "location": location,
            "referenceIds": parse_reference_ids(vuln),
        }

        cwes = parse_cwes(vuln)
        if cwes:
            finding["cwes"] = cwes

        finding["details"] = {
            "asset_key_mode": "repo/file:branch",
            "asset_key_value": asset_key,
            "affected_components": affected_components,
            "source": vuln.get("source", {}),
            "ratings": vuln.get("ratings", []),
        }
        findings.append(finding)
    return findings


def build_payload(
    sbom: Dict,
    assessment_name: str,
    import_type: str,
    repo: str,
    file_path: str,
    branch: str,
    origin: str,
    ci_meta: Optional[Dict[str, str]] = None,
) -> Dict:
    asset_key = f"{repo}/{file_path}:{branch}"
    ref_to_name, installed_software = build_component_maps(sbom)
    findings = build_findings(sbom, ref_to_name, asset_key)
    ci_meta = ci_meta or {}

    tags = [
        {"key": "scanner", "value": "cyclonedx"},
        {"key": "scanType", "value": "sca"},
        {"key": "repository", "value": repo},
        {"key": "branch", "value": branch},
        {"key": "sourceFile", "value": file_path},
        {"key": "assetKeyMode", "value": "repo/file:branch"},
    ]
    if ci_meta.get("commit"):
        tags.append({"key": "commit", "value": ci_meta["commit"]})
    if ci_meta.get("build_number"):
        tags.append({"key": "ciBuildNumber", "value": ci_meta["build_number"]})
    if ci_meta.get("pipeline_url"):
        tags.append({"key": "ciPipelineUrl", "value": ci_meta["pipeline_url"]})

    return {
        "importType": import_type,
        "assessment": {
            "assetType": "BUILD",
            "name": assessment_name,
        },
        "assets": [
            {
                "attributes": {
                    "buildFile": asset_key,
                    "origin": origin,
                },
                "tags": tags,
                "installedSoftware": installed_software,
                "findings": findings,
            }
        ],
    }


def container_identity_from_sbom(sbom: Dict) -> Dict[str, str]:
    """
    Pull image name, tag, digest and registry out of a container BOM's metadata.component.

    Trivy records the image as name:tag in `name` and repeats the detail in a purl and in
    aquasecurity properties. The digest is taken from the purl or RepoDigest; note it is
    whichever digest the build environment had, and an image built but not yet pushed may have
    none - so every field here is best-effort and absent keys are simply omitted.
    """
    component = (sbom.get("metadata") or {}).get("component") or {}
    out: Dict[str, str] = {}

    raw_name = str(component.get("name") or "")
    if raw_name:
        # "repo/image:tag" - split on the last colon only if it is not part of a port or digest.
        if ":" in raw_name and "/" not in raw_name.rsplit(":", 1)[1]:
            name, tag = raw_name.rsplit(":", 1)
            out["name"], out["version"] = name, tag
        else:
            out["name"] = raw_name

    if component.get("version"):
        out["version"] = str(component["version"])

    props = {p.get("name"): p.get("value") for p in component.get("properties") or []}
    purl = str(component.get("purl") or "")

    match = re.search(r"@(sha256:[0-9a-f]{64})", purl)
    if match:
        out["digest"] = match.group(1)
    else:
        repo_digest = str(props.get("aquasecurity:trivy:RepoDigest") or "")
        match = re.search(r"(sha256:[0-9a-f]{64})", repo_digest)
        if match:
            out["digest"] = match.group(1)

    registry = urllib.parse.parse_qs(urllib.parse.urlparse(purl).query).get("repository_url", [""])[0]
    if registry:
        # repository_url carries the full path; the registry host is its first segment.
        out["registry"] = registry.split("/")[0]

    return out

"""
CycloneDX parsing and Phoenix payload construction.

Reads a CycloneDX JSON SBOM (Trivy, dep-scan VDR, cdxgen, Grype, or a vendor SBOM), maps its
components and vulnerabilities onto the Phoenix asset-import shape, and normalises severity.
"""

import json
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
    if bom_format != "CycloneDX":
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
    the first one encountered. Scanners such as Trivy derive their own headline
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
        location = ", ".join(affected_components[:5]) if affected_components else asset_key

        description = vuln.get("description") or f"Vulnerability {vuln_id} detected from CycloneDX SBOM"
        remedy = vuln.get("recommendation") or "See vulnerability advisory and update the affected package"

        finding = {
            "name": vuln_id,
            "description": description[:500],
            "remedy": remedy[:500],
            "severity": normalize_severity(vuln),
            "location": location[:500],
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

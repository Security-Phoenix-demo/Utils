#!/usr/bin/env python3
"""
Single-repo CycloneDX SBOM importer for Phoenix.

Purpose:
- Read one CycloneDX JSON SBOM
- Build one BUILD asset keyed as repo/file:branch
- Import SBOM vulnerabilities into Phoenix /v1/import/assets
"""

import argparse
import configparser
import json
import os
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import requests
from requests.auth import HTTPBasicAuth


@dataclass
class PhoenixConfig:
    client_id: str
    client_secret: str
    api_base_url: str
    import_type: str
    assessment_name: str
    verify_tls: bool
    timeout_seconds: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Import CycloneDX SBOM findings to Phoenix as a single BUILD asset"
    )
    parser.add_argument("--sbom-file", required=True, help="Path to CycloneDX JSON file")
    parser.add_argument("--repo", help="Repository name, e.g. org/service")
    parser.add_argument("--file-path", help="Manifest/file path, e.g. package-lock.json")
    parser.add_argument("--branch", help="Branch name, e.g. main")
    parser.add_argument(
        "--from-bitbucket-env",
        action="store_true",
        help="Populate repo/branch/commit/build metadata from Bitbucket Pipeline environment variables",
    )
    parser.add_argument("--assessment-name", help="Phoenix assessment name override")
    parser.add_argument("--import-type", choices=["new", "merge", "delta"], help="Phoenix import type")
    parser.add_argument("--config", default="config.ini", help="INI configuration file")
    parser.add_argument("--origin", default="cyclonedx-sca", help="Phoenix asset origin value")
    parser.add_argument("--api-base-url", help="Phoenix API base URL override")
    parser.add_argument("--client-id", help="Phoenix client_id override")
    parser.add_argument("--client-secret", help="Phoenix client_secret override")
    parser.add_argument("--verify-tls", action="store_true", help="Force TLS certificate verification")
    parser.add_argument("--no-verify-tls", action="store_true", help="Disable TLS verification")
    parser.add_argument("--dry-run", action="store_true", help="Build payload but do not call Phoenix")
    parser.add_argument("--payload-out", help="Write generated JSON payload to this file")
    return parser.parse_args()


def load_config(config_file: str, args: argparse.Namespace) -> PhoenixConfig:
    parser = configparser.ConfigParser()
    if os.path.exists(config_file):
        parser.read(config_file)

    phoenix_section = parser["phoenix"] if "phoenix" in parser else {}
    options_section = parser["options"] if "options" in parser else {}

    client_id = args.client_id or os.getenv("PHOENIX_CLIENT_ID") or phoenix_section.get("client_id", "")
    client_secret = (
        args.client_secret or os.getenv("PHOENIX_CLIENT_SECRET") or phoenix_section.get("client_secret", "")
    )
    api_base_url = (
        args.api_base_url
        or os.getenv("PHOENIX_API_BASE_URL")
        or phoenix_section.get("api_base_url", "https://api.securityphoenix.cloud")
    ).rstrip("/")
    import_type = args.import_type or phoenix_section.get("import_type", "merge")
    assessment_name = args.assessment_name or phoenix_section.get("assessment_name", "single-repo-sca-sbom")

    verify_tls = True
    if options_section:
        verify_tls = options_section.get("verify_tls", "true").strip().lower() == "true"
    if args.verify_tls:
        verify_tls = True
    if args.no_verify_tls:
        verify_tls = False

    timeout_seconds = int(options_section.get("timeout_seconds", "60")) if options_section else 60

    missing = []
    if not client_id:
        missing.append("client_id")
    if not client_secret:
        missing.append("client_secret")
    if not api_base_url:
        missing.append("api_base_url")
    if missing:
        raise ValueError(f"Missing required Phoenix configuration: {', '.join(missing)}")

    return PhoenixConfig(
        client_id=client_id,
        client_secret=client_secret,
        api_base_url=api_base_url,
        import_type=import_type,
        assessment_name=assessment_name,
        verify_tls=verify_tls,
        timeout_seconds=timeout_seconds,
    )


def read_sbom(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if data.get("bomFormat") != "CycloneDX":
        raise ValueError("Input is not a CycloneDX JSON SBOM (bomFormat != CycloneDX)")
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


def normalize_severity(vuln: Dict) -> str:
    ratings = vuln.get("ratings", [])
    text = ""
    score = None

    for rating in ratings:
        if not text and rating.get("severity"):
            text = str(rating["severity"]).strip().lower()
        if score is None and rating.get("score") is not None:
            try:
                score = float(rating["score"])
            except (TypeError, ValueError):
                score = None

    if score is not None:
        if score >= 9.0:
            return "10.0"
        if score >= 7.0:
            return "8.0"
        if score >= 4.0:
            return "5.0"
        if score > 0.0:
            return "2.0"
        return "1.0"

    text_map = {
        "critical": "10.0",
        "high": "8.0",
        "medium": "5.0",
        "moderate": "5.0",
        "low": "2.0",
        "info": "1.0",
        "informational": "1.0",
    }
    return text_map.get(text, "5.0")


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


def resolve_repo_context(args: argparse.Namespace) -> Dict[str, str]:
    """
    Resolve required repository context from CLI and optionally Bitbucket env vars.
    """
    context = {
        "repo": args.repo or "",
        "file_path": args.file_path or "",
        "branch": args.branch or "",
        "commit": "",
        "build_number": "",
        "pipeline_url": "",
    }

    if args.from_bitbucket_env:
        context["repo"] = context["repo"] or os.getenv("BITBUCKET_REPO_FULL_NAME", "")
        context["branch"] = context["branch"] or os.getenv("BITBUCKET_BRANCH", "")
        context["commit"] = os.getenv("BITBUCKET_COMMIT", "")
        context["build_number"] = os.getenv("BITBUCKET_BUILD_NUMBER", "")

        workspace = os.getenv("BITBUCKET_WORKSPACE", "")
        repo_slug = os.getenv("BITBUCKET_REPO_SLUG", "")
        if workspace and repo_slug and context["build_number"]:
            context["pipeline_url"] = (
                f"https://bitbucket.org/{workspace}/{repo_slug}/pipelines/results/{context['build_number']}"
            )

    missing = []
    if not context["repo"]:
        missing.append("repo")
    if not context["file_path"]:
        missing.append("file_path")
    if not context["branch"]:
        missing.append("branch")
    if missing:
        mode_hint = " (tip: use --from-bitbucket-env in Bitbucket Pipelines)" if args.from_bitbucket_env else ""
        raise ValueError(f"Missing required repository context: {', '.join(missing)}{mode_hint}")

    return context


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
    bitbucket_meta: Optional[Dict[str, str]] = None,
) -> Dict:
    asset_key = f"{repo}/{file_path}:{branch}"
    ref_to_name, installed_software = build_component_maps(sbom)
    findings = build_findings(sbom, ref_to_name, asset_key)
    bitbucket_meta = bitbucket_meta or {}

    tags = [
        {"key": "scanner", "value": "cyclonedx"},
        {"key": "scanType", "value": "sca"},
        {"key": "repository", "value": repo},
        {"key": "branch", "value": branch},
        {"key": "sourceFile", "value": file_path},
        {"key": "assetKeyMode", "value": "repo/file:branch"},
    ]
    if bitbucket_meta.get("commit"):
        tags.append({"key": "commit", "value": bitbucket_meta["commit"]})
    if bitbucket_meta.get("build_number"):
        tags.append({"key": "ciBuildNumber", "value": bitbucket_meta["build_number"]})
    if bitbucket_meta.get("pipeline_url"):
        tags.append({"key": "ciPipelineUrl", "value": bitbucket_meta["pipeline_url"]})

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


def get_access_token(cfg: PhoenixConfig) -> str:
    url = f"{cfg.api_base_url}/v1/auth/access_token"
    response = requests.get(
        url,
        auth=HTTPBasicAuth(cfg.client_id, cfg.client_secret),
        timeout=cfg.timeout_seconds,
        verify=cfg.verify_tls,
    )
    if response.status_code != 200:
        raise RuntimeError(f"Token request failed: HTTP {response.status_code} - {response.text[:300]}")
    token = response.json().get("token")
    if not token:
        raise RuntimeError("Token request succeeded but no token returned")
    return token


def import_assets(cfg: PhoenixConfig, token: str, payload: Dict) -> Dict:
    url = f"{cfg.api_base_url}/v1/import/assets"
    response = requests.post(
        url,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json=payload,
        timeout=cfg.timeout_seconds,
        verify=cfg.verify_tls,
    )
    if response.status_code not in (200, 201):
        raise RuntimeError(f"Import failed: HTTP {response.status_code} - {response.text[:500]}")
    return response.json() if response.text.strip() else {"status": "accepted"}


def main() -> int:
    args = parse_args()

    try:
        cfg = load_config(args.config, args)
        sbom = read_sbom(args.sbom_file)
        context = resolve_repo_context(args)

        payload = build_payload(
            sbom=sbom,
            assessment_name=cfg.assessment_name,
            import_type=cfg.import_type,
            repo=context["repo"],
            file_path=context["file_path"],
            branch=context["branch"],
            origin=args.origin,
            bitbucket_meta=context,
        )

        if args.payload_out:
            with open(args.payload_out, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)

        assets_count = len(payload.get("assets", []))
        findings_count = len(payload["assets"][0].get("findings", [])) if assets_count else 0
        print(f"Prepared payload: assets={assets_count}, findings={findings_count}")

        if args.dry_run:
            print("Dry-run enabled: no API call was made.")
            return 0

        token = get_access_token(cfg)
        result = import_assets(cfg, token, payload)
        print("Import submitted successfully.")
        print(json.dumps(result, indent=2))
        return 0

    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

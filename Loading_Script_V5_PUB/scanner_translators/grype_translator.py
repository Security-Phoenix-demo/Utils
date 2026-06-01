#!/usr/bin/env python3
"""
Anchore Grype Scanner Translator
=================================

Translator for Anchore Grype container vulnerability scanner.

Supported Formats:
- Native Grype JSON (--output json)
- CycloneDX JSON (--output cyclonedx-json)  ← grype ≥ v0.40

Scanner Detection:
- Native: 'descriptor.name' == 'grype' or 'matches' with vulnerability/artifact
- CycloneDX: bomFormat == 'CycloneDX' AND metadata.tools contains 'grype'
             OR filename contains 'grype' and bomFormat == 'CycloneDX'

Asset Type: CONTAINER

Tagging / Attributes:
- All labels -> Phoenix asset tags (verbatim key/value).
- org.opencontainers.image.base.digest -> tag + asset_attributes['baseImageDigest']
- org.opencontainers.image.base.name   -> tag + asset_attributes['baseImageName']
- Missing / null / empty labels are tolerated; the translator never crashes.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig

logger = logging.getLogger(__name__)


class GrypeTranslator(ScannerTranslator):
    """Translator for Anchore Grype scanner results (native JSON + CycloneDX JSON)"""

    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a Grype scan file (native or CycloneDX format)"""
        if not file_path.lower().endswith('.json'):
            return False

        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)

            if not isinstance(file_content, dict):
                return False

            # --- Native Grype JSON ---
            if 'descriptor' in file_content:
                descriptor = file_content.get('descriptor', {})
                if isinstance(descriptor, dict) and descriptor.get('name', '').lower() == 'grype':
                    return True

            if 'matches' in file_content:
                matches = file_content.get('matches', [])
                if matches and isinstance(matches, list):
                    first = matches[0] if matches else {}
                    if 'vulnerability' in first and 'artifact' in first:
                        return True
                    if 'vulnerability' in first:
                        vuln = first.get('vulnerability', {})
                        if 'dataSource' in vuln or 'namespace' in vuln or 'fix' in vuln:
                            return True

            # --- CycloneDX JSON produced by grype --output cyclonedx-json ---
            if file_content.get('bomFormat') == 'CycloneDX':
                if self._is_cyclonedx_from_grype(file_content, file_path):
                    return True

            return False
        except Exception as e:
            logger.debug(f"GrypeTranslator.can_handle failed: {e}")
            return False

    @staticmethod
    def _is_cyclonedx_from_grype(data: dict, file_path: str) -> bool:
        """Return True when the CycloneDX document was produced by grype."""
        tools_section = data.get('metadata', {}).get('tools', {})
        tool_components = (
            tools_section.get('components', [])
            if isinstance(tools_section, dict)
            else tools_section if isinstance(tools_section, list)
            else []
        )
        for tool in tool_components:
            if isinstance(tool, dict) and 'grype' in tool.get('name', '').lower():
                return True
        # Fallback: filename hint (e.g. *-grype.json)
        return 'grype' in Path(file_path).name.lower()

    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Grype scan results (auto-detects native vs CycloneDX format)"""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to read Grype file: {e}")
            raise

        if data.get('bomFormat') == 'CycloneDX':
            logger.info(f"Parsing Grype CycloneDX output: {file_path}")
            return self._parse_cyclonedx(data, file_path)

        logger.info(f"Parsing Anchore Grype scan file: {file_path}")
        return self._parse_native(data)

    # ------------------------------------------------------------------
    # Native Grype JSON
    # ------------------------------------------------------------------

    def _parse_native(self, data: dict) -> List[AssetData]:
        source = data.get('source', {})
        source_type = source.get('type', 'unknown')
        target_info = source.get('target', {})

        if isinstance(target_info, dict):
            image_name = target_info.get('userInput', target_info.get('imageID', 'unknown'))
        else:
            image_name = str(target_info) if target_info else 'unknown'

        label_attributes, label_tags = self.promote_oci_labels(target_info)

        asset = AssetData(
            asset_type="CONTAINER",
            attributes={
                'dockerfile': image_name,
                'origin': 'anchore-grype',
                'repository': image_name,
                **label_attributes,
            },
            tags=self.tag_config.get_all_tags() + [
                {"key": "scanner", "value": "anchore-grype"},
                {"key": "source-type", "value": source_type},
            ] + label_tags
        )

        for match in data.get('matches', []):
            vuln_data = match.get('vulnerability', {})
            artifact_data = match.get('artifact', {})
            vuln_id = vuln_data.get('id', '')
            if not vuln_id:
                continue

            severity = vuln_data.get('severity', 'Unknown')
            cvss_list = vuln_data.get('cvss', [])
            cvss_v2_score = cvss_v3_score = None
            for cvss in cvss_list:
                ver = cvss.get('version', '')
                metrics = cvss.get('metrics', {})
                if ver.startswith('2'):
                    cvss_v2_score = metrics.get('baseScore')
                elif ver.startswith('3'):
                    cvss_v3_score = metrics.get('baseScore')

            fix_info = vuln_data.get('fix', {})
            fix_versions = fix_info.get('versions', [])
            fix_state = fix_info.get('state', 'unknown')
            pkg_name = artifact_data.get('name', '')

            vulnerability = VulnerabilityData(
                name=vuln_id,
                description=vuln_data.get('description', '') or f"Vulnerability {vuln_id} found in {pkg_name or 'package'}",
                remedy=f"Update {pkg_name or 'package'} to fixed version: {', '.join(fix_versions)}" if fix_versions else "No fix available",
                severity=self.normalize_severity(severity),
                location=f"{pkg_name}@{artifact_data.get('version', '')}",
                reference_ids=[vuln_id] if vuln_id.startswith(('CVE-', 'GHSA-')) else [],
                details={
                    'package_name': pkg_name,
                    'package_version': artifact_data.get('version', ''),
                    'package_type': artifact_data.get('type', ''),
                    'package_language': artifact_data.get('language', ''),
                    'fix_versions': fix_versions,
                    'fix_state': fix_state,
                    'cvss_v2_score': cvss_v2_score,
                    'cvss_v3_score': cvss_v3_score,
                    'data_source': vuln_data.get('dataSource', ''),
                    'namespace': vuln_data.get('namespace', ''),
                    'urls': vuln_data.get('urls', []),
                }
            )
            asset.findings.append(vulnerability.__dict__)

        assets = [self.ensure_asset_has_findings(asset)]
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets

    # ------------------------------------------------------------------
    # CycloneDX output from grype --output cyclonedx-json
    # ------------------------------------------------------------------

    def _parse_cyclonedx(self, data: dict, file_path: str) -> List[AssetData]:
        """Parse grype CycloneDX JSON output as a single CONTAINER asset.

        Image name resolution order:
        1. metadata.component.name  (e.g. "cfcm/edvin-cmx")
        2. filename stem with scanner suffix stripped (e.g. "edvin-cmx-2026.5.28-453")
        """
        meta_component = data.get('metadata', {}).get('component', {})
        image_name = meta_component.get('name', '').strip()
        if not image_name:
            stem = Path(file_path).stem
            for suffix in ('-grype', '-trivy', '-anchore'):
                if stem.lower().endswith(suffix):
                    stem = stem[:len(stem) - len(suffix)]
                    break
            image_name = stem

        logger.info(f"CycloneDX grype scan — target: {image_name}")

        # Build component lookup: bom-ref → component dict
        comp_index: Dict[str, dict] = {}
        for comp in data.get('components', []):
            ref = comp.get('bom-ref', '')
            if ref:
                comp_index[ref] = comp
            purl = comp.get('purl', '')
            if purl and purl not in comp_index:
                comp_index[purl] = comp

        asset = AssetData(
            asset_type="CONTAINER",
            attributes={
                'dockerfile': 'Dockerfile',
                'repository': image_name,
                'origin': 'anchore-grype',
            },
            tags=self.tag_config.get_all_tags() + [
                {"key": "scanner", "value": "anchore-grype"},
                {"key": "format", "value": "cyclonedx"},
            ]
        )

        for vuln in data.get('vulnerabilities', []):
            vuln_id = vuln.get('id', '')
            if not vuln_id:
                continue

            # Resolve affected component for location/package details
            affects = vuln.get('affects', [])
            comp = {}
            if affects:
                ref = affects[0].get('ref', '')
                comp = comp_index.get(ref, {})
                if not comp:
                    base_ref = ref.split('?')[0]
                    for k, v in comp_index.items():
                        if k.split('?')[0] == base_ref:
                            comp = v
                            break

            pkg_name = comp.get('name', '')
            pkg_version = comp.get('version', '')
            pkg_purl = comp.get('purl', '')

            # Severity + CVSS — prefer CVSSv3 rating
            severity = 'Unknown'
            cvss_score: Optional[float] = None
            for rating in vuln.get('ratings', []):
                method = rating.get('method', '')
                if 'CVSS' in method.upper() and '3' in method:
                    severity = rating.get('severity', severity)
                    cvss_score = rating.get('score')
                    break
            if severity == 'Unknown':
                for rating in vuln.get('ratings', []):
                    if 'severity' in rating:
                        severity = rating['severity']
                        cvss_score = cvss_score or rating.get('score')
                        break

            description = vuln.get('description', '') or f"Vulnerability {vuln_id} in {pkg_name or image_name}"
            if len(description) > 500:
                description = description[:497] + '...'

            advisories = vuln.get('advisories', [])
            urls = [a.get('url', '') for a in advisories if a.get('url')]

            vulnerability = VulnerabilityData(
                name=vuln_id,
                description=description,
                remedy=f"Review advisories for {vuln_id}" + (f": {urls[0]}" if urls else ""),
                severity=self.normalize_severity(severity),
                location=f"{pkg_name}@{pkg_version}" if pkg_name else image_name,
                reference_ids=[vuln_id] if vuln_id.startswith(('CVE-', 'GHSA-')) else [],
                details={
                    'package_name': pkg_name,
                    'package_version': pkg_version,
                    'package_purl': pkg_purl,
                    'cvss_score': cvss_score,
                    'advisories': urls,
                    'affects': [a.get('ref', '') for a in affects],
                }
            )
            asset.findings.append(vulnerability.__dict__)

        assets = [self.ensure_asset_has_findings(asset)]
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets


__all__ = ['GrypeTranslator']

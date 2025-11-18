#!/usr/bin/env python3
"""
Trivy Scanner Translator
=========================

Translator for Aqua Security Trivy vulnerability scanner.

Supported Formats:
- New format: dict with 'Results' array
- Legacy format: array with 'Target', 'Type', 'Vulnerabilities'
- Kubernetes format: dict with 'Resources' array

Scanner Detection:
- Checks for 'Results' in dict (new format)
- Checks for 'Resources' in dict (Kubernetes format)
- Checks for 'Target' + 'Vulnerabilities'/'Results' in array items (legacy)

Asset Types: CONTAINER (container/image scans), INFRA (Kubernetes scans)
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig

logger = logging.getLogger(__name__)


class TrivyTranslator(ScannerTranslator):
    """Translator for Trivy scanner results - handles multiple Trivy formats"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a Trivy scan file"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Check for Trivy-specific structures
            if isinstance(file_content, dict):
                # New format: Has "Results" array
                if 'Results' in file_content and isinstance(file_content.get('Results'), list):
                    return True
                # Kubernetes format: Has "Resources" array with "Results" nested
                if 'Resources' in file_content and isinstance(file_content.get('Resources'), list):
                    resources = file_content.get('Resources', [])
                    if resources and 'Results' in resources[0]:
                        return True
            elif isinstance(file_content, list):
                # Legacy format: Root is an array with Target, Type, Vulnerabilities
                if file_content and isinstance(file_content[0], dict):
                    first_item = file_content[0]
                    if 'Target' in first_item and ('Vulnerabilities' in first_item or 'Results' in first_item):
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"TrivyTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Trivy scan results - supports multiple formats"""
        logger.info(f"Parsing Trivy scan file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to parse Trivy file: {e}")
            raise
        
        assets = []
        
        # Detect format and parse accordingly
        if isinstance(data, dict):
            if 'Results' in data:
                # New format: Results[] → Vulnerabilities[] or Misconfigurations[]
                assets = self._parse_new_format(data, file_path)
            elif 'Resources' in data:
                # Kubernetes format: Resources[] → Results[] → Misconfigurations[] or Vulnerabilities[]
                assets = self._parse_kubernetes_format(data, file_path)
        elif isinstance(data, list):
            # Legacy format: Array of targets with Vulnerabilities[]
            assets = self._parse_legacy_format(data, file_path)
        
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets
    
    def _parse_new_format(self, data: Dict, file_path: str) -> List[AssetData]:
        """Parse new Trivy format: Results[] → Vulnerabilities[]"""
        assets = []
        
        # Get artifact info
        artifact_name = data.get('ArtifactName', data.get('ArtifactPath', 'unknown'))
        artifact_type = data.get('ArtifactType', 'CONTAINER')
        
        # Create asset
        asset_attributes = {
            'dockerfile': artifact_name if 'Dockerfile' not in artifact_name else 'Dockerfile',
            'origin': 'trivy',
            'repository': artifact_name
        }
        
        asset = AssetData(
            asset_type="CONTAINER",
            attributes=asset_attributes,
            tags=self.tag_config.get_all_tags() + [
                {"key": "scanner", "value": "trivy"},
                {"key": "artifact_type", "value": artifact_type}
            ]
        )
        
        # Process Results[] → Vulnerabilities[]
        results = data.get('Results', [])
        for result in results:
            target = result.get('Target', '')
            result_class = result.get('Class', '')
            
            # Process vulnerabilities
            vulnerabilities = result.get('Vulnerabilities', [])
            if vulnerabilities:
                for vuln_data in vulnerabilities:
                    vuln = self._create_vulnerability(vuln_data, target)
                    if vuln:
                        asset.findings.append(vuln)
            
            # Process misconfigurations
            misconfigs = result.get('Misconfigurations', [])
            if misconfigs:
                for misconfig_data in misconfigs:
                    vuln = self._create_misconfiguration_finding(misconfig_data, target)
                    if vuln:
                        asset.findings.append(vuln)
        
        assets.append(self.ensure_asset_has_findings(asset))
        return assets
    
    def _parse_legacy_format(self, data: List, file_path: str) -> List[AssetData]:
        """Parse legacy Trivy format: Array → Vulnerabilities[]"""
        assets = []
        
        for item in data:
            target = item.get('Target', 'unknown')
            target_type = item.get('Type', 'unknown')
            
            # Create asset
            asset_attributes = {
                'dockerfile': 'Dockerfile' if 'Dockerfile' in target else target,
                'origin': 'trivy',
                'repository': target
            }
            
            asset = AssetData(
                asset_type="CONTAINER",
                attributes=asset_attributes,
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "trivy"},
                    {"key": "target_type", "value": target_type}
                ]
            )
            
            # Process vulnerabilities
            vulnerabilities = item.get('Vulnerabilities', [])
            if vulnerabilities:
                for vuln_data in vulnerabilities:
                    vuln = self._create_vulnerability(vuln_data, target)
                    if vuln:
                        asset.findings.append(vuln)
            
            assets.append(self.ensure_asset_has_findings(asset))
        
        return assets
    
    def _parse_kubernetes_format(self, data: Dict, file_path: str) -> List[AssetData]:
        """Parse Kubernetes Trivy format: Resources[] → Results[] → Misconfigurations[]"""
        assets = []
        
        resources = data.get('Resources', [])
        for resource in resources:
            namespace = resource.get('Namespace', 'default')
            kind = resource.get('Kind', 'unknown')
            name = resource.get('Name', 'unknown')
            
            # Create asset - INFRA type requires hostname
            asset_attributes = {
                'dockerfile': f"{kind}/{name}",
                'origin': 'trivy-kubernetes',
                'repository': f"{namespace}/{kind}/{name}",
                'hostname': f"{name}.{namespace}.k8s"  # Add hostname for INFRA assets
            }
            
            asset = AssetData(
                asset_type="INFRA",
                attributes=asset_attributes,
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "trivy"},
                    {"key": "kubernetes_namespace", "value": namespace},
                    {"key": "kubernetes_kind", "value": kind}
                ]
            )
            
            # Process Results[] → Misconfigurations[] or Vulnerabilities[]
            results = resource.get('Results', [])
            for result in results:
                target = result.get('Target', '')
                
                # Process misconfigurations
                misconfigs = result.get('Misconfigurations', [])
                if misconfigs:
                    for misconfig_data in misconfigs:
                        vuln = self._create_misconfiguration_finding(misconfig_data, target)
                        if vuln:
                            asset.findings.append(vuln)
                
                # Process vulnerabilities
                vulnerabilities = result.get('Vulnerabilities', [])
                if vulnerabilities:
                    for vuln_data in vulnerabilities:
                        vuln = self._create_vulnerability(vuln_data, target)
                        if vuln:
                            asset.findings.append(vuln)
            
            assets.append(self.ensure_asset_has_findings(asset))
        
        return assets
    
    def _create_vulnerability(self, vuln_data: Dict, target: str) -> Optional[Dict]:
        """Create a vulnerability finding from Trivy data"""
        vuln_id = vuln_data.get('VulnerabilityID', '')
        if not vuln_id:
            return None
        
        # Get severity
        severity = vuln_data.get('Severity', 'UNKNOWN')
        
        # Get package info
        pkg_name = vuln_data.get('PkgName', '')
        installed_version = vuln_data.get('InstalledVersion', '')
        fixed_version = vuln_data.get('FixedVersion', '')
        
        # Get dates
        published_date = vuln_data.get('PublishedDate', '')
        last_modified_date = vuln_data.get('LastModifiedDate', '')
        
        # Format published date to Phoenix format (ISO-8601 with T separator)
        if published_date:
            try:
                dt = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                published_date = dt.strftime("%Y-%m-%dT%H:%M:%S")
            except:
                published_date = None
        
        # Get CWE IDs
        cwe_ids = vuln_data.get('CweIDs', [])
        
        # Create remedy
        if fixed_version:
            remedy = f"Update {pkg_name} from {installed_version} to {fixed_version}"
        else:
            remedy = "No fix available"
        
        vulnerability = VulnerabilityData(
            name=vuln_id,
            description=vuln_data.get('Description', vuln_data.get('Title', 'No description available')),
            remedy=remedy,
            severity=self.normalize_severity(severity),
            location=f"{pkg_name}@{installed_version}" if pkg_name else target,
            reference_ids=[vuln_id] if vuln_id.startswith('CVE-') else [],
            published_date_time=published_date,
            details={
                'package_name': pkg_name,
                'installed_version': installed_version,
                'fixed_version': fixed_version,
                'target': target,
                'severity_source': vuln_data.get('SeveritySource', ''),
                'primary_url': vuln_data.get('PrimaryURL', ''),
                'references': vuln_data.get('References', []),
                'cwe_ids': cwe_ids,
                'last_modified_date': last_modified_date
            }
        )
        
        return vulnerability.__dict__
    
    def _create_misconfiguration_finding(self, misconfig_data: Dict, target: str) -> Optional[Dict]:
        """Create a misconfiguration finding from Trivy data"""
        vuln_id = misconfig_data.get('ID', misconfig_data.get('AVDID', ''))
        if not vuln_id:
            return None
        
        # Get severity
        severity = misconfig_data.get('Severity', 'UNKNOWN')
        
        vulnerability = VulnerabilityData(
            name=vuln_id,
            description=misconfig_data.get('Description', misconfig_data.get('Message', 'No description available')),
            remedy=misconfig_data.get('Resolution', 'No remedy provided'),
            severity=self.normalize_severity(severity),
            location=target,
            reference_ids=[vuln_id],
            details={
                'type': misconfig_data.get('Type', ''),
                'title': misconfig_data.get('Title', ''),
                'message': misconfig_data.get('Message', ''),
                'primary_url': misconfig_data.get('PrimaryURL', ''),
                'references': misconfig_data.get('References', []),
                'status': misconfig_data.get('Status', ''),
                'namespace': misconfig_data.get('Namespace', ''),
                'query': misconfig_data.get('Query', '')
            }
        )
        
        return vulnerability.__dict__


__all__ = ['TrivyTranslator']


#!/usr/bin/env python3
"""
JFrog XRay Scanner Translators
==============================

Hard-coded translators for all JFrog XRay format variations:
1. JFrog XRay Unified
2. JFrog XRay API Summary Artifact
3. JFrog XRay On-Demand Binary Scan
4. JFrogXray (legacy)

Author: Auto-generated from comprehensive test results
Date: 2025-11-11
"""

import json
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime
from pathlib import Path

# Import base classes (adjust imports based on your structure)
try:
    from phoenix_import_refactored import AssetData, VulnerabilityData
    from phoenix_multi_scanner_import import ScannerTranslator, error_tracker
    from tag_utils import get_tags_safely
except ImportError:
    # Fallback for testing
    pass

logger = logging.getLogger(__name__)


class JFrogXRayAPISummaryArtifactTranslator(ScannerTranslator):
    """Translator for JFrog XRay API Summary Artifact format
    
    Format: artifacts[] → issues[] structure
    Example: {"artifacts": [{"general": {...}, "issues": [...]}]}
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect JFrog XRay API Summary Artifact format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            if isinstance(file_content, dict):
                # Check for artifacts[] with issues[] structure
                if 'artifacts' in file_content:
                    artifacts = file_content.get('artifacts', [])
                    if artifacts and isinstance(artifacts, list):
                        first_artifact = artifacts[0]
                        # JFrog specific: has 'general', 'issues', 'licenses'
                        if 'general' in first_artifact and 'issues' in first_artifact:
                            return True
            
            return False
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse JFrog XRay API Summary Artifact scan results"""
        logger.info(f"Parsing JFrog XRay API Summary Artifact file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            error_tracker.log_error(e, "JFrog XRay API Summary Parsing", file_path, "parse_file")
            raise
        
        assets = []
        artifacts = data.get('artifacts', [])
        
        for artifact in artifacts:
            general = artifact.get('general', {})
            issues = artifact.get('issues', [])
            
            # Extract artifact info
            artifact_name = general.get('name', general.get('component_id', 'unknown'))
            pkg_type = general.get('pkg_type', 'unknown')
            path = general.get('path', '')
            sha256 = general.get('sha256', '')
            
            # Create asset
            asset_attributes = {
                'dockerfile': 'Dockerfile' if pkg_type == 'Docker' else artifact_name,
                'origin': 'jfrog-xray',
                'repository': artifact_name
            }
            
            asset = AssetData(
                asset_type="CONTAINER" if pkg_type in ['Docker', 'OCI'] else "BUILD",
                attributes=asset_attributes,
                tags=get_tags_safely(self.tag_config) + [
                    {"key": "scanner", "value": "jfrog-xray"},
                    {"key": "package_type", "value": pkg_type},
                    {"key": "sha256", "value": sha256[:12] if sha256 else "unknown"}
                ]
            )
            
            # Parse issues (vulnerabilities)
            for issue in issues:
                vuln = self._parse_issue(issue, artifact_name)
                if vuln:
                    asset.findings.append(vuln)
            
            assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets
    
    def _parse_issue(self, issue: Dict, artifact_name: str) -> Optional[Dict]:
        """Parse a single JFrog issue into vulnerability format"""
        issue_id = issue.get('issue_id', issue.get('cve', 'UNKNOWN'))
        if not issue_id:
            return None
        
        # Get CVEs
        cves_list = issue.get('cves', [])
        cves = []
        cvss_v3_score = None
        
        if cves_list:
            for cve_data in cves_list:
                if isinstance(cve_data, dict):
                    cves.append(cve_data.get('cve', issue_id))
                    if not cvss_v3_score:
                        cvss_v3 = cve_data.get('cvss_v3', '')
                        if cvss_v3 and '/' in cvss_v3:
                            try:
                                cvss_v3_score = float(cvss_v3.split('/')[0])
                            except:
                                pass
        
        if not cves:
            cves = [issue_id]
        
        # Map severity
        severity = issue.get('severity', 'Unknown')
        severity_num = self.normalize_severity(severity)
        
        # Get impact path
        impact_paths = issue.get('impact_path', [])
        location = impact_paths[0] if impact_paths else artifact_name
        
        # Create vulnerability
        vulnerability = VulnerabilityData(
            name=issue_id,
            description=issue.get('description', issue.get('summary', f"JFrog XRay issue: {issue_id}")),
            remedy=f"See JFrog recommendations for {issue_id}",
            severity=severity_num,
            location=str(location),
            reference_ids=cves,
            details={
                'issue_type': issue.get('issue_type', 'security'),
                'provider': issue.get('provider', 'JFrog'),
                'created': issue.get('created', ''),
                'impact_path': impact_paths,
                'cvss_v3_score': cvss_v3_score
            }
        )
        
        return vulnerability.__dict__


class JFrogXRayUnifiedTranslator(ScannerTranslator):
    """Translator for JFrog XRay Unified format
    
    Format: rows[] structure with CVE details
    Example: {"total_rows": 1, "rows": [{"cves": [...], "summary": "..."}]}
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect JFrog XRay Unified format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            if isinstance(file_content, dict):
                # Check for rows[] structure with JFrog-specific fields
                if 'rows' in file_content and 'total_rows' in file_content:
                    rows = file_content.get('rows', [])
                    if rows and isinstance(rows, list) and len(rows) > 0:
                        first_row = rows[0]
                        # JFrog specific: has vulnerable_component, impacted_artifact
                        if 'vulnerable_component' in first_row or 'issue_id' in first_row:
                            if 'provider' in first_row and first_row.get('provider') == 'JFrog':
                                return True
            
            return False
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse JFrog XRay Unified scan results"""
        logger.info(f"Parsing JFrog XRay Unified file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            error_tracker.log_error(e, "JFrog XRay Unified Parsing", file_path, "parse_file")
            raise
        
        assets = []
        rows = data.get('rows', [])
        
        # Group vulnerabilities by impacted artifact
        artifacts_dict = {}
        
        for row in rows:
            artifact_name = row.get('impacted_artifact', row.get('vulnerable_component', 'unknown'))
            
            if artifact_name not in artifacts_dict:
                artifacts_dict[artifact_name] = []
            
            vuln = self._parse_row(row)
            if vuln:
                artifacts_dict[artifact_name].append(vuln)
        
        # Create assets
        for artifact_name, vulns in artifacts_dict.items():
            pkg_type = artifact_name.split('://')[0] if '://' in artifact_name else 'unknown'
            
            asset_attributes = {
                'dockerfile': 'Dockerfile' if pkg_type == 'docker' else artifact_name,
                'origin': 'jfrog-xray',
                'repository': artifact_name
            }
            
            asset = AssetData(
                asset_type="BUILD",
                attributes=asset_attributes,
                tags=get_tags_safely(self.tag_config) + [
                    {"key": "scanner", "value": "jfrog-xray-unified"},
                    {"key": "package_type", "value": pkg_type}
                ]
            )
            
            asset.findings.extend(vulns)
            assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets
    
    def _parse_row(self, row: Dict) -> Optional[Dict]:
        """Parse a single row into vulnerability format"""
        issue_id = row.get('issue_id', 'UNKNOWN')
        if not issue_id:
            return None
        
        # Get CVEs
        cves_list = row.get('cves', [])
        cves = []
        cvss_v3_score = row.get('cvss3_max_score')
        
        for cve_data in cves_list:
            if isinstance(cve_data, dict):
                cves.append(cve_data.get('cve', issue_id))
        
        if not cves:
            cves = [issue_id]
        
        # Map severity
        severity = row.get('severity', 'Unknown')
        severity_num = self.normalize_severity(severity)
        
        # Get component info
        vulnerable_component = row.get('vulnerable_component', '')
        fixed_versions = row.get('fixed_versions', [])
        remedy = f"Upgrade to version: {', '.join(fixed_versions)}" if fixed_versions else "No fix available"
        
        # Create vulnerability
        vulnerability = VulnerabilityData(
            name=issue_id,
            description=row.get('description', row.get('summary', f"JFrog XRay issue: {issue_id}")),
            remedy=remedy,
            severity=severity_num,
            location=vulnerable_component,
            reference_ids=cves,
            details={
                'provider': row.get('provider', 'JFrog'),
                'package_type': row.get('package_type', 'unknown'),
                'path': row.get('path', ''),
                'impact_path': row.get('impact_path', []),
                'fixed_versions': fixed_versions,
                'published': row.get('published', ''),
                'cvss_v3_score': cvss_v3_score,
                'references': row.get('references', [])
            }
        )
        
        return vulnerability.__dict__


class JFrogXRayOnDemandTranslator(ScannerTranslator):
    """Translator for JFrog XRay On-Demand Binary Scan format
    
    Format: Array of scan results with vulnerabilities
    Example: [{"scan_id": "...", "vulnerabilities": [...], "component_id": "..."}]
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect JFrog XRay On-Demand format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # On-Demand format is an array at root
            if isinstance(file_content, list) and len(file_content) > 0:
                first_item = file_content[0]
                # Check for JFrog On-Demand specific fields
                if 'scan_id' in first_item and 'vulnerabilities' in first_item:
                    if 'component_id' in first_item or 'package_type' in first_item:
                        return True
            
            return False
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse JFrog XRay On-Demand scan results"""
        logger.info(f"Parsing JFrog XRay On-Demand file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            error_tracker.log_error(e, "JFrog XRay On-Demand Parsing", file_path, "parse_file")
            raise
        
        assets = []
        
        # Data is an array of scan results
        if not isinstance(data, list):
            data = [data]
        
        for scan_result in data:
            component_id = scan_result.get('component_id', 'unknown')
            package_type = scan_result.get('package_type', 'unknown')
            scan_id = scan_result.get('scan_id', 'unknown')
            vulnerabilities = scan_result.get('vulnerabilities', [])
            
            # Create asset
            asset_attributes = {
                'dockerfile': 'Dockerfile' if package_type in ['Docker', 'OCI'] else component_id,
                'origin': 'jfrog-xray-ondemand',
                'repository': component_id
            }
            
            asset = AssetData(
                asset_type="BUILD",
                attributes=asset_attributes,
                tags=get_tags_safely(self.tag_config) + [
                    {"key": "scanner", "value": "jfrog-xray-ondemand"},
                    {"key": "package_type", "value": package_type},
                    {"key": "scan_id", "value": scan_id[:12] if scan_id else "unknown"}
                ]
            )
            
            # Parse vulnerabilities
            for vuln_data in vulnerabilities:
                vuln = self._parse_vulnerability(vuln_data, component_id)
                if vuln:
                    asset.findings.append(vuln)
            
            assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets
    
    def _parse_vulnerability(self, vuln_data: Dict, component_id: str) -> Optional[Dict]:
        """Parse a single vulnerability"""
        issue_id = vuln_data.get('issue_id', 'UNKNOWN')
        if not issue_id:
            return None
        
        # Get CVEs
        cves_list = vuln_data.get('cves', [])
        cves = []
        cvss_v3_score = None
        
        for cve_data in cves_list:
            if isinstance(cve_data, dict):
                cves.append(cve_data.get('cve', issue_id))
        
        if not cves:
            cves = [issue_id]
        
        # Map severity
        severity = vuln_data.get('severity', 'Unknown')
        severity_num = self.normalize_severity(severity)
        
        # Get component info and fixed versions
        components = vuln_data.get('components', {})
        fixed_versions = []
        impact_paths = []
        
        for comp_name, comp_data in components.items():
            if isinstance(comp_data, dict):
                comp_fixed = comp_data.get('fixed_versions', [])
                fixed_versions.extend(comp_fixed)
                comp_paths = comp_data.get('impact_paths', [])
                impact_paths.extend(comp_paths)
        
        remedy = f"Upgrade to version: {', '.join(fixed_versions)}" if fixed_versions else "No fix available"
        
        # Create vulnerability
        vulnerability = VulnerabilityData(
            name=issue_id,
            description=vuln_data.get('summary', f"JFrog XRay issue: {issue_id}"),
            remedy=remedy,
            severity=severity_num,
            location=component_id,
            reference_ids=cves,
            details={
                'fixed_versions': fixed_versions,
                'impact_paths': impact_paths,
                'references': vuln_data.get('references', [])
            }
        )
        
        return vulnerability.__dict__


class JFrogXrayLegacyTranslator(ScannerTranslator):
    """Translator for legacy JFrogXray format
    
    Format: {"total_count": N, "data": [...]} with component_versions structure
    Different from Unified format
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect legacy JFrogXray format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Legacy format has total_count and data[] with specific structure
            if isinstance(file_content, dict):
                if 'total_count' in file_content and 'data' in file_content:
                    data = file_content.get('data', [])
                    if data and isinstance(data, list) and len(data) > 0:
                        first_item = data[0]
                        # Check for JFrog legacy specific fields
                        if 'component_versions' in first_item and 'source_comp_id' in first_item:
                            return True
            
            return False
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse legacy JFrogXray scan results"""
        logger.info(f"Parsing legacy JFrogXray file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data_root = json.load(f)
        except Exception as e:
            error_tracker.log_error(e, "JFrogXray Legacy Parsing", file_path, "parse_file")
            raise
        
        assets = []
        data_items = data_root.get('data', [])
        
        # Group by component
        components_dict = {}
        
        for item in data_items:
            component = item.get('component', item.get('source_comp_id', 'unknown'))
            
            if component not in components_dict:
                components_dict[component] = []
            
            vuln = self._parse_legacy_item(item)
            if vuln:
                components_dict[component].append(vuln)
        
        # Create assets
        for component, vulns in components_dict.items():
            asset_attributes = {
                'dockerfile': 'Dockerfile',
                'origin': 'jfrogxray-legacy',
                'repository': component
            }
            
            asset = AssetData(
                asset_type="BUILD",
                attributes=asset_attributes,
                tags=get_tags_safely(self.tag_config) + [
                    {"key": "scanner", "value": "jfrogxray-legacy"}
                ]
            )
            
            asset.findings.extend(vulns)
            assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets
    
    def _parse_legacy_item(self, item: Dict) -> Optional[Dict]:
        """Parse a legacy JFrogXray data item"""
        # Get CVEs from component_versions.more_details.cves
        component_versions = item.get('component_versions', {})
        more_details = component_versions.get('more_details', {})
        cves_list = more_details.get('cves', [])
        
        cves = []
        cvss_v3_score = None
        
        for cve_data in cves_list:
            if isinstance(cve_data, dict):
                cve_id = cve_data.get('cve', '')
                if cve_id:
                    cves.append(cve_id)
                    if not cvss_v3_score:
                        cvss_v3 = cve_data.get('cvss_v3', '')
                        if cvss_v3 and '/' in cvss_v3:
                            try:
                                cvss_v3_score = float(cvss_v3.split('/')[0])
                            except:
                                pass
        
        # Use first CVE as vulnerability ID, or create one
        vuln_id = cves[0] if cves else item.get('id', 'UNKNOWN')
        if not vuln_id or vuln_id == '':
            return None
        
        # Get severity
        severity = item.get('severity', 'Unknown')
        severity_num = self.normalize_severity(severity)
        
        # Get fixed versions
        fixed_versions = component_versions.get('fixed_versions', [])
        remedy = f"Upgrade to version: {', '.join(fixed_versions)}" if fixed_versions else "No fix available"
        
        # Create vulnerability
        vulnerability = VulnerabilityData(
            name=vuln_id,
            description=more_details.get('description', item.get('summary', f"JFrogXray issue: {vuln_id}"))[:500],
            remedy=remedy,
            severity=severity_num,
            location=item.get('component', 'unknown'),
            reference_ids=cves,
            details={
                'provider': item.get('provider', 'JFrog'),
                'issue_type': item.get('issue_type', 'security'),
                'source_comp_id': item.get('source_comp_id', ''),
                'vulnerable_versions': component_versions.get('vulnerable_versions', []),
                'fixed_versions': fixed_versions,
                'cvss_v3_score': cvss_v3_score
            }
        )
        
        return vulnerability.__dict__


# Export all translators
__all__ = [
    'JFrogXRayAPISummaryArtifactTranslator',
    'JFrogXRayUnifiedTranslator',
    'JFrogXRayOnDemandTranslator',
    'JFrogXrayLegacyTranslator'
]


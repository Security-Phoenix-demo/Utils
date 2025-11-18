#!/usr/bin/env python3
"""
Round 17 Additional Translators
================================

Hard-coded translators for remaining failing scanners:
- NSP (Node Security Project - deprecated but still used)
- Snyk CLI (different format than Snyk API)
"""

import json
import logging
from typing import Any, Dict, List, Optional

from phoenix_multi_scanner_import import (
    ScannerConfig,
    ScannerTranslator,
    VulnerabilityData
)
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class NSPTranslator(ScannerTranslator):
    """Translator for Node Security Project (NSP) JSON format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect NSP JSON format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # NSP format has specific structure
            if isinstance(file_content, list) and len(file_content) > 0:
                first = file_content[0]
                if isinstance(first, dict):
                    # Check for NSP-specific fields
                    if 'id' in first and 'module' in first and 'vulnerable_versions' in first:
                        return True
            elif isinstance(file_content, dict):
                # Alternative format with advisories
                if 'advisories' in file_content:
                    return True
            
            return False
        except Exception as e:
            logger.debug(f"NSPTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse NSP JSON file"""
        logger.info(f"Parsing NSP file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Handle different NSP formats
            if isinstance(data, dict) and 'advisories' in data:
                advisories = data['advisories']
            elif isinstance(data, list):
                advisories = data
            else:
                logger.warning("Unknown NSP format")
                return []
            
            # Group vulnerabilities by module
            modules = {}
            for advisory in advisories:
                if isinstance(advisory, dict):
                    module_name = advisory.get('module', advisory.get('module_name', 'unknown'))
                    
                    if module_name not in modules:
                        modules[module_name] = []
                    
                    vuln = self._parse_advisory(advisory)
                    if vuln:
                        modules[module_name].append(vuln)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for module_name, vulns in modules.items():
                if not vulns:
                    continue
                
                asset = AssetData(
                    asset_type='BUILD',
                    attributes={
                        'name': module_name,
                        'buildFile': 'package.json',
                        'scanner': 'NSP'
                    },
                    tags=tags + [{"key": "scanner", "value": "nsp"}]
                )
                
                for vuln in vulns:
                    asset.findings.append(vuln)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} modules with {sum(len(a.findings) for a in assets)} vulnerabilities from NSP")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing NSP file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_advisory(self, advisory: Dict) -> Optional[Dict]:
        """Parse a single NSP advisory"""
        try:
            advisory_id = advisory.get('id', advisory.get('advisory', 'UNKNOWN'))
            title = advisory.get('title', advisory.get('overview', 'Security Advisory'))
            module = advisory.get('module', advisory.get('module_name', 'unknown'))
            severity = advisory.get('severity', 'medium')
            
            # Normalize severity
            severity_normalized = self.normalize_severity(severity)
            
            return {
                'name': f"NSP-{advisory_id}: {title}",
                'description': advisory.get('overview', title),
                'remedy': advisory.get('recommendation', 'Update to a non-vulnerable version'),
                'severity': severity_normalized,
                'location': module,
                'reference_ids': [f"NSP-{advisory_id}"],
                'details': {
                    'vulnerable_versions': advisory.get('vulnerable_versions', ''),
                    'patched_versions': advisory.get('patched_versions', ''),
                    'cves': advisory.get('cves', []),
                    'cvss_score': advisory.get('cvss_score', 0)
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing NSP advisory: {e}")
            return None


class SnykCLITranslator(ScannerTranslator):
    """Translator for Snyk CLI output (different from Snyk API)"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Snyk CLI JSON format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Snyk CLI format has vulnerabilities array and packageManager
            if isinstance(file_content, dict):
                if 'vulnerabilities' in file_content and 'packageManager' in file_content:
                    return True
                # Alternative: array of project results
                if 'vulnerabilities' in file_content and 'dependencyCount' in file_content:
                    return True
            elif isinstance(file_content, list) and len(file_content) > 0:
                # Array of scan results
                first = file_content[0]
                if isinstance(first, dict) and 'vulnerabilities' in first:
                    return True
            
            return False
        except Exception as e:
            logger.debug(f"SnykCLITranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Snyk CLI JSON file"""
        logger.info(f"Parsing Snyk CLI file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Handle array of projects or single project
            if isinstance(data, list):
                projects = data
            else:
                projects = [data]
            
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for project in projects:
                if not isinstance(project, dict):
                    continue
                
                project_name = project.get('projectName', project.get('displayTargetFile', 'unknown'))
                package_manager = project.get('packageManager', 'npm')
                vulnerabilities = project.get('vulnerabilities', [])
                
                if not vulnerabilities:
                    continue
                
                asset = AssetData(
                    asset_type='BUILD',
                    attributes={
                        'name': project_name,
                        'buildFile': project_name,
                        'packageManager': package_manager,
                        'scanner': 'Snyk CLI'
                    },
                    tags=tags + [
                        {"key": "scanner", "value": "snyk-cli"},
                        {"key": "package_manager", "value": package_manager}
                    ]
                )
                
                for vuln in vulnerabilities:
                    vuln_data = self._parse_vulnerability(vuln)
                    if vuln_data:
                        asset.findings.append(vuln_data)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} projects with {sum(len(a.findings) for a in assets)} vulnerabilities from Snyk CLI")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Snyk CLI file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_vulnerability(self, vuln: Dict) -> Optional[Dict]:
        """Parse a single Snyk CLI vulnerability"""
        try:
            vuln_id = vuln.get('id', 'UNKNOWN')
            title = vuln.get('title', vuln.get('name', 'Security Vulnerability'))
            package = vuln.get('packageName', vuln.get('name', 'unknown'))
            severity = vuln.get('severity', 'medium')
            
            # Normalize severity
            severity_normalized = self.normalize_severity(severity)
            
            # Get upgrade path
            upgrade_path = vuln.get('upgradePath', [])
            if upgrade_path:
                remedy = f"Upgrade to {upgrade_path[-1]}" if len(upgrade_path) > 0 else "See Snyk for remediation"
            else:
                remedy = "See Snyk for remediation"
            
            return {
                'name': f"{vuln_id}: {title}",
                'description': vuln.get('description', title),
                'remedy': remedy,
                'severity': severity_normalized,
                'location': f"{package}@{vuln.get('version', 'unknown')}",
                'reference_ids': [vuln_id] + vuln.get('identifiers', {}).get('CVE', []),
                'cvss_score': vuln.get('cvssScore', 0),
                'cwes': [f"CWE-{cwe}" for cwe in vuln.get('identifiers', {}).get('CWE', [])],
                'details': {
                    'is_upgradable': vuln.get('isUpgradable', False),
                    'is_patchable': vuln.get('isPatchable', False),
                    'exploit_maturity': vuln.get('exploitMaturity', ''),
                    'publication_time': vuln.get('publicationTime', ''),
                    'disclosure_time': vuln.get('disclosureTime', '')
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing Snyk CLI vulnerability: {e}")
            return None


# Export all translators
__all__ = [
    'NSPTranslator',
    'SnykCLITranslator'
]


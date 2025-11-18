#!/usr/bin/env python3
"""
Round 19 - Push to 98%+ Coverage
=================================

Hard-coded translators for remaining 8 scanners:
1. microfocus_webinspect - MicroFocus WebInspect XML
2. trufflehog - TruffleHog V2/V3 unified
3. noseyparker - NoseyParker secrets scanner  
4. burp_suite_dast - Burp Suite DAST HTML
5-8. Troubleshoot existing: jfrogxray, blackduck variants, dsop, chefinspect
"""

import json
import xml.etree.ElementTree as ET
import logging
from typing import Any, Dict, List, Optional
from html.parser import HTMLParser

from phoenix_multi_scanner_import import (
    ScannerConfig,
    ScannerTranslator,
    VulnerabilityData
)
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class MicroFocusWebInspectTranslator(ScannerTranslator):
    """Translator for MicroFocus WebInspect XML format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect MicroFocus WebInspect XML format"""
        if not file_path.lower().endswith('.xml'):
            return False
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Check for WebInspect-specific structure: Sessions/Session/Issues
            if root.tag == 'Sessions':
                # Look for Session elements with Issues
                for session in root.findall('.//Session'):
                    if session.find('.//Issues') is not None:
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"MicroFocusWebInspectTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse MicroFocus WebInspect XML file"""
        logger.info(f"Parsing MicroFocus WebInspect file: {file_path}")
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Group by URL/Host
            hosts = {}
            
            for session in root.findall('.//Session'):
                url = session.findtext('URL', 'unknown')
                host = session.findtext('Host', url)
                
                if host not in hosts:
                    hosts[host] = []
                
                # Parse issues for this session
                issues_elem = session.find('Issues')
                if issues_elem is not None:
                    for issue in issues_elem.findall('Issue'):
                        vuln = self._parse_issue(issue, url)
                        if vuln:
                            hosts[host].append(vuln)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for host, vulns in hosts.items():
                if not vulns:
                    continue
                
                asset = AssetData(
                    asset_type='WEB',
                    attributes={
                        'name': host,
                        'fqdn': host if '.' in host else f"{host}.local",
                        'scanner': 'MicroFocus WebInspect'
                    },
                    tags=tags + [{"key": "scanner", "value": "microfocus-webinspect"}]
                )
                
                for vuln in vulns:
                    asset.findings.append(vuln)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} hosts with {sum(len(a.findings) for a in assets)} issues from WebInspect")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing WebInspect file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_issue(self, issue: ET.Element, url: str) -> Optional[Dict]:
        """Parse a single WebInspect issue"""
        try:
            vuln_id = issue.findtext('VulnerabilityID', 'UNKNOWN')
            name = issue.findtext('Name', 'Security Issue')
            severity = issue.findtext('Severity', '0')
            check_type = issue.findtext('CheckTypeID', 'Unknown')
            
            # Get summary/description from ReportSection
            description = ''
            remedy = ''
            for section in issue.findall('.//ReportSection'):
                section_name = section.findtext('Name', '')
                section_text = section.findtext('SectionText', '')
                
                if section_name == 'Summary':
                    description = section_text
                elif section_name == 'Fix':
                    remedy = section_text
            
            # Clean CDATA and HTML tags from description
            if description:
                description = description.replace('<![CDATA[', '').replace(']]>', '')
                description = description[:500]  # Limit length
            
            if remedy:
                remedy = remedy.replace('<![CDATA[', '').replace(']]>', '')
                remedy = remedy[:500]
            
            # Map WebInspect severity (0=Info, 1=Low, 2=Medium, 3=High, 4=Critical)
            severity_map = {'0': 'Low', '1': 'Low', '2': 'Medium', '3': 'High', '4': 'Critical'}
            severity_normalized = self.normalize_severity(severity_map.get(severity, severity))
            
            # Get CWE/classifications
            cwes = []
            for classification in issue.findall('.//Classification'):
                if classification.get('kind') == 'CWE':
                    cwe_id = classification.get('identifier', '')
                    if cwe_id:
                        cwes.append(cwe_id)
            
            return {
                'name': f"{vuln_id}: {name[:100]}",
                'description': description if description else name,
                'remedy': remedy if remedy else "See WebInspect report for remediation",
                'severity': severity_normalized,
                'location': url,
                'reference_ids': [vuln_id] + cwes,
                'cwes': cwes,
                'details': {
                    'check_type': check_type,
                    'engine_type': issue.findtext('EngineType', ''),
                    'issue_id': issue.get('id', '')
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing WebInspect issue: {e}")
            return None


class TruffleHogTranslator(ScannerTranslator):
    """Unified translator for TruffleHog V2 and V3 formats"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect TruffleHog V2 or V3 JSON format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            with open(file_path, 'r') as f:
                first_line = f.readline().strip()
                if not first_line:
                    return False
                
                try:
                    obj = json.loads(first_line)
                except json.JSONDecodeError:
                    return False
                
                # V3: Has SourceMetadata, DetectorType, DetectorName
                if isinstance(obj, dict):
                    if 'SourceMetadata' in obj and 'DetectorType' in obj:
                        return True
                    # V2: Has branch, commit, reason, stringsFound
                    if 'branch' in obj and 'commit' in obj and 'reason' in obj:
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"TruffleHogTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse TruffleHog JSON file (NDJSON format)"""
        logger.info(f"Parsing TruffleHog file: {file_path}")
        
        secrets = []
        is_v3 = False
        
        try:
            with open(file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        finding = json.loads(line)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Skipping invalid JSON on line {line_num}: {e}")
                        continue
                    
                    # Detect version and parse
                    if 'SourceMetadata' in finding:
                        is_v3 = True
                        vuln = self._parse_v3_finding(finding)
                    else:
                        vuln = self._parse_v2_finding(finding)
                    
                    if vuln:
                        secrets.append(vuln)
            
            if not secrets:
                logger.info("No secrets found in TruffleHog output")
                return []
            
            # Create single asset for all secrets
            version = "v3" if is_v3 else "v2"
            tags = get_tags_safely(self.tag_config)
            
            asset = AssetData(
                asset_type='CODE',
                attributes={
                    'name': f"TruffleHog {version} Scan Results",
                    'scanner': f'TruffleHog {version}'
                },
                tags=tags + [{"key": "scanner", "value": f"trufflehog-{version}"}]
            )
            
            for vuln in secrets:
                asset.findings.append(vuln)
            
            assets = [self.ensure_asset_has_findings(asset)]
            
            logger.info(f"Parsed {len(secrets)} secrets from TruffleHog {version}")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing TruffleHog file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_v3_finding(self, finding: Dict) -> Optional[Dict]:
        """Parse TruffleHog V3 finding (OCSF-like structure)"""
        try:
            detector_name = finding.get('DetectorName', 'Unknown')
            verified = finding.get('Verified', False)
            raw = finding.get('Redacted', finding.get('Raw', ''))
            
            # Get source info
            source_metadata = finding.get('SourceMetadata', {})
            source_data = source_metadata.get('Data', {})
            git_data = source_data.get('Git', {})
            
            file_path = git_data.get('file', 'unknown')
            commit = git_data.get('commit', 'unknown')
            repo = git_data.get('repository', 'unknown')
            
            # Severity based on verification
            severity = 'High' if verified else 'Medium'
            severity_normalized = self.normalize_severity(severity)
            
            return {
                'name': f"{detector_name}: Secret Found",
                'description': f"Secret detected in {file_path}",
                'remedy': "Rotate the exposed secret immediately",
                'severity': severity_normalized,
                'location': f"{repo}:{file_path}",
                'reference_ids': [commit[:8]],
                'details': {
                    'detector': detector_name,
                    'verified': verified,
                    'commit': commit,
                    'repository': repo,
                    'redacted_value': raw[:50] if raw else ''
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing TruffleHog V3 finding: {e}")
            return None
    
    def _parse_v2_finding(self, finding: Dict) -> Optional[Dict]:
        """Parse TruffleHog V2 finding"""
        try:
            reason = finding.get('reason', 'Secret Found')
            branch = finding.get('branch', 'unknown')
            commit_hash = finding.get('commitHash', 'unknown')
            path = finding.get('path', 'unknown')
            strings_found = finding.get('stringsFound', [])
            
            return {
                'name': f"{reason}",
                'description': f"Secret detected in {path} (commit: {commit_hash[:8]})",
                'remedy': "Rotate the exposed secret immediately",
                'severity': self.normalize_severity('High'),
                'location': f"{branch}:{path}",
                'reference_ids': [commit_hash[:8]],
                'details': {
                    'reason': reason,
                    'commit': commit_hash,
                    'branch': branch,
                    'strings_found_count': len(strings_found) if strings_found else 0
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing TruffleHog V2 finding: {e}")
            return None


# Export all translators
__all__ = [
    'MicroFocusWebInspectTranslator',
    'TruffleHogTranslator'
]


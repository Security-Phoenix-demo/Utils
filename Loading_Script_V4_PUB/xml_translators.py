#!/usr/bin/env python3
"""
XML Translators Module
======================

Dedicated translators for XML-based scanner formats.
Uses the xml_parsers module for actual XML parsing logic.

Includes:
- Burp Suite XML Export
- Checkmarx CxSAST XML
- Qualys VM/WebApp XML
"""

import logging
from typing import Any, Dict, List, Optional
from pathlib import Path

from phoenix_multi_scanner_import import (
    ScannerConfig,
    ScannerTranslator,
    VulnerabilityData
)
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely
from xml_parsers import BurpSuiteXMLParser, CheckmarxXMLParser, QualysXMLParser

logger = logging.getLogger(__name__)


class BurpXMLTranslator(ScannerTranslator):
    """Translator for Burp Suite XML export format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Burp Suite XML format"""
        if not file_path.lower().endswith('.xml'):
            return False
        
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Check for Burp XML structure (root: issues or contains issue elements)
            if root.tag in ['issues', 'issue'] or root.find('.//issue') is not None:
                return True
            
            return False
        except Exception as e:
            logger.debug(f"BurpXMLTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Burp Suite XML file"""
        logger.info(f"Parsing Burp Suite XML file: {file_path}")
        
        # Use XML parser
        findings = BurpSuiteXMLParser.parse(file_path)
        
        if not findings:
            logger.info("No issues found in Burp Suite XML")
            return []
        
        # Group findings by host
        findings_by_host = {}
        for finding in findings:
            host = finding.get('host', 'unknown')
            if host not in findings_by_host:
                findings_by_host[host] = []
            findings_by_host[host].append(finding)
        
        # Create assets
        assets = []
        tags = get_tags_safely(self.tag_config)
        
        for host, host_findings in findings_by_host.items():
            # Extract FQDN from host
            fqdn = host.replace('https://', '').replace('http://', '').split('/')[0]
            
            asset = AssetData(
                asset_type='WEB',
                attributes={
                    'name': fqdn,
                    'fqdn': fqdn,
                    'scanner': 'Burp Suite'
                },
                tags=tags + [{"key": "scanner", "value": "burp-suite"}]
            )
            
            # Add findings
            for finding in host_findings:
                vuln = self._parse_finding(finding)
                if vuln:
                    asset.findings.append(vuln)
            
            assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Parsed {len(assets)} hosts with {sum(len(a.findings) for a in assets)} issues from Burp Suite XML")
        return assets
    
    def _parse_finding(self, finding: Dict) -> Optional[Dict]:
        """Convert Burp finding to vulnerability format"""
        try:
            name = finding.get('name', 'Unknown Issue')
            severity = finding.get('severity', 'Medium')
            location = finding.get('path', '/')
            
            # Normalize severity
            severity_normalized = self.normalize_severity(severity)
            
            # Get description
            desc_parts = []
            if finding.get('issue_background'):
                desc_parts.append(finding['issue_background'])
            if finding.get('issue_detail'):
                desc_parts.append(finding['issue_detail'])
            description = ' '.join(desc_parts)[:500] if desc_parts else name
            
            # Get remediation
            remedy_parts = []
            if finding.get('remediation_background'):
                remedy_parts.append(finding['remediation_background'])
            if finding.get('remediation_detail'):
                remedy_parts.append(finding['remediation_detail'])
            remedy = ' '.join(remedy_parts)[:500] if remedy_parts else "See Burp documentation"
            
            return {
                'name': name,
                'description': description,
                'remedy': remedy,
                'severity': severity_normalized,
                'location': f"{finding.get('host', '')}{location}",
                'reference_ids': [],
                'details': {
                    'confidence': finding.get('confidence', 'Certain'),
                    'vulnerability_classifications': finding.get('vulnerability_classifications', ''),
                    'references': finding.get('references', '')
                }
            }
        except Exception as e:
            logger.debug(f"Error parsing Burp finding: {e}")
            return None


class CheckmarxXMLTranslator(ScannerTranslator):
    """Translator for Checkmarx CxSAST XML format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Checkmarx XML format"""
        if not file_path.lower().endswith('.xml'):
            return False
        
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Check for Checkmarx XML structure
            if 'CxXML' in root.tag or root.find('.//Query') is not None:
                return True
            
            return False
        except Exception as e:
            logger.debug(f"CheckmarxXMLTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Checkmarx XML file"""
        logger.info(f"Parsing Checkmarx XML file: {file_path}")
        
        # Use XML parser
        findings = CheckmarxXMLParser.parse(file_path)
        
        if not findings:
            logger.info("No results found in Checkmarx XML")
            return []
        
        # Group findings by file
        findings_by_file = {}
        for finding in findings:
            file_name = finding.get('file_name', 'unknown')
            if file_name not in findings_by_file:
                findings_by_file[file_name] = []
            findings_by_file[file_name].append(finding)
        
        # Create assets
        assets = []
        tags = get_tags_safely(self.tag_config)
        
        for file_name, file_findings in findings_by_file.items():
            asset = AssetData(
                asset_type='CODE',
                attributes={
                    'name': file_name,
                    'scanner': 'Checkmarx CxSAST',
                    'language': file_findings[0].get('language', 'Unknown') if file_findings else 'Unknown'
                },
                tags=tags + [{"key": "scanner", "value": "checkmarx"}]
            )
            
            # Add findings
            for finding in file_findings:
                vuln = self._parse_finding(finding)
                if vuln:
                    asset.findings.append(vuln)
            
            assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Parsed {len(assets)} files with {sum(len(a.findings) for a in assets)} results from Checkmarx XML")
        return assets
    
    def _parse_finding(self, finding: Dict) -> Optional[Dict]:
        """Convert Checkmarx finding to vulnerability format"""
        try:
            name = finding.get('name', 'Unknown Query')
            severity = finding.get('severity', 'Medium')
            line = finding.get('line', '')
            file_name = finding.get('file_name', '')
            
            # Normalize severity
            severity_normalized = self.normalize_severity(severity)
            
            # Create location
            location = f"{file_name}:{line}" if line else file_name
            
            # Get description from path
            path = finding.get('path', [])
            if path:
                desc = f"Data flow: {len(path)} nodes"
            else:
                desc = name
            
            return {
                'name': name,
                'description': desc,
                'remedy': "Review code and apply secure coding practices",
                'severity': severity_normalized,
                'location': location,
                'reference_ids': [finding.get('deep_link', '')] if finding.get('deep_link') else [],
                'details': {
                    'group': finding.get('group', ''),
                    'language': finding.get('language', ''),
                    'false_positive': finding.get('false_positive', 'False'),
                    'status': finding.get('status', 'New')
                }
            }
        except Exception as e:
            logger.debug(f"Error parsing Checkmarx finding: {e}")
            return None


class QualysXMLTranslator(ScannerTranslator):
    """Translator for Qualys XML format (VM/WebApp)"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Qualys XML format"""
        if not file_path.lower().endswith('.xml'):
            return False
        
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Check for Qualys XML structure
            if 'WAS_SCAN' in root.tag.upper() or 'QUALYS' in root.tag.upper() or root.find('.//VULNERABILITY') is not None:
                return True
            
            return False
        except Exception as e:
            logger.debug(f"QualysXMLTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Qualys XML file"""
        logger.info(f"Parsing Qualys XML file: {file_path}")
        
        # Use XML parser
        findings = QualysXMLParser.parse(file_path)
        
        if not findings:
            logger.info("No vulnerabilities found in Qualys XML")
            return []
        
        # Determine format type from first finding
        is_webapp = 'url' in findings[0]
        
        if is_webapp:
            return self._create_webapp_assets(findings)
        else:
            return self._create_vm_assets(findings)
    
    def _create_webapp_assets(self, findings: List[Dict]) -> List[AssetData]:
        """Create assets for WebApp format"""
        # Group by URL
        findings_by_url = {}
        for finding in findings:
            url = finding.get('url', 'unknown')
            # Extract base URL
            if '/' in url:
                base_url = '/'.join(url.split('/')[:3])  # protocol://domain
            else:
                base_url = url
                
            if base_url not in findings_by_url:
                findings_by_url[base_url] = []
            findings_by_url[base_url].append(finding)
        
        assets = []
        tags = get_tags_safely(self.tag_config)
        
        for url, url_findings in findings_by_url.items():
            # Extract FQDN
            fqdn = url.replace('https://', '').replace('http://', '').split('/')[0]
            
            asset = AssetData(
                asset_type='WEB',
                attributes={
                    'name': fqdn,
                    'fqdn': fqdn,
                    'scanner': 'Qualys WebApp'
                },
                tags=tags + [{"key": "scanner", "value": "qualys-webapp"}]
            )
            
            # Add findings
            for finding in url_findings:
                vuln = self._parse_webapp_finding(finding)
                if vuln:
                    asset.findings.append(vuln)
            
            assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Parsed {len(assets)} web assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets
    
    def _create_vm_assets(self, findings: List[Dict]) -> List[AssetData]:
        """Create assets for VM/VMDR format"""
        # Group by host
        findings_by_host = {}
        for finding in findings:
            host_ip = finding.get('host_ip', 'unknown')
            if host_ip not in findings_by_host:
                findings_by_host[host_ip] = []
            findings_by_host[host_ip].append(finding)
        
        assets = []
        tags = get_tags_safely(self.tag_config)
        
        for host_ip, host_findings in findings_by_host.items():
            # Get DNS/NetBIOS name if available
            host_name = host_findings[0].get('host_dns') or host_findings[0].get('host_netbios') or host_ip
            
            asset = AssetData(
                asset_type='INFRA',
                attributes={
                    'name': host_name,
                    'ip': host_ip,
                    'scanner': 'Qualys VM'
                },
                tags=tags + [{"key": "scanner", "value": "qualys-vm"}]
            )
            
            # Add findings
            for finding in host_findings:
                vuln = self._parse_vm_finding(finding)
                if vuln:
                    asset.findings.append(vuln)
            
            assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Parsed {len(assets)} hosts with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets
    
    def _parse_webapp_finding(self, finding: Dict) -> Optional[Dict]:
        """Convert Qualys WebApp finding to vulnerability format"""
        try:
            qid = finding.get('qid', '')
            name = finding.get('name', 'Unknown')
            severity = finding.get('severity', 'Medium')
            url = finding.get('url', '')
            
            # Normalize severity
            severity_normalized = self.normalize_severity(severity)
            
            return {
                'name': f"QID-{qid}: {name}" if qid else name,
                'description': finding.get('description', name),
                'remedy': finding.get('solution', 'See Qualys documentation'),
                'severity': severity_normalized,
                'location': url,
                'reference_ids': [qid] if qid else [],
                'details': {
                    'category': finding.get('category', ''),
                    'group': finding.get('group', ''),
                    'param': finding.get('param', ''),
                    'detection_id': finding.get('detection_id', ''),
                    'times_detected': finding.get('times_detected', '0')
                }
            }
        except Exception as e:
            logger.debug(f"Error parsing Qualys WebApp finding: {e}")
            return None
    
    def _parse_vm_finding(self, finding: Dict) -> Optional[Dict]:
        """Convert Qualys VM finding to vulnerability format"""
        try:
            qid = finding.get('qid', '')
            severity = finding.get('severity', 'Medium')
            port = finding.get('port', '')
            protocol = finding.get('protocol', '')
            
            # Normalize severity
            severity_normalized = self.normalize_severity(severity)
            
            # Create location
            location_parts = []
            if port:
                location_parts.append(f"port {port}")
            if protocol:
                location_parts.append(protocol)
            location = '/'.join(location_parts) if location_parts else 'host'
            
            return {
                'name': f"QID-{qid}" if qid else 'Unknown',
                'description': finding.get('results', f"Vulnerability QID-{qid}"),
                'remedy': "See Qualys documentation for remediation",
                'severity': severity_normalized,
                'location': location,
                'reference_ids': [qid] if qid else [],
                'details': {
                    'type': finding.get('type', ''),
                    'status': finding.get('status', ''),
                    'first_found': finding.get('first_found', ''),
                    'last_found': finding.get('last_found', ''),
                    'times_found': finding.get('times_found', '0')
                }
            }
        except Exception as e:
            logger.debug(f"Error parsing Qualys VM finding: {e}")
            return None


# Export all XML translators
__all__ = [
    'BurpXMLTranslator',
    'CheckmarxXMLTranslator',
    'QualysXMLTranslator'
]


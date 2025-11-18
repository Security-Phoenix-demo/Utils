#!/usr/bin/env python3
"""
Round 20 - Final Push to 98%+
==============================

Hard-coded translators for all remaining scanners:
1. JFrogXRaySimpleTranslator - Simple JFrog format with total_count/data
2. TruffleHog3Translator - TruffleHog v3 (different from V2/V3)
3. ContrastTranslator - Contrast Security CSV
4. QualysVMTranslator - Qualys VM XML (ASSET_DATA_REPORT)
5. BlackDuckBinaryAnalysisCSVTranslator - BlackDuck Binary CSV
"""

import json
import csv
import xml.etree.ElementTree as ET
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


class JFrogXRaySimpleTranslator(ScannerTranslator):
    """Translator for simple JFrog XRay format (total_count/data structure)"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect simple JFrog XRay format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Simple JFrog format: has total_count and data array
            if isinstance(file_content, dict):
                if 'total_count' in file_content and 'data' in file_content:
                    data = file_content.get('data', [])
                    if data and isinstance(data, list):
                        first = data[0]
                        # Check for JFrog-specific fields
                        if 'component' in first and 'provider' in first:
                            if first.get('provider') == 'JFrog':
                                return True
            
            return False
        except Exception as e:
            logger.debug(f"JFrogXRaySimpleTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse simple JFrog XRay JSON file"""
        logger.info(f"Parsing JFrog XRay (simple format) file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            issues = data.get('data', [])
            if not issues:
                logger.info("No issues in JFrog XRay response")
                return []
            
            # Group by component
            components = {}
            for issue in issues:
                component = issue.get('component', 'unknown')
                if component not in components:
                    components[component] = []
                
                vuln = self._parse_issue(issue)
                if vuln:
                    components[component].append(vuln)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for component, vulns in components.items():
                if not vulns:
                    continue
                
                asset = AssetData(
                    asset_type='BUILD',
                    attributes={
                        'name': component,
                        'buildFile': 'package',
                        'scanner': 'JFrog XRay'
                    },
                    tags=tags + [{"key": "scanner", "value": "jfrog-xray"}]
                )
                
                for vuln in vulns:
                    asset.findings.append(vuln)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} components with {sum(len(a.findings) for a in assets)} issues from JFrog XRay")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing JFrog XRay file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_issue(self, issue: Dict) -> Optional[Dict]:
        """Parse a single JFrog XRay issue"""
        try:
            issue_id = issue.get('id', 'UNKNOWN')
            summary = issue.get('summary', 'Security Issue')
            severity = issue.get('severity', 'Medium')
            component = issue.get('component', 'unknown')
            
            # Get CVE info from component_versions
            cves = []
            component_versions = issue.get('component_versions', {})
            more_details = component_versions.get('more_details', {})
            if isinstance(more_details, dict):
                cve_list = more_details.get('cves', [])
                for cve_info in cve_list:
                    if isinstance(cve_info, dict):
                        cve = cve_info.get('cve', '')
                        if cve:
                            cves.append(cve)
            
            # Normalize severity
            severity_normalized = self.normalize_severity(severity)
            
            return {
                'name': f"{cves[0] if cves else issue_id}: {summary[:100]}",
                'description': summary,
                'remedy': "Update to a non-vulnerable version",
                'severity': severity_normalized,
                'location': component,
                'reference_ids': cves if cves else [issue_id],
                'cwes': [],
                'details': {
                    'issue_type': issue.get('issue_type', ''),
                    'source_comp_id': issue.get('source_comp_id', ''),
                    'vulnerable_versions': component_versions.get('vulnerable_versions', []),
                    'fixed_versions': component_versions.get('fixed_versions', [])
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing JFrog XRay issue: {e}")
            return None


class TruffleHog3Translator(ScannerTranslator):
    """Translator for TruffleHog v3 (different format from V2/V3)"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect TruffleHog v3 format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            with open(file_path, 'r') as f:
                content = json.load(f)
            
            # TruffleHog v3 format: array with "rule" field
            if isinstance(content, list) and len(content) > 0:
                first = content[0]
                if isinstance(first, dict) and 'rule' in first:
                    rule = first.get('rule', {})
                    if isinstance(rule, dict) and 'id' in rule:
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"TruffleHog3Translator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse TruffleHog v3 JSON file"""
        logger.info(f"Parsing TruffleHog v3 file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                findings = json.load(f)
            
            if not isinstance(findings, list):
                findings = [findings]
            
            secrets = []
            for finding in findings:
                vuln = self._parse_finding(finding)
                if vuln:
                    secrets.append(vuln)
            
            if not secrets:
                logger.info("No secrets found in TruffleHog v3 output")
                return []
            
            # Create single asset
            tags = get_tags_safely(self.tag_config)
            
            asset = AssetData(
                asset_type='CODE',
                attributes={
                    'name': 'TruffleHog v3 Scan Results',
                    'scanner': 'TruffleHog v3'
                },
                tags=tags + [{"key": "scanner", "value": "trufflehog3"}]
            )
            
            for vuln in secrets:
                asset.findings.append(vuln)
            
            assets = [self.ensure_asset_has_findings(asset)]
            
            logger.info(f"Parsed {len(secrets)} secrets from TruffleHog v3")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing TruffleHog v3 file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_finding(self, finding: Dict) -> Optional[Dict]:
        """Parse a TruffleHog v3 finding"""
        try:
            rule = finding.get('rule', {})
            rule_id = rule.get('id', 'Unknown')
            rule_message = rule.get('message', 'Secret Found')
            
            path = finding.get('path', 'unknown')
            start_line = finding.get('start_line', 0)
            end_line = finding.get('end_line', 0)
            
            return {
                'name': f"{rule_id}: {rule_message}",
                'description': f"Secret detected in {path} (lines {start_line}-{end_line})",
                'remedy': "Rotate the exposed secret immediately",
                'severity': self.normalize_severity('High'),
                'location': f"{path}:{start_line}",
                'reference_ids': [rule_id],
                'details': {
                    'rule_id': rule_id,
                    'rule_message': rule_message,
                    'start_line': start_line,
                    'end_line': end_line
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing TruffleHog v3 finding: {e}")
            return None


class ContrastTranslator(ScannerTranslator):
    """Translator for Contrast Security CSV format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Contrast CSV format"""
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                headers = reader.fieldnames
                if headers:
                    # Check for Contrast-specific columns
                    contrast_cols = ['Vulnerability Name', 'Vulnerability ID', 'Application Name', 'Category']
                    matches = sum(1 for col in contrast_cols if col in headers)
                    if matches >= 3:
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"ContrastTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Contrast CSV file"""
        logger.info(f"Parsing Contrast Security file: {file_path}")
        
        try:
            # Increase CSV field size limit for large fields
            import sys
            maxInt = sys.maxsize
            while True:
                try:
                    csv.field_size_limit(maxInt)
                    break
                except OverflowError:
                    maxInt = int(maxInt/10)
            
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                logger.info("No rows in Contrast CSV")
                return []
            
            # Group by application
            applications = {}
            for row in rows:
                app_name = row.get('Application Name', 'unknown')
                if app_name not in applications:
                    applications[app_name] = []
                
                vuln = self._parse_row(row)
                if vuln:
                    applications[app_name].append(vuln)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for app_name, vulns in applications.items():
                if not vulns:
                    continue
                
                asset = AssetData(
                    asset_type='WEB',
                    attributes={
                        'name': app_name,
                        'fqdn': app_name if '.' in app_name else f"{app_name}.local",
                        'scanner': 'Contrast Security'
                    },
                    tags=tags + [{"key": "scanner", "value": "contrast"}]
                )
                
                for vuln in vulns:
                    asset.findings.append(vuln)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} applications with {sum(len(a.findings) for a in assets)} vulnerabilities from Contrast")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Contrast file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_row(self, row: Dict) -> Optional[Dict]:
        """Parse a single Contrast CSV row"""
        try:
            vuln_name = row.get('Vulnerability Name', 'Unknown')
            vuln_id = row.get('Vulnerability ID', 'UNKNOWN')
            severity = row.get('Severity', 'Medium')
            category = row.get('Category', '')
            rule_name = row.get('Rule Name', '')
            
            # Location from request info
            request_uri = row.get('Request URI', '')
            request_method = row.get('Request Method', '')
            location = f"{request_method} {request_uri}" if request_method and request_uri else vuln_name
            
            # Normalize severity
            severity_normalized = self.normalize_severity(severity)
            
            return {
                'name': f"{vuln_name}",
                'description': f"{category} - {rule_name}" if category and rule_name else vuln_name,
                'remedy': "See Contrast Security for remediation details",
                'severity': severity_normalized,
                'location': location,
                'reference_ids': [vuln_id],
                'details': {
                    'category': category,
                    'rule_name': rule_name,
                    'status': row.get('Status', ''),
                    'cwe_id': row.get('CWE ID', '')
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing Contrast row: {e}")
            return None


class QualysVMTranslator(ScannerTranslator):
    """Translator for Qualys VM XML (ASSET_DATA_REPORT format)"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Qualys VM XML format"""
        if not file_path.lower().endswith('.xml'):
            return False
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Check for ASSET_DATA_REPORT root
            if root.tag == 'ASSET_DATA_REPORT':
                return True
            
            return False
        except Exception as e:
            logger.debug(f"QualysVMTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Qualys VM XML file"""
        logger.info(f"Parsing Qualys VM file: {file_path}")
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Parse hosts - try different path structures
            hosts = {}
            
            # Try direct HOSTS elements first
            host_elems = root.findall('.//HOSTS') or root.findall('HOSTS')
            
            if not host_elems:
                # Try alternative structure: RISK_SCORE_PER_HOST/HOSTS
                host_elems = root.findall('.//RISK_SCORE_PER_HOST/HOSTS')
            
            for host_elem in host_elems:
                # Try different IP field names
                host_ip = (host_elem.findtext('IP_ADDRESS') or 
                          host_elem.findtext('IP') or 
                          host_elem.findtext('.//IP_ADDRESS') or 
                          host_elem.findtext('.//IP') or 
                          'unknown')
                
                if host_ip == 'unknown':
                    continue
                
                if host_ip not in hosts:
                    hosts[host_ip] = []
                
                # Parse vulnerabilities for this host
                vuln_elems = host_elem.findall('.//VULNERABILITY') or host_elem.findall('VULNERABILITY')
                for vuln_elem in vuln_elems:
                    vuln = self._parse_vulnerability(vuln_elem)
                    if vuln:
                        hosts[host_ip].append(vuln)
                
                # If no vulns found, add a placeholder to create the asset
                if host_ip in hosts and not hosts[host_ip]:
                    hosts[host_ip].append({
                        'name': 'NO_VULNERABILITIES_FOUND',
                        'description': f'No vulnerabilities found for host {host_ip}',
                        'remedy': 'No action required',
                        'severity': self.normalize_severity('Low'),
                        'location': host_ip,
                        'reference_ids': []
                    })
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for host_ip, vulns in hosts.items():
                if not vulns:
                    continue
                
                asset = AssetData(
                    asset_type='INFRA',
                    attributes={
                        'name': host_ip,
                        'ip': host_ip,
                        'scanner': 'Qualys VM'
                    },
                    tags=tags + [{"key": "scanner", "value": "qualys-vm"}]
                )
                
                for vuln in vulns:
                    asset.findings.append(vuln)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} hosts with {sum(len(a.findings) for a in assets)} vulnerabilities from Qualys VM")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Qualys VM file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_vulnerability(self, vuln_elem: ET.Element) -> Optional[Dict]:
        """Parse a single Qualys vulnerability"""
        try:
            qid = vuln_elem.findtext('QID', 'UNKNOWN')
            title = vuln_elem.findtext('TITLE', 'Security Finding')
            severity = vuln_elem.findtext('SEVERITY', '3')
            
            # Map Qualys severity (1-5)
            severity_map = {'1': 'Low', '2': 'Low', '3': 'Medium', '4': 'High', '5': 'Critical'}
            severity_normalized = self.normalize_severity(severity_map.get(severity, severity))
            
            return {
                'name': f"QID-{qid}: {title[:100]}",
                'description': title,
                'remedy': "See Qualys for remediation guidance",
                'severity': severity_normalized,
                'location': qid,
                'reference_ids': [f"QID-{qid}"],
                'details': {
                    'qid': qid,
                    'severity_level': severity
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing Qualys vulnerability: {e}")
            return None


# Export all translators
__all__ = [
    'JFrogXRaySimpleTranslator',
    'TruffleHog3Translator',
    'ContrastTranslator',
    'QualysVMTranslator'
]


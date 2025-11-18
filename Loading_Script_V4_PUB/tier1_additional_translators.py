#!/usr/bin/env python3
"""
Tier 1 Additional Translators - High Priority Scanners
=======================================================

Hard-coded translators for commonly-used enterprise scanners:
- Tenable Nessus (CSV format)
- OWASP Dependency Check (XML format)
- SonarQube (JSON format)

These scanners are industry standards and require robust parsing.
"""

import csv
import json
import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from phoenix_multi_scanner_import import (
    ScannerConfig,
    ScannerTranslator,
    VulnerabilityData
)

from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class TenableNessusTranslator(ScannerTranslator):
    """Translator for Tenable Nessus CSV exports"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Tenable Nessus CSV format"""
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                headers = set(reader.fieldnames or [])
                
                # Check for Tenable-specific headers (multiple variants)
                # Variant 1: Plugin ID, CVE, Risk, Host, Name
                variant1 = {'Plugin ID', 'CVE', 'Risk', 'Host', 'Name'}
                # Variant 2: Plugin, Severity, IP Address, Plugin Name (actual format)
                variant2 = {'Plugin', 'Severity', 'IP Address', 'Plugin Name'}
                # Variant 3: Plugin, Plugin Name, Family, Severity
                variant3 = {'Plugin', 'Plugin Name', 'Family', 'Severity'}
                
                optional_headers = {'CVSS', 'Synopsis', 'Description', 'Solution', 'Plugin Output'}
                
                # Check if any variant matches
                if (variant1.issubset(headers) or 
                    variant2.issubset(headers) or 
                    variant3.issubset(headers)):
                    # Check if at least some optional headers are present
                    if any(h in headers for h in optional_headers):
                        return True
                
            return False
        except Exception as e:
            logger.debug(f"TenableNessusTranslator.can_handle failed for {file_path}: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[Dict]:
        """Parse Tenable Nessus CSV file"""
        assets = []
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                
                # Group vulnerabilities by host
                hosts_data = {}
                
                for row in reader:
                    # Skip informational rows (support both 'Risk' and 'Severity')
                    risk = row.get('Risk', row.get('Severity', '')).strip()
                    if not risk or risk.lower() in ['none', 'info', 'informational']:
                        continue
                    
                    # Get host identifier (support multiple header variants)
                    host = row.get('Host', row.get('DNS Name', '')).strip()
                    ip = row.get('IP Address', row.get('IP', '')).strip()
                    fqdn = row.get('FQDN', row.get('DNS Name', '')).strip()
                    
                    # Use best available identifier
                    host_key = host or ip or fqdn or 'unknown'
                    
                    if host_key not in hosts_data:
                        hosts_data[host_key] = {
                            'host': host,
                            'ip': ip,
                            'fqdn': fqdn,
                            'os': row.get('OS', row.get('Operating System', '')).strip(),
                            'vulnerabilities': []
                        }
                    
                    # Parse vulnerability
                    vuln = self._parse_vulnerability(row)
                    if vuln:
                        hosts_data[host_key]['vulnerabilities'].append(vuln)
                
                # Convert to asset format
                for host_key, host_data in hosts_data.items():
                    if not host_data['vulnerabilities']:
                        continue
                    
                    # Create asset attributes (note: 'name' goes in attributes dict for AssetData)
                    attributes = {
                        'name': host_data['host'] or host_data['ip'] or host_data['fqdn'] or host_key
                    }
                    if host_data['ip']:
                        attributes['IP'] = host_data['ip']
                    if host_data['fqdn']:
                        attributes['FQDN'] = host_data['fqdn']
                    if host_data['host']:
                        attributes['hostname'] = host_data['host']
                    if host_data['os']:
                        attributes['OS'] = host_data['os']
                    
                    # Create AssetData object (findings added separately)
                    asset = AssetData(
                        asset_type='INFRA',
                        attributes=attributes
                    )
                    
                    # Add findings (vulnerabilities)
                    for v_dict in host_data['vulnerabilities']:
                        # Separate extra fields into details dict
                        details = {}
                        if 'cvss_score' in v_dict:
                            details['cvss_score'] = v_dict.pop('cvss_score')
                        if 'cvss3_score' in v_dict:
                            details['cvss3_score'] = v_dict.pop('cvss3_score')
                        if 'issue_type' in v_dict:
                            details['issue_type'] = v_dict.pop('issue_type')
                        
                        # Add details if present
                        if details:
                            v_dict['details'] = details
                        
                        vuln = VulnerabilityData(**v_dict)
                        asset.findings.append(vuln.__dict__)
                    
                    assets.append(self.ensure_asset_has_findings(asset))
                
            logger.info(f"Parsed {len(assets)} assets with vulnerabilities from Tenable CSV")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Tenable CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_vulnerability(self, row: Dict) -> Optional[Dict]:
        """Parse a single vulnerability from CSV row"""
        try:
            # Get vulnerability ID (support multiple header variants)
            plugin_id = row.get('Plugin ID', row.get('Plugin', '')).strip()
            cve = row.get('CVE', '').strip()
            name = row.get('Name', row.get('Plugin Name', '')).strip()
            
            if not name:
                return None
            
            # Use CVE if available, otherwise Plugin ID
            vuln_id = cve if cve and cve != 'N/A' else f"Plugin-{plugin_id}"
            
            # Get severity (support both 'Risk' and 'Severity')
            risk = row.get('Risk', row.get('Severity', 'Unknown')).strip()
            severity = self._map_risk_to_severity(risk)
            
            # Get description
            synopsis = row.get('Synopsis', '').strip()
            description = row.get('Description', '').strip()
            full_description = f"{synopsis}\n\n{description}".strip() if synopsis and description else (description or synopsis or name)
            
            # Truncate description
            if len(full_description) > 500:
                full_description = full_description[:497] + "..."
            
            # Get solution
            solution = row.get('Solution', '').strip() or "See scanner output for remediation"
            if len(solution) > 500:
                solution = solution[:497] + "..."
            
            # Get location (port + protocol)
            port = row.get('Port', '').strip()
            protocol = row.get('Protocol', '').strip()
            location = f"{protocol}/{port}" if protocol and port else (port or 'general')
            
            # Create vulnerability
            vulnerability = VulnerabilityData(
                name=vuln_id,
                description=full_description,
                remedy=solution,
                severity=severity,
                location=location,
                reference_ids=[vuln_id] if vuln_id else []
            )
            
            # Add optional fields
            vuln_dict = vulnerability.__dict__.copy()
            
            # Add CVSS scores if available
            cvss_score = row.get('CVSS', '').strip() or row.get('CVSS Base Score', '').strip()
            if cvss_score:
                try:
                    vuln_dict['cvss_score'] = float(cvss_score)
                except:
                    pass
            
            cvss3_score = row.get('CVSS3 Base Score', '').strip()
            if cvss3_score:
                try:
                    vuln_dict['cvss3_score'] = float(cvss3_score)
                except:
                    pass
            
            # Add CVE to reference IDs if different from name
            if cve and cve != vuln_id:
                vuln_dict['reference_ids'].append(cve)
            
            return vuln_dict
            
        except Exception as e:
            logger.debug(f"Error parsing Tenable vulnerability: {e}")
            return None
    
    def _map_risk_to_severity(self, risk: str) -> str:
        """Map Tenable risk level to Phoenix severity"""
        risk_lower = risk.lower()
        
        if risk_lower in ['critical']:
            return 'Critical'
        elif risk_lower in ['high']:
            return 'High'
        elif risk_lower in ['medium', 'moderate']:
            return 'Medium'
        elif risk_lower in ['low']:
            return 'Low'
        else:
            return 'Info'


class DependencyCheckTranslator(ScannerTranslator):
    """Translator for OWASP Dependency Check XML format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Dependency Check XML format"""
        if not file_path.lower().endswith('.xml'):
            return False
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Check for Dependency Check namespace and structure
            if 'dependency-check' in root.tag.lower() or \
               'DependencyCheck' in root.tag or \
               any('dependency-check' in str(ns) for ns in (root.attrib.get('xmlns', ''),)):
                return True
            
            # Check for characteristic elements
            if root.find('.//dependencies') is not None or \
               root.find('.//projectInfo') is not None:
                return True
            
            return False
        except Exception as e:
            logger.debug(f"DependencyCheckTranslator.can_handle failed for {file_path}: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[Dict]:
        """Parse Dependency Check XML file"""
        assets = []
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Get project name from projectInfo if available
            project_name = "Application"
            project_info = root.find('.//{*}projectInfo')
            if project_info is not None:
                name_elem = project_info.find('.//{*}name')
                if name_elem is not None and name_elem.text:
                    project_name = name_elem.text.strip()
            
            # Find dependencies
            dependencies = root.findall('.//{*}dependency')
            
            for dependency in dependencies:
                asset = self._parse_dependency(dependency, project_name)
                if asset:
                    assets.append(asset)
            
            logger.info(f"Parsed {len(assets)} dependencies with vulnerabilities from Dependency Check XML")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Dependency Check XML: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_dependency(self, dependency: ET.Element, project_name: str) -> Optional[Dict]:
        """Parse a single dependency"""
        try:
            # Get file name
            file_name_elem = dependency.find('.//{*}fileName')
            file_name = file_name_elem.text.strip() if file_name_elem is not None and file_name_elem.text else "unknown"
            
            # Get file path
            file_path_elem = dependency.find('.//{*}filePath')
            file_path = file_path_elem.text.strip() if file_path_elem is not None and file_path_elem.text else ""
            
            # Parse vulnerabilities
            vulnerabilities = []
            vuln_elements = dependency.findall('.//{*}vulnerability')
            
            for vuln_elem in vuln_elements:
                vuln = self._parse_vulnerability(vuln_elem, file_name)
                if vuln:
                    vulnerabilities.append(vuln)
            
            # Only create asset if it has vulnerabilities
            if not vulnerabilities:
                return None
            
            # Add asset attributes (name goes in attributes dict)
            attributes = {
                'name': file_name,
                'component': file_name,
                'application': project_name
            }
            
            if file_path:
                attributes['file_path'] = file_path
            
            # Get package URL or identifier
            identifiers = dependency.findall('.//{*}identifier')
            for identifier in identifiers:
                id_type = identifier.get('type', '')
                name_elem = identifier.find('.//{*}name')
                if name_elem is not None and name_elem.text:
                    if id_type == 'maven':
                        attributes['maven_coordinates'] = name_elem.text.strip()
                    elif id_type == 'npm':
                        attributes['npm_package'] = name_elem.text.strip()
                    elif id_type == 'cpe':
                        attributes['cpe'] = name_elem.text.strip()
            
            # Create AssetData object (findings added separately)
            asset = AssetData(
                asset_type='BUILD',
                attributes=attributes
            )
            
            # Add findings (vulnerabilities)
            for v_dict in vulnerabilities:
                # Separate extra fields into details dict
                details = {}
                if 'cvss_score' in v_dict:
                    details['cvss_score'] = v_dict.pop('cvss_score')
                if 'cwes' in v_dict:
                    # cwes is already a field in VulnerabilityData
                    pass
                
                # Add details if present
                if details:
                    v_dict['details'] = details
                
                vuln = VulnerabilityData(**v_dict)
                asset.findings.append(vuln.__dict__)
            
            return self.ensure_asset_has_findings(asset)
            
        except Exception as e:
            logger.debug(f"Error parsing Dependency Check dependency: {e}")
            return None
    
    def _parse_vulnerability(self, vuln_elem: ET.Element, component: str) -> Optional[Dict]:
        """Parse a single vulnerability"""
        try:
            # Get CVE name
            name_elem = vuln_elem.find('.//{*}name')
            if name_elem is None or not name_elem.text:
                return None
            
            vuln_id = name_elem.text.strip()
            
            # Get severity
            severity_elem = vuln_elem.find('.//{*}severity')
            severity_str = severity_elem.text.strip() if severity_elem is not None and severity_elem.text else "Unknown"
            severity = self.normalize_severity(severity_str)
            
            # Get description
            desc_elem = vuln_elem.find('.//{*}description')
            description = desc_elem.text.strip() if desc_elem is not None and desc_elem.text else f"Vulnerability {vuln_id} in {component}"
            if len(description) > 500:
                description = description[:497] + "..."
            
            # Get CVSS score
            cvss_score = None
            cvss_elem = vuln_elem.find('.//{*}cvssScore')
            if cvss_elem is not None and cvss_elem.text:
                try:
                    cvss_score = float(cvss_elem.text.strip())
                except:
                    pass
            
            # Get CWE
            cwes = []
            cwe_elem = vuln_elem.find('.//{*}cwe')
            if cwe_elem is not None and cwe_elem.text:
                cwes.append(cwe_elem.text.strip())
            
            # Create vulnerability
            vulnerability = VulnerabilityData(
                name=vuln_id,
                description=description,
                remedy="Update dependency to a non-vulnerable version. See scanner output for details.",
                severity=severity,
                location=component,
                reference_ids=[vuln_id]
            )
            
            vuln_dict = vulnerability.__dict__.copy()
            
            if cvss_score:
                vuln_dict['cvss_score'] = cvss_score
            
            if cwes:
                vuln_dict['cwes'] = cwes
            
            return vuln_dict
            
        except Exception as e:
            logger.debug(f"Error parsing Dependency Check vulnerability: {e}")
            return None


class SonarQubeTranslator(ScannerTranslator):
    """Translator for SonarQube JSON export format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect SonarQube JSON format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Check for SonarQube-specific structure
            if isinstance(file_content, dict):
                # SonarQube export has 'issues' array and 'rules' dict
                if 'issues' in file_content and 'rules' in file_content:
                    # Verify structure
                    if isinstance(file_content['issues'], list) and \
                       isinstance(file_content['rules'], dict):
                        return True
                
                # Also check for SonarQube API response format
                if 'issues' in file_content and 'components' in file_content and 'paging' in file_content:
                    return True
            
            return False
        except Exception as e:
            logger.debug(f"SonarQubeTranslator.can_handle failed for {file_path}: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[Dict]:
        """Parse SonarQube JSON file"""
        assets = []
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Get project name
            project_name = data.get('projectName', 'Application')
            
            # Get rules for reference
            rules = data.get('rules', {})
            
            # Group issues by component (file)
            components_data = {}
            
            issues = data.get('issues', [])
            for issue in issues:
                # Skip security hotspots unless they're confirmed
                status = issue.get('status', '')
                if status.upper() in ['TO_REVIEW', 'REVIEWED'] and issue.get('type') == 'SECURITY_HOTSPOT':
                    continue
                
                component = issue.get('component', 'unknown')
                
                if component not in components_data:
                    components_data[component] = []
                
                vuln = self._parse_issue(issue, rules)
                if vuln:
                    components_data[component].append(vuln)
            
            # Convert to asset format
            for component, vulnerabilities in components_data.items():
                if not vulnerabilities:
                    continue
                
                # Extract file name from component path
                file_name = component.split(':')[-1] if ':' in component else component
                
                # Create AssetData object (findings added separately)
                asset = AssetData(
                    asset_type='CODE',
                    attributes={
                        'name': file_name,
                        'component': component,
                        'application': project_name,
                        'scanner': 'SonarQube'
                    }
                )
                
                # Add findings (vulnerabilities)
                for v_dict in vulnerabilities:
                    # Separate extra fields into details dict
                    details = {}
                    if 'issue_type' in v_dict:
                        details['issue_type'] = v_dict.pop('issue_type')
                    
                    # Add details if present
                    if details:
                        v_dict['details'] = details
                    
                    vuln = VulnerabilityData(**v_dict)
                    asset.findings.append(vuln.__dict__)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} code components with {sum(len(a.findings) for a in assets)} issues from SonarQube")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing SonarQube JSON: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_issue(self, issue: Dict, rules: Dict) -> Optional[Dict]:
        """Parse a single SonarQube issue"""
        try:
            # Get rule key
            rule_key = issue.get('rule', '')
            if not rule_key:
                return None
            
            # Get rule details
            rule_details = rules.get(rule_key, {})
            
            # Get issue details
            severity_str = issue.get('severity', rule_details.get('severity', 'INFO'))
            severity = self._map_sonar_severity(severity_str)
            
            # Build description
            message = issue.get('message', '')
            rule_name = rule_details.get('name', rule_key)
            description = f"{rule_name}: {message}" if message else rule_name
            
            if len(description) > 500:
                description = description[:497] + "..."
            
            # Get location
            line = issue.get('line', '')
            location = f"line {line}" if line else "file"
            
            # Create vulnerability
            vulnerability = VulnerabilityData(
                name=rule_key,
                description=description,
                remedy="Review and fix the code issue. See SonarQube for detailed recommendations.",
                severity=severity,
                location=location,
                reference_ids=[rule_key, issue.get('key', '')]
            )
            
            vuln_dict = vulnerability.__dict__.copy()
            
            # Add issue type if available
            issue_type = issue.get('type', '')
            if issue_type:
                vuln_dict['issue_type'] = issue_type
            
            return vuln_dict
            
        except Exception as e:
            logger.debug(f"Error parsing SonarQube issue: {e}")
            return None
    
    def _map_sonar_severity(self, severity: str) -> str:
        """Map SonarQube severity to Phoenix severity"""
        severity_lower = severity.lower()
        
        if severity_lower in ['blocker', 'critical']:
            return 'Critical'
        elif severity_lower in ['major']:
            return 'High'
        elif severity_lower in ['minor']:
            return 'Medium'
        elif severity_lower in ['info', 'trivial']:
            return 'Low'
        else:
            return 'Info'


# Export all translators
__all__ = [
    'TenableNessusTranslator',
    'DependencyCheckTranslator',
    'SonarQubeTranslator'
]


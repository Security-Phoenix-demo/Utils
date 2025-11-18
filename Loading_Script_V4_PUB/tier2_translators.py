#!/usr/bin/env python3
"""
Tier 2 Translators - Common Open Source & Enterprise Scanners
==============================================================

Hard-coded translators for widely-used scanners:
- CycloneDX (SBOM standard)
- npm audit (Node.js package vulnerabilities)
- pip-audit (Python package vulnerabilities)
- Qualys WebApp (Enterprise web app scanner)

These formats are industry standards and require robust parsing.
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
from tag_utils import get_tags_safely

from phoenix_import_refactored import AssetData

logger = logging.getLogger(__name__)


class CycloneDXTranslator(ScannerTranslator):
    """Translator for CycloneDX SBOM format (Software Bill of Materials)"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect CycloneDX JSON/XML format"""
        if file_path.lower().endswith('.json'):
            try:
                if file_content is None:
                    with open(file_path, 'r') as f:
                        file_content = json.load(f)
                
                # Check for CycloneDX structure
                if isinstance(file_content, dict):
                    if file_content.get('bomFormat') == 'CycloneDX' or \
                       'specVersion' in file_content and 'components' in file_content:
                        return True
                
                return False
            except Exception as e:
                logger.debug(f"CycloneDXTranslator.can_handle failed for {file_path}: {e}")
                return False
        
        elif file_path.lower().endswith('.xml'):
            try:
                tree = ET.parse(file_path)
                root = tree.getroot()
                
                # Check for CycloneDX XML namespace or structure
                if 'cyclonedx' in root.tag.lower() or \
                   any('cyclonedx' in str(ns).lower() for ns in (root.attrib.get('xmlns', ''),)):
                    return True
                
                return False
            except Exception as e:
                logger.debug(f"CycloneDXTranslator.can_handle failed for {file_path}: {e}")
                return False
        
        return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse CycloneDX SBOM file"""
        assets = []
        
        try:
            if file_path.lower().endswith('.json'):
                with open(file_path, 'r') as f:
                    data = json.load(f)
                assets = self._parse_json(data)
            elif file_path.lower().endswith('.xml'):
                tree = ET.parse(file_path)
                root = tree.getroot()
                assets = self._parse_xml(root)
            
            logger.info(f"Parsed {len(assets)} components with vulnerabilities from CycloneDX SBOM")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing CycloneDX: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_json(self, data: Dict) -> List[AssetData]:
        """Parse CycloneDX JSON format"""
        assets = []
        
        # Get component name from metadata
        metadata = data.get('metadata', {})
        project_name = metadata.get('component', {}).get('name', 'Application')
        
        # Get components
        components = data.get('components', [])
        
        # Get vulnerabilities
        vulnerabilities = data.get('vulnerabilities', [])
        
        # Group vulnerabilities by component
        vuln_by_component = {}
        for vuln in vulnerabilities:
            affects = vuln.get('affects', [])
            for affect in affects:
                ref = affect.get('ref', '')
                if ref not in vuln_by_component:
                    vuln_by_component[ref] = []
                vuln_by_component[ref].append(vuln)
        
        # Create assets for each component with vulnerabilities
        for component in components:
            bom_ref = component.get('bom-ref', '')
            vulns = vuln_by_component.get(bom_ref, [])
            
            if not vulns:
                continue
            
            # Parse component info
            comp_name = component.get('name', 'unknown')
            comp_version = component.get('version', '')
            comp_type = component.get('type', 'library')
            purl = component.get('purl', '')
            
            # Create asset attributes
            attributes = {
                'name': f"{comp_name}@{comp_version}" if comp_version else comp_name,
                'component': comp_name,
                'version': comp_version,
                'component_type': comp_type,
                'application': project_name,
                'buildFile': purl if purl else f"{comp_name}@{comp_version}"
            }
            
            if purl:
                attributes['purl'] = purl
            
            # Create asset
            asset = AssetData(
                asset_type='BUILD',
                attributes=attributes
            )
            
            # Add vulnerabilities
            for vuln in vulns:
                vuln_data = self._parse_vulnerability_json(vuln, comp_name)
                if vuln_data:
                    vuln_obj = VulnerabilityData(**vuln_data)
                    asset.findings.append(vuln_obj.__dict__)
            
            if asset.findings:
                assets.append(self.ensure_asset_has_findings(asset))
        
        return assets
    
    def _parse_vulnerability_json(self, vuln: Dict, component: str) -> Optional[Dict]:
        """Parse a CycloneDX vulnerability"""
        try:
            vuln_id = vuln.get('id', 'UNKNOWN')
            if not vuln_id:
                return None
            
            # Get description
            description = vuln.get('description', f"Vulnerability {vuln_id} in {component}")
            if len(description) > 500:
                description = description[:497] + "..."
            
            # Get severity from ratings
            ratings = vuln.get('ratings', [])
            severity = 'Medium'  # default
            cvss_score = None
            
            for rating in ratings:
                if 'severity' in rating:
                    severity = self._normalize_cyclone_severity(rating['severity'])
                if 'score' in rating:
                    try:
                        cvss_score = float(rating['score'])
                    except:
                        pass
            
            # Get recommendation/remedy
            recommendation = vuln.get('recommendation', "See SBOM for remediation details")
            if len(recommendation) > 500:
                recommendation = recommendation[:497] + "..."
            
            # Get CWEs
            cwes = []
            if 'cwes' in vuln:
                cwes = [str(cwe) for cwe in vuln['cwes']]
            
            # Create vulnerability dict
            vuln_dict = {
                'name': vuln_id,
                'description': description,
                'remedy': recommendation,
                'severity': severity,
                'location': component,
                'reference_ids': [vuln_id]
            }
            
            if cwes:
                vuln_dict['cwes'] = cwes
            
            if cvss_score:
                vuln_dict['details'] = {'cvss_score': cvss_score}
            
            return vuln_dict
            
        except Exception as e:
            logger.debug(f"Error parsing CycloneDX vulnerability: {e}")
            return None
    
    def _parse_xml(self, root: ET.Element) -> List[AssetData]:
        """Parse CycloneDX XML format"""
        assets = []
        
        # Get XML namespace (e.g., http://cyclonedx.org/schema/bom/1.4)
        ns = {'cdx': root.tag.split('}')[0].strip('{')} if '}' in root.tag else {}
        
        # Build component lookup by bom-ref or name
        components = {}
        components_elem = root.find('cdx:components', ns) if ns else root.find('components')
        if components_elem is not None:
            for comp in components_elem.findall('cdx:component', ns) if ns else components_elem.findall('component'):
                bom_ref = comp.get('bom-ref')
                name = comp.findtext('cdx:name', default='', namespaces=ns) if ns else comp.findtext('name', default='')
                version = comp.findtext('cdx:version', default='', namespaces=ns) if ns else comp.findtext('version', default='')
                purl = comp.findtext('cdx:purl', default='', namespaces=ns) if ns else comp.findtext('purl', default='')
                
                # Use bom-ref if available, otherwise use name as key
                if name:
                    key = bom_ref if bom_ref else f"{name}@{version}" if version else name
                    components[key] = {
                        'name': name,
                        'version': version,
                        'purl': purl
                    }
        
        # Parse vulnerabilities (optional - SBOM may have components without vulns)
        vulns_elem = root.find('cdx:vulnerabilities', ns) if ns else root.find('vulnerabilities')
        if vulns_elem is None:
            logger.info("No vulnerabilities section found in CycloneDX XML - will return components as assets")
            # Create assets from all components even without vulnerabilities
            tags = get_tags_safely(self.tag_config)
            for comp_ref, comp_info in components.items():
                comp_name = f"{comp_info['name']}@{comp_info['version']}" if comp_info['version'] else comp_info['name']
                asset = AssetData(
                    asset_type='BUILD',
                    attributes={
                        'name': comp_name,
                        'version': comp_info['version'],
                        'buildFile': comp_info['purl'] if comp_info['purl'] else comp_name,
                        'scanner': 'CycloneDX'
                    },
                    tags=tags + [{"key": "component", "value": comp_info['name']}]
                )
                # Add a "no vulnerabilities" finding to satisfy Phoenix API
                asset.findings.append({
                    'name': 'NO_VULNERABILITIES_FOUND',
                    'description': f'No vulnerabilities found for component {comp_name}',
                    'remedy': 'No action required',
                    'severity': '0.0',
                    'location': comp_name,
                    'reference_ids': []
                })
                assets.append(asset)
            
            logger.info(f"Parsed {len(assets)} components (no vulnerabilities) from CycloneDX SBOM")
            return assets
        
        # Group vulnerabilities by affected component
        comp_vulns = {}
        for vuln_elem in vulns_elem.findall('cdx:vulnerability', ns) if ns else vulns_elem.findall('vulnerability'):
            # Parse vulnerability details
            vuln_id = vuln_elem.findtext('cdx:id', default='UNKNOWN', namespaces=ns) if ns else vuln_elem.findtext('id', default='UNKNOWN')
            description = vuln_elem.findtext('cdx:description', default='', namespaces=ns) if ns else vuln_elem.findtext('description', default='')
            recommendation = vuln_elem.findtext('cdx:recommendation', default='', namespaces=ns) if ns else vuln_elem.findtext('recommendation', default='')
            
            # Parse severity and score from ratings
            severity = 'Medium'
            cvss_score = None
            ratings_elem = vuln_elem.find('cdx:ratings', ns) if ns else vuln_elem.find('ratings')
            if ratings_elem is not None:
                rating_elem = ratings_elem.find('cdx:rating', ns) if ns else ratings_elem.find('rating')
                if rating_elem is not None:
                    sev_text = rating_elem.findtext('cdx:severity', default='', namespaces=ns) if ns else rating_elem.findtext('severity', default='')
                    if sev_text:
                        severity = self._normalize_cyclone_severity(sev_text)
                    score_text = rating_elem.findtext('cdx:score', default='', namespaces=ns) if ns else rating_elem.findtext('score', default='')
                    if score_text:
                        try:
                            cvss_score = float(score_text)
                        except:
                            pass
            
            # Parse CWEs
            cwes = []
            cwes_elem = vuln_elem.find('cdx:cwes', ns) if ns else vuln_elem.find('cwes')
            if cwes_elem is not None:
                for cwe_elem in cwes_elem.findall('cdx:cwe', ns) if ns else cwes_elem.findall('cwe'):
                    if cwe_elem.text:
                        cwes.append(f"CWE-{cwe_elem.text}")
            
            # Find affected components
            affects_elem = vuln_elem.find('cdx:affects', ns) if ns else vuln_elem.find('affects')
            if affects_elem is not None:
                for target_elem in affects_elem.findall('cdx:target', ns) if ns else affects_elem.findall('target'):
                    ref = target_elem.findtext('cdx:ref', default='', namespaces=ns) if ns else target_elem.findtext('ref', default='')
                    if ref and ref in components:
                        comp_info = components[ref]
                        comp_name = f"{comp_info['name']}@{comp_info['version']}" if comp_info['version'] else comp_info['name']
                        
                        if comp_name not in comp_vulns:
                            comp_vulns[comp_name] = {
                                'component': comp_info,
                                'vulns': []
                            }
                        
                        vuln_dict = {
                            'name': vuln_id,
                            'description': description[:500] if description else f"Vulnerability {vuln_id}",
                            'remedy': recommendation[:500] if recommendation else "See SBOM for remediation",
                            'severity': severity,
                            'location': comp_name,
                            'reference_ids': [vuln_id]
                        }
                        
                        if cwes:
                            vuln_dict['cwes'] = cwes
                        if cvss_score:
                            vuln_dict['details'] = {'cvss_score': cvss_score}
                        
                        comp_vulns[comp_name]['vulns'].append(vuln_dict)
        
        # Create assets from components with vulnerabilities
        tags = get_tags_safely(self.tag_config)
        for comp_name, data in comp_vulns.items():
            comp_info = data['component']
            
            attributes = {
                'name': comp_name,
                'component': comp_info['name'],
                'version': comp_info.get('version', ''),
                'buildFile': comp_info.get('purl', comp_name),  # Required for BUILD assets
            }
            
            if comp_info.get('purl'):
                attributes['purl'] = comp_info['purl']
            
            if tags:
                attributes.update(tags)
            
            asset = AssetData(
                asset_type='BUILD',
                attributes=attributes
            )
            
            # Add vulnerabilities
            for vuln_data in data['vulns']:
                vuln_obj = VulnerabilityData(**vuln_data)
                asset.findings.append(vuln_obj.__dict__)
            
            if asset.findings:
                assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Parsed {len(assets)} components with {sum(len(a.findings) for a in assets)} vulnerabilities from CycloneDX XML")
        return assets
    
    def _normalize_cyclone_severity(self, severity: str) -> str:
        """Normalize CycloneDX severity to Phoenix format"""
        severity_lower = severity.lower()
        
        if severity_lower in ['critical']:
            return 'Critical'
        elif severity_lower in ['high']:
            return 'High'
        elif severity_lower in ['medium', 'moderate']:
            return 'Medium'
        elif severity_lower in ['low']:
            return 'Low'
        else:
            return 'Info'


class NpmAuditTranslator(ScannerTranslator):
    """Translator for npm audit JSON format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect npm audit JSON format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # npm audit v7+ format has 'vulnerabilities' dict
            # npm audit v6 format has 'advisories' dict and 'actions' array
            if isinstance(file_content, dict):
                if 'vulnerabilities' in file_content and 'metadata' in file_content:
                    return True
                if 'advisories' in file_content and 'actions' in file_content:
                    return True
                # npm audit fix --dry-run format
                if 'actions' in file_content and isinstance(file_content['actions'], list):
                    actions = file_content['actions']
                    if actions and isinstance(actions[0], dict) and 'resolves' in actions[0]:
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"NpmAuditTranslator.can_handle failed for {file_path}: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse npm audit JSON file"""
        assets = []
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Determine format version
            if 'vulnerabilities' in data:
                assets = self._parse_v7_format(data)
            elif 'advisories' in data:
                assets = self._parse_v6_format(data)
            
            logger.info(f"Parsed {len(assets)} npm packages with vulnerabilities")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing npm audit: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_v7_format(self, data: Dict) -> List[AssetData]:
        """Parse npm audit v7+ format"""
        assets = []
        
        vulnerabilities = data.get('vulnerabilities', {})
        
        for package_name, vuln_info in vulnerabilities.items():
            # Get vulnerability details
            vuln_name = vuln_info.get('via', [])
            if not vuln_name:
                continue
            
            # Create asset
            asset_name = f"{package_name}@{vuln_info.get('range', 'unknown')}"
            
            asset = AssetData(
                asset_type='BUILD',
                attributes={
                    'name': asset_name,
                    'component': package_name,
                    'version': vuln_info.get('range', 'unknown'),
                    'scanner': 'npm-audit',
                    'buildFile': 'package.json'
                }
            )
            
            # Add vulnerabilities
            for via in vuln_info.get('via', []):
                if isinstance(via, dict):
                    vuln_data = self._parse_vuln_v7(via, package_name)
                    if vuln_data:
                        vuln_obj = VulnerabilityData(**vuln_data)
                        asset.findings.append(vuln_obj.__dict__)
            
            if asset.findings:
                assets.append(self.ensure_asset_has_findings(asset))
        
        return assets
    
    def _parse_v6_format(self, data: Dict) -> List[AssetData]:
        """Parse npm audit v6 format"""
        assets = []
        
        advisories = data.get('advisories', {})
        
        for adv_id, advisory in advisories.items():
            module_name = advisory.get('module_name', 'unknown')
            
            # Create asset
            asset = AssetData(
                asset_type='BUILD',
                attributes={
                    'name': module_name,
                    'component': module_name,
                    'scanner': 'npm-audit',
                    'buildFile': 'package.json'
                }
            )
            
            # Parse vulnerability
            vuln_data = self._parse_vuln_v6(advisory, module_name)
            if vuln_data:
                vuln_obj = VulnerabilityData(**vuln_data)
                asset.findings.append(vuln_obj.__dict__)
                assets.append(self.ensure_asset_has_findings(asset))
        
        return assets
    
    def _parse_vuln_v7(self, via: Dict, package: str) -> Optional[Dict]:
        """Parse npm audit v7 vulnerability"""
        try:
            vuln_id = via.get('source', '') or via.get('title', 'UNKNOWN')
            if not vuln_id:
                return None
            
            title = via.get('title', vuln_id)
            url = via.get('url', '')
            severity = self.normalize_severity(via.get('severity', 'medium'))
            
            description = title
            if url:
                description += f"\n{url}"
            
            if len(description) > 500:
                description = description[:497] + "..."
            
            return {
                'name': str(vuln_id),
                'description': description,
                'remedy': "Update to a non-vulnerable version. Run: npm audit fix",
                'severity': severity,
                'location': package,
                'reference_ids': [str(vuln_id)]
            }
            
        except Exception as e:
            logger.debug(f"Error parsing npm audit v7 vulnerability: {e}")
            return None
    
    def _parse_vuln_v6(self, advisory: Dict, package: str) -> Optional[Dict]:
        """Parse npm audit v6 advisory"""
        try:
            vuln_id = advisory.get('cves', [''])[0] if advisory.get('cves') else str(advisory.get('id', 'UNKNOWN'))
            title = advisory.get('title', vuln_id)
            overview = advisory.get('overview', '')
            recommendation = advisory.get('recommendation', 'Update to a non-vulnerable version')
            severity = self.normalize_severity(advisory.get('severity', 'moderate'))
            
            description = f"{title}\n{overview}" if overview else title
            if len(description) > 500:
                description = description[:497] + "..."
            
            if len(recommendation) > 500:
                recommendation = recommendation[:497] + "..."
            
            # Get CWEs
            cwes = []
            if 'cwe' in advisory:
                cwes = [advisory['cwe']]
            
            vuln_dict = {
                'name': vuln_id,
                'description': description,
                'remedy': recommendation,
                'severity': severity,
                'location': package,
                'reference_ids': [vuln_id]
            }
            
            if cwes:
                vuln_dict['cwes'] = cwes
            
            # Add CVSS if available
            if 'cvss' in advisory:
                vuln_dict['details'] = {'cvss_score': advisory['cvss'].get('score')}
            
            return vuln_dict
            
        except Exception as e:
            logger.debug(f"Error parsing npm audit v6 advisory: {e}")
            return None


class PipAuditTranslator(ScannerTranslator):
    """Translator for pip-audit JSON format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect pip-audit JSON format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # pip-audit produces an array of vulnerability objects
            # Each has 'name', 'version', 'vulns' fields
            if isinstance(file_content, list):
                if len(file_content) == 0:
                    # Empty results - could be pip-audit
                    # Check filename as hint
                    if 'pip' in Path(file_path).stem.lower():
                        return True
                elif len(file_content) > 0:
                    first_item = file_content[0]
                    if isinstance(first_item, dict) and \
                       'name' in first_item and \
                       'version' in first_item and \
                       'vulns' in first_item:
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"PipAuditTranslator.can_handle failed for {file_path}: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse pip-audit JSON file"""
        assets = []
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            if not isinstance(data, list):
                return assets
            
            # Each item is a package with vulnerabilities
            for package_info in data:
                name = package_info.get('name', 'unknown')
                version = package_info.get('version', 'unknown')
                vulns = package_info.get('vulns', [])
                
                if not vulns:
                    continue
                
                # Create asset
                asset = AssetData(
                    asset_type='BUILD',
                    attributes={
                        'name': f"{name}=={version}",
                        'component': name,
                        'version': version,
                        'scanner': 'pip-audit',
                        'buildFile': 'requirements.txt'
                    }
                )
                
                # Add vulnerabilities
                for vuln in vulns:
                    vuln_data = self._parse_vulnerability(vuln, name)
                    if vuln_data:
                        vuln_obj = VulnerabilityData(**vuln_data)
                        asset.findings.append(vuln_obj.__dict__)
                
                if asset.findings:
                    assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} Python packages with vulnerabilities from pip-audit")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing pip-audit: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_vulnerability(self, vuln: Dict, package: str) -> Optional[Dict]:
        """Parse pip-audit vulnerability"""
        try:
            vuln_id = vuln.get('id', 'UNKNOWN')
            if not vuln_id:
                return None
            
            description = vuln.get('description', f"Vulnerability {vuln_id} in {package}")
            fix_versions = vuln.get('fix_versions', [])
            aliases = vuln.get('aliases', [])
            
            if len(description) > 500:
                description = description[:497] + "..."
            
            # Build remedy message
            if fix_versions:
                remedy = f"Update to version: {', '.join(fix_versions)}"
            else:
                remedy = "No fix available yet. See advisory for details."
            
            # Reference IDs include main ID and aliases
            reference_ids = [vuln_id] + aliases
            
            return {
                'name': vuln_id,
                'description': description,
                'remedy': remedy,
                'severity': 'Medium',  # pip-audit doesn't provide severity
                'location': package,
                'reference_ids': reference_ids
            }
            
        except Exception as e:
            logger.debug(f"Error parsing pip-audit vulnerability: {e}")
            return None


class QualysWebAppTranslator(ScannerTranslator):
    """Translator for Qualys WebApp Scanner XML format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Qualys WebApp XML format"""
        if not file_path.lower().endswith('.xml'):
            return False
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Check for Qualys WebApp specific structure
            if root.tag == 'WAS_SCAN_REPORT' or root.tag == 'WAS_WEBAPP_REPORT':
                return True
            
            return False
        except Exception as e:
            logger.debug(f"QualysWebAppTranslator.can_handle failed for {file_path}: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Qualys WebApp XML file"""
        assets = []
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Get web app name
            webapp_name = "Web Application"
            target = root.find('.//TARGET')
            if target is not None:
                scan_elem = target.find('.//SCAN')
                if scan_elem is not None and scan_elem.text:
                    webapp_name = scan_elem.text.strip()
            
            # Parse vulnerabilities
            vulnerabilities = []
            vuln_list = root.find('.//VULNERABILITY_LIST')
            if vuln_list is not None:
                for vuln_elem in vuln_list.findall('.//VULNERABILITY'):
                    vuln = self._parse_vulnerability(vuln_elem)
                    if vuln:
                        vulnerabilities.append(vuln)
            
            # Create asset if vulnerabilities found
            if vulnerabilities:
                asset = AssetData(
                    asset_type='WEB',
                    attributes={
                        'name': webapp_name,
                        'application': webapp_name,
                        'scanner': 'Qualys WebApp Scanner'
                    }
                )
                
                for vuln_dict in vulnerabilities:
                    vuln_obj = VulnerabilityData(**vuln_dict)
                    asset.findings.append(vuln_obj.__dict__)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} web applications with {len(vulnerabilities)} vulnerabilities from Qualys")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Qualys WebApp XML: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_vulnerability(self, vuln_elem: ET.Element) -> Optional[Dict]:
        """Parse Qualys WebApp vulnerability"""
        try:
            # Get QID (Qualys ID)
            qid_elem = vuln_elem.find('.//QID')
            qid = qid_elem.text.strip() if qid_elem is not None and qid_elem.text else 'UNKNOWN'
            
            # Get vulnerability name/title
            name_elem = vuln_elem.find('.//NAME')
            name = name_elem.text.strip() if name_elem is not None and name_elem.text else qid
            
            # Get URL where vulnerability was found
            url_elem = vuln_elem.find('.//URL')
            url = url_elem.text.strip() if url_elem is not None and url_elem.text else ''
            
            # Get severity (LEVEL1-5, where 5 is critical)
            severity = 'Medium'
            severity_elem = vuln_elem.find('.//SEVERITY')
            if severity_elem is not None and severity_elem.text:
                level = severity_elem.text.strip()
                severity = self._map_qualys_severity(level)
            
            # Get description/impact
            impact_elem = vuln_elem.find('.//IMPACT')
            impact = impact_elem.text.strip() if impact_elem is not None and impact_elem.text else ''
            
            description = name
            if impact:
                description += f"\n\n{impact}"
            
            if len(description) > 500:
                description = description[:497] + "..."
            
            # Get solution
            solution_elem = vuln_elem.find('.//SOLUTION')
            solution = solution_elem.text.strip() if solution_elem is not None and solution_elem.text else "See Qualys for remediation"
            if len(solution) > 500:
                solution = solution[:497] + "..."
            
            # Get CVE if available
            cve_elem = vuln_elem.find('.//CVE_ID_LIST/CVE_ID')
            reference_ids = [f"QID-{qid}"]
            if cve_elem is not None and cve_elem.text:
                cve = cve_elem.text.strip()
                reference_ids.append(cve)
            
            return {
                'name': f"QID-{qid}",
                'description': description,
                'remedy': solution,
                'severity': severity,
                'location': url if url else 'web-application',
                'reference_ids': reference_ids
            }
            
        except Exception as e:
            logger.debug(f"Error parsing Qualys vulnerability: {e}")
            return None
    
    def _map_qualys_severity(self, level: str) -> str:
        """Map Qualys severity level to Phoenix severity"""
        level_str = level.strip().upper()
        
        if level_str in ['5', 'LEVEL5', 'URGENT']:
            return 'Critical'
        elif level_str in ['4', 'LEVEL4', 'CRITICAL']:
            return 'High'
        elif level_str in ['3', 'LEVEL3', 'SERIOUS']:
            return 'Medium'
        elif level_str in ['2', 'LEVEL2', 'MEDIUM']:
            return 'Low'
        else:
            return 'Info'


# Export all translators
__all__ = [
    'CycloneDXTranslator',
    'NpmAuditTranslator',
    'PipAuditTranslator',
    'QualysWebAppTranslator'
]


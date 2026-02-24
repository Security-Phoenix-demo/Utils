#!/usr/bin/env python3
"""
CycloneDX SBOM Translator
==========================

Translator for CycloneDX SBOM (Software Bill of Materials) standard.

Supported Formats:
- JSON format with 'bomFormat': 'CycloneDX'
- XML format with cyclonedx namespace

Scanner Detection:
- JSON: 'bomFormat' == 'CycloneDX' OR ('specVersion' AND 'components')
- XML: 'cyclonedx' in root tag or xmlns attribute

Asset Type: BUILD
"""

import json
import logging
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig

logger = logging.getLogger(__name__)


def get_tags_safely(tag_config):
    """Safely get tags from tag_config"""
    if not tag_config:
        return []
    if hasattr(tag_config, 'get_all_tags'):
        return tag_config.get_all_tags()
    return []


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
        logger.info(f"Parsing CycloneDX SBOM file: {file_path}")
        
        try:
            if file_path.lower().endswith('.json'):
                with open(file_path, 'r') as f:
                    data = json.load(f)
                assets = self._parse_json(data)
            elif file_path.lower().endswith('.xml'):
                tree = ET.parse(file_path)
                root = tree.getroot()
                assets = self._parse_xml(root)
            else:
                assets = []
            
            logger.info(f"Parsed {len(assets)} components with {sum(len(a.findings) for a in assets)} vulnerabilities from CycloneDX SBOM")
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
            
            # Create asset
            asset = AssetData(
                asset_type='BUILD',
                attributes={
                    'buildFile': purl if purl else f"{comp_name}@{comp_version}",
                    'origin': 'cyclonedx',
                    'component': comp_name,
                    'version': comp_version,
                    'component_type': comp_type,
                    'application': project_name
                },
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "cyclonedx"},
                    {"key": "sbom-type", "value": "cyclonedx"}
                ]
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
            logger.info("No vulnerabilities section found in CycloneDX XML")
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
        for comp_name, data in comp_vulns.items():
            comp_info = data['component']
            
            asset = AssetData(
                asset_type='BUILD',
                attributes={
                    'buildFile': comp_info.get('purl', comp_name),
                    'origin': 'cyclonedx',
                    'component': comp_info['name'],
                    'version': comp_info.get('version', '')
                },
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "cyclonedx"},
                    {"key": "sbom-type", "value": "cyclonedx"}
                ]
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


__all__ = ['CycloneDXTranslator']


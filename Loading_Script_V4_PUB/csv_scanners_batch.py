"""
CSV Scanners Batch - Dedicated CSV Translators
===============================================

Collection of CSV-specific translators for scanners that require
custom parsing logic beyond YAML mappings.
"""

import csv
import logging
import sys
from pathlib import Path
from typing import List, Dict, Any
from phoenix_multi_scanner_import import (
    ScannerTranslator, AssetData, VulnerabilityData, ScannerConfig
)
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


def increase_csv_field_size_limit():
    """Increase CSV field size limit to handle large fields"""
    maxInt = sys.maxsize
    while True:
        try:
            csv.field_size_limit(maxInt)
            break
        except OverflowError:
            maxInt = int(maxInt/10)


class BugCrowdCSVTranslator(ScannerTranslator):
    """Translator for BugCrowd CSV exports"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        if not file_path.lower().endswith('.csv'):
            return False
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().lower()
                return 'reference_number' in first_line and 'bounty_code' in first_line
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        logger.info(f"Parsing BugCrowd CSV: {file_path}")
        increase_csv_field_size_limit()
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                return []
            
            # Group by target
            targets = {}
            for row in rows:
                target = row.get('target_name', 'Unknown Target')
                if target not in targets:
                    targets[target] = []
                
                title = row.get('title', row.get('caption', 'BugCrowd Finding'))
                severity = row.get('priority', row.get('severity', '3'))
                
                targets[target].append(VulnerabilityData(
                    name=title[:100],
                    description=row.get('description', title)[:500],
                    remedy=row.get('remediation_advice', 'See BugCrowd platform'),
                    severity=self._map_priority_to_severity(severity),
                    location=target,
                    reference_ids=[row.get('reference_number', row.get('bug_url', ''))]
                ))
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for target_name, vulns in targets.items():
                asset = AssetData(
                    asset_type='WEB',
                    attributes={'fqdn': target_name if '.' in target_name else f"{target_name}.local"},
                    findings=vulns if vulns else [VulnerabilityData(
                        name="NO_FINDINGS",
                        description="No vulnerabilities found",
                        remedy="No action required",
                        severity="0.0",
                        location=target_name
                    )],
                    tags=tags
                )
                assets.append(asset)
            
            logger.info(f"Parsed {len(assets)} assets from BugCrowd CSV")
            return assets
        except Exception as e:
            logger.error(f"Error parsing BugCrowd CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_priority_to_severity(self, priority: str) -> str:
        """Map BugCrowd priority (1-5) to severity"""
        mapping = {'1': '3.0', '2': '5.0', '3': '7.0', '4': '8.5', '5': '10.0'}
        return mapping.get(str(priority).strip(), '5.0')


class AzureSecurityCenterCSVTranslator(ScannerTranslator):
    """Translator for Azure Security Center Recommendations CSV"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        if not file_path.lower().endswith('.csv'):
            return False
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().lower()
                return 'subscriptionid' in first_line and 'recommendationname' in first_line
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        logger.info(f"Parsing Azure Security Center CSV: {file_path}")
        increase_csv_field_size_limit()
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                return []
            
            # Group by resource
            resources = {}
            for row in rows:
                resource_id = row.get('resourceId', row.get('resourceName', 'Unknown'))
                if resource_id not in resources:
                    resources[resource_id] = {
                        'name': row.get('resourceName', resource_id),
                        'type': row.get('resourceType', 'Azure Resource'),
                        'group': row.get('resourceGroup', ''),
                        'vulns': []
                    }
                
                # Only include unhealthy/failed recommendations
                state = row.get('state', '').lower()
                if state in ['unhealthy', 'failed', 'open']:
                    recommendation = row.get('recommendationDisplayName', row.get('recommendationName', 'Azure Recommendation'))
                    severity = row.get('severity', 'Medium')
                    
                    resources[resource_id]['vulns'].append(VulnerabilityData(
                        name=recommendation[:100],
                        description=row.get('description', recommendation)[:500],
                        remedy=row.get('remediationSteps', 'See Azure Security Center'),
                        severity=self._map_azure_severity(severity),
                        location=resource_id,
                        reference_ids=[row.get('recommendationId', '')]
                    ))
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for resource_id, data in resources.items():
                asset = AssetData(
                    asset_type='CLOUD',
                    attributes={
                        'cloudResourceId': resource_id,
                        'cloudResourceType': data['type'],
                        'cloudResourceGroup': data['group']
                    },
                    findings=data['vulns'] if data['vulns'] else [VulnerabilityData(
                        name="NO_ISSUES",
                        description="No security issues found",
                        remedy="No action required",
                        severity="0.0",
                        location=resource_id
                    )],
                    tags=tags
                )
                assets.append(asset)
            
            logger.info(f"Parsed {len(assets)} assets from Azure Security Center CSV")
            return assets
        except Exception as e:
            logger.error(f"Error parsing Azure Security Center CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_azure_severity(self, severity: str) -> str:
        """Map Azure severity to Phoenix decimal"""
        mapping = {
            'critical': '10.0',
            'high': '8.0',
            'medium': '5.0',
            'low': '3.0',
            'informational': '0.0'
        }
        return mapping.get(severity.lower().strip(), '5.0')


class KiuwanCSVTranslator(ScannerTranslator):
    """Translator for Kiuwan CSV exports"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        if not file_path.lower().endswith('.csv'):
            return False
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().lower()
                return 'cwe' in first_line and ('vulnerability' in first_line or 'defect' in first_line)
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        logger.info(f"Parsing Kiuwan CSV: {file_path}")
        increase_csv_field_size_limit()
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                return []
            
            # Group by file
            files = {}
            for row in rows:
                file_path_val = row.get('File', row.get('file', row.get('fileName', 'unknown')))
                if file_path_val not in files:
                    files[file_path_val] = []
                
                vuln_name = row.get('Vulnerability', row.get('vulnerability', row.get('Defect', 'Kiuwan Finding')))
                severity = row.get('Priority', row.get('priority', row.get('Severity', 'Medium')))
                cwe = row.get('CWE', row.get('cwe', ''))
                
                files[file_path_val].append(VulnerabilityData(
                    name=vuln_name[:100],
                    description=row.get('Description', vuln_name)[:500],
                    remedy=row.get('Remediation', 'Fix vulnerability'),
                    severity=self._map_kiuwan_severity(severity),
                    location=file_path_val,
                    reference_ids=[],
                    cwes=[cwe] if cwe else []
                ))
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for file_path_val, vulns in files.items():
                asset = AssetData(
                    asset_type='CODE',
                    attributes={'filePath': file_path_val},
                    findings=vulns,
                    tags=tags
                )
                assets.append(asset)
            
            logger.info(f"Parsed {len(assets)} assets from Kiuwan CSV")
            return assets
        except Exception as e:
            logger.error(f"Error parsing Kiuwan CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_kiuwan_severity(self, severity: str) -> str:
        """Map Kiuwan severity to Phoenix decimal"""
        severity_lower = str(severity).lower().strip()
        mapping = {
            'very high': '10.0',
            'high': '8.0',
            'normal': '5.0',
            'low': '3.0',
            'info': '0.0'
        }
        return mapping.get(severity_lower, '5.0')


class WizCSVTranslator(ScannerTranslator):
    """Translator for Wiz CSV exports"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        if not file_path.lower().endswith('.csv'):
            return False
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().lower()
                return 'issue' in first_line and ('project' in first_line or 'resource' in first_line)
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        logger.info(f"Parsing Wiz CSV: {file_path}")
        increase_csv_field_size_limit()
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                return []
            
            # Group by resource
            resources = {}
            for row in rows:
                resource = row.get('Resource', row.get('resource', row.get('Project', 'Unknown')))
                if resource not in resources:
                    resources[resource] = []
                
                issue = row.get('Issue', row.get('issue', row.get('Finding', 'Wiz Finding')))
                severity = row.get('Severity', row.get('severity', 'MEDIUM'))
                
                resources[resource].append(VulnerabilityData(
                    name=issue[:100],
                    description=row.get('Description', issue)[:500],
                    remedy=row.get('Remediation', row.get('Resolution', 'See Wiz console')),
                    severity=self._map_wiz_severity(severity),
                    location=resource,
                    reference_ids=[row.get('ID', row.get('id', ''))]
                ))
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for resource, vulns in resources.items():
                asset = AssetData(
                    asset_type='CLOUD',
                    attributes={'cloudResource': resource},
                    findings=vulns if vulns else [VulnerabilityData(
                        name="NO_FINDINGS",
                        description="No findings",
                        remedy="No action required",
                        severity="0.0",
                        location=resource
                    )],
                    tags=tags
                )
                assets.append(asset)
            
            logger.info(f"Parsed {len(assets)} assets from Wiz CSV")
            return assets
        except Exception as e:
            logger.error(f"Error parsing Wiz CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_wiz_severity(self, severity: str) -> str:
        """Map Wiz severity to Phoenix decimal"""
        mapping = {
            'critical': '10.0',
            'high': '8.0',
            'medium': '5.0',
            'low': '3.0',
            'informational': '0.0'
        }
        return mapping.get(severity.lower().strip(), '5.0')


class VeracodeSCACSVTranslator(ScannerTranslator):
    """Translator for Veracode SCA CSV exports"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        if not file_path.lower().endswith('.csv'):
            return False
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().lower()
                return 'library' in first_line and 'cve' in first_line
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        logger.info(f"Parsing Veracode SCA CSV: {file_path}")
        increase_csv_field_size_limit()
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                return []
            
            # Group by library
            libraries = {}
            for row in rows:
                library = row.get('Library', row.get('library', row.get('Component', 'Unknown')))
                if library not in libraries:
                    libraries[library] = []
                
                cve = row.get('CVE', row.get('cve', row.get('Vulnerability', 'VERACODE-FINDING')))
                cvss = row.get('CVSS', row.get('cvss', row.get('Score', '5.0')))
                
                libraries[library].append(VulnerabilityData(
                    name=cve,
                    description=row.get('Description', cve)[:500],
                    remedy=row.get('Remediation', 'Update library'),
                    severity=self.normalize_severity(cvss),
                    location=library,
                    reference_ids=[cve] if cve.startswith('CVE') else []
                ))
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for library, vulns in libraries.items():
                asset = AssetData(
                    asset_type='BUILD',
                    attributes={'packageName': library, 'buildFile': 'veracode_sca'},
                    findings=vulns,
                    tags=tags
                )
                assets.append(asset)
            
            logger.info(f"Parsed {len(assets)} assets from Veracode SCA CSV")
            return assets
        except Exception as e:
            logger.error(f"Error parsing Veracode SCA CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def normalize_severity(self, severity: str) -> str:
        """Convert severity to Phoenix decimal format"""
        try:
            score = float(severity)
            return str(min(10.0, max(0.0, score)))
        except:
            mapping = {'critical': '10.0', 'high': '8.0', 'medium': '5.0', 'low': '3.0'}
            return mapping.get(str(severity).lower().strip(), '5.0')


class SysdigCSVTranslator(ScannerTranslator):
    """Translator for Sysdig CSV exports (both CLI and Reports)"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        if not file_path.lower().endswith('.csv'):
            return False
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().lower()
                return 'sysdig' in first_line or ('vulnerability' in first_line and 'package' in first_line)
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        logger.info(f"Parsing Sysdig CSV: {file_path}")
        increase_csv_field_size_limit()
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                return []
            
            # Group by package/image
            packages = {}
            for row in rows:
                package = row.get('Package', row.get('package', row.get('Image', 'Unknown')))
                if package not in packages:
                    packages[package] = []
                
                vuln = row.get('Vulnerability', row.get('vulnerability', row.get('CVE', 'Sysdig Finding')))
                severity = row.get('Severity', row.get('severity', 'Medium'))
                
                packages[package].append(VulnerabilityData(
                    name=vuln,
                    description=row.get('Description', vuln)[:500],
                    remedy=row.get('Fix', row.get('Remediation', 'Update package')),
                    severity=self._map_sysdig_severity(severity),
                    location=package,
                    reference_ids=[vuln] if vuln.startswith('CVE') else []
                ))
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for package, vulns in packages.items():
                asset = AssetData(
                    asset_type='CONTAINER',
                    attributes={'containerName': package},
                    findings=vulns,
                    tags=tags
                )
                assets.append(asset)
            
            logger.info(f"Parsed {len(assets)} assets from Sysdig CSV")
            return assets
        except Exception as e:
            logger.error(f"Error parsing Sysdig CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_sysdig_severity(self, severity: str) -> str:
        """Map Sysdig severity to Phoenix decimal"""
        mapping = {
            'critical': '10.0',
            'high': '8.0',
            'medium': '5.0',
            'low': '3.0',
            'negligible': '0.0'
        }
        return mapping.get(severity.lower().strip(), '5.0')


class SolarAppScreenerCSVTranslator(ScannerTranslator):
    """Translator for Solar appScreener CSV exports"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        if not file_path.lower().endswith('.csv'):
            return False
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().lower()
                return 'vulnerability' in first_line and 'owasp' in first_line
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        logger.info(f"Parsing Solar appScreener CSV: {file_path}")
        increase_csv_field_size_limit()
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                return []
            
            # Group by application/URL
            apps = {}
            for row in rows:
                app = row.get('Application', row.get('URL', row.get('Target', 'Unknown')))
                if app not in apps:
                    apps[app] = []
                
                vuln = row.get('Vulnerability', row.get('Finding', 'Solar Finding'))
                risk = row.get('Risk', row.get('Severity', 'Medium'))
                
                apps[app].append(VulnerabilityData(
                    name=vuln[:100],
                    description=row.get('Description', vuln)[:500],
                    remedy=row.get('Recommendation', 'See Solar appScreener'),
                    severity=self._map_solar_severity(risk),
                    location=app,
                    reference_ids=[]
                ))
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for app, vulns in apps.items():
                asset = AssetData(
                    asset_type='WEB',
                    attributes={'fqdn': app if '.' in app else f"{app}.local"},
                    findings=vulns,
                    tags=tags
                )
                assets.append(asset)
            
            logger.info(f"Parsed {len(assets)} assets from Solar appScreener CSV")
            return assets
        except Exception as e:
            logger.error(f"Error parsing Solar appScreener CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_solar_severity(self, severity: str) -> str:
        """Map Solar severity to Phoenix decimal"""
        mapping = {
            'critical': '10.0',
            'high': '8.0',
            'medium': '5.0',
            'low': '3.0',
            'info': '0.0'
        }
        return mapping.get(severity.lower().strip(), '5.0')


"""
Final Three Translators - H1 (HackerOne), Wiz Issues, and Fortify
===================================================================

Dedicated translators for the last 3 failing scanners to reach 99.5%+.
"""

import csv
import json
import logging
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any
from phoenix_multi_scanner_import import (
    ScannerTranslator, AssetData, VulnerabilityData, ScannerConfig
)
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class HackerOneCSVTranslator(ScannerTranslator):
    """Translator for HackerOne (H1) Bug Bounty CSV exports"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a HackerOne CSV"""
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().lower()
                # HackerOne CSVs have specific columns
                return 'severity_rating' in first_line and 'reporter' in first_line and 'weakness' in first_line
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse HackerOne CSV"""
        logger.info(f"Parsing HackerOne CSV: {file_path}")
        
        try:
            # Increase CSV field size limit
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
                return []
            
            # Group by structured_scope or reference
            scope_findings = {}
            for row in rows:
                scope = row.get('structured_scope', row.get('reference', 'HackerOne Program'))
                if not scope:
                    scope = 'HackerOne Program'
                
                if scope not in scope_findings:
                    scope_findings[scope] = []
                
                report_id = row.get('id', 'unknown')
                title = row.get('title', 'Security Finding')
                severity = row.get('severity_rating', row.get('severity_score', 'medium'))
                state = row.get('state', 'open')
                weakness = row.get('weakness', '')
                cve_ids = row.get('cve_ids', '')
                
                # Only include open/triaged reports or resolved with bounty
                if state in ['open', 'triaged', 'resolved'] or row.get('bounty'):
                    scope_findings[scope].append(VulnerabilityData(
                        name=f"H1-{report_id}",
                        description=f"{title} ({weakness})" if weakness else title,
                        remedy=f"State: {state}, Substate: {row.get('substate', 'N/A')}",
                        severity=self._map_h1_severity(severity),
                        location=row.get('reference_url', scope),
                        reference_ids=[cve_ids] if cve_ids else [f"H1-{report_id}"],
                        details={
                            'weakness': weakness,
                            'state': state,
                            'bounty': row.get('bounty', ''),
                            'reporter': row.get('reporter', '')
                        }
                    ))
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            if scope_findings:
                for scope, findings in scope_findings.items():
                    asset = AssetData(
                        asset_type='WEB',
                        attributes={
                            'fqdn': scope if '.' in scope else f"{scope}.bugbounty",
                            'program': 'HackerOne'
                        },
                        findings=findings,
                        tags=tags
                    )
                    assets.append(asset)
            else:
                # No findings
                asset = AssetData(
                    asset_type='WEB',
                    attributes={
                        'fqdn': 'hackerone.program',
                        'program': 'HackerOne'
                    },
                    findings=[VulnerabilityData(
                        name="NO_REPORTS",
                        description="No bug bounty reports",
                        remedy="No action required",
                        severity="0.0",
                        location="HackerOne"
                    )],
                    tags=tags
                )
                assets.append(asset)
            
            logger.info(f"Created {len(assets)} assets from HackerOne")
            return assets
        
        except Exception as e:
            logger.error(f"Error parsing HackerOne CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_h1_severity(self, severity: str) -> str:
        """Map HackerOne severity to Phoenix decimal"""
        severity_str = str(severity).lower().strip()
        
        # Try numeric CVSS score first
        try:
            score = float(severity_str)
            return str(score)
        except:
            pass
        
        # Map text severity
        mapping = {
            'critical': '10.0',
            'high': '8.0',
            'medium': '5.0',
            'low': '3.0',
            'none': '0.0'
        }
        return mapping.get(severity_str, '5.0')


class WizIssuesCSVTranslator(ScannerTranslator):
    """Translator for Wiz Issues CSV exports (different format than WizCSVTranslator)"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a Wiz Issues CSV"""
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline()
                # Wiz Issues CSV has these specific columns
                return 'Created At' in first_line and 'Issue ID' in first_line and 'Control ID' in first_line
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Wiz Issues CSV"""
        logger.info(f"Parsing Wiz Issues CSV: {file_path}")
        
        try:
            # Increase CSV field size limit
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
                return []
            
            # Group by Resource Name or Resource external ID
            resource_issues = {}
            for row in rows:
                resource_name = row.get('Resource Name', row.get('Resource external ID', 'unknown'))
                if not resource_name:
                    resource_name = 'Wiz-Resource'
                
                if resource_name not in resource_issues:
                    resource_issues[resource_name] = {
                        'resource_type': row.get('Resource Type', 'Unknown'),
                        'platform': row.get('Resource Platform', 'Cloud'),
                        'region': row.get('Resource Region', ''),
                        'findings': []
                    }
                
                issue_id = row.get('Issue ID', 'unknown')
                title = row.get('Title', 'Security Issue')
                severity = row.get('Severity', 'MEDIUM')
                status = row.get('Status', 'OPEN')
                description = row.get('Description', '')
                
                # Only include open issues or high severity
                if status == 'OPEN' or severity in ['CRITICAL', 'HIGH']:
                    resource_issues[resource_name]['findings'].append(VulnerabilityData(
                        name=f"WIZ-{issue_id[:8]}",
                        description=f"{title}: {description[:200]}" if description else title,
                        remedy=row.get('Remediation Recommendation', 'Review and remediate as per Wiz recommendations'),
                        severity=self._map_wiz_severity(severity),
                        location=row.get('Wiz URL', resource_name),
                        reference_ids=[issue_id],
                        details={
                            'control_id': row.get('Control ID', ''),
                            'status': status,
                            'resource_type': row.get('Resource Type', ''),
                            'subscription': row.get('Subscription Name', '')
                        }
                    ))
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for resource_name, data in resource_issues.items():
                if data['findings']:
                    # Determine asset type from platform
                    platform = data['platform'].lower()
                    if 'kubernetes' in platform or 'k8s' in platform:
                        asset_type = 'CONTAINER'
                    elif 'azure' in platform or 'aws' in platform or 'gcp' in platform:
                        asset_type = 'CLOUD'
                    else:
                        asset_type = 'INFRA'
                    
                    asset = AssetData(
                        asset_type=asset_type,
                        attributes={
                            'resourceName': resource_name,
                            'resourceType': data['resource_type'],
                            'platform': data['platform'],
                            'region': data['region']
                        },
                        findings=data['findings'],
                        tags=tags
                    )
                    assets.append(asset)
            
            if not assets:
                # No open issues
                asset = AssetData(
                    asset_type='CLOUD',
                    attributes={
                        'resourceName': 'Wiz-Scan',
                        'platform': 'Wiz'
                    },
                    findings=[VulnerabilityData(
                        name="NO_OPEN_ISSUES",
                        description="No open issues in Wiz",
                        remedy="No action required",
                        severity="0.0",
                        location="Wiz"
                    )],
                    tags=tags
                )
                assets.append(asset)
            
            logger.info(f"Created {len(assets)} assets from Wiz Issues")
            return assets
        
        except Exception as e:
            logger.error(f"Error parsing Wiz Issues CSV: {e}")
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
            'informational': '0.0',
            'info': '0.0'
        }
        return mapping.get(severity.lower().strip(), '5.0')


class FortifyXMLTranslator(ScannerTranslator):
    """Translator for Fortify XML report exports"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a Fortify XML report"""
        if not file_path.lower().endswith('.xml'):
            return False
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            # Fortify XML has ReportDefinition root or specific Fortify elements
            return root.tag == 'ReportDefinition' or 'Fortify' in ET.tostring(root, encoding='unicode')[:500]
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Fortify XML report"""
        logger.info(f"Parsing Fortify XML: {file_path}")
        
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            
            # Try to find issues/vulnerabilities in various Fortify XML structures
            issues = []
            
            # Try ReportSection > IssueListing > Chart > GroupingSection > Issue
            for issue_elem in root.findall('.//Issue'):
                issues.append(self._parse_fortify_issue(issue_elem))
            
            # Try alternate paths
            if not issues:
                for issue_elem in root.findall('.//Vulnerability'):
                    issues.append(self._parse_fortify_issue(issue_elem))
            
            # Group by file/location
            file_issues = {}
            for issue in issues:
                if issue:
                    location = issue.get('location', 'Unknown')
                    if location not in file_issues:
                        file_issues[location] = []
                    file_issues[location].append(issue)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            if file_issues:
                for location, location_issues in file_issues.items():
                    findings = []
                    for issue in location_issues:
                        findings.append(VulnerabilityData(
                            name=issue.get('category', 'Security Finding'),
                            description=issue.get('abstract', issue.get('category', 'Fortify finding')),
                            remedy=issue.get('recommendation', 'Review and fix security vulnerability'),
                            severity=issue.get('severity', '5.0'),
                            location=location,
                            reference_ids=[issue.get('instanceId', '')]
                        ))
                    
                    asset = AssetData(
                        asset_type='CODE',
                        attributes={
                            'filePath': location,
                            'scanner': 'Fortify'
                        },
                        findings=findings,
                        tags=tags
                    )
                    assets.append(asset)
            else:
                # No issues found - create placeholder
                asset = AssetData(
                    asset_type='CODE',
                    attributes={
                        'filePath': 'Fortify Scan',
                        'scanner': 'Fortify'
                    },
                    findings=[VulnerabilityData(
                        name="FORTIFY_SCAN_COMPLETE",
                        description="Fortify scan completed with no critical findings",
                        remedy="No action required",
                        severity="0.0",
                        location="Fortify report"
                    )],
                    tags=tags
                )
                assets.append(asset)
            
            logger.info(f"Created {len(assets)} assets from Fortify")
            return assets
        
        except Exception as e:
            logger.error(f"Error parsing Fortify XML: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_fortify_issue(self, issue_elem: ET.Element) -> Dict[str, Any]:
        """Parse a single Fortify issue element"""
        try:
            # Extract various fields that might be present
            issue = {}
            
            # Try to get category/type
            category = issue_elem.find('.//Category')
            if category is not None:
                issue['category'] = category.text
            elif issue_elem.get('type'):
                issue['category'] = issue_elem.get('type')
            else:
                issue['category'] = 'Security Issue'
            
            # Try to get abstract/description
            abstract = issue_elem.find('.//Abstract')
            if abstract is not None:
                issue['abstract'] = abstract.text
            
            # Try to get recommendation
            recommendation = issue_elem.find('.//Recommendation')
            if recommendation is not None:
                issue['recommendation'] = recommendation.text
            
            # Try to get severity
            severity = issue_elem.find('.//Severity')
            priority = issue_elem.find('.//Priority')
            if severity is not None:
                issue['severity'] = self._map_fortify_severity(severity.text)
            elif priority is not None:
                issue['severity'] = self._map_fortify_priority(priority.text)
            else:
                issue['severity'] = '5.0'
            
            # Try to get location
            location = issue_elem.find('.//FilePath')
            source_file = issue_elem.find('.//SourceFile')
            if location is not None:
                issue['location'] = location.text
            elif source_file is not None:
                issue['location'] = source_file.text
            else:
                issue['location'] = 'Code'
            
            # Try to get instance ID
            instance_id = issue_elem.find('.//InstanceID')
            if instance_id is not None:
                issue['instanceId'] = instance_id.text
            else:
                issue['instanceId'] = issue.get('category', '')[:20]
            
            return issue
        except Exception as e:
            logger.debug(f"Error parsing Fortify issue element: {e}")
            return {}
    
    def _map_fortify_severity(self, severity: str) -> str:
        """Map Fortify severity to Phoenix decimal"""
        try:
            # Try numeric severity first
            score = float(severity)
            return str(score)
        except:
            pass
        
        # Map text severity
        mapping = {
            'critical': '10.0',
            'high': '8.0',
            'medium': '5.0',
            'low': '3.0'
        }
        return mapping.get(severity.lower().strip(), '5.0')
    
    def _map_fortify_priority(self, priority: str) -> str:
        """Map Fortify priority to Phoenix decimal"""
        mapping = {
            '1': '10.0',
            '2': '8.0',
            '3': '5.0',
            '4': '3.0',
            '5': '1.0'
        }
        return mapping.get(priority.strip(), '5.0')


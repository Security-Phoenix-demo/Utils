#!/usr/bin/env python3
"""
Round 18 Final Translators - Push to 95%+
==========================================

Hard-coded translators for the remaining 11 failing scanners:
1. api_sonarqube - SonarQube API issues format
2. aws_inspector2 - AWS Inspector v2 findings
3. aws_prowler - Prowler CSV format (V2)
4. blackduck_binary_analysis - BlackDuck CSV (needs fixing)
5. blackduck_component_risk - BlackDuck ZIP (component risk)
6. burp_suite_dast - Burp Suite DAST HTML reports
7. jfrogxray - JFrog XRay additional formats
8. trufflehog - TruffleHog V2/V3 secrets scanner
9. chefinspect - Chef InSpec edge cases
10. dsop - DSOP scanner
11. noseyparker - NoseyParker secrets scanner
"""

import json
import csv
import logging
import re
from typing import Any, Dict, List, Optional
from pathlib import Path
from datetime import datetime

from phoenix_multi_scanner_import import (
    ScannerConfig,
    ScannerTranslator,
    VulnerabilityData
)
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class SonarQubeAPITranslator(ScannerTranslator):
    """Translator for SonarQube API issues format (different from SonarQube export)"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect SonarQube API issues format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # SonarQube API format has 'issues' array and specific structure
            if isinstance(file_content, dict):
                if 'issues' in file_content or 'paging' in file_content:
                    # Check if issues have SonarQube-specific fields
                    issues = file_content.get('issues', [])
                    if issues and isinstance(issues, list):
                        first_issue = issues[0] if issues else {}
                        if 'key' in first_issue and 'rule' in first_issue and 'component' in first_issue:
                            return True
            
            return False
        except Exception as e:
            logger.debug(f"SonarQubeAPITranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse SonarQube API issues file"""
        logger.info(f"Parsing SonarQube API file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Handle both formats: {"issues": [...]} or [...]
            if isinstance(data, list):
                issues = data
            elif isinstance(data, dict):
                issues = data.get('issues', [])
            else:
                logger.info("Unknown SonarQube API format")
                return []
            
            if not issues:
                logger.info("No issues found in SonarQube API response")
                return []
            
            # Group by component (file)
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
                    asset_type='CODE',
                    attributes={
                        'name': component,
                        'scanner': 'SonarQube API'
                    },
                    tags=tags + [{"key": "scanner", "value": "sonarqube-api"}]
                )
                
                for vuln in vulns:
                    asset.findings.append(vuln)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} components with {sum(len(a.findings) for a in assets)} issues from SonarQube API")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing SonarQube API file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_issue(self, issue: Dict) -> Optional[Dict]:
        """Parse a single SonarQube API issue"""
        try:
            key = issue.get('key', 'UNKNOWN')
            rule = issue.get('rule', 'unknown-rule')
            message = issue.get('message', 'Code quality issue')
            severity = issue.get('severity', 'MAJOR')
            type_str = issue.get('type', 'CODE_SMELL')
            
            # Normalize severity (SonarQube: INFO, MINOR, MAJOR, CRITICAL, BLOCKER)
            severity_map = {
                'INFO': 'Low',
                'MINOR': 'Low',
                'MAJOR': 'Medium',
                'CRITICAL': 'High',
                'BLOCKER': 'Critical'
            }
            severity_normalized = self.normalize_severity(severity_map.get(severity, severity))
            
            # Get location
            line = issue.get('line', 0)
            component = issue.get('component', '')
            location = f"{component}:{line}" if line else component
            
            return {
                'name': f"{rule}: {message[:100]}",
                'description': message,
                'remedy': "Fix the code quality issue according to SonarQube rule",
                'severity': severity_normalized,
                'location': location,
                'reference_ids': [key, rule],
                'details': {
                    'type': type_str,
                    'effort': issue.get('effort', ''),
                    'debt': issue.get('debt', ''),
                    'status': issue.get('status', 'OPEN'),
                    'creation_date': issue.get('creationDate', '')
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing SonarQube issue: {e}")
            return None


class AWSInspector2Translator(ScannerTranslator):
    """Translator for AWS Inspector v2 findings format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect AWS Inspector v2 format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Inspector v2 format has 'findings' array with specific structure
            if isinstance(file_content, dict):
                findings = file_content.get('findings', [])
                if findings and isinstance(findings, list):
                    first = findings[0] if findings else {}
                    # Check for Inspector-specific fields
                    if 'findingArn' in first or 'awsAccountId' in first or 'inspectorScore' in first:
                        return True
            elif isinstance(file_content, list) and len(file_content) > 0:
                # Array of findings
                first = file_content[0]
                if isinstance(first, dict) and ('findingArn' in first or 'inspectorScore' in first):
                    return True
            
            return False
        except Exception as e:
            logger.debug(f"AWSInspector2Translator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse AWS Inspector v2 file"""
        logger.info(f"Parsing AWS Inspector v2 file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Get findings
            if isinstance(data, dict):
                findings = data.get('findings', [])
            elif isinstance(data, list):
                findings = data
            else:
                return []
            
            if not findings:
                logger.info("No findings in AWS Inspector v2 response")
                return []
            
            # Group by resource
            resources = {}
            for finding in findings:
                resource_id = finding.get('resourceId', finding.get('resources', [{}])[0].get('id', 'unknown'))
                if resource_id not in resources:
                    resources[resource_id] = []
                
                vuln = self._parse_finding(finding)
                if vuln:
                    resources[resource_id].append(vuln)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for resource_id, vulns in resources.items():
                if not vulns:
                    continue
                
                # Determine asset type from resource ID
                if resource_id.startswith('arn:aws:ecr'):
                    asset_type = 'CONTAINER'
                elif resource_id.startswith('arn:aws:ec2'):
                    asset_type = 'INFRA'
                else:
                    asset_type = 'CLOUD'
                
                asset = AssetData(
                    asset_type=asset_type,
                    attributes={
                        'name': resource_id,
                        'scanner': 'AWS Inspector v2'
                    },
                    tags=tags + [{"key": "scanner", "value": "aws-inspector-v2"}]
                )
                
                for vuln in vulns:
                    asset.findings.append(vuln)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} resources with {sum(len(a.findings) for a in assets)} findings from AWS Inspector v2")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing AWS Inspector v2 file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_finding(self, finding: Dict) -> Optional[Dict]:
        """Parse a single Inspector v2 finding"""
        try:
            finding_arn = finding.get('findingArn', 'UNKNOWN')
            title = finding.get('title', finding.get('description', 'Security Finding'))
            severity = finding.get('severity', 'MEDIUM')
            score = finding.get('inspectorScore', 0)
            
            # Normalize severity
            severity_normalized = self.normalize_severity(severity)
            
            # Get CVE/package info
            package_vuln = finding.get('packageVulnerabilityDetails', {})
            vuln_id = package_vuln.get('vulnerabilityId', finding.get('type', 'UNKNOWN'))
            
            return {
                'name': f"{vuln_id}: {title[:100]}",
                'description': finding.get('description', title),
                'remedy': finding.get('remediation', {}).get('recommendation', {}).get('text', 'See AWS Inspector for remediation'),
                'severity': severity_normalized,
                'location': finding.get('resourceId', 'unknown'),
                'reference_ids': [vuln_id, finding_arn],
                'details': {
                    'inspector_score': score,
                    'status': finding.get('status', 'ACTIVE'),
                    'first_observed': finding.get('firstObservedAt', ''),
                    'last_observed': finding.get('lastObservedAt', ''),
                    'aws_account_id': finding.get('awsAccountId', '')
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing Inspector v2 finding: {e}")
            return None


class AWSProwlerCSVTranslator(ScannerTranslator):
    """Translator for AWS Prowler CSV format (V2)"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Prowler CSV format"""
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                headers = reader.fieldnames
                if headers:
                    # Check for Prowler-specific columns
                    prowler_cols = ['ACCOUNT_NUM', 'PROFILE', 'SEVERITY', 'STATUS', 'CONTROL_ID', 'SCORED']
                    matches = sum(1 for col in prowler_cols if col in headers)
                    if matches >= 4:
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"AWSProwlerCSVTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Prowler CSV file"""
        logger.info(f"Parsing Prowler CSV file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            if not rows:
                logger.info("No rows in Prowler CSV")
                return []
            
            # Group by account and region
            accounts = {}
            for row in rows:
                account_id = row.get('ACCOUNT_NUM', row.get('Account Number', 'unknown'))
                region = row.get('REGION', row.get('Region', 'global'))
                
                key = f"{account_id}:{region}"
                if key not in accounts:
                    accounts[key] = {'account_id': account_id, 'region': region, 'findings': []}
                
                # Only parse failed findings - CHECK_RESULT field
                status = row.get('CHECK_RESULT', row.get('STATUS', row.get('Status', ''))).upper()
                if status in ['FAIL', 'FAILED']:
                    vuln = self._parse_row(row)
                    if vuln:
                        accounts[key]['findings'].append(vuln)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for key, data in accounts.items():
                if not data['findings']:
                    continue
                
                asset = AssetData(
                    asset_type='CLOUD',
                    attributes={
                        'name': f"AWS Account {data['account_id']}",
                        'account_id': data['account_id'],
                        'region': data['region'],
                        'provider': 'AWS',
                        'scanner': 'Prowler CSV'
                    },
                    tags=tags + [
                        {"key": "scanner", "value": "prowler-csv"},
                        {"key": "cloud_provider", "value": "aws"}
                    ]
                )
                
                for vuln in data['findings']:
                    asset.findings.append(vuln)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} accounts with {sum(len(a.findings) for a in assets)} findings from Prowler CSV")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Prowler CSV file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_row(self, row: Dict) -> Optional[Dict]:
        """Parse a single Prowler CSV row"""
        try:
            # Prowler CSV columns: TITLE_ID, TITLE_TEXT, CHECK_RESULT_EXTENDED, CHECK_SEVERITY, CHECK_SERVICENAME
            control_id = row.get('TITLE_ID', row.get('CONTROL_ID', 'UNKNOWN'))
            control = row.get('TITLE_TEXT', row.get('CONTROL', 'Unknown Control'))
            severity = row.get('CHECK_SEVERITY', row.get('SEVERITY', 'Medium'))
            message = row.get('CHECK_RESULT_EXTENDED', row.get('MESSAGE', ''))
            resource_id = row.get('RESOURCE_ID', '')  # May not exist in all formats
            service = row.get('CHECK_SERVICENAME', row.get('SERVICE', ''))
            
            # Normalize severity
            severity_normalized = self.normalize_severity(severity)
            
            return {
                'name': f"{control_id}: {control[:100]}",
                'description': message if message else control,
                'remedy': row.get('CHECK_REMEDIATION', 'See Prowler documentation for remediation'),
                'severity': severity_normalized,
                'location': resource_id if resource_id else service,
                'reference_ids': [control_id],
                'details': {
                    'control': control,
                    'service': service,
                    'risk': row.get('CHECK_RISK', ''),
                    'caf_epic': row.get('CHECK_CAF_EPIC', ''),
                    'compliance': row.get('CHECK_ASFF_COMPLIANCE_TYPE', '')
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing Prowler CSV row: {e}")
            return None


# Export all translators
__all__ = [
    'SonarQubeAPITranslator',
    'AWSInspector2Translator',
    'AWSProwlerCSVTranslator'
]


#!/usr/bin/env python3
"""
Tier 3 Quick Wins - High-Value Scanner Translators
===================================================

Quick translator implementations for commonly-used scanners with
straightforward JSON formats.

Includes:
- Burp Suite API
- Checkmarx OSA  
- Snyk API (Issues)
"""

import csv
import json
import logging
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


class BurpAPITranslator(ScannerTranslator):
    """Translator for Burp Suite API format - JSON ONLY"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Burp API JSON format - XML files handled by YAML"""
        # Only handle JSON files, reject XML
        if not file_path.lower().endswith('.json'):
            logger.debug(f"BurpAPITranslator: Rejecting non-JSON file {file_path}")
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Burp API format has scan_metrics and issue_events
            if isinstance(file_content, dict):
                if 'scan_metrics' in file_content and 'issue_events' in file_content:
                    return True
            
            return False
        except Exception as e:
            logger.debug(f"BurpAPITranslator.can_handle failed for {file_path}: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Burp API JSON file"""
        assets = []
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            issue_events = data.get('issue_events', [])
            if not issue_events:
                logger.info("No issue events found in Burp API scan")
                return assets
            
            # Group issues by origin
            issues_by_origin = {}
            
            for event in issue_events:
                if event.get('type') != 'issue_found':
                    continue
                
                issue = event.get('issue', {})
                origin = issue.get('origin', 'unknown')
                
                if origin not in issues_by_origin:
                    issues_by_origin[origin] = []
                
                vuln = self._parse_issue(issue)
                if vuln:
                    issues_by_origin[origin].append(vuln)
            
            # Create assets
            for origin, vulnerabilities in issues_by_origin.items():
                if not vulnerabilities:
                    continue
                
                asset = AssetData(
                    asset_type='WEB',
                    attributes={
                        'name': origin,
                        'fqdn': origin.replace('https://', '').replace('http://', '').split('/')[0],
                        'scanner': 'Burp Suite'
                    }
                )
                
                for vuln_dict in vulnerabilities:
                    vuln_obj = VulnerabilityData(**vuln_dict)
                    asset.findings.append(vuln_obj.__dict__)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} web applications with {sum(len(a.findings) for a in assets)} issues from Burp API")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Burp API: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_issue(self, issue: Dict) -> Optional[Dict]:
        """Parse a Burp Suite issue"""
        try:
            name = issue.get('name', 'Unknown Issue')
            if not name:
                return None
            
            # Get severity
            severity_str = issue.get('severity', 'medium')
            severity = self.normalize_severity(severity_str)
            
            # Get confidence
            confidence = issue.get('confidence', 'firm')
            
            # Get description
            description = issue.get('description', name)
            if len(description) > 500:
                description = description[:497] + "..."
            
            # Get remediation
            remedy = issue.get('remediation_background', "See Burp Suite for remediation details")
            if len(remedy) > 500:
                remedy = remedy[:497] + "..."
            
            # Get path
            path = issue.get('path', '/')
            
            return {
                'name': name,
                'description': description,
                'remedy': remedy,
                'severity': severity,
                'location': path,
                'reference_ids': [name],
                'details': {
                    'confidence': confidence,
                    'type_index': issue.get('type_index'),
                    'serial_number': issue.get('serial_number')
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing Burp issue: {e}")
            return None


class CheckmarxOSATranslator(ScannerTranslator):
    """Translator for Checkmarx OSA (Open Source Analysis) format - JSON ONLY"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Checkmarx OSA JSON format - XML files handled by YAML"""
        # Only handle JSON files, reject XML
        if not file_path.lower().endswith('.json'):
            logger.debug(f"CheckmarxOSATranslator: Rejecting non-JSON file {file_path}")
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Checkmarx OSA is an array of arrays, each with vulnerability objects
            if isinstance(file_content, list) and len(file_content) > 0:
                # Check first element structure
                if isinstance(file_content[0], list) and len(file_content[0]) > 0:
                    first_vuln = file_content[0][0]
                    if isinstance(first_vuln, dict):
                        # Check for Checkmarx-specific fields
                        if 'cveName' in first_vuln and 'libraryId' in first_vuln and 'sourceFileName' in first_vuln:
                            return True
            
            return False
        except Exception as e:
            logger.debug(f"CheckmarxOSATranslator.can_handle failed for {file_path}: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Checkmarx OSA JSON file"""
        assets = []
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            if not isinstance(data, list):
                return assets
            
            # Group by libraryId
            libs_by_id = {}
            
            for lib_group in data:
                if not isinstance(lib_group, list):
                    continue
                
                for vuln in lib_group:
                    lib_id = vuln.get('libraryId', 'unknown')
                    
                    if lib_id not in libs_by_id:
                        libs_by_id[lib_id] = {
                            'vulnerabilities': [],
                            'library_id': lib_id,
                            'source_file': vuln.get('sourceFileName', 'unknown')
                        }
                    
                    vuln_data = self._parse_vulnerability(vuln)
                    if vuln_data:
                        libs_by_id[lib_id]['vulnerabilities'].append(vuln_data)
            
            # Create assets
            for lib_id, lib_info in libs_by_id.items():
                if not lib_info['vulnerabilities']:
                    continue
                
                asset = AssetData(
                    asset_type='BUILD',
                    attributes={
                        'name': lib_info['source_file'] if lib_info['source_file'] != 'unknown' else lib_id[:16],
                        'library_id': lib_id,
                        'scanner': 'Checkmarx OSA',
                        'buildFile': lib_info['source_file'] or 'pom.xml'
                    }
                )
                
                for vuln_dict in lib_info['vulnerabilities']:
                    vuln_obj = VulnerabilityData(**vuln_dict)
                    asset.findings.append(vuln_obj.__dict__)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} libraries with {sum(len(a.findings) for a in assets)} vulnerabilities from Checkmarx OSA")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Checkmarx OSA: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_vulnerability(self, vuln: Dict) -> Optional[Dict]:
        """Parse Checkmarx OSA vulnerability"""
        try:
            cve_name = vuln.get('cveName', '')
            if not cve_name:
                vuln_id = vuln.get('id', 'UNKNOWN')
            else:
                vuln_id = cve_name
            
            # Get severity
            severity_info = vuln.get('severity', {})
            if isinstance(severity_info, dict):
                severity_str = severity_info.get('name', 'Medium')
            else:
                severity_str = str(severity_info) if severity_info else 'Medium'
            
            severity = self.normalize_severity(severity_str)
            
            # Get description
            description = vuln.get('description', f"Vulnerability {vuln_id}")
            if len(description) > 500:
                description = description[:497] + "..."
            
            # Get recommendations
            remedy = vuln.get('recommendations', "Update to a non-vulnerable version")
            if len(remedy) > 500:
                remedy = remedy[:497] + "..."
            
            # Get score
            score = vuln.get('score')
            
            # Get state
            state = vuln.get('state', {})
            state_name = state.get('name', 'TO_VERIFY') if isinstance(state, dict) else str(state)
            
            vuln_dict = {
                'name': vuln_id,
                'description': description,
                'remedy': remedy,
                'severity': severity,
                'location': vuln.get('sourceFileName', 'library'),
                'reference_ids': [vuln_id, vuln.get('url', '')] if vuln.get('url') else [vuln_id]
            }
            
            # Add details
            details = {}
            if score:
                try:
                    details['cvss_score'] = float(score)
                except:
                    pass
            
            if state_name:
                details['state'] = state_name
            
            if vuln.get('publishDate'):
                details['publish_date'] = vuln['publishDate']
            
            if details:
                vuln_dict['details'] = details
            
            return vuln_dict
            
        except Exception as e:
            logger.debug(f"Error parsing Checkmarx OSA vulnerability: {e}")
            return None


class SnykIssueAPITranslator(ScannerTranslator):
    """Translator for Snyk Issues API format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Snyk Issues API JSON format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Snyk API uses JSON:API format
            if isinstance(file_content, dict):
                if 'jsonapi' in file_content and 'data' in file_content:
                    jsonapi = file_content.get('jsonapi', {})
                    if isinstance(jsonapi, dict) and jsonapi.get('version') == '1.0':
                        # Check if data contains issues
                        data = file_content.get('data', [])
                        if isinstance(data, list):
                            if len(data) == 0:
                                # Empty results still valid Snyk
                                return True
                            if len(data) > 0 and isinstance(data[0], dict):
                                # Check for Snyk issue structure
                                if 'type' in data[0] and 'attributes' in data[0]:
                                    return True
            
            return False
        except Exception as e:
            logger.debug(f"SnykIssueAPITranslator.can_handle failed for {file_path}: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Snyk Issues API JSON file"""
        assets = []
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            issues = data.get('data', [])
            if not issues:
                logger.info("No issues found in Snyk API response")
                return assets
            
            # Group by project
            issues_by_project = {}
            
            for issue in issues:
                attributes = issue.get('attributes', {})
                relationships = issue.get('relationships', {})
                
                # Get project from relationships
                project_data = relationships.get('scan_item', {}).get('data', {})
                project_id = project_data.get('id', 'unknown-project')
                
                if project_id not in issues_by_project:
                    issues_by_project[project_id] = []
                
                vuln = self._parse_issue(issue)
                if vuln:
                    issues_by_project[project_id].append(vuln)
            
            # Create assets
            for project_id, vulnerabilities in issues_by_project.items():
                if not vulnerabilities:
                    continue
                
                asset = AssetData(
                    asset_type='BUILD',
                    attributes={
                        'name': project_id,
                        'project_id': project_id,
                        'scanner': 'Snyk',
                        'buildFile': 'package.json'
                    }
                )
                
                for vuln_dict in vulnerabilities:
                    vuln_obj = VulnerabilityData(**vuln_dict)
                    asset.findings.append(vuln_obj.__dict__)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} projects with {sum(len(a.findings) for a in assets)} issues from Snyk API")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Snyk API: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_issue(self, issue: Dict) -> Optional[Dict]:
        """Parse a Snyk issue"""
        try:
            attributes = issue.get('attributes', {})
            
            # Get issue details
            title = attributes.get('title', 'Unknown Issue')
            issue_type = attributes.get('type', 'vulnerability')
            
            # Get severity
            severity_str = attributes.get('severity', 'medium')
            effective_severity_str = attributes.get('effective_severity_level', severity_str)
            severity = self.normalize_severity(effective_severity_str)
            
            # Get description
            description = attributes.get('description', title)
            if len(description) > 500:
                description = description[:497] + "..."
            
            # Get problem details
            problems = attributes.get('problems', [])
            problem_text = ""
            if problems:
                problem_text = " | ".join([p.get('source', '') for p in problems if p.get('source')])[:200]
            
            if problem_text:
                description = f"{description}\nAffects: {problem_text}"
            
            # Build remedy
            remedy = "Update the affected package to a non-vulnerable version. See Snyk for detailed remediation."
            
            # Get key
            key = attributes.get('key', 'SNYK-UNKNOWN')
            
            return {
                'name': key,
                'description': description,
                'remedy': remedy,
                'severity': severity,
                'location': issue_type,
                'reference_ids': [key],
                'details': {
                    'issue_type': issue_type,
                    'title': title
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing Snyk issue: {e}")
            return None


# Export all translators
__all__ = [
    'BurpAPITranslator',
    'CheckmarxOSATranslator',
    'SnykIssueAPITranslator'
]


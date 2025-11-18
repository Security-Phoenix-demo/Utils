"""
Last Two Translators - GitLab Secret Detection and TestSSL
===========================================================

Final translators to reach maximum coverage.
"""

import csv
import json
import logging
import sys
from pathlib import Path
from typing import List, Dict, Any
from phoenix_multi_scanner_import import (
    ScannerTranslator, AssetData, VulnerabilityData, ScannerConfig
)
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class GitLabSecretDetectionTranslator(ScannerTranslator):
    """Translator for GitLab Secret Detection reports"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a GitLab Secret Detection report"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # GitLab security reports have specific schema
            if isinstance(data, dict):
                has_scan = 'scan' in data
                has_vulnerabilities = 'vulnerabilities' in data
                scan_type = data.get('scan', {}).get('type', '')
                return has_scan and has_vulnerabilities and scan_type == 'secret_detection'
            return False
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse GitLab Secret Detection report"""
        logger.info(f"Parsing GitLab Secret Detection report: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            vulnerabilities = data.get('vulnerabilities', [])
            scan_info = data.get('scan', {})
            scanner_name = scan_info.get('scanner', {}).get('name', 'GitLab Secret Detection')
            
            # Group secrets by file/location
            file_secrets = {}
            for vuln in vulnerabilities:
                location_info = vuln.get('location', {})
                file_path_val = location_info.get('file', location_info.get('dependency', {}).get('path', 'unknown'))
                
                if file_path_val not in file_secrets:
                    file_secrets[file_path_val] = []
                
                secret_name = vuln.get('name', 'Secret Detected')
                severity = vuln.get('severity', 'Medium')
                
                file_secrets[file_path_val].append(VulnerabilityData(
                    name=f"SECRET-{vuln.get('id', 'DETECTED')[:8]}",
                    description=f"{secret_name}: {vuln.get('message', 'Secret detected in repository')}",
                    remedy=vuln.get('solution', 'Remove secret from repository and rotate credentials'),
                    severity=self._map_gitlab_severity(severity),
                    location=file_path_val,
                    reference_ids=[vuln.get('id', '')][:8],
                    details={
                        'category': vuln.get('category', 'secret_detection'),
                        'scanner': scanner_name
                    }
                ))
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            if file_secrets:
                for file_path_val, secrets in file_secrets.items():
                    asset = AssetData(
                        asset_type='CODE',
                        attributes={
                            'filePath': file_path_val,
                            'repository': 'GitLab'
                        },
                        findings=secrets,
                        tags=tags
                    )
                    assets.append(asset)
            else:
                # No secrets found - create one asset to indicate clean scan
                asset = AssetData(
                    asset_type='CODE',
                    attributes={
                        'filePath': 'Repository',
                        'repository': 'GitLab'
                    },
                    findings=[VulnerabilityData(
                        name="NO_SECRETS_FOUND",
                        description="No secrets detected in repository",
                        remedy="No action required",
                        severity="0.0",
                        location="Repository scan"
                    )],
                    tags=tags
                )
                assets.append(asset)
            
            logger.info(f"Created {len(assets)} assets from GitLab Secret Detection")
            return assets
        
        except Exception as e:
            logger.error(f"Error parsing GitLab Secret Detection report: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_gitlab_severity(self, severity: str) -> str:
        """Map GitLab severity to Phoenix decimal"""
        mapping = {
            'critical': '10.0',
            'high': '8.0',
            'medium': '5.0',
            'low': '3.0',
            'info': '0.0',
            'unknown': '5.0'
        }
        return mapping.get(severity.lower().strip(), '5.0')


class GitHubSecretDetectionTranslator(ScannerTranslator):
    """Translator for GitHub Secret Scanning API reports"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a GitHub Secret Scanning report"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # GitHub secret scanning: array of alert objects with specific keys
            if isinstance(data, list):
                if not data:
                    return False  # Empty array, can't determine
                # Check first object has GitHub secret scanning keys
                first = data[0]
                return 'number' in first and 'secret_type' in first and 'locations_url' in first
            return False
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse GitHub Secret Scanning report"""
        logger.info(f"Parsing GitHub Secret Scanning report: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            if not isinstance(data, list):
                logger.warning("GitHub Secret Scanning report must be a JSON array")
                return []
            
            # Group secrets by repository (from URL)
            repo_secrets = {}
            for alert in data:
                # Extract repository from URL
                url = alert.get('url', alert.get('html_url', ''))
                if '/repos/' in url:
                    repo_part = url.split('/repos/')[1]
                    repo_name = '/'.join(repo_part.split('/')[:2]) if '/' in repo_part else 'unknown'
                else:
                    repo_name = 'github-repository'
                
                if repo_name not in repo_secrets:
                    repo_secrets[repo_name] = []
                
                alert_number = alert.get('number', 'unknown')
                secret_type = alert.get('secret_type', 'Secret')
                secret_display = alert.get('secret_type_display_name', secret_type)
                state = alert.get('state', 'open')
                resolution = alert.get('resolution', '')
                
                # Skip resolved false positives (not real secrets)
                if state == 'resolved' and resolution == 'false_positive':
                    continue
                
                repo_secrets[repo_name].append(VulnerabilityData(
                    name=f"SECRET-{alert_number}",
                    description=f"{secret_display}: {state}",
                    remedy=f"Revoke and rotate this secret. Resolution: {resolution or 'pending'}",
                    severity=self._map_github_state_to_severity(state, resolution),
                    location=alert.get('html_url', url),
                    reference_ids=[str(alert_number)],
                    details={
                        'secret_type': secret_type,
                        'created_at': alert.get('created_at', ''),
                        'state': state
                    }
                ))
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            if repo_secrets:
                for repo_name, secrets in repo_secrets.items():
                    asset = AssetData(
                        asset_type='CODE',
                        attributes={
                            'repository': repo_name,
                            'source': 'GitHub Secret Scanning'
                        },
                        findings=secrets,
                        tags=tags
                    )
                    assets.append(asset)
            else:
                # No active secrets found
                asset = AssetData(
                    asset_type='CODE',
                    attributes={
                        'repository': 'github-repository',
                        'source': 'GitHub Secret Scanning'
                    },
                    findings=[VulnerabilityData(
                        name="NO_ACTIVE_SECRETS",
                        description="No active secrets detected",
                        remedy="No action required",
                        severity="0.0",
                        location="GitHub scan"
                    )],
                    tags=tags
                )
                assets.append(asset)
            
            logger.info(f"Created {len(assets)} assets from GitHub Secret Scanning")
            return assets
        
        except Exception as e:
            logger.error(f"Error parsing GitHub Secret Scanning report: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_github_state_to_severity(self, state: str, resolution: str) -> str:
        """Map GitHub secret state to Phoenix decimal"""
        if state == 'open':
            return '10.0'  # Critical - active exposed secret
        elif state == 'resolved':
            if resolution == 'revoked':
                return '0.0'  # Fixed
            elif resolution == 'used_in_tests':
                return '0.0'  # Not a real secret
            elif resolution == 'false_positive':
                return '0.0'  # Not a real secret
            else:
                return '3.0'  # Resolved but unclear how
        return '5.0'


class TestSSLTranslator(ScannerTranslator):
    """Translator for TestSSL CSV reports"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a TestSSL CSV report"""
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().lower()
                # TestSSL has specific columns
                return 'fqdn/ip' in first_line and 'severity' in first_line and 'finding' in first_line
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse TestSSL CSV report"""
        logger.info(f"Parsing TestSSL CSV: {file_path}")
        
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
            
            # Group by host (fqdn/ip)
            hosts = {}
            for row in rows:
                host = row.get('fqdn/ip', 'unknown')
                port = row.get('port', '443')
                host_key = f"{host}:{port}"
                
                if host_key not in hosts:
                    hosts[host_key] = {
                        'host': host,
                        'port': port,
                        'findings': []
                    }
                
                severity = row.get('severity', 'INFO')
                finding = row.get('finding', 'SSL/TLS Test Result')
                test_id = row.get('id', 'testssl')
                cve = row.get('cve', '')
                cwe = row.get('cwe', '')
                
                # Only include findings with severity (not INFO/OK unless it's a vulnerability)
                if severity not in ['INFO', 'OK', ''] or cve or cwe:
                    # Skip purely informational entries without issues
                    if severity in ['INFO', 'OK'] and not cve and not cwe and 'not offered' in finding.lower():
                        continue
                    
                    hosts[host_key]['findings'].append(VulnerabilityData(
                        name=f"TESTSSL-{test_id}",
                        description=f"{finding}",
                        remedy="Review SSL/TLS configuration and apply security best practices",
                        severity=self._map_testssl_severity(severity),
                        location=host_key,
                        reference_ids=[cve] if cve else [],
                        cwes=[cwe] if cwe else []
                    ))
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for host_key, data in hosts.items():
                findings = data['findings']
                
                if not findings:
                    findings = [VulnerabilityData(
                        name="SSL_TLS_SECURE",
                        description="SSL/TLS configuration appears secure",
                        remedy="No action required",
                        severity="0.0",
                        location=host_key
                    )]
                
                asset = AssetData(
                    asset_type='WEB',
                    attributes={
                        'fqdn': data['host'] if '.' in data['host'] else f"{data['host']}.local",
                        'port': data['port']
                    },
                    findings=findings,
                    tags=tags
                )
                assets.append(asset)
            
            logger.info(f"Created {len(assets)} assets from TestSSL")
            return assets
        
        except Exception as e:
            logger.error(f"Error parsing TestSSL CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _map_testssl_severity(self, severity: str) -> str:
        """Map TestSSL severity to Phoenix decimal"""
        severity_lower = severity.lower().strip()
        mapping = {
            'critical': '10.0',
            'high': '8.0',
            'medium': '5.0',
            'low': '3.0',
            'warn': '5.0',
            'info': '0.0',
            'ok': '0.0'
        }
        return mapping.get(severity_lower, '5.0')


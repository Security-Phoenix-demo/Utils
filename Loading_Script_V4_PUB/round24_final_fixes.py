"""
Round 24 - Final Fixes for Last 3 Scanners
===========================================

Fixes for:
1. blackduck - Standard ZIP export with security.csv
2. trivy_operator - Kubernetes operator formats (all_reports_in_dict, cis_benchmark)
3. qualys - CSV parsing issues
"""

import json
import csv
import logging
import zipfile
import tempfile
import os
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from phoenix_multi_scanner_import import (
    ScannerTranslator, AssetData, VulnerabilityData, ScannerConfig
)
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class BlackDuckStandardZIPTranslator(ScannerTranslator):
    """Translator for BlackDuck standard ZIP exports with security.csv"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a BlackDuck standard ZIP"""
        if not file_path.lower().endswith('.zip'):
            return False
        
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                files = zip_ref.namelist()
                # Look for security.csv which is the signature file
                has_security = any('security.csv' in f.lower() for f in files)
                has_files = any('files.csv' in f.lower() for f in files)
                return has_security and has_files
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse BlackDuck standard ZIP"""
        logger.info(f"Parsing BlackDuck standard ZIP: {file_path}")
        
        try:
            # Extract ZIP to temp directory
            with tempfile.TemporaryDirectory() as temp_dir:
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                
                # Parse security.csv (main vulnerabilities)
                security_csv = None
                files_csv = None
                components_csv = None
                
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path_full = os.path.join(root, file)
                        if file.lower() == 'security.csv':
                            security_csv = file_path_full
                        elif file.lower() == 'files.csv':
                            files_csv = file_path_full
                        elif file.lower() == 'components.csv':
                            components_csv = file_path_full
                
                if not security_csv:
                    logger.warning("No security.csv found in ZIP")
                    return []
                
                return self._parse_security_csv(security_csv)
        
        except Exception as e:
            logger.error(f"Error parsing BlackDuck standard ZIP: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_security_csv(self, csv_path: str) -> List[AssetData]:
        """Parse security.csv from BlackDuck"""
        try:
            # Increase CSV field size limit
            maxInt = sys.maxsize
            while True:
                try:
                    csv.field_size_limit(maxInt)
                    break
                except OverflowError:
                    maxInt = int(maxInt/10)
            
            with open(csv_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            logger.info(f"Parsed {len(rows)} rows from security.csv")
            
            if not rows:
                return []
            
            # Group by component
            components = {}
            for row in rows:
                # Try various column names for component identification
                component = (row.get('Channel version origin id') or  # maven coordinates
                           row.get('Project name') or  # project name
                           row.get('Component') or 
                           row.get('Component name') or 
                           'unknown')
                
                if component == 'unknown' or not component:
                    continue
                
                if component not in components:
                    components[component] = []
                
                # Extract vulnerability details
                vuln_id = row.get('Vulnerability id') or row.get('Vulnerability')
                
                if vuln_id and vuln_id != 'None':
                    # Use Base score or Security Risk for severity
                    severity_str = row.get('Base score') or row.get('Security Risk') or row.get('Severity') or 'Medium'
                    
                    components[component].append({
                        'name': f"BDSA-{vuln_id}" if not vuln_id.startswith('CVE') else vuln_id,
                        'description': row.get('Description', f"BlackDuck vulnerability {vuln_id}"),
                        'remedy': row.get('Remediation comment', 'Update component to fix vulnerability'),
                        'severity': self.normalize_severity(str(severity_str)),
                        'location': component,
                        'reference_ids': [str(vuln_id)]
                    })
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            logger.info(f"Processing {len(components)} components")
            
            for component_name, vulns in components.items():
                # Ensure vulns is a list
                if not isinstance(vulns, list):
                    logger.warning(f"Component {component_name} has non-list vulns: {type(vulns)}")
                    continue
                
                # Create VulnerabilityData objects
                findings = []
                for v in vulns:
                    try:
                        findings.append(VulnerabilityData(**v))
                    except Exception as e:
                        logger.warning(f"Failed to create VulnerabilityData: {e}")
                
                if not findings:
                    findings = [VulnerabilityData(
                        name="NO_VULNERABILITIES_FOUND",
                        description="No vulnerabilities found for this component",
                        remedy="No action required",
                        severity="0.0",
                        location=component_name
                    )]
                
                asset = AssetData(
                    asset_type=self.scanner_config.asset_type,
                    attributes={
                        'packageName': component_name,
                        'buildFile': 'blackduck_security_export'
                    },
                    findings=findings,
                    tags=tags
                )
                assets.append(asset)
            
            logger.info(f"Created {len(assets)} assets from BlackDuck ZIP")
            return assets
        
        except Exception as e:
            logger.error(f"Error parsing security.csv: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def normalize_severity(self, severity: str) -> str:
        """Convert severity to Phoenix decimal format"""
        severity_lower = str(severity).lower().strip()
        
        # Try numeric first
        try:
            score = float(severity_lower)
            return str(min(10.0, max(0.0, score)))
        except ValueError:
            pass
        
        # Text mappings
        mapping = {
            'critical': '10.0',
            'high': '8.0',
            'medium': '5.0',
            'low': '3.0',
            'info': '0.0',
            'informational': '0.0'
        }
        return mapping.get(severity_lower, '5.0')


class TrivyOperatorTranslator(ScannerTranslator):
    """Translator for Trivy Operator Kubernetes CRD formats"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a Trivy Operator report"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Check for Trivy Operator signatures
            if isinstance(data, dict):
                # CRD format (cis_benchmark.json)
                if data.get('apiVersion', '').startswith('aquasecurity.github.io'):
                    return True
                
                # All reports in dict format
                if any(key.endswith('aquasecurity.github.io') for key in data.keys()):
                    return True
            
            return False
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Trivy Operator report"""
        logger.info(f"Parsing Trivy Operator report: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            # Check format
            if data.get('apiVersion', '').startswith('aquasecurity.github.io'):
                # CRD format (single resource)
                return self._parse_crd_format(data)
            elif any(key.endswith('aquasecurity.github.io') for key in data.keys()):
                # Multiple reports in dict
                return self._parse_all_reports_format(data)
            
            return []
        
        except Exception as e:
            logger.error(f"Error parsing Trivy Operator report: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_crd_format(self, data: Dict) -> List[AssetData]:
        """Parse Kubernetes CRD format (e.g., cis_benchmark.json)"""
        try:
            kind = data.get('kind', '')
            metadata = data.get('metadata', {})
            status = data.get('status', {})
            
            # Get asset name from metadata
            asset_name = metadata.get('name', 'trivy-operator-report')
            namespace = metadata.get('namespace', 'default')
            
            # Parse findings based on kind
            findings = []
            
            if 'Compliance' in kind or 'Benchmark' in kind:
                # Compliance/Benchmark report
                summary = status.get('summary', {})
                fail_count = summary.get('failCount', 0)
                pass_count = summary.get('passCount', 0)
                
                # Get detailed checks
                checks = status.get('detailReport', {}).get('results', [])
                
                for check in checks:
                    if isinstance(check, dict):
                        check_id = check.get('id', check.get('checkID', 'unknown'))
                        severity = check.get('severity', 'MEDIUM')
                        status_check = check.get('status', 'FAIL')
                        
                        if status_check in ['FAIL', 'ERROR']:
                            findings.append(VulnerabilityData(
                                name=f"CIS-{check_id}",
                                description=check.get('description', check.get('title', f"CIS check {check_id} failed")),
                                remedy=check.get('remediation', 'Follow CIS benchmarkrecommendations'),
                                severity=self._map_trivy_severity(severity),
                                location=f"{namespace}/{asset_name}",
                                reference_ids=[check_id]
                            ))
            
            elif 'Vulnerability' in kind:
                # Vulnerability report
                vulnerabilities = status.get('vulnerabilities', [])
                
                for vuln in vulnerabilities:
                    if isinstance(vuln, dict):
                        vuln_id = vuln.get('vulnerabilityID', 'unknown')
                        findings.append(VulnerabilityData(
                            name=vuln_id,
                            description=vuln.get('title', vuln_id),
                            remedy=vuln.get('fixedVersion', 'Update package'),
                            severity=self._map_trivy_severity(vuln.get('severity', 'MEDIUM')),
                            location=vuln.get('resource', asset_name),
                            reference_ids=[vuln_id]
                        ))
            
            # Create asset
            if not findings:
                findings = [VulnerabilityData(
                    name="NO_FINDINGS",
                    description="No findings in Trivy Operator report",
                    remedy="No action required",
                    severity="0.0",
                    location=asset_name
                )]
            
            tags = get_tags_safely(self.tag_config)
            
            asset = AssetData(
                asset_type='CONTAINER',
                attributes={
                    'containerName': asset_name,
                    'namespace': namespace,
                    'kind': kind
                },
                findings=findings,
                tags=tags
            )
            
            return [asset]
        
        except Exception as e:
            logger.error(f"Error parsing CRD format: {e}")
            return []
    
    def _parse_all_reports_format(self, data: Dict) -> List[AssetData]:
        """Parse all_reports_in_dict format"""
        try:
            assets = []
            
            for report_type, reports in data.items():
                if not isinstance(reports, (list, dict)):
                    continue
                
                # Convert single dict to list
                if isinstance(reports, dict):
                    reports = [reports]
                
                for report in reports:
                    if isinstance(report, dict):
                        # Parse each report as a CRD
                        parsed = self._parse_crd_format(report)
                        assets.extend(parsed)
            
            return assets
        
        except Exception as e:
            logger.error(f"Error parsing all_reports format: {e}")
            return []
    
    def _map_trivy_severity(self, severity: str) -> str:
        """Map Trivy severity to Phoenix decimal"""
        mapping = {
            'CRITICAL': '10.0',
            'HIGH': '8.0',
            'MEDIUM': '5.0',
            'LOW': '3.0',
            'UNKNOWN': '0.0',
            'INFO': '0.0'
        }
        return mapping.get(str(severity).upper(), '5.0')


class QualysCSVTranslator(ScannerTranslator):
    """Enhanced Qualys CSV translator"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a Qualys CSV"""
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                first_line = f.readline().lower()
                # Qualys CSV usually has specific headers
                return any(keyword in first_line for keyword in ['qid', 'qualys', 'vulnerability', 'severity'])
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Qualys CSV"""
        logger.info(f"Parsing Qualys CSV: {file_path}")
        
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
            
            logger.info(f"Parsed {len(rows)} rows from Qualys CSV")
            
            if not rows:
                return []
            
            # Log columns for debugging
            logger.info(f"CSV columns: {list(rows[0].keys())[:10]}")
            
            # Group by host/IP
            hosts = {}
            
            for row in rows:
                # Try multiple column names for host
                host = (row.get('IP') or row.get('IP Address') or 
                       row.get('Host') or row.get('DNS') or 'unknown')
                
                if host == 'unknown':
                    continue
                
                if host not in hosts:
                    hosts[host] = []
                
                # Extract vulnerability
                qid = row.get('QID') or row.get('Vuln ID') or row.get('ID')
                title = row.get('Title') or row.get('Vulnerability') or row.get('Name')
                
                if qid or title:
                    severity_str = (row.get('Severity') or row.get('Level') or 
                                  row.get('Risk') or 'Medium')
                    
                    hosts[host].append({
                        'name': f"QID-{qid}" if qid else title,
                        'description': title or f"Qualys finding {qid}",
                        'remedy': row.get('Solution', 'See Qualys console'),
                        'severity': self.normalize_severity(str(severity_str)),
                        'location': host,
                        'reference_ids': [str(qid)] if qid else []
                    })
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for host, vulns in hosts.items():
                findings = [VulnerabilityData(**v) for v in vulns]
                
                if not findings:
                    findings = [VulnerabilityData(
                        name="NO_VULNERABILITIES_FOUND",
                        description="No vulnerabilities found",
                        remedy="No action required",
                        severity="0.0",
                        location=host
                    )]
                
                asset = AssetData(
                    asset_type='INFRA',
                    attributes={
                        'ip': host,
                        'fqdn': host if '.' in host else f"{host}.local"
                    },
                    findings=findings,
                    tags=tags
                )
                assets.append(asset)
            
            logger.info(f"Created {len(assets)} assets from Qualys CSV")
            return assets
        
        except Exception as e:
            logger.error(f"Error parsing Qualys CSV: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def normalize_severity(self, severity: str) -> str:
        """Convert severity to Phoenix decimal format"""
        severity_lower = str(severity).lower().strip()
        
        # Try numeric first
        try:
            score = float(severity_lower)
            return str(min(10.0, max(0.0, score)))
        except ValueError:
            pass
        
        # Text mappings
        mapping = {
            '5': '10.0',  # Qualys uses 1-5 scale
            '4': '8.0',
            '3': '5.0',
            '2': '3.0',
            '1': '0.0',
            'critical': '10.0',
            'high': '8.0',
            'medium': '5.0',
            'low': '3.0',
            'info': '0.0',
            'informational': '0.0'
        }
        return mapping.get(severity_lower, '5.0')


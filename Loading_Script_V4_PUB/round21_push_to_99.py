#!/usr/bin/env python3
"""
Round 21 - Final Push to 99%+
==============================

Hard-coded translators for the last 6 remaining scanners:
1. BlackDuckBinaryCSVTranslator - BlackDuck Binary Analysis CSV
2. NoseyParkerTranslator - NoseyParker secrets scanner JSONL
3. Update ChefInspecTranslator - Handle .log files (JSON format)

Remaining to investigate: blackduck_component_risk (ZIP), burp_suite_dast (HTML), dsop
"""

import json
import csv
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


class BlackDuckBinaryCSVTranslator(ScannerTranslator):
    """Translator for BlackDuck Binary Analysis CSV format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect BlackDuck Binary Analysis CSV format"""
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            # Increase CSV field size limit
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
                headers = reader.fieldnames
                if headers:
                    # Check for BlackDuck Binary-specific columns
                    bd_cols = ['Component', 'Version', 'CVE', 'Object', 'Object full path']
                    matches = sum(1 for col in bd_cols if col in headers)
                    if matches >= 4:
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"BlackDuckBinaryCSVTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse BlackDuck Binary CSV file"""
        logger.info(f"Parsing BlackDuck Binary Analysis file: {file_path}")
        
        try:
            # Increase CSV field size limit
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
                logger.info("No rows in BlackDuck Binary CSV")
                return []
            
            # Group by component
            components = {}
            for row in rows:
                component = row.get('Component', 'unknown')
                version = row.get('Version', '')
                key = f"{component}:{version}" if version else component
                
                if key not in components:
                    components[key] = []
                
                vuln = self._parse_row(row)
                if vuln:
                    components[key].append(vuln)
            
            # Create assets
            assets = []
            tags = get_tags_safely(self.tag_config)
            
            for component_key, vulns in components.items():
                if not vulns:
                    continue
                
                asset = AssetData(
                    asset_type='BUILD',
                    attributes={
                        'name': component_key,
                        'buildFile': 'binary',
                        'scanner': 'BlackDuck Binary Analysis'
                    },
                    tags=tags + [{"key": "scanner", "value": "blackduck-binary"}]
                )
                
                for vuln in vulns:
                    asset.findings.append(vuln)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} components with {sum(len(a.findings) for a in assets)} vulnerabilities from BlackDuck Binary")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing BlackDuck Binary file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_row(self, row: Dict) -> Optional[Dict]:
        """Parse a single BlackDuck Binary CSV row"""
        try:
            cve = row.get('CVE', '').strip()
            if not cve:
                return None  # Skip rows without CVE
            
            component = row.get('Component', 'unknown')
            version = row.get('Version', '')
            summary = row.get('Summary', '')
            cvss3 = row.get('CVSS3', '0.0')
            object_name = row.get('Object', '')
            object_path = row.get('Object full path', '')
            
            # Map CVSS3 to severity
            try:
                cvss3_float = float(cvss3)
                if cvss3_float >= 9.0:
                    severity = 'Critical'
                elif cvss3_float >= 7.0:
                    severity = 'High'
                elif cvss3_float >= 4.0:
                    severity = 'Medium'
                else:
                    severity = 'Low'
            except ValueError:
                severity = 'Medium'
            
            severity_normalized = self.normalize_severity(severity)
            
            return {
                'name': f"{cve}: {component} {version}",
                'description': summary if summary else f"Vulnerability in {component}",
                'remedy': "Update to latest non-vulnerable version",
                'severity': severity_normalized,
                'location': object_path if object_path else object_name,
                'reference_ids': [cve],
                'details': {
                    'component': component,
                    'version': version,
                    'cvss3': cvss3,
                    'object': object_name
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing BlackDuck Binary row: {e}")
            return None


class NoseyParkerTranslator(ScannerTranslator):
    """Translator for NoseyParker secrets scanner JSONL format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect NoseyParker JSONL format"""
        if not file_path.lower().endswith(('.jsonl', '.json')):
            return False
        
        try:
            with open(file_path, 'r') as f:
                first_line = f.readline().strip()
                if not first_line:
                    return False
                
                try:
                    obj = json.loads(first_line)
                except json.JSONDecodeError:
                    return False
                
                # NoseyParker format: has "rule_name", "blob_metadata"
                if isinstance(obj, dict):
                    if 'rule_name' in obj and 'blob_metadata' in obj:
                        return True
            
            return False
        except Exception as e:
            logger.debug(f"NoseyParkerTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse NoseyParker JSONL file"""
        logger.info(f"Parsing NoseyParker file: {file_path}")
        
        secrets = []
        
        try:
            with open(file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        finding = json.loads(line)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Skipping invalid JSON on line {line_num}: {e}")
                        continue
                    
                    vuln = self._parse_finding(finding)
                    if vuln:
                        secrets.append(vuln)
            
            if not secrets:
                logger.info("No secrets found in NoseyParker output")
                return []
            
            # Create single asset
            tags = get_tags_safely(self.tag_config)
            
            asset = AssetData(
                asset_type='CODE',
                attributes={
                    'name': 'NoseyParker Scan Results',
                    'scanner': 'NoseyParker'
                },
                tags=tags + [{"key": "scanner", "value": "noseyparker"}]
            )
            
            for vuln in secrets:
                asset.findings.append(vuln)
            
            assets = [self.ensure_asset_has_findings(asset)]
            
            logger.info(f"Parsed {len(secrets)} secrets from NoseyParker")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing NoseyParker file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_finding(self, finding: Dict) -> Optional[Dict]:
        """Parse a NoseyParker finding"""
        try:
            rule_name = finding.get('rule_name', 'Secret Found')
            
            # Get blob metadata for location
            blob_metadata = finding.get('blob_metadata', [])
            if blob_metadata and len(blob_metadata) > 0:
                first_blob = blob_metadata[0]
                repo = first_blob.get('repository', {})
                repo_name = repo.get('name', 'unknown')
                blob_path = first_blob.get('blob_path', 'unknown')
                location = f"{repo_name}:{blob_path}"
            else:
                location = "unknown"
            
            # Get match info
            matches = finding.get('matches', [])
            match_count = len(matches)
            
            return {
                'name': f"{rule_name}",
                'description': f"Secret detected ({match_count} match{'es' if match_count != 1 else ''}) in {location}",
                'remedy': "Rotate the exposed secret immediately and remove from repository history",
                'severity': self.normalize_severity('High'),
                'location': location,
                'reference_ids': [rule_name],
                'details': {
                    'rule_name': rule_name,
                    'match_count': match_count
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing NoseyParker finding: {e}")
            return None


# Export all translators
__all__ = [
    'BlackDuckBinaryCSVTranslator',
    'NoseyParkerTranslator'
]


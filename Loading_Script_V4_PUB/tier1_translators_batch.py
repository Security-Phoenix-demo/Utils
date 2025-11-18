#!/usr/bin/env python3
"""
Tier 1 Critical Scanner Translators - Batch Generated
Auto-generated hard-coded translators for critical scanners
"""

import json
import csv
import logging
from typing import Any, Dict, List, Optional
from phoenix_import_refactored import AssetData, VulnerabilityData
from phoenix_multi_scanner_import import ScannerTranslator, error_tracker

logger = logging.getLogger(__name__)


# ============================================================================
# BLACK DUCK BINARY ANALYSIS - CSV FORMAT
# ============================================================================

class BlackDuckBinaryAnalysisTranslator(ScannerTranslator):
    """Translator for blackduck-binary-analysis CSV format"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect blackduck-binary-analysis CSV format"""
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                first_row = next(reader, None)
                if first_row:
                    # Check for required columns
                    required_cols = ["Component", "Version", "CVE"]
                    if all(col in first_row for col in required_cols):
                        return True
        except:
            pass
        return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse blackduck-binary-analysis CSV scan results"""
        logger.info(f"Parsing blackduck-binary-analysis CSV file: {file_path}")
        
        try:
            with open(file_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
        except Exception as e:
            error_tracker.log_error(e, "blackduck-binary-analysis CSV Parsing", file_path, "parse_file")
            raise
        
        # Group by component
        assets_dict = {}
        
        for row in rows:
            component = row.get('Component', 'unknown')
            version = row.get('Version', '')
            asset_name = f"{component}:{version}" if version else component
            
            if asset_name not in assets_dict:
                assets_dict[asset_name] = {
                    'attributes': {
                        'dockerfile': 'Dockerfile',
                        'origin': 'blackduck-binary-analysis',
                        'repository': component
                    },
                    'vulns': []
                }
            
            # Parse vulnerability
            vuln = self._parse_csv_vulnerability(row)
            if vuln:
                assets_dict[asset_name]['vulns'].append(vuln)
        
        # Create assets
        assets = []
        for asset_name, asset_data in assets_dict.items():
            asset = AssetData(
                asset_type="BUILD",
                attributes=asset_data['attributes'],
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "blackduck-binary-analysis"}
                ]
            )
            asset.findings.extend(asset_data['vulns'])
            assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets
    
    def _parse_csv_vulnerability(self, row: Dict) -> Optional[Dict]:
        """Parse vulnerability from CSV row"""
        vuln_id = row.get('CVE', row.get('BDSA', 'UNKNOWN'))
        if not vuln_id or vuln_id == '':
            return None
        
        # Get CVSS score
        cvss_str = row.get('CVSS3', '0.0')
        try:
            cvss_score = float(cvss_str) if cvss_str else 0.0
        except:
            cvss_score = 0.0
        
        # Map CVSS to severity
        if cvss_score >= 9.0:
            severity = 5  # Critical
        elif cvss_score >= 7.0:
            severity = 4  # High
        elif cvss_score >= 4.0:
            severity = 3  # Medium
        elif cvss_score > 0:
            severity = 2  # Low
        else:
            severity = 1  # Informational
        
        # Create vulnerability
        vulnerability = VulnerabilityData(
            name=vuln_id,
            description=row.get('Summary', f"Vulnerability: {vuln_id}")[:500],
            remedy="See vendor advisories for remediation",
            severity=severity,
            location=row.get('Object', 'unknown'),
            reference_ids=[vuln_id],
            details={
                'cvss_score': cvss_score,
                'cvss_vector_v3': row.get('CVSS vector (v3)', ''),
                'url': row.get('Vulnerability URL', '')
            }
        )
        
        return vulnerability.__dict__

# ============================================================================
# API BLACK DUCK - JSON FORMAT
# ============================================================================

class APIBlackDuckTranslator(ScannerTranslator):
    """Translator for api-blackduck scanner results"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect api-blackduck file format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Check for api-blackduck specific structure
            if isinstance(file_content, list) and len(file_content) > 0:
                first_item = file_content[0]
                # Detection keys: "componentName", "componentVersionName", "vulnerabilityWithRemediation"
                if isinstance(first_item, dict):
                    required_keys = ["componentName", "vulnerabilityWithRemediation"]
                    if len(required_keys) > 0 and all(k in first_item for k in required_keys):
                        return True
            
            return False
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse api-blackduck scan results"""
        logger.info(f"Parsing api-blackduck file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            error_tracker.log_error(e, "api-blackduck Parsing", file_path, "parse_file")
            raise
        
        if not isinstance(data, list):
            data = [data]
        
        # Group by asset
        assets_dict = {}
        
        for item in data:
            asset_name = item.get('componentName', 'unknown')
            
            if asset_name not in assets_dict:
                assets_dict[asset_name] = {
                    'attributes': {
                        'dockerfile': 'Dockerfile',
                        'origin': 'api-blackduck',
                        'repository': asset_name
                    },
                    'vulns': []
                }
            
            # Parse vulnerability
            vuln = self._parse_vulnerability(item)
            if vuln:
                assets_dict[asset_name]['vulns'].append(vuln)
        
        # Create assets
        assets = []
        for asset_name, asset_data in assets_dict.items():
            asset = AssetData(
                asset_type="BUILD",
                attributes=asset_data['attributes'],
                tags=self.tag_config.get_all_tags() + [
                    {"key": "scanner", "value": "api-blackduck"}
                ]
            )
            asset.findings.extend(asset_data['vulns'])
            assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets
    
    def _parse_vulnerability(self, item: Dict) -> Optional[Dict]:
        """Parse vulnerability from item"""
        vuln_with_rem = item.get('vulnerabilityWithRemediation', {})
        if not vuln_with_rem:
            return None
        
        vuln_id = vuln_with_rem.get('vulnerabilityName', 'UNKNOWN')
        if not vuln_id:
            return None
        
        # Get severity
        severity_str = vuln_with_rem.get('severity', 'Unknown')
        severity = self.normalize_severity(severity_str)
        
        # Get description
        description = vuln_with_rem.get('description', f"Vulnerability: {vuln_id}")
        
        # Create vulnerability
        vulnerability = VulnerabilityData(
            name=vuln_id,
            description=description[:500],
            remedy=vuln_with_rem.get('remediationComment', "See scanner output for remediation"),
            severity=severity,
            location=item.get('componentVersionName', 'unknown'),
            reference_ids=[vuln_id]
        )
        
        return vulnerability.__dict__


# Export all translators
__all__ = [
    'BlackDuckBinaryAnalysisTranslator',
    'APIBlackDuckTranslator'
]

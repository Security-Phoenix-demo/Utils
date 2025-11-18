#!/usr/bin/env python3
"""
Aqua Security Scanner Translator
==================================

Translator for Aqua Security container vulnerability scanner.

Supported Formats:
- JSON output from Aqua scanner

Scanner Detection:
- Checks for Aqua-specific fields: 'image', 'resources', 'vulnerability_summary', 'aqua_score'
- Excludes Grype files (checks descriptor.name != 'grype')

Asset Type: CONTAINER
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List

from phoenix_import_refactored import AssetData, VulnerabilityData
from .base_translator import ScannerTranslator, ScannerConfig

logger = logging.getLogger(__name__)


class AquaTranslator(ScannerTranslator):
    """Translator for Aqua Security scanner results"""
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is an Aqua scan file"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # Check for Aqua-specific fields (but NOT Grype fields)
            if isinstance(file_content, dict):
                # Exclude Grype files
                if 'descriptor' in file_content:
                    descriptor = file_content.get('descriptor', {})
                    if isinstance(descriptor, dict) and descriptor.get('name', '').lower() == 'grype':
                        return False
                
                # Check for Aqua-specific fields
                aqua_indicators = ['image', 'resources', 'vulnerability_summary', 'aqua_score', 'aqua_severity']
                return any(indicator in str(file_content) for indicator in aqua_indicators)
            
            return False
        except Exception as e:
            logger.debug(f"AquaTranslator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Aqua scan results"""
        logger.info(f"Parsing Aqua scan file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to parse Aqua file: {e}")
            raise
        
        assets = []
        
        # Extract image information
        image_name = data.get('image', 'unknown-image')
        image_digest = data.get('digest', '')
        os_info = f"{data.get('os', '')} {data.get('version', '')}".strip()
        
        # Create container asset
        asset_attributes = {
            'dockerfile': 'Dockerfile',
            'origin': 'aqua-scan'
        }
        
        if image_name:
            asset_attributes['repository'] = image_name
        
        asset = AssetData(
            asset_type="CONTAINER",
            attributes=asset_attributes,
            tags=self.tag_config.get_all_tags() + [
                {"key": "scanner", "value": "aqua"},
                {"key": "image-digest", "value": image_digest[:16] if image_digest else ""},
                {"key": "os", "value": os_info if os_info else "unknown"}
            ]
        )
        
        # Process vulnerabilities from resources
        resources = data.get('resources', [])
        for resource in resources:
            resource_info = resource.get('resource', {})
            vulnerabilities = resource.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                # Create vulnerability
                vulnerability = VulnerabilityData(
                    name=vuln.get('name', 'Unknown Vulnerability'),
                    description=vuln.get('description', ''),
                    remedy=vuln.get('solution', 'No solution provided'),
                    severity=self.normalize_severity(vuln.get('aqua_severity', vuln.get('nvd_severity', 'medium'))),
                    location=f"{resource_info.get('name', '')}:{resource_info.get('version', '')}",
                    reference_ids=[vuln.get('name', '')] if vuln.get('name', '').startswith('CVE-') else [],
                    published_date_time=vuln.get('publish_date', datetime.now().strftime("%Y-%m-%d")),
                    details={
                        'package_name': resource_info.get('name', ''),
                        'package_version': resource_info.get('version', ''),
                        'package_format': resource_info.get('format', ''),
                        'package_arch': resource_info.get('arch', ''),
                        'nvd_score': vuln.get('nvd_score', ''),
                        'nvd_score_v3': vuln.get('nvd_score_v3', ''),
                        'aqua_score': vuln.get('aqua_score', ''),
                        'fix_version': vuln.get('fix_version', ''),
                        'nvd_url': vuln.get('nvd_url', ''),
                        'vendor_severity': vuln.get('vendor_severity', ''),
                        'modification_date': vuln.get('modification_date', '')
                    }
                )
                
                asset.findings.append(vulnerability.__dict__)
        
        assets.append(self.ensure_asset_has_findings(asset))
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets


__all__ = ['AquaTranslator']


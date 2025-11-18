#!/usr/bin/env python3
"""
Format Handlers for Non-Standard Scanner Output Formats
========================================================

This module provides handlers for scanner output formats that aren't
standard JSON/XML/CSV:

1. NDJSON (Newline-Delimited JSON) - ChefInspec, and others
2. JavaScript-wrapped JSON - Scout Suite
3. Future: Excel, ZIP, etc.

Author: Round 5 Implementation
Date: 2025-11-11
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional
from pathlib import Path

from phoenix_multi_scanner_import import (
    ScannerConfig,
    ScannerTranslator,
    VulnerabilityData
)
from phoenix_import_refactored import AssetData
from tag_utils import get_tags_safely

logger = logging.getLogger(__name__)


class ChefInspecTranslator(ScannerTranslator):
    """
    Translator for Chef InSpec NDJSON format.
    
    InSpec outputs JSON-per-line (NDJSON) where each line is a complete JSON object
    representing a control result.
    
    Format:
    {"status":"passed","control_id":"cis-dil-benchmark-1.1.1",...}
    {"status":"failed","control_id":"cis-dil-benchmark-1.1.2",...}
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect ChefInspec NDJSON/JSON format in .log files"""
        if not file_path.lower().endswith(('.log', '.json', '.jsonl')):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Read first few lines
                for i in range(5):
                    line = f.readline().strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        # Check for InSpec-specific fields
                        if 'control_id' in data or 'id' in data:
                            if 'status' in data and 'platform' in data:
                                return True
                    except json.JSONDecodeError:
                        continue
            
            return False
            
        except Exception as e:
            logger.debug(f"ChefInspecTranslator.can_handle failed for {file_path}: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse ChefInspec NDJSON file"""
        assets = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            logger.info(f"Parsing ChefInspec NDJSON file: {file_path} ({len(lines)} lines)")
            
            # Group by platform (asset)
            platforms = {}
            
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    control = json.loads(line)
                except json.JSONDecodeError:
                    continue
                
                # Include all controls (compliance report should show all findings)
                status = control.get('status', '').lower()
                # Only skip truly empty statuses
                if not status:
                    continue
                
                # Get platform info
                platform = control.get('platform', {})
                platform_name = platform.get('name', 'unknown')
                platform_release = platform.get('release', 'unknown')
                target_id = platform.get('target_id', 'unknown')
                
                asset_key = f"{platform_name}-{target_id}"
                
                if asset_key not in platforms:
                    platforms[asset_key] = {
                        'platform_name': platform_name,
                        'platform_release': platform_release,
                        'target_id': target_id,
                        'findings': []
                    }
                
                # Parse control as vulnerability
                vuln = self._parse_control(control)
                if vuln:
                    platforms[asset_key]['findings'].append(vuln)
            
            # Convert to AssetData
            for asset_key, platform_data in platforms.items():
                if not platform_data['findings']:
                    continue
                
                base_tags = get_tags_safely(self.tag_config)
                
                asset = AssetData(
                    asset_type='INFRA',
                    attributes={
                        'name': platform_data['target_id'],
                        'OS': f"{platform_data['platform_name']} {platform_data['platform_release']}",
                        'scanner': 'ChefInspec'
                    },
                    tags=base_tags
                )
                
                for vuln_dict in platform_data['findings']:
                    asset.findings.append(vuln_dict)
                
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} assets from ChefInspec NDJSON")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing ChefInspec NDJSON: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_control(self, control: Dict) -> Optional[Dict]:
        """Parse a single InSpec control"""
        try:
            control_id = control.get('id', control.get('control_id', 'unknown'))
            title = control.get('title', control_id)
            description = control.get('description', '')
            impact = control.get('impact', 0.0)
            
            # Map impact to severity
            if impact >= 0.7:
                severity = 'HIGH'
            elif impact >= 0.4:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
            
            # Get failure details
            results = control.get('results', [])
            failed_results = [r for r in results if r.get('status') == 'failed']
            
            location = 'system'
            if failed_results:
                code_desc = failed_results[0].get('code_desc', '')
                if code_desc:
                    location = code_desc
            
            return {
                'name': control_id,
                'description': f"{title}\n\n{description}".strip(),
                'remedy': 'Review InSpec control documentation for remediation steps',
                'severity': severity,
                'location': location,
                'reference_ids': [f"InSpec-{control_id}"],
                'cwes': []
            }
            
        except Exception as e:
            logger.debug(f"Error parsing control: {e}")
            return None


class ScoutSuiteTranslator(ScannerTranslator):
    """
    Translator for Scout Suite JavaScript-wrapped JSON format.
    
    Scout Suite outputs JavaScript files with JSON data:
    scoutsuite_results = {JSON DATA HERE}
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Scout Suite JS format"""
        if not file_path.lower().endswith('.js'):
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read(1000)  # Read first 1000 chars
            
            # Check for Scout Suite signature
            if 'scoutsuite_results' in content.lower():
                return True
            
            return False
            
        except Exception as e:
            logger.debug(f"ScoutSuiteTranslator.can_handle failed for {file_path}: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Scout Suite JS file"""
        assets = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            logger.info(f"Parsing Scout Suite JS file: {file_path}")
            
            # Extract JSON from JavaScript
            # Pattern: scoutsuite_results = {JSON}
            match = re.search(r'scoutsuite_results\s*=\s*({.+})', content, re.DOTALL)
            if not match:
                logger.warning("Could not extract JSON from Scout Suite JS file")
                return []
            
            json_str = match.group(1)
            data = json.loads(json_str)
            
            # Parse Scout Suite structure
            account_id = data.get('account_id', 'unknown')
            last_run = data.get('last_run', {})
            
            # Group findings by service
            services = last_run.get('summary', {})
            
            # Create asset per cloud service with findings
            for service_name, service_data in services.items():
                flagged = service_data.get('flagged_items', 0)
                if flagged == 0:
                    continue
                
                base_tags = get_tags_safely(self.tag_config)
                
                asset = AssetData(
                    asset_type='CLOUD',
                    attributes={
                        'name': f"{account_id}-{service_name}",
                        'cloud_account': account_id,
                        'service': service_name,
                        'scanner': 'Scout Suite'
                    },
                    tags=base_tags
                )
                
                # Create a finding for the service
                finding = {
                    'name': f"Scout Suite - {service_name} issues",
                    'description': f"Scout Suite found {flagged} flagged items in {service_name}",
                    'remedy': 'Review Scout Suite report for detailed remediation steps',
                    'severity': 'MEDIUM',
                    'location': service_name,
                    'reference_ids': [f"ScoutSuite-{service_name}"],
                    'cwes': []
                }
                
                asset.findings.append(finding)
                assets.append(self.ensure_asset_has_findings(asset))
            
            logger.info(f"Parsed {len(assets)} assets from Scout Suite")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Scout Suite JS: {e}")
            import traceback
            traceback.print_exc()
            return []


# Export for easy import
__all__ = ['ChefInspecTranslator', 'ScoutSuiteTranslator']


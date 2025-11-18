#!/usr/bin/env python3
"""
Tenable PCI Format Translator
============================

Specialized translator for Tenable CSV files with PCI-specific columns.
Handles the duplicate Description columns and missing Risk column.

Author: Francesco Cipollone
Date: October 1, 2025
"""

import csv
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime

from phoenix_import_refactored import AssetData, VulnerabilityData
from phoenix_multi_scanner_import import ScannerTranslator, ScannerConfig, TagConfig

logger = logging.getLogger(__name__)


class TenablePCITranslator(ScannerTranslator):
    """Specialized translator for Tenable PCI format CSV files"""
    
    def _convert_date_to_iso8601(self, date_str: str) -> str:
        """Convert date string to ISO-8601 format, handling N/A and various formats"""
        if not date_str or date_str.strip() in ['N/A', '', 'NULL', 'null', 'None']:
            return datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        
        # Clean the date string
        date_str = date_str.strip()
        
        # Common date formats to handle
        date_formats = [
            '%Y-%m-%dT%H:%M:%S',      # ISO format
            '%Y-%m-%d %H:%M:%S',      # Standard datetime
            '%Y-%m-%d',               # Date only
            '%m/%d/%Y %H:%M:%S',      # US format with time
            '%m/%d/%Y',               # US format
            '%d/%m/%Y %H:%M:%S',      # EU format with time
            '%d/%m/%Y',               # EU format
            '%b %d, %Y %H:%M:%S',     # Text month with time
            '%b %d, %Y',              # Text month
            '%Y/%m/%d',               # Alternative format
        ]
        
        for fmt in date_formats:
            try:
                dt = datetime.strptime(date_str, fmt)
                return dt.strftime('%Y-%m-%dT%H:%M:%S')
            except ValueError:
                continue
        
        # If no format matches, log warning and return current time
        logger.warning(f"Could not parse date '{date_str}', using current time")
        return datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Check if this is a Tenable PCI format file"""
        if not file_path.lower().endswith('.csv'):
            return False
        
        try:
            with open(file_path, 'r') as f:
                first_line = f.readline().lower()
                # Look for PCI-specific indicators
                pci_indicators = ['pci severity', 'pci-', 'plugin name', 'cvss v2 base score']
                tenable_indicators = ['plugin', 'synopsis', 'cvss']
                
                has_pci = any(indicator in first_line for indicator in pci_indicators)
                has_tenable = any(indicator in first_line for indicator in tenable_indicators)
                
                return has_pci and has_tenable
        except:
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Tenable PCI format scan results"""
        logger.info(f"Parsing Tenable PCI format file: {file_path}")
        
        assets_map = {}
        
        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                # Extract asset information
                ip_address = row.get('IP Address', '').strip()
                hostname = row.get('DNS Name', '').strip()
                mac_address = row.get('MAC Address', '').strip()
                
                # Create asset key
                asset_key = ip_address or hostname or mac_address or 'unknown-host'
                
                if asset_key not in assets_map:
                    # Create new asset
                    attributes = {}
                    if ip_address:
                        attributes['ip'] = ip_address
                    if hostname:
                        attributes['hostname'] = hostname
                        attributes['fqdn'] = hostname
                    if mac_address:
                        attributes['macAddress'] = mac_address  # Fixed field name for Phoenix API
                    
                    # Ensure required fields
                    if not attributes.get('ip') and not attributes.get('hostname'):
                        attributes['hostname'] = f"tenable-pci-host-{asset_key}"
                    
                    asset = AssetData(
                        asset_type="INFRA",
                        attributes=attributes,
                        tags=self.tag_config.get_all_tags() + [
                            {"key": "scanner", "value": "tenable"},
                            {"key": "scan-type", "value": "pci-compliance"},
                            {"key": "format", "value": "pci-csv"}
                        ]
                    )
                    assets_map[asset_key] = asset
                
                # Extract vulnerability information
                plugin_id = row.get('Plugin', '').strip()
                plugin_name = row.get('Plugin Name', '').strip()
                severity = row.get('Severity', '').strip()
                pci_severity = row.get('PCI Severity', '').strip()
                
                # Skip if no essential vulnerability data
                if not plugin_id or not plugin_name:
                    continue
                
                # Use PCI severity if available, otherwise use regular severity
                risk_level = pci_severity if pci_severity and pci_severity.lower() not in ['pass', ''] else severity
                
                # Skip informational findings unless they're PCI failures
                if (risk_level.lower() in ['none', 'info', 'pass'] and 
                    pci_severity.lower() != 'fail'):
                    continue
                
                # Handle duplicate Description columns - use the first non-empty one
                description = ''
                if 'Description' in row:
                    # Get all Description columns (there might be multiple)
                    descriptions = []
                    for key, value in row.items():
                        if key == 'Description' and value and value.strip():
                            descriptions.append(value.strip())
                    
                    # Use the first non-empty description
                    description = descriptions[0] if descriptions else row.get('Synopsis', '')
                else:
                    description = row.get('Synopsis', '')
                
                vulnerability = VulnerabilityData(
                    name=f"Plugin-{plugin_id}: {plugin_name}",
                    description=description,
                    remedy=row.get('Solution', 'No solution provided'),
                    severity=self.normalize_pci_severity(risk_level, pci_severity),
                    location=f"{ip_address}:{row.get('Port', '')}",
                    reference_ids=self.extract_cves(row.get('CVE', '')),
                    published_date_time=self._convert_date_to_iso8601(row.get('Plugin Publication Date', '')),
                    tags=self.tag_config.vulnerability_tags.copy(),  # Add vulnerability tags from config
                    details={
                        'plugin_id': plugin_id,
                        'plugin_family': row.get('Family', ''),
                        'port': row.get('Port', ''),
                        'protocol': row.get('Protocol', ''),
                        'pci_severity': pci_severity,
                        'severity': severity,
                        'cvss_v2_base_score': row.get('CVSS V2 Base Score', ''),
                        'cvss_v3_base_score': row.get('CVSS V3 Base Score', ''),
                        'cvss_v2_vector': row.get('CVSS V2 Vector', ''),
                        'cvss_v3_vector': row.get('CVSS V3 Vector', ''),
                        'exploit_available': row.get('Exploit?', ''),
                        'first_discovered': self._convert_date_to_iso8601(row.get('First Discovered', '')),
                        'last_observed': self._convert_date_to_iso8601(row.get('Last Observed', '')),
                        'vuln_publication_date': self._convert_date_to_iso8601(row.get('Vuln Publication Date', '')),
                        'patch_publication_date': self._convert_date_to_iso8601(row.get('Patch Publication Date', '')),
                        'plugin_modification_date': self._convert_date_to_iso8601(row.get('Plugin Modification Date', '')),
                        'risk_factor': row.get('Risk Factor', ''),
                        'vpr_score': row.get('Vulnerability Priority Rating', ''),
                        'synopsis': row.get('Synopsis', '')
                    }
                )
                
                assets_map[asset_key].findings.append(vulnerability.__dict__)
        
        # Ensure all assets have findings if create_empty_assets is enabled
        assets = [self.ensure_asset_has_findings(asset) for asset in assets_map.values()]
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} vulnerabilities")
        return assets
    
    def normalize_pci_severity(self, severity: str, pci_severity: str) -> str:
        """Normalize PCI severity to numeric scale"""
        # PCI failures are always high priority
        if pci_severity and pci_severity.lower() == 'fail':
            # Map based on underlying severity
            severity_map = {
                'critical': '10.0',
                'high': '8.0', 
                'medium': '5.0',
                'low': '3.0',
                'info': '1.0'
            }
            return severity_map.get(severity.lower(), '5.0')  # Default to medium for PCI failures
        
        # Standard severity mapping
        return self.normalize_severity(severity)

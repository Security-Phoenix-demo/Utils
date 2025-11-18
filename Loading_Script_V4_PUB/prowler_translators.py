#!/usr/bin/env python3
"""
Prowler Scanner Translators
============================

Hard-coded translators for AWS Prowler security scanner formats:
1. AWS Prowler v3.x (OCSF 1.2.0 format)
2. AWS Prowler v4.x/v5.x (OCSF 1.5.0 format)

All versions use OCSF (Open Cybersecurity Schema Framework)

Author: Auto-generated from user requirements
Date: 2025-11-11
"""

import json
import csv
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime
from pathlib import Path

# Import base classes
try:
    from phoenix_import_refactored import AssetData, VulnerabilityData
    from phoenix_multi_scanner_import import ScannerTranslator, error_tracker
    from tag_utils import get_tags_safely
except ImportError:
    pass

logger = logging.getLogger(__name__)


class AWSProwlerV2Translator(ScannerTranslator):
    """Translator for AWS Prowler v2.x with NDJSON format
    
    Format: Newline-delimited JSON (one finding per line)
    Each line is a JSON object with Control, Severity, Status, etc.
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Prowler v2 NDJSON format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            with open(file_path, 'r') as f:
                first_line = f.readline().strip()
                if not first_line:
                    return False
                
                # Try to parse first line as JSON
                try:
                    obj = json.loads(first_line)
                except json.JSONDecodeError:
                    return False
                
                # Check for Prowler V2 specific fields
                if isinstance(obj, dict):
                    prowler_v2_fields = ['Control', 'Account Number', 'Severity', 'Status', 'Control ID', 'CAF Epic']
                    matches = sum(1 for field in prowler_v2_fields if field in obj)
                    return matches >= 4  # At least 4 of 6 fields
            
            return False
        except Exception as e:
            logger.debug(f"AWSProwlerV2Translator.can_handle failed: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Prowler v2 NDJSON file"""
        logger.info(f"Parsing Prowler v2 NDJSON file: {file_path}")
        
        assets_by_account = {}
        
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
                    
                    # Get account info
                    account_id = finding.get('Account Number', 'unknown-account')
                    region = finding.get('Region', 'global')
                    
                    # Create asset key
                    asset_key = f"{account_id}:{region}"
                    
                    if asset_key not in assets_by_account:
                        # Create new asset
                        tags = get_tags_safely(self.tag_config)
                        asset = AssetData(
                            asset_type='CLOUD',
                            attributes={
                                'name': f"AWS Account {account_id}",
                                'account_id': account_id,
                                'region': region,
                                'provider': 'AWS',
                                'scanner': 'Prowler v2'
                            },
                            tags=tags + [
                                {"key": "scanner", "value": "prowler-v2"},
                                {"key": "cloud_provider", "value": "aws"}
                            ]
                        )
                        assets_by_account[asset_key] = asset
                    
                    # Parse finding
                    status = finding.get('Status', '').upper()
                    if status in ['FAIL', 'FAILED']:
                        vuln = self._parse_finding(finding)
                        if vuln:
                            assets_by_account[asset_key].findings.append(vuln)
            
            # Ensure all assets have findings
            assets = [self.ensure_asset_has_findings(asset) for asset in assets_by_account.values()]
            
            logger.info(f"Parsed {len(assets)} accounts with {sum(len(a.findings) for a in assets)} findings from Prowler v2")
            return assets
            
        except Exception as e:
            logger.error(f"Error parsing Prowler v2 file: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def _parse_finding(self, finding: Dict) -> Optional[Dict]:
        """Parse a Prowler v2 finding into vulnerability format"""
        try:
            control = finding.get('Control', 'Unknown Control')
            control_id = finding.get('Control ID', '')
            severity = finding.get('Severity', 'Medium')
            message = finding.get('Message', '')
            resource_id = finding.get('Resource ID', '')
            service = finding.get('Service', '')
            risk = finding.get('Risk', '')
            remediation = finding.get('Remediation', '')
            
            # Create vulnerability name
            name = f"{control_id}: {control}" if control_id else control
            
            # Normalize severity
            severity_normalized = self.normalize_severity(severity)
            
            # Create location
            location = resource_id if resource_id else service
            
            return {
                'name': name,
                'description': message if message else risk,
                'remedy': remediation if remediation else "See Prowler documentation",
                'severity': severity_normalized,
                'location': location,
                'reference_ids': [control_id] if control_id else [],
                'details': {
                    'control': control,
                    'control_id': control_id,
                    'service': service,
                    'caf_epic': finding.get('CAF Epic', ''),
                    'compliance': finding.get('Compliance', ''),
                    'doc_link': finding.get('Doc link', ''),
                    'resource_id': resource_id,
                    'timestamp': finding.get('Timestamp', '')
                }
            }
            
        except Exception as e:
            logger.debug(f"Error parsing Prowler v2 finding: {e}")
            return None


class AWSProwlerV3Translator(ScannerTranslator):
    """Translator for AWS Prowler v3.x with OCSF format
    
    Format: JSON array of OCSF findings with metadata, resources, cloud info
    
    ✅ SUPPORTED VERSIONS:
    - Prowler v3.x (OCSF 1.2.0+) ✅
    
    Example structure:
    [{
        "metadata": {"product": {"name": "Prowler", "version": "3.x.x"}},
        "severity": "High",
        "status_code": "FAIL",
        "finding_info": {...},
        "resources": [{...}],
        "cloud": {"account": {...}, "region": "..."},
        "remediation": {...}
    }]
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Prowler v3.x OCSF format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # OCSF format is an array of findings
            if isinstance(file_content, list) and len(file_content) > 0:
                first_item = file_content[0]
                
                # Check for Prowler OCSF specific structure
                if isinstance(first_item, dict):
                    metadata = first_item.get('metadata', {})
                    product = metadata.get('product', {})
                    
                    # Must have Prowler product name
                    if product.get('name') == 'Prowler':
                        # OCSF specific fields
                        if 'finding_info' in first_item and 'resources' in first_item:
                            if 'cloud' in first_item:
                                # Check version - v3.x
                                version = product.get('version', '')
                                if version.startswith('3.') or not version or version.startswith('4.') or version.startswith('5.'):
                                    # Accept all versions for v3 translator (backward compat)
                                    return True
            
            return False
        except Exception as e:
            logger.debug(f"AWSProwlerV3Translator.can_handle error: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Prowler OCSF scan results"""
        logger.info(f"Parsing Prowler v3 OCSF file: {file_path}")
        
        try:
            with open(file_path, 'r') as f:
                findings = json.load(f)
        except Exception as e:
            error_tracker.log_error(e, "Prowler v3 OCSF Parsing", file_path, "parse_file")
            raise
        
        if not isinstance(findings, list):
            findings = [findings]
        
        # Group findings by resource/account
        assets_dict = {}
        
        for finding in findings:
            # Extract cloud and resource info
            cloud_info = finding.get('cloud', {})
            account_info = cloud_info.get('account', {})
            account_id = account_info.get('uid', 'unknown')
            region = cloud_info.get('region', 'global')
            provider = cloud_info.get('provider', 'aws')
            
            # Get resources
            resources = finding.get('resources', [])
            
            # If no resources, create one generic asset per account
            if not resources:
                asset_key = f"{provider}-{account_id}-{region}"
                
                if asset_key not in assets_dict:
                    # Map provider string to Phoenix format
                    provider_type_map = {
                        'aws': 'AWS',
                        'azure': 'AZURE',
                        'gcp': 'GCP',
                        'google': 'GCP'
                    }
                    provider_type = provider_type_map.get(provider.lower(), 'AWS')
                    
                    assets_dict[asset_key] = {
                        'asset_type': 'CLOUD',  # Changed from INFRA to CLOUD
                        'attributes': {
                            'providerType': provider_type,  # Required for CLOUD assets
                            'providerAccountId': account_id,  # Required for CLOUD assets
                            'region': region,  # Required for CLOUD assets
                            'origin': f'prowler-{provider}'
                        },
                        'tags': [
                            {'key': 'cloud_provider', 'value': provider},
                            {'key': 'account_id', 'value': account_id},
                            {'key': 'region', 'value': region}
                        ],
                        'findings': []
                    }
                
                vuln = self._parse_finding(finding, None, account_id, region)
                if vuln:
                    assets_dict[asset_key]['findings'].append(vuln)
            else:
                # Create asset per resource
                for resource in resources:
                    resource_uid = resource.get('uid', resource.get('name', 'unknown'))
                    resource_name = resource.get('name', resource_uid)
                    resource_type = resource.get('type', 'Unknown')
                    
                    asset_key = resource_uid
                    
                    if asset_key not in assets_dict:
                        # Determine asset type based on resource type
                        asset_type = self._map_resource_type_to_asset_type(resource_type)
                        
                        assets_dict[asset_key] = {
                            'asset_type': asset_type,
                            'attributes': self._create_asset_attributes(resource, provider, account_id, region),
                            'tags': [
                                {'key': 'cloud_provider', 'value': provider},
                                {'key': 'account_id', 'value': account_id},
                                {'key': 'region', 'value': region},
                                {'key': 'resource_type', 'value': resource_type}
                            ],
                            'findings': []
                        }
                    
                    vuln = self._parse_finding(finding, resource, account_id, region)
                    if vuln:
                        assets_dict[asset_key]['findings'].append(vuln)
        
        # Convert to AssetData objects
        assets = []
        for asset_key, asset_info in assets_dict.items():
            # Get tags safely (handle both TagConfig object and dict)
            base_tags = []
            if self.tag_config:
                if hasattr(self.tag_config, 'get_all_tags'):
                    base_tags = self.tag_config.get_all_tags()
                elif isinstance(self.tag_config, dict):
                    base_tags = self.tag_config.get('tags', [])
            
            asset = AssetData(
                asset_type=asset_info['asset_type'],
                attributes=asset_info['attributes'],
                tags=base_tags + asset_info['tags']
            )
            asset.findings.extend(asset_info['findings'])
            assets.append(self.ensure_asset_has_findings(asset))
        
        logger.info(f"Created {len(assets)} assets with {sum(len(a.findings) for a in assets)} findings")
        return assets
    
    def _map_resource_type_to_asset_type(self, resource_type: str) -> str:
        """Map AWS/cloud resource type to Phoenix asset type"""
        resource_type_lower = resource_type.lower()
        
        # Container/Kubernetes resources
        if any(x in resource_type_lower for x in ['container', 'ecs', 'eks', 'kubernetes', 'pod']):
            return 'CONTAINER'
        
        # Web/application resources
        if any(x in resource_type_lower for x in ['lambda', 'apigateway', 'cloudfront', 'elb', 'alb']):
            return 'WEB'
        
        # Default: Cloud resources (changed from INFRA to CLOUD for Prowler)
        return 'CLOUD'
    
    def _create_asset_attributes(self, resource: Dict, provider: str, account_id: str, region: str) -> Dict:
        """Create asset attributes from resource info"""
        resource_name = resource.get('name', 'unknown')
        resource_uid = resource.get('uid', resource_name)
        resource_type = resource.get('type', 'Unknown')
        
        # Extract additional metadata if available
        data = resource.get('data', {})
        metadata = data.get('metadata', {})
        
        # Create CLOUD asset attributes (Phoenix API requirement)
        # Map provider string to Phoenix format
        provider_type_map = {
            'aws': 'AWS',
            'azure': 'AZURE',
            'gcp': 'GCP',
            'google': 'GCP'
        }
        provider_type = provider_type_map.get(provider.lower(), 'AWS')
        
        attributes = {
            'providerType': provider_type,  # Required for CLOUD assets
            'providerAccountId': account_id,  # Required for CLOUD assets
            'region': region,  # Required for CLOUD assets
            'origin': f'prowler-{provider}'
        }
        
        # Add resource name/uid as additional fields
        if resource_name and resource_name != 'unknown':
            attributes['resourceName'] = resource_name
        
        # Add ARN if available (AWS specific)
        if 'arn:' in resource_uid:
            attributes['cloud_resource_id'] = resource_uid
        
        # Add resource type
        if resource_type and resource_type != 'Unknown':
            attributes['resourceType'] = resource_type
        
        # Add resource-specific attributes
        if metadata:
            # Extract useful metadata fields
            for key in ['state', 'status', 'tags']:
                if key in metadata:
                    attributes[f'resource_{key}'] = str(metadata[key])
        
        return attributes
    
    def _parse_finding(self, finding: Dict, resource: Optional[Dict], account_id: str, region: str) -> Optional[Dict]:
        """Parse a single Prowler finding into vulnerability format"""
        
        finding_info = finding.get('finding_info', {})
        finding_uid = finding_info.get('uid', 'UNKNOWN')
        
        if not finding_uid or finding_uid == 'UNKNOWN':
            return None
        
        # Extract finding details
        title = finding_info.get('title', finding.get('message', 'Security Finding'))
        description = finding_info.get('desc', finding.get('status_detail', title))
        
        # Get severity
        severity_str = finding.get('severity', 'Unknown')
        severity_id = finding.get('severity_id', 3)
        
        # Map OCSF severity_id to Phoenix severity (1-5)
        # OCSF: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical
        severity_num = min(severity_id, 5)
        
        # Get status
        status_code = finding.get('status_code', 'UNKNOWN')
        
        # Only import FAILed findings (not PASS, not INFO)
        if status_code not in ['FAIL', 'FAILED']:
            return None
        
        # Get remediation
        remediation_info = finding.get('remediation', {})
        remedy = remediation_info.get('desc', 'See Prowler documentation for remediation')
        references = remediation_info.get('references', [])
        
        # Get compliance mappings
        unmapped = finding.get('unmapped', {})
        compliance = unmapped.get('compliance', {})
        categories = unmapped.get('categories', [])
        
        # Get metadata
        metadata = finding.get('metadata', {})
        event_code = metadata.get('event_code', finding_uid.split('-')[-1] if '-' in finding_uid else 'check')
        
        # Create location
        resource_name = resource.get('name', account_id) if resource else account_id
        location = f"{region}/{resource_name}"
        
        # Get timestamp
        finding_time = finding.get('time', finding.get('event_time', ''))
        if isinstance(finding_time, int):
            # Unix timestamp
            try:
                finding_time = datetime.fromtimestamp(finding_time).isoformat()
            except:
                finding_time = datetime.now().isoformat()
        elif not finding_time:
            finding_time = datetime.now().isoformat()
        
        # Create vulnerability
        vulnerability = VulnerabilityData(
            name=event_code,
            description=description[:500],
            remedy=remedy[:500],
            severity=severity_num,
            location=location,
            reference_ids=[finding_uid],
            details={
                'title': title,
                'status_code': status_code,
                'severity_name': severity_str,
                'event_code': event_code,
                'finding_uid': finding_uid,
                'compliance': compliance,
                'categories': categories if isinstance(categories, list) else [categories],
                'references': references[:5] if references else [],
                'risk_details': finding.get('risk_details', ''),
                'found_at': finding_time,
                'cloud_provider': finding.get('cloud', {}).get('provider', 'aws'),
                'account_id': account_id,
                'region': region
            }
        )
        
        return vulnerability.__dict__


class AWSProwlerV4Translator(AWSProwlerV3Translator):
    """Translator for AWS Prowler v4.x and v5.x with OCSF 1.5.0 format
    
    Format: JSON array of OCSF findings with metadata, resources, cloud info
    
    ✅ FULLY SUPPORTED VERSIONS:
    - Prowler v4.x (OCSF 1.3.0+) ✅
    - Prowler v5.x (OCSF 1.5.0+) ✅
    
    Note: Prowler v5 uses the same OCSF format as v4, so this translator
    handles both versions. Scanner type 'aws_prowler_v5' is aliased to use
    this translator.
    
    Inherits from v3 translator as the format is similar, with enhanced features.
    
    Example structure:
    [{
        "metadata": {"product": {"name": "Prowler", "version": "5.10.0"}},
        "severity": "High",
        "status_code": "FAIL",
        "finding_info": {...},
        "resources": [{...}],
        "cloud": {"account": {...}, "region": "..."},
        "remediation": {...}
    }]
    """
    
    def can_handle(self, file_path: str, file_content: Any = None) -> bool:
        """Detect Prowler v4/v5 OCSF format"""
        if not file_path.lower().endswith('.json'):
            return False
        
        try:
            if file_content is None:
                with open(file_path, 'r') as f:
                    file_content = json.load(f)
            
            # OCSF format is an array of findings
            if isinstance(file_content, list) and len(file_content) > 0:
                first_item = file_content[0]
                
                # Check for Prowler OCSF specific structure
                if isinstance(first_item, dict):
                    metadata = first_item.get('metadata', {})
                    product = metadata.get('product', {})
                    
                    # Must have Prowler product name
                    if product.get('name') == 'Prowler':
                        # OCSF specific fields
                        if 'finding_info' in first_item and 'resources' in first_item:
                            if 'cloud' in first_item:
                                # Check version - v4.x or v5.x preferred, but accept any
                                version = product.get('version', '')
                                if version.startswith('4.') or version.startswith('5.') or not version:
                                    return True
            
            return False
        except Exception as e:
            logger.debug(f"AWSProwlerV4Translator.can_handle error: {e}")
            return False
    
    def parse_file(self, file_path: str) -> List[AssetData]:
        """Parse Prowler v4/v5 OCSF scan results (uses v3 parser)
        
        Note: This method handles both Prowler v4.x and v5.x as they use
        the same OCSF format structure. The parser is inherited from the
        v3 translator as the OCSF format is consistent across versions.
        """
        logger.info(f"Parsing Prowler v4/v5 OCSF file: {file_path}")
        # Use parent class implementation as formats are compatible
        return super().parse_file(file_path)


# Backward compatibility and version aliases
ProwlerOCSFTranslator = AWSProwlerV3Translator  # Legacy alias
AWSProwlerV5Translator = AWSProwlerV4Translator  # V5 uses V4 translator


# Export all translators
__all__ = [
    'AWSProwlerV3Translator',
    'AWSProwlerV4Translator',
    'AWSProwlerV5Translator',  # Alias to V4
    'ProwlerOCSFTranslator'     # Backward compatibility
]

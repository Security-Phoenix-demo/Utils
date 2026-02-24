#!/usr/bin/env python3
"""
CSV Vulnerability Translator
Converts vulnerability export CSV/JSON to Phoenix Security import formats.
Supports: infra, cloud, web, and software asset types.
Supports: CSV exports and Prowler OCSF JSON format.
"""

import csv
import json
import argparse
import os
from datetime import datetime
from typing import Dict, List, Optional, Any

# Format configurations
FORMAT_CONFIGS = {
    'infra': {
        'template': 'template/import_infra_assets_vulnerabilities_template (4).csv',
        'headers': ['a_id', 'a_subtype', 'at_ip', 'at_network', 'at_hostname', 'at_netbios', 
                   'at_os', 'at_mac', 'at_fqdn', 'a_tags', 'v_name', 'v_description', 'v_remedy', 
                   'v_severity', 'v_cve', 'v_cwe', 'v_published_datetime', 'v_tags', 'v_details']
    },
    'cloud': {
        'template': 'template/import_cloud_assets_vulnerabilities_template (1).csv',
        'headers': ['a_id', 'a_subtype', 'at_provider_type', 'at_provider_resource_id', 'at_vpc', 
                   'at_subnet', 'at_region', 'at_resource_group', 'at_provider_asset_id', 'a_tags', 
                   'v_name', 'v_description', 'v_remedy', 'v_severity', 'v_cve', 'v_cwe', 
                   'v_published_datetime', 'v_tags', 'v_details']
    },
    'web': {
        'template': 'template/import_web_assets_vulnerabilities_template (1).csv',
        'headers': ['a_id', 'a_subtype', 'at_ip', 'at_fqdn', 'a_tags', 'v_name', 'v_description', 
                   'v_remedy', 'v_severity', 'v_location', 'v_cve', 'v_cwe', 'v_published_datetime', 
                   'v_tags', 'v_details']
    },
    'software': {
        'template': 'template/software_import_common_assets_vulnerabilities_template (2).csv',
        'headers': ['a_id', 'a_subtype', 'a_resource_type', 'at_origin', 'at_repository', 'at_build', 
                   'at_dockerfile', 'at_scanner_source', 'at_image_digest', 'at_image_name', 'at_registry', 
                   'a_tags', 'v_name', 'v_description', 'v_remedy', 'v_severity', 'v_location', 'v_cve', 
                   'v_cwe', 'v_published_datetime', 'v_tags', 'v_details']
    }
}


class CSVConverter:
    """Converts vulnerability CSV exports to Phoenix Security import formats."""
    
    # Maximum file size in bytes (5 MB)
    MAX_FILE_SIZE = 5 * 1024 * 1024
    
    def __init__(self, source_file: str, output_format: str, output_file: Optional[str] = None, scanner_name: str = None):
        """
        Initialize the converter.
        
        Args:
            source_file: Path to source CSV file
            output_format: Target format (infra, cloud, web, software)
            output_file: Optional output file path (defaults to auto-generated)
            scanner_name: Optional scanner name (defaults to 'vulnerability_scanner' or 'prowler')
        """
        self.source_file = source_file
        self.output_format = output_format.lower()
        self.scanner_name = scanner_name  # Store custom scanner name
        
        if self.output_format not in FORMAT_CONFIGS:
            raise ValueError(f"Invalid format: {output_format}. Must be one of: {', '.join(FORMAT_CONFIGS.keys())}")
        
        self.config = FORMAT_CONFIGS[self.output_format]
        
        # Generate output filename if not provided
        if output_file:
            self.output_file = output_file
        else:
            base_name = os.path.splitext(os.path.basename(source_file))[0]
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            self.output_file = f"results/{base_name}_{output_format}_{timestamp}.csv"
    
    @staticmethod
    def parse_date(date_str: str) -> str:
        """
        Parse various date formats and convert to DD-MM-YYYY HH:MM:SS format.
        
        Args:
            date_str: Date string in various formats
            
        Returns:
            Formatted date string
        """
        if not date_str or date_str.strip() == '':
            return datetime.now().strftime('%d-%m-%Y %H:%M:%S')
        
        # Common date formats to try
        formats = [
            '%m/%d/%y',      # 2/19/24
            '%m/%d/%Y',      # 2/19/2024
            '%Y-%m-%d',      # 2024-02-19
            '%d-%m-%Y',      # 19-02-2024
            '%m-%d-%Y',      # 02-19-2024
            '%Y/%m/%d',      # 2024/02/19
            '%d/%m/%Y',      # 19/02/2024
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(date_str.strip(), fmt)
                return dt.strftime('%d-%m-%Y %H:%M:%S')
            except ValueError:
                continue
        
        # If no format matches, return current datetime
        print(f"Warning: Could not parse date '{date_str}', using current datetime")
        return datetime.now().strftime('%d-%m-%Y %H:%M:%S')
    
    @staticmethod
    def format_tags(tags: List[Dict[str, str]]) -> str:
        """
        Format tags as JSON array of objects with key-value pairs.
        
        Args:
            tags: List of tag dictionaries (each dict should have single key-value pair)
            
        Returns:
            JSON formatted string
        """
        if not tags:
            return '[]'
        
        # Tags are already in the correct format as list of dicts
        # Each dict in the list should already have "key" and "value" keys
        return json.dumps(tags)
    
    @staticmethod
    def extract_cve(title: str) -> Optional[str]:
        """
        Extract CVE identifier from vulnerability title.
        
        Args:
            title: Vulnerability title
            
        Returns:
            CVE identifier or None
        """
        import re
        cve_match = re.search(r'CVE-\d{4}-\d+', title, re.IGNORECASE)
        return cve_match.group(0) if cve_match else None
    
    @staticmethod
    def map_severity(severity_str: str, cvss_v3: str = '', risk: str = '') -> int:
        """
        Map severity string to Phoenix Security severity scale (1-10).
        
        Args:
            severity_str: Severity string (Critical, Severe, Moderate, etc.)
            cvss_v3: CVSS v3 score
            risk: Risk score
            
        Returns:
            Severity value (1-10)
        """
        severity_map = {
            'critical': 10,
            'severe': 8,
            'high': 7,
            'moderate': 5,
            'medium': 5,
            'low': 3,
            'info': 1,
            'informational': 1
        }
        
        # Try to map by severity string
        severity_lower = severity_str.lower().strip()
        if severity_lower in severity_map:
            return severity_map[severity_lower]
        
        # Try to use CVSS v3 score
        try:
            cvss = float(cvss_v3)
            if cvss >= 9.0:
                return 10
            elif cvss >= 7.0:
                return 8
            elif cvss >= 4.0:
                return 5
            else:
                return 3
        except (ValueError, TypeError):
            pass
        
        # Default to moderate
        return 5
    
    def convert_row(self, source_row: Dict[str, str], row_number: int = 0) -> Dict[str, str]:
        """
        Convert a source row to target format.
        
        Args:
            source_row: Source CSV row as dictionary
            row_number: Row number for generating unique identifiers
            
        Returns:
            Converted row as dictionary
        """
        # Initialize output row with empty values
        output_row = {header: '' for header in self.config['headers']}
        
        # Extract CVE from title
        cve = self.extract_cve(source_row.get('Title', ''))
        full_title = source_row.get('Title', '')
        
        # Map common fields - v_name is just CVE, v_description is full title
        output_row['v_name'] = cve if cve else full_title[:100]  # Just CVE or truncated title
        output_row['v_description'] = full_title  # Full description/title
        output_row['v_remedy'] = 'Please refer to vendor security advisory for remediation steps.'
        output_row['v_severity'] = str(self.map_severity(
            source_row.get('Severity', ''),
            source_row.get('CVSSv3', ''),
            source_row.get('Risk', '')
        ))
        output_row['v_cve'] = cve if cve else ''
        output_row['v_published_datetime'] = self.parse_date(source_row.get('Published On', ''))
        
        # Format vulnerability tags as key-value pairs
        v_tags = []
        if source_row.get('Severity'):
            v_tags.append({"key": "severity", "value": source_row['Severity']})
        if source_row.get('CVSSv3'):
            v_tags.append({"key": "cvss_v3", "value": source_row['CVSSv3']})
        
        # Add scanner name and import info to vulnerability tags
        scanner = self.scanner_name if self.scanner_name else "vulnerability_scanner"
        v_tags.append({"key": "scanner_name", "value": scanner})
        v_tags.append({"key": "import_type", "value": "imported"})
        v_tags.append({"key": "import_date", "value": datetime.now().strftime('%Y-%m-%d')})
        
        output_row['v_tags'] = self.format_tags(v_tags) if v_tags else ''
        
        # Build v_details with additional metadata
        details = {}
        if source_row.get('CVSSv2'):
            details['cvss_v2'] = source_row['CVSSv2']
        if source_row.get('CVSSv3'):
            details['cvss_v3'] = source_row['CVSSv3']
        if source_row.get('Risk'):
            details['risk_score'] = source_row['Risk']
        if source_row.get('Instances'):
            details['instances'] = source_row['Instances']
        if source_row.get('Exploits'):
            details['exploits'] = source_row['Exploits']
        if source_row.get('Malware'):
            details['malware'] = source_row['Malware']
        if source_row.get('Modified On'):
            details['modified_on'] = source_row['Modified On']
        
        output_row['v_details'] = json.dumps(details) if details else ''
        
        # Format-specific fields
        if self.output_format == 'infra':
            # Generate unique hostname if not provided
            # Phoenix Security requires at least one of: at_ip, at_hostname, or at_fqdn
            # Use row number to create unique asset identifiers
            output_row['at_hostname'] = f'imported-infra-asset-{row_number:04d}'
            output_row['at_network'] = 'imported-network'
            
        elif self.output_format == 'cloud':
            # Leave cloud-specific fields empty
            pass
            
        elif self.output_format == 'web':
            # Leave web-specific fields empty
            output_row['v_location'] = '/'
            
        elif self.output_format == 'software':
            # Leave software-specific fields empty
            pass
        
        # Set default asset tags
        scanner = self.scanner_name if self.scanner_name else "vulnerability_scanner"
        a_tags = [
            {"key": "scanner_name", "value": scanner},
            {"key": "import_type", "value": "imported"},
            {"key": "import_date", "value": datetime.now().strftime('%Y-%m-%d')}
        ]
        output_row['a_tags'] = self.format_tags(a_tags)
        
        return output_row
    
    def convert_prowler_json_to_cloud(self, finding: Dict[str, Any]) -> Dict[str, str]:
        """
        Convert Prowler OCSF JSON finding to cloud format.
        
        Args:
            finding: Prowler OCSF finding dictionary
            
        Returns:
            Converted row as dictionary
        """
        # Initialize output row with empty values
        output_row = {header: '' for header in self.config['headers']}
        
        try:
            # Extract basic finding information
            message = finding.get('message', '')
            title = finding.get('finding_info', {}).get('title', message)
            event_code = finding.get('metadata', {}).get('event_code', '')
            
            # Map vulnerability fields - v_name is short identifier, v_description is full title
            output_row['v_name'] = event_code if event_code else title[:100]  # Check name or short title
            output_row['v_description'] = title  # Full description/title
            
            # Remediation
            remediation = finding.get('remediation', {})
            output_row['v_remedy'] = remediation.get('desc', 'Please refer to cloud provider documentation.')
            
            # Severity mapping
            severity = finding.get('severity', '')
            severity_id = finding.get('severity_id', 0)
            
            # Map Prowler severity to 1-10 scale
            severity_map = {
                'Critical': 10,
                'High': 8,
                'Medium': 5,
                'Low': 3,
                'Informational': 1,
                'Info': 1
            }
            output_row['v_severity'] = str(severity_map.get(severity, 5))
            
            # Published datetime
            created_time_dt = finding.get('finding_info', {}).get('created_time_dt', '')
            if created_time_dt:
                try:
                    # Parse ISO format datetime
                    dt = datetime.fromisoformat(created_time_dt.replace('Z', '+00:00'))
                    output_row['v_published_datetime'] = dt.strftime('%d-%m-%Y %H:%M:%S')
                except:
                    output_row['v_published_datetime'] = self.parse_date(created_time_dt)
            else:
                output_row['v_published_datetime'] = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
            
            # Cloud asset information
            cloud = finding.get('cloud', {})
            provider = cloud.get('provider', '').upper()
            if provider == 'AWS':
                output_row['at_provider_type'] = 'AWS'
            elif provider == 'AZURE':
                output_row['at_provider_type'] = 'AZURE'
            elif provider == 'GCP':
                output_row['at_provider_type'] = 'GCP'
            else:
                output_row['at_provider_type'] = provider.upper() if provider else ''
            
            output_row['at_region'] = cloud.get('region', '')
            
            # Resource information
            resources = finding.get('resources', [])
            if resources and len(resources) > 0:
                resource = resources[0]
                output_row['at_provider_resource_id'] = resource.get('uid', '')
                output_row['at_provider_asset_id'] = resource.get('uid', '')
                
                # Extract VPC/Subnet from resource metadata if available
                resource_data = resource.get('data', {}).get('metadata', {})
                if 'vpc_id' in resource_data:
                    output_row['at_vpc'] = resource_data.get('vpc_id', '')
                if 'subnet_id' in resource_data:
                    output_row['at_subnet'] = resource_data.get('subnet_id', '')
            
            # Account information
            account = cloud.get('account', {})
            account_uid = account.get('uid', '')
            
            # Build asset tags
            a_tags = [
                {"key": "scanner_name", "value": "prowler"},
                {"key": "import_type", "value": "imported"},
                {"key": "import_date", "value": datetime.now().strftime('%Y-%m-%d')},
                {"key": "account_id", "value": account_uid}
            ]
            
            # Add resource tags if available
            if resources and len(resources) > 0:
                resource_labels = resources[0].get('labels', [])
                for label in resource_labels[:5]:  # Limit to 5 labels
                    if ':' in label:
                        key, value = label.split(':', 1)
                        a_tags.append({"key": key, "value": value})
            
            output_row['a_tags'] = self.format_tags(a_tags)
            
            # Build vulnerability tags
            v_tags = [
                {"key": "severity", "value": severity},
                {"key": "status", "value": finding.get('status_code', '')},
                {"key": "check", "value": finding.get('metadata', {}).get('event_code', '')},
                {"key": "scanner_name", "value": "prowler"},
                {"key": "import_type", "value": "imported"},
                {"key": "import_date", "value": datetime.now().strftime('%Y-%m-%d')}
            ]
            output_row['v_tags'] = self.format_tags(v_tags)
            
            # Build v_details with additional metadata
            details = {
                "finding_uid": finding.get('finding_info', {}).get('uid', ''),
                "status": finding.get('status', ''),
                "status_code": finding.get('status_code', ''),
                "risk_details": finding.get('risk_details', ''),
                "event_code": finding.get('metadata', {}).get('event_code', ''),
                "category": finding.get('category_name', ''),
                "class": finding.get('class_name', ''),
            }
            
            # Add compliance information
            compliance = finding.get('unmapped', {}).get('compliance', {})
            if compliance:
                details['compliance'] = compliance
            
            # Add related URL
            related_url = finding.get('unmapped', {}).get('related_url', '')
            if related_url:
                details['related_url'] = related_url
            
            # Add remediation references
            references = remediation.get('references', [])
            if references:
                details['remediation_references'] = references
            
            # Add categories
            categories = finding.get('unmapped', {}).get('categories', [])
            if categories:
                details['categories'] = categories
            
            output_row['v_details'] = json.dumps(details)
            
        except Exception as e:
            print(f"Warning: Error processing finding: {e}")
            # Return partially filled row
        
        return output_row
    
    def is_json_file(self) -> bool:
        """Check if source file is JSON based on extension."""
        return self.source_file.lower().endswith('.json')
    
    def load_json_findings(self) -> List[Dict[str, Any]]:
        """
        Load findings from Prowler OCSF JSON file.
        
        Returns:
            List of finding dictionaries
        """
        findings = []
        
        try:
            with open(self.source_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                
                # Handle array of objects or newline-delimited JSON
                if content.startswith('['):
                    # JSON array
                    findings = json.loads(content)
                else:
                    # Newline-delimited JSON (one object per line)
                    # Also handle files that start with comma or brace
                    lines = content.split('\n')
                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue
                        # Remove leading comma if present
                        if line.startswith(',{'):
                            line = line[1:]
                        elif line.startswith('},'):
                            line = line[:-1]
                        
                        if line.startswith('{') and line.endswith('}'):
                            try:
                                finding = json.loads(line)
                                findings.append(finding)
                            except json.JSONDecodeError as e:
                                print(f"Warning: Skipping invalid JSON line: {e}")
                                continue
                        
        except Exception as e:
            print(f"Error loading JSON file: {e}")
            raise
        
        return findings
    
    def get_part_filename(self, part_number: int) -> str:
        """
        Generate filename for a file part.
        
        Args:
            part_number: Part number (1-based)
            
        Returns:
            Filename with part number
        """
        if part_number == 1:
            return self.output_file
        
        # Insert part number before extension
        base, ext = os.path.splitext(self.output_file)
        return f"{base}_part{part_number}{ext}"
    
    def write_csv_with_split(self, rows_generator, total_hint: int = 0):
        """
        Write CSV rows to file(s), splitting if necessary to keep files under 5 MB.
        
        Args:
            rows_generator: Generator or iterable yielding converted rows
            total_hint: Hint about total number of rows (for progress)
            
        Returns:
            List of created filenames
        """
        created_files = []
        part_number = 1
        current_file = None
        current_writer = None
        rows_in_current_file = 0
        total_rows = 0
        
        try:
            for row in rows_generator:
                # Check if we need to start a new file
                if current_file is None:
                    # Start first file or new part
                    filename = self.get_part_filename(part_number)
                    current_file = open(filename, 'w', newline='', encoding='utf-8')
                    current_writer = csv.DictWriter(current_file, fieldnames=self.config['headers'])
                    current_writer.writeheader()
                    created_files.append(filename)
                    rows_in_current_file = 0
                    
                    if part_number > 1:
                        print(f"  → Starting part {part_number}: {os.path.basename(filename)}")
                
                # Write the row
                current_writer.writerow(row)
                rows_in_current_file += 1
                total_rows += 1
                
                # Progress indicator for large files
                if total_rows % 100 == 0 and total_hint > 1000:
                    print(f"  Processed {total_rows} findings...")
                
                # Check if current file exceeds size limit
                current_size = current_file.tell()
                if current_size >= self.MAX_FILE_SIZE:
                    print(f"  Part {part_number} complete: {rows_in_current_file} rows, {current_size / (1024*1024):.2f} MB")
                    current_file.close()
                    current_file = None
                    current_writer = None
                    part_number += 1
            
            # Close final file if open
            if current_file:
                current_size = current_file.tell()
                print(f"  Part {part_number} complete: {rows_in_current_file} rows, {current_size / (1024*1024):.2f} MB")
                current_file.close()
        
        except Exception as e:
            if current_file:
                current_file.close()
            raise e
        
        return created_files, total_rows
    
    def convert(self):
        """Execute the conversion process."""
        # Ensure results directory exists
        os.makedirs(os.path.dirname(self.output_file) if os.path.dirname(self.output_file) else 'results', exist_ok=True)
        
        # Check if input is JSON or CSV
        is_json = self.is_json_file()
        
        print(f"Converting {self.source_file} to {self.output_format} format...")
        print(f"Input format: {'JSON (Prowler OCSF)' if is_json else 'CSV'}")
        print(f"Output will be saved to: {self.output_file}")
        print(f"Files will be split at 5 MB maximum")
        
        skipped_count = 0
        
        # Generator function for rows
        def row_generator():
            nonlocal skipped_count
            
            if is_json:
                # Handle JSON input (Prowler OCSF format)
                if self.output_format != 'cloud':
                    print(f"Warning: JSON input currently only supports 'cloud' format. Using cloud format.")
                
                findings = self.load_json_findings()
                print(f"Loaded {len(findings)} findings from JSON file")
                
                for finding in findings:
                    try:
                        # Only convert FAIL findings (skip PASS findings)
                        status_code = finding.get('status_code', '')
                        if status_code != 'FAIL':
                            skipped_count += 1
                            continue
                        
                        converted_row = self.convert_prowler_json_to_cloud(finding)
                        yield converted_row
                            
                    except Exception as e:
                        print(f"Error converting finding: {e}")
                        skipped_count += 1
                        continue
            else:
                # Handle CSV input
                with open(self.source_file, 'r', encoding='utf-8') as infile:
                    reader = csv.DictReader(infile)
                    
                    for row_num, row in enumerate(reader, start=1):
                        try:
                            converted_row = self.convert_row(row, row_num)
                            yield converted_row
                        except Exception as e:
                            print(f"Error converting row: {e}")
                            print(f"Row data: {row}")
                            skipped_count += 1
                            continue
        
        # Use the split writer
        total_hint = 0
        if is_json:
            # For JSON, we know the total after loading
            try:
                with open(self.source_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                    total_hint = content.count('"status_code"')
            except:
                pass
        
        created_files, converted_count = self.write_csv_with_split(row_generator(), total_hint)
        
        print(f"\n✓ Conversion complete!")
        print(f"  - Converted {converted_count} vulnerabilities")
        if skipped_count > 0:
            print(f"  - Skipped {skipped_count} items (non-FAIL status or errors)")
        
        if len(created_files) == 1:
            print(f"  - Output file: {created_files[0]}")
            file_size = os.path.getsize(created_files[0]) / (1024 * 1024)
            print(f"  - File size: {file_size:.2f} MB")
        else:
            print(f"  - Output split into {len(created_files)} files:")
            for i, filename in enumerate(created_files, 1):
                file_size = os.path.getsize(filename) / (1024 * 1024)
                print(f"    {i}. {os.path.basename(filename)} ({file_size:.2f} MB)")
        
        print(f"\nNote: Asset identification fields are empty. Please fill them before importing.")


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Convert vulnerability CSV/JSON exports to Phoenix Security import formats',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Convert CSV to infrastructure format
  python csv_converter.py source/VulnerabilityListingExport.csv --format infra
  
  # Convert CSV to cloud format with custom output
  python csv_converter.py source/VulnerabilityListingExport.csv --format cloud --output my_vulns.csv
  
  # Convert Prowler JSON to cloud format
  python csv_converter.py source/prowler-output.ocsf.json --format cloud
  
  # Convert to web format
  python csv_converter.py source/VulnerabilityListingExport.csv --format web
  
  # Convert to software format
  python csv_converter.py source/VulnerabilityListingExport.csv --format software

Supported input formats:
  - CSV:  Generic vulnerability export CSV
  - JSON: Prowler OCSF format (automatically detected, outputs to cloud format)

Supported output formats:
  - infra:    Infrastructure assets (IP, hostname, OS, etc.)
  - cloud:    Cloud assets (AWS, Azure, GCP resources)
  - web:      Web assets (websites, web applications)
  - software: Software assets (repositories, code, containers)
        """
    )
    
    parser.add_argument('source_file', help='Path to source CSV or JSON file')
    parser.add_argument('-f', '--format', required=True, choices=['infra', 'cloud', 'web', 'software'],
                       help='Target format for conversion')
    parser.add_argument('-o', '--output', help='Output file path (optional, auto-generated if not provided)')
    parser.add_argument('-s', '--scanner', help='Scanner name (e.g., rapid7, tenable, qualys)')
    
    args = parser.parse_args()
    
    # Check if source file exists
    if not os.path.exists(args.source_file):
        print(f"Error: Source file '{args.source_file}' not found!")
        return 1
    
    try:
        converter = CSVConverter(args.source_file, args.format, args.output, args.scanner)
        converter.convert()
        return 0
    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == '__main__':
    exit(main())


# Quick Start Guide

## 📁 Directory Setup

**Before you start**, understand the directory structure:

```
csv_translator/
├── source/          ← PUT YOUR INPUT FILES HERE
├── results/         ← OUTPUT FILES SAVED HERE AUTOMATICALLY
├── template/        ← Templates (reference only)
└── csv_converter.py
```

### Step 1: Place Your File
```bash
# Copy your source file to the source/ directory
cp your-vulnerability-file.csv source/
# OR for JSON
cp prowler-output.json source/
```

### Step 2: Run Conversion
The script will automatically read from `source/` and save to `results/`

---

## Simple Usage

### Option 1: Using the Bash Script (Recommended)

```bash
# Convert CSV to infrastructure format
./convert.sh --format infra

# Convert CSV to cloud format
./convert.sh --format cloud

# Convert CSV to web format
./convert.sh --format web

# Convert CSV to software format
./convert.sh --format software

# Use a custom source file (CSV or JSON)
./convert.sh --format infra --source my_vulnerabilities.csv
./convert.sh --format cloud --source prowler-output.json

# Specify custom output file
./convert.sh --format cloud --output my_output.csv
```

### Option 2: Using Python Directly

```bash
# Convert CSV to infrastructure format
python3 csv_converter.py source/VulnerabilityListingExport.csv --format infra

# Convert CSV to cloud format
python3 csv_converter.py source/VulnerabilityListingExport.csv --format cloud

# Convert Prowler JSON to cloud format
python3 csv_converter.py source/prowler-output.ocsf.json --format cloud

# Convert to web format
python3 csv_converter.py source/VulnerabilityListingExport.csv --format web

# Convert to software format
python3 csv_converter.py source/VulnerabilityListingExport.csv --format software
```

## JSON Support (Prowler OCSF Format)

**NEW**: The tool now supports Prowler OCSF JSON format as input!

```bash
# Convert Prowler JSON to cloud format
python3 csv_converter.py source/prowler-output.ocsf.json --format cloud

# Or using the bash wrapper
./convert.sh --format cloud --source prowler-output.json
```

### Prowler JSON Features
- ✅ Automatically detects JSON input (by `.json` extension)
- ✅ Converts to Cloud format (AWS, Azure, GCP resources)
- ✅ Extracts resource ARN/IDs automatically
- ✅ Maps severity levels (Critical/High/Medium/Low)
- ✅ Includes compliance frameworks in v_details
- ✅ Skips PASS findings (only converts FAIL findings)
- ✅ Preserves remediation steps and references
- ✅ Handles large files efficiently (progress indicators)

### Prowler JSON Field Mapping
| Prowler Field | Maps To | Notes |
|--------------|---------|-------|
| `finding_info.title` | `v_name` | Vulnerability name |
| `finding_info.desc` | `v_description` | Full description |
| `severity` | `v_severity` | Mapped to 1-10 scale |
| `cloud.provider` | `at_provider_type` | AWS/AZURE/GCP |
| `cloud.region` | `at_region` | Cloud region |
| `resources[0].uid` | `at_provider_resource_id` | Resource ARN/ID |
| `remediation.desc` | `v_remedy` | Remediation steps |
| `unmapped.compliance` | `v_details` | Compliance frameworks |
| `status_code` | Filter | Only FAIL findings converted |

## Output

The converted file will be **automatically saved** in the `results/` directory with a timestamp:
- `results/VulnerabilityListingExport_infra_20251111_163434.csv`
- `results/VulnerabilityListingExport_cloud_20251111_163434.csv`
- `results/prowler-output_cloud_20251111_163434.csv`
- etc.

**You don't need to specify the output path** - it's handled automatically!

## Important Notes

### 1. Comment Lines Removed
The script automatically removes the comment and example lines (lines 2-7) from the templates. The output will only contain:
- Header row
- Data rows

### 2. Date Format
All dates are converted to the required format: `DD-MM-YYYY HH:MM:SS`
- Example: `19-02-2024 00:00:00`

### 3. Tag Format
Tags are formatted as JSON arrays with key-value pairs:
```json
[
  {"key": "severity", "value": "Critical"},
  {"key": "cvss_v3", "value": "8.1"}
]
```

### 4. Asset Fields
The converted CSV will have **empty asset identification fields**. You MUST fill these before importing:

#### For Infrastructure:
- `at_ip`: IP address (e.g., `192.168.1.100`)
- `at_hostname`: Hostname (e.g., `web-server-01`)
- `at_os`: Operating System (e.g., `Ubuntu 22.04`)
- etc.

#### For Cloud:
- `at_provider_type`: `AWS`, `AZURE`, or `GCP`
- `at_provider_resource_id`: ARN or Resource ID
- `at_region`: Cloud region (e.g., `us-east-1`, `eastus`)
- etc.

#### For Web:
- `at_ip`: IP address OR
- `at_fqdn`: Fully qualified domain name
- `v_location`: URL path (e.g., `/api/endpoint`)

#### For Software:
- `at_repository`: Repository name
- `at_origin`: Origin (github, gitlab, etc.)
- `v_location`: File path (e.g., `src/main/App.java`)
- etc.

## Complete Workflow

1. **Place your source file**
   ```bash
   cp your-vulnerability-export.csv source/
   ```

2. **Convert the file**
   ```bash
   ./convert.sh --format infra
   # Script reads from source/ and saves to results/
   ```

3. **Open the generated file**
   - Navigate to `results/` directory
   - Open the CSV file with a spreadsheet application or text editor
   ```bash
   ls -lh results/
   # Open the most recent file
   ```

3. **Fill asset fields**
   - For each vulnerability row, fill in the asset identification fields
   - You can use the same asset information for multiple vulnerabilities on the same asset

4. **Review**
   - Check severity values (1-10 scale)
   - Verify dates are correct
   - Confirm tags are properly formatted

5. **Import**
   - Import the completed CSV into Phoenix Security

## Field Mapping Reference

### Source (Input) → Target (Output)

| Source Field    | Maps To                      | Notes                              |
|----------------|------------------------------|------------------------------------|
| Title          | v_name, v_description        | Also used to extract CVE           |
| Severity       | v_severity, v_tags           | Mapped to 1-10 scale               |
| CVSSv3         | v_severity, v_tags, v_details| Used for severity calculation      |
| Published On   | v_published_datetime         | Converted to DD-MM-YYYY format     |
| CVE (in title) | v_cve                        | Extracted automatically            |
| CVSSv2         | v_details                    | Stored as metadata                 |
| Risk           | v_details                    | Stored as metadata                 |
| Instances      | v_details                    | Stored as metadata                 |
| Exploits       | v_details                    | Stored as metadata                 |
| Modified On    | v_details                    | Stored as metadata                 |

## Severity Mapping

| Original Severity | CVSS v3   | Phoenix Severity |
|------------------|-----------|------------------|
| Critical         | 9.0-10.0  | 10               |
| Severe/High      | 7.0-8.9   | 8                |
| Moderate/Medium  | 4.0-6.9   | 5                |
| Low              | 0.1-3.9   | 3                |
| Info             | 0.0       | 1                |

## Troubleshooting

### Script not executable
```bash
chmod +x convert.sh
chmod +x csv_converter.py
```

### Source file not found
- **Solution**: Ensure the file is in the `source/` directory
  ```bash
  # Check if file exists
  ls source/
  
  # Copy your file to source/
  cp /path/to/your/file.csv source/
  ```
- Or use `--source` flag to specify a different path:
  ```bash
  ./convert.sh --format infra --source /path/to/file.csv
  ```

### Python not found
- Ensure Python 3 is installed: `python3 --version`
- If not installed, install Python 3.6 or higher

## Examples

### Example 1: Basic Infrastructure Conversion
```bash
./convert.sh --format infra
# Output: results/VulnerabilityListingExport_infra_20251111_163434.csv
```

### Example 2: Cloud Conversion with Custom Output
```bash
./convert.sh --format cloud --output results/aws_vulnerabilities.csv
# Output: results/aws_vulnerabilities.csv
```

### Example 3: Convert Multiple Formats
```bash
# Generate all formats
./convert.sh --format infra
./convert.sh --format cloud
./convert.sh --format web
./convert.sh --format software
```

## Support

For detailed documentation, see [README.md](README.md)

For issues or questions:
- Check the [README.md](README.md) for detailed field descriptions
- Review the template files in `template/` directory
- Refer to Phoenix Security documentation


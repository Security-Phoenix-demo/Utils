# Wiz Asset Count Scripts

Two powerful scripts to fetch cloud resources from Wiz API and generate comprehensive asset reports with detailed breakdowns by cloud account and resource types.

## Table of Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Installation](#installation)
- [Credential Configuration](#credential-configuration)
- [Usage and Commands](#usage-and-commands)
- [Complete Command Examples](#complete-command-examples)
- [Output Examples](#output-examples)
- [Command Line Parameters Reference](#command-line-parameters-reference)
- [Troubleshooting](#troubleshooting)
- [Quick Reference](#quick-reference)

## Quick Start

### Option 1: Light Script (Recommended - Faster)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set up credentials
# Create wiz_config.ini with your Wiz API credentials:
cat > wiz_config.ini << EOF
[wiz]
client_id = your_client_id_here
client_secret = your_client_secret_here
EOF

# 3. Run the script (specify output filename)
python wiz_assets_count_light.py wiz_assets.csv

# Output: 
# - wiz_assets.csv (detailed breakdown)
# - wiz_assets_summary.csv (totals and aggregates)
# - wiz_assets.json (structured data)
```

### Option 2: Standard Script

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set up credentials (same as above)

# 3. Run the script (auto-generates timestamped files)
python asset-count-wiz.py

# Output:
# - wiz_assets_20231215_143022.csv
# - wiz_assets_20231215_143022.json
```

### Quick Test Run

```bash
# Test credentials and see sample data (both scripts)
python asset-count-wiz.py --test-mode
python wiz_assets_count_light.py test.csv --test-mode
```

## Features

### Common Features (Both Scripts)
- ✅ Fetches all cloud resources from Wiz API with pagination (500 per page)
- ✅ Groups assets by cloud account (provider:name:ID)
- ✅ Shows resource type breakdown for each account
- ✅ Includes discovered images (unlinked container images)
- ✅ Multiple credential input methods (config file, env vars, CLI args)
- ✅ Test mode for quick validation
- ✅ JSON and CSV exports

### Light Script Exclusive Features
- ⚡ **Faster performance** - Uses aggregated GraphQL queries
- 📊 **Summary CSV** - Separate file with totals by account and asset type
- 🖥️ **Console summary** - Always displays totals on screen
- 📝 **Custom filenames** - Specify your own output file names
- 📋 **--print-table** - Optional detailed table output

### Standard Script Exclusive Features
- 🕐 **Timestamped files** - Automatic timestamp in filenames
- 📦 **Individual resources** - Fetches full resource details (slower but more detailed)

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                         WORKFLOW                                │
└─────────────────────────────────────────────────────────────────┘

1. Credential Loading
   ├── wiz_config.ini (recommended)
   ├── Environment variables
   ├── Command line arguments
   └── Interactive prompt

2. Authentication
   └── Get OAuth token from Wiz API

3. Data Fetching (Paginated)
   ├── Cloud resources (by account and type)
   ├── Discovered images (unlinked containers)
   └── Progress displayed in console

4. Data Processing
   ├── Group by cloud account
   ├── Aggregate by asset type
   └── Calculate totals and summaries

5. Output Generation
   ├── Console: Summary statistics
   ├── CSV (detailed): Account + Type breakdown
   ├── CSV (summary): Totals and aggregates (light script only)
   └── JSON: Structured data with all details

┌─────────────────────────────────────────────────────────────────┐
│                    EXAMPLE OUTPUT FILES                         │
└─────────────────────────────────────────────────────────────────┘

Light Script: python wiz_assets_count_light.py report.csv
├── report.csv ..................... Detailed breakdown
├── report_summary.csv ............. Account totals + asset type totals
└── report.json .................... Structured JSON data

Standard Script: python asset-count-wiz.py
├── wiz_assets_20231215_143022.csv . Detailed breakdown
└── wiz_assets_20231215_143022.json  Structured JSON data
```

## Installation

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

### Install Dependencies

Install the required Python libraries using pip:

```bash
pip install -r requirements.txt
```

Or install manually:

```bash
pip install requests
```

### Verify Installation

You can verify the installation by checking the requests library:

```bash
python -c "import requests; print(f'requests version: {requests.__version__}')"
```

## Credential Configuration

The script supports multiple ways to provide credentials (in order of precedence):

### 1. Config File (Recommended)

Create a `wiz_config.ini` file in the same directory as the script:

```ini
[wiz]
client_id = your_client_id_here
client_secret = your_client_secret_here
```

Example file provided: `wiz_config.ini.example`

### 2. Environment Variables

```bash
export WIZ_CLIENT_ID="your_client_id"
export WIZ_CLIENT_SECRET="your_client_secret"
python asset-count-wiz.py
```

### 3. Command Line Arguments

```bash
python asset-count-wiz.py --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET
```

### 4. Interactive Input

If no credentials are found, the script will prompt you to enter them interactively.

## Usage and Commands

### Overview

There are two scripts available:

| Script | Purpose | Best For |
|--------|---------|----------|
| `asset-count-wiz.py` | Fetches individual resources with full details slower but more precise | Small-medium environments (<10k resources) |
| `wiz_assets_count_light.py` | Uses aggregated queries for faster performance faster but  | Large environments (>10k resources) |

### Standard Script (asset-count-wiz.py)

The standard script fetches all individual cloud resources with full details:

```bash
# Basic usage
python asset-count-wiz.py

# Test mode (fetch only 500 resources)
python asset-count-wiz.py --test-mode

# With credentials
python asset-count-wiz.py --client-id YOUR_ID --client-secret YOUR_SECRET
```

**Output files:**
- `wiz_assets_YYYYMMDD_HHMMSS.json`
- `wiz_assets_YYYYMMDD_HHMMSS.csv`

### Light Script (wiz_assets_count_light.py) - Recommended for Large Environments

The light version uses aggregated queries for better performance and faster execution:

```bash
# Basic usage - specify output CSV filename
python wiz_assets_count_light.py output.csv

# Test mode (fetch only first page for testing)
python wiz_assets_count_light.py output.csv --test-mode

# With credentials
python wiz_assets_count_light.py output.csv --client-id YOUR_ID --client-secret YOUR_SECRET

# Print table to console as well
python wiz_assets_count_light.py output.csv --print-table

# Full example with all options
python wiz_assets_count_light.py wiz_assets.csv --client-id YOUR_ID --client-secret YOUR_SECRET --test-mode --print-table
```

**Output files:**
- `output.csv` - Detailed breakdown by account and asset type
- `output_summary.csv` - Summary totals by account + asset type aggregates
- `output.json` - Structured JSON with all details

**Key differences:**
- **Light version**: Uses `cloudResourcesGroupedByValues` query - faster, aggregated data
- **Standard version**: Uses `cloudResources` query - slower, individual resource details
- **Light version**: Requires output filename as argument
- **Standard version**: Auto-generates timestamped filenames

**When to use which:**
- Use **light version** for quick asset counts and large environments (10,000+ resources)
- Use **standard version** for detailed resource information and smaller environments

## Output Examples

### Standard Script Output (asset-count-wiz.py)

```
================================================================================
TOTAL ASSET COUNT: 2500
================================================================================

Grouping assets by cloud account...

================================================================================
ASSETS GROUPED BY CLOUD ACCOUNT
================================================================================

AWS:Production Account (123456789012)
  Count: 1250
  Resource types:
    - EC2_INSTANCE: 450
    - S3_BUCKET: 300
    - RDS_INSTANCE: 200
    - LAMBDA_FUNCTION: 150
    - ...

Azure:Development Subscription (sub-abc-123)
  Count: 780
  Resource types:
    - VIRTUAL_MACHINE: 250
    - STORAGE_ACCOUNT: 180
    - ...

================================================================================
SUMMARY
================================================================================
Total Cloud Accounts: 5
Total Cloud Resources: 2500
Discovered Images (unlinked): 150
GRAND TOTAL ASSETS: 2650
```

### Light Script Output (wiz_assets_count_light.py)

```
Loading credentials from wiz_config.ini

Authenticating with Wiz API...
Authentication successful!

Fetching cloud resources (grouped by account and type)...
Fetched 150 resource groups so far...
Fetched 300 resource groups so far...

Fetching discovered images count...

================================================================================
SUMMARY BY CLOUD ACCOUNT
================================================================================
AWS:Production Account (123456789012)
  Total Resources: 1,250
Azure:Development Subscription (sub-abc-123)
  Total Resources: 780
GCP:Test Project (project-456)
  Total Resources: 470

================================================================================
SUMMARY BY ASSET TYPE (ACROSS ALL ACCOUNTS)
================================================================================
  EC2_INSTANCE: 450
  S3_BUCKET: 300
  VIRTUAL_MACHINE: 250
  STORAGE_ACCOUNT: 180
  CONTAINER_IMAGE: 150
  RDS_INSTANCE: 200
  ...

================================================================================
GRAND TOTALS
================================================================================
Total Cloud Accounts: 5
Total Cloud Resources: 2,500
Discovered Images (unlinked): 150
GRAND TOTAL ASSETS: 2,650
================================================================================

================================================================================
EXPORTING DATA
================================================================================

Exporting detailed data to CSV: output.csv
✅ Detailed CSV saved to: output.csv
✅ Summary CSV saved to: output_summary.csv
✅ JSON export saved to: output.json

================================================================================
✅ Export complete!
================================================================================

Files created:
  1. Detailed CSV: output.csv
  2. Summary CSV:  output_summary.csv
  3. JSON:         output.json
================================================================================
```

### CSV Output Formats

#### Detailed CSV (output.csv) - Both Scripts

```csv
Account Name,Account ID,Provider,Asset Type,Asset Count
Production Account,123456789012,AWS,EC2_INSTANCE,450
Production Account,123456789012,AWS,S3_BUCKET,300
Development Subscription,sub-abc-123,Azure,VIRTUAL_MACHINE,250
Discovered Images,not-real-account,Various,CONTAINER_IMAGE,150
```

#### Summary CSV (output_summary.csv) - Light Script Only

```csv
SUMMARY BY CLOUD ACCOUNT
Cloud Provider,Account Name,Account ID,Total Resources

AWS,Production Account,123456789012,1250
Azure,Development Subscription,sub-abc-123,780
GCP,Test Project,project-456,470

TOTAL CLOUD RESOURCES,,,2500


SUMMARY BY ASSET TYPE (ACROSS ALL ACCOUNTS)
Asset Type,Total Count

EC2_INSTANCE,450
S3_BUCKET,300
VIRTUAL_MACHINE,250
STORAGE_ACCOUNT,180
CONTAINER_IMAGE,150

GRAND TOTAL ASSETS,2650
- Cloud Resources,2500
- Discovered Images,150
```

### JSON Output Format

```json
{
  "export_timestamp": "2023-12-15T14:30:22.123456",
  "summary": {
    "total_cloud_accounts": 5,
    "total_cloud_resources": 2500,
    "discovered_images_unlinked": 150,
    "grand_total_assets": 2650
  },
  "accounts": [
    {
      "cloud_provider": "AWS",
      "account_name": "Production Account",
      "account_id": "123456789012",
      "total_resources": 1250,
      "resource_types": [
        {"type": "EC2_INSTANCE", "count": 450},
        {"type": "S3_BUCKET", "count": 300}
      ]
    }
  ]
}
```

## Command Line Parameters Reference

### asset-count-wiz.py Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--client-id` | String | No* | Wiz Client ID for authentication |
| `--client-secret` | String | No* | Wiz Client Secret for authentication |
| `--test-mode` | Flag | No | Fetch only 500 resources for testing |

*Required if not provided via config file or environment variables

**Output:** Creates timestamped files automatically
- `wiz_assets_YYYYMMDD_HHMMSS.json`
- `wiz_assets_YYYYMMDD_HHMMSS.csv`

### wiz_assets_count_light.py Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `csv_file` | String | Yes | Path to output CSV file (positional argument) |
| `--client-id` | String | No* | Wiz Client ID for authentication |
| `--client-secret` | String | No* | Wiz Client Secret for authentication |
| `--test-mode` | Flag | No | Fetch only first page (500 resource groups) |
| `--print-table` | Flag | No | Print detailed table to console |

*Required if not provided via config file or environment variables

**Output:** Creates files based on specified CSV name
- `{csv_file}` - Detailed CSV
- `{csv_file_basename}_summary.csv` - Summary CSV
- `{csv_file_basename}.json` - JSON file

## Complete Command Examples

### Basic Usage (Using Config File)

```bash
# Standard script - auto-generates timestamped files
python asset-count-wiz.py

# Light script - specify output filename
python wiz_assets_count_light.py wiz_assets.csv
```

### Using Command Line Credentials

```bash
# Standard script
python asset-count-wiz.py \
  --client-id YOUR_WIZ_CLIENT_ID \
  --client-secret YOUR_WIZ_CLIENT_SECRET

# Light script
python wiz_assets_count_light.py wiz_assets.csv \
  --client-id YOUR_WIZ_CLIENT_ID \
  --client-secret YOUR_WIZ_CLIENT_SECRET
```

### Using Environment Variables

```bash
# Set environment variables (bash/zsh)
export WIZ_CLIENT_ID="YOUR_WIZ_CLIENT_ID"
export WIZ_CLIENT_SECRET="YOUR_WIZ_CLIENT_SECRET"

# Run scripts
python asset-count-wiz.py
python wiz_assets_count_light.py wiz_assets.csv
```

### Test Mode (Quick Testing)

```bash
# Standard script - fetch only 500 resources
python asset-count-wiz.py --test-mode

# Light script - fetch only first page
python wiz_assets_count_light.py test_output.csv --test-mode
```

### With Console Output (Light Script Only)

```bash
# Print detailed table to console
python wiz_assets_count_light.py wiz_assets.csv --print-table

# Combine with test mode
python wiz_assets_count_light.py wiz_assets.csv --test-mode --print-table
```

### Complete Example with All Options

```bash
# Light script with all parameters
python wiz_assets_count_light.py wiz_assets_report.csv \
  --client-id YOUR_CLIENT_ID \
  --client-secret YOUR_CLIENT_SECRET \
  --test-mode \
  --print-table

# This creates:
# - wiz_assets_report.csv (detailed breakdown)
# - wiz_assets_report_summary.csv (summary totals)
# - wiz_assets_report.json (structured data)
```

### Scheduled/Automated Runs

```bash
# Using cron (runs daily at 2 AM)
0 2 * * * cd /path/to/script && python asset-count-wiz.py

# Using cron with specific output name (light script)
0 2 * * * cd /path/to/script && python wiz_assets_count_light.py daily_assets_$(date +\%Y\%m\%d).csv

# Windows Task Scheduler (PowerShell)
cd C:\path\to\script
python asset-count-wiz.py
```

### Output to Specific Directory

```bash
# Specify full path for output files
python wiz_assets_count_light.py /path/to/reports/wiz_assets.csv

# Or use relative paths
python wiz_assets_count_light.py ./reports/wiz_assets.csv
```

## Troubleshooting

### Common Issues

**1. Authentication Error**
```
Error: Error when trying to get token: 401
```
**Solution:** Check that your Client ID and Client Secret are correct in `wiz_config.ini`

**2. Missing requests library**
```
Error: 'requests' library is not installed
```
**Solution:** Run `pip install -r requirements.txt`

**3. Permission denied on output file**
```
Error: Permission denied: 'output.csv'
```
**Solution:** Ensure you have write permissions to the output directory, or specify a different path

**4. Script runs slowly**
```
Large environment taking too long to fetch
```
**Solution:** Use the light script (`wiz_assets_count_light.py`) which uses aggregated queries

**5. Test mode in production**
```
Data seems incomplete
```
**Solution:** Remove `--test-mode` flag to fetch all data

### Getting Wiz API Credentials

1. Log in to Wiz Console
2. Go to **Settings** → **Service Accounts**
3. Click **Add Service Account**
4. Give it a name (e.g., "Asset Count Script")
5. Assign appropriate permissions:
   - `read:resources` (required)
   - `read:cloud_accounts` (required)
6. Copy the **Client ID** and **Client Secret**
7. Add them to `wiz_config.ini`

## Quick Reference

### Command Cheat Sheet

| Task | Command |
|------|---------|
| Basic run (config file) | `python wiz_assets_count_light.py output.csv` |
| With credentials | `python wiz_assets_count_light.py output.csv --client-id ID --client-secret SECRET` |
| Test mode (faster) | `python wiz_assets_count_light.py output.csv --test-mode` |
| Show table on screen | `python wiz_assets_count_light.py output.csv --print-table` |
| All options | `python wiz_assets_count_light.py output.csv --test-mode --print-table` |
| Standard script | `python asset-count-wiz.py` |
| Standard with test mode | `python asset-count-wiz.py --test-mode` |

### File Output Reference

| Script | Files Created |
|--------|---------------|
| **asset-count-wiz.py** | `wiz_assets_YYYYMMDD_HHMMSS.json`<br>`wiz_assets_YYYYMMDD_HHMMSS.csv` |
| **wiz_assets_count_light.py** | `{name}.csv` (detailed)<br>`{name}_summary.csv` (totals)<br>`{name}.json` (structured) |

### When to Use Which Script

| Scenario | Recommended Script |
|----------|-------------------|
| < 10,000 resources | Either script works fine |
| > 10,000 resources | `wiz_assets_count_light.py` (faster) |
| Need detailed resource info | `asset-count-wiz.py` |
| Need aggregated summaries | `wiz_assets_count_light.py` |
| Quick testing | Either with `--test-mode` |
| Automated/scheduled runs | `wiz_assets_count_light.py` (predictable filenames) |

## Notes

- Both scripts use pagination to fetch all resources (500 per page)
- Progress is shown during data fetching
- Accounts are sorted by resource count (highest first)
- Resource types are sorted by count within each account
- Light version is significantly faster for large environments (uses aggregated queries)
- Both scripts support the same credential loading methods (config file, env vars, CLI args)
- Test mode is useful for validating credentials and testing without fetching all data
- Summary CSV is only created by the light script
- Console summary output is always displayed by the light script


# asset-count-scripts

**Version**: 1.0
**Last Updated**: February 2026
**Path**: `Utils/asset-count-scripts/`

---

## Overview

Asset counting scripts for inventorying assets across cloud providers (AWS, Azure, GCP), Git platforms (GitHub, GitLab), and Wiz cloud security. Each sub-folder contains a standalone counter that queries provider APIs and produces structured inventory reports.

These scripts are **read-only** — they count and catalog assets without modifying anything in Phoenix or the cloud providers.

## Key Features

- Count and categorize assets across AWS, Azure, and GCP
- Inventory Git repositories across GitHub and GitLab organizations
- Count Wiz cloud security assets
- JSON/CSV output for reporting and analysis
- No Phoenix API dependency (cloud provider credentials only)

## Sub-Folders

| Folder | Provider | Scripts |
|--------|----------|---------|
| `cloud/` | AWS, Azure, GCP | `aws-asset-counter.py`, `azure-asset-counter.py`, `gcp-asset-counter.py` |
| `git/` | GitHub, GitLab | Git repository counters |
| `wiz/` | Wiz | `wiz_assets_count_light.py`, `asset-count-wiz.py` |

## Prerequisites

- Python 3.8+
- Cloud provider credentials (AWS CLI profile, Azure service principal, GCP service account)
- For Git counters: GitHub/GitLab personal access token
- For Wiz: Wiz API token

## Quick Start

```bash
cd Utils/asset-count-scripts/cloud

# AWS asset count
python3 aws-asset-counter.py --profile default --output aws_inventory.json

# Azure asset count
python3 azure-asset-counter.py --subscription SUB_ID --output azure_inventory.json

# GCP asset count
python3 gcp-asset-counter.py --project PROJECT_ID --output gcp_inventory.json
```

## Output Format

JSON inventory with asset counts by type, region, and account:

```json
{
  "provider": "AWS",
  "total_assets": 1523,
  "by_type": {
    "EC2": 245,
    "RDS": 32,
    "Lambda": 189,
    "S3": 47
  },
  "by_region": {
    "us-east-1": 890,
    "eu-west-1": 433
  }
}
```

## Related Documents

- [Quick Start](QUICK_START.md)
- [Configuration Guide](CONFIGURATION_GUIDE.md)
- [Utils Master Index](../UTILS_MASTER_INDEX.md)

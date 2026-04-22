# asset-count-scripts — Quick Start

**Last Updated**: February 2026 | **Path**: `Utils/asset-count-scripts/`

---

## Cloud Asset Counting

```bash
cd Utils/asset-count-scripts/cloud
pip install boto3 azure-mgmt-resource google-cloud-asset

# AWS
python3 aws-asset-counter.py --profile default --output aws_inventory.json

# Azure
python3 azure-asset-counter.py --subscription YOUR_SUBSCRIPTION_ID --output azure_inventory.json

# GCP
python3 gcp-asset-counter.py --project YOUR_PROJECT_ID --output gcp_inventory.json
```

## Git Repository Counting

```bash
cd Utils/asset-count-scripts/git
# Follow README.md for GitHub/GitLab token setup
```

## Wiz Asset Counting

```bash
cd Utils/asset-count-scripts/wiz
python3 wiz_assets_count_light.py
```

## Verify Output

Check generated JSON files for asset counts by type and region.

## Related Documents

- [README](README.md) · [Configuration Guide](CONFIGURATION_GUIDE.md) · [Utils Master Index](../UTILS_MASTER_INDEX.md)

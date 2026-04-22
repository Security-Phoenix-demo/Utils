# asset-count-scripts — Configuration Guide

**Last Updated**: February 2026 | **Path**: `Utils/asset-count-scripts/`

---

## Cloud Counters

### AWS Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--profile` | string | No | AWS CLI profile name (default: `default`) |
| `--region` | string | No | Specific region to scan (default: all regions) |
| `--output` | string | No | Output file path |

**Authentication**: Uses AWS CLI credentials (`~/.aws/credentials`) or IAM role.

### Azure Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--subscription` | string | Yes | Azure subscription ID |
| `--output` | string | No | Output file path |

**Authentication**: Uses Azure CLI (`az login`) or service principal via environment variables.

### GCP Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `--project` | string | Yes | GCP project ID |
| `--output` | string | No | Output file path |

**Authentication**: Uses `GOOGLE_APPLICATION_CREDENTIALS` environment variable or ADC.

## Wiz Configuration

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| Wiz API token | env var | Yes | Set via `WIZ_API_TOKEN` |
| Wiz API URL | env var | Yes | Set via `WIZ_API_URL` |

## Related Documents

- [README](README.md) · [Quick Start](QUICK_START.md) · [Utils Master Index](../UTILS_MASTER_INDEX.md)

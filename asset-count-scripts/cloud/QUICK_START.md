# Quick Start Guide - Cloud Asset Counter

Get up and running in 5 minutes!

## 🚀 Quick Setup

### 1. Install Dependencies

```bash
cd Utils/asset-count-scripts/cloud
pip install -r requirements.txt
```

### 2. Configure Authentication

Choose your cloud provider and follow the setup:

#### AWS (Fastest: Use AWS CLI)
```bash
# If you already have AWS CLI configured:
python aws-asset-counter.py

# Or configure now:
aws configure
# Enter your access key and secret when prompted
```

#### Azure (Fastest: Use Azure CLI)
```bash
# Login to Azure:
az login

# Run the script:
python azure-asset-counter.py
```

#### GCP (Fastest: Use gcloud CLI)
```bash
# Login with application default credentials:
gcloud auth application-default login

# Run the script:
python gcp-asset-counter.py
```

### 3. Run Your First Scan

```bash
# AWS
python aws-asset-counter.py

# Azure
python azure-asset-counter.py

# GCP
python gcp-asset-counter.py
```

### 4. Check Results

Look for output files in the `./output` directory:
- `cloud_assets_YYYYMMDD_HHMM.json` - Structured data
- `cloud_assets_YYYYMMDD_HHMM.csv` - Spreadsheet format

---

## 📝 Common Use Cases

### Scan Multiple AWS Accounts

1. Copy the template:
```bash
cp aws_config.ini.template aws_config.ini
```

2. Edit `aws_config.ini`:
```ini
[accounts]
production = prod-profile
staging = staging-profile
development = dev-profile
```

3. Run:
```bash
python aws-asset-counter.py
```

### Scan Specific Azure Subscription

```bash
python azure-asset-counter.py --subscription-id 12345678-1234-1234-1234-123456789012
```

### Scan Specific GCP Project

```bash
python gcp-asset-counter.py --project-id my-project-123456
```

### Custom Output Name

```bash
python aws-asset-counter.py --output-prefix quarterly_audit_q4
```

---

## 🔒 Access Requirements Summary

### AWS - Need:
- IAM user/role with read-only permissions
- **Quick setup**: Use AWS CLI (`aws configure`)
- **Production setup**: See `aws-iam-policy.yaml`

### Azure - Need:
- Reader role on subscription(s)
- **Quick setup**: Use Azure CLI (`az login`)
- **Production setup**: See `azure-service-principal.json`

### GCP - Need:
- Cloud Asset Viewer + Viewer roles
- **Quick setup**: Use gcloud CLI (`gcloud auth application-default login`)
- **Production setup**: See `gcp-service-account.tf`

---

## 🎯 Output Format

### Console Output
```
AWS:production-account (123456789012)
  Count: 8608
  Resource types:
    - VIRTUAL_MACHINE: 150
    - BUCKET: 45
    - DATABASE: 12
    - FIREWALL: 668
    - SECRET: 550
    ...
```

### JSON Output
```json
{
  "scan_timestamp": "2025-12-12T14:30:00Z",
  "provider": "AWS",
  "accounts": [
    {
      "account_name": "production",
      "account_id": "123456789012",
      "total_count": 8608,
      "resource_types": {
        "VIRTUAL_MACHINE": 150,
        "BUCKET": 45
      }
    }
  ]
}
```

### CSV Output
```csv
Provider,AccountName,AccountID,ResourceType,Count,ScanTimestamp
AWS,production,123456789012,VIRTUAL_MACHINE,150,2025-12-12T14:30:00Z
AWS,production,123456789012,BUCKET,45,2025-12-12T14:30:00Z
```

---

## 🛠️ Troubleshooting

### "Unable to locate credentials" (AWS)
```bash
# Configure AWS CLI
aws configure
```

### "No subscriptions found" (Azure)
```bash
# Login to Azure
az login

# Check subscriptions
az account list
```

### "Could not determine credentials" (GCP)
```bash
# Setup application default credentials
gcloud auth application-default login
```

### "Permission denied" / "Access denied"
- AWS: Check IAM permissions (see `aws-iam-policy.yaml`)
- Azure: Ensure you have Reader role on subscription
- GCP: Verify Cloud Asset Viewer role is assigned

---

## 📚 Next Steps

1. **Customize Output**: Edit `cloud_config.ini`
2. **Production Setup**: Deploy IAM policies (see deployment templates)
3. **Automation**: Schedule with cron or CI/CD
4. **Integration**: Use CSV output in your dashboards/CMDB

---

## 📖 Full Documentation

See `README.md` for comprehensive documentation including:
- Detailed configuration options
- Access requirement details
- Advanced usage scenarios
- Security best practices
- Integration examples

---

## 💡 Quick Tips

- Use `--help` to see all command options
- Set `verbose = true` in `cloud_config.ini` for debugging
- Results are timestamped automatically
- Scripts handle multiple accounts/subscriptions/projects
- All errors are logged clearly

---

**Need Help?** Check the full README.md or deployment templates!








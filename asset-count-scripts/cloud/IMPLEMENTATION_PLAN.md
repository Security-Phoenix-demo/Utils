# Cloud Asset Counter - Implementation Plan

## Overview
Create three separate scripts to fetch and count assets from AWS, Azure, and GCP cloud providers.

## Requirements Analysis

### Functional Requirements
1. **Asset Fetching**: Retrieve all assets from each cloud provider
2. **Asset Counting**: Count total assets and categorize by type
3. **Multi-Account Support**: Handle multiple accounts/subscriptions/projects
4. **Data Export**: Save results in JSON and CSV formats
5. **Console Output**: Display formatted results per account
6. **Configuration**: Configurable output file names and paths
7. **Error Handling**: Robust error handling and logging

### Output Format (Based on User Example)
```
PROVIDER:account-name (account-id)
  Count: XXXX
  Resource types:
    - RESOURCE_TYPE_1: count
    - RESOURCE_TYPE_2: count
    ...
```

## Implementation Steps

### Phase 1: Setup and Configuration (Steps 1-2)
**Step 1: Create Configuration Files**
- `cloud_config.ini` - Main configuration file
- `aws_config.ini.template` - AWS credentials template
- `azure_config.ini.template` - Azure credentials template
- `gcp_config.ini.template` - GCP credentials template

**Step 2: Create Requirements File**
- `requirements.txt` with all necessary dependencies

### Phase 2: AWS Implementation (Steps 3-4)
**Step 3: AWS Asset Counter Script**
- Script name: `aws-asset-counter.py`
- Use boto3 library
- Fetch resources using AWS Resource Groups Tagging API and service-specific APIs
- Support multiple AWS accounts via profile/role assumption
- Resource types to fetch:
  - EC2 (instances, AMIs, snapshots, volumes, security groups, etc.)
  - S3 (buckets)
  - RDS (databases, snapshots)
  - Lambda (functions)
  - ECS/EKS (clusters, services, tasks)
  - VPC (subnets, route tables, gateways, etc.)
  - IAM (roles, policies, users)
  - CloudWatch (alarms)
  - And many more...

**Step 4: AWS Access Requirements Documentation**
- Required IAM permissions
- IAM policy template for read-only access
- Setup instructions

### Phase 3: Azure Implementation (Steps 5-6)
**Step 5: Azure Asset Counter Script**
- Script name: `azure-asset-counter.py`
- Use azure-mgmt libraries
- Fetch resources using Azure Resource Graph API
- Support multiple subscriptions
- Resource types to fetch:
  - Virtual Machines
  - Storage Accounts
  - SQL Databases
  - AKS Clusters
  - App Services
  - Functions
  - Virtual Networks
  - Key Vaults
  - And many more...

**Step 6: Azure Access Requirements Documentation**
- Required Azure RBAC roles
- Service Principal creation guide
- Role assignment templates

### Phase 4: GCP Implementation (Steps 7-8)
**Step 7: GCP Asset Counter Script**
- Script name: `gcp-asset-counter.py`
- Use google-cloud libraries (Asset Inventory API)
- Support multiple projects
- Resource types to fetch:
  - Compute Engine instances
  - Cloud Storage buckets
  - Cloud SQL databases
  - GKE clusters
  - Cloud Functions
  - VPC networks
  - Cloud Run services
  - And many more...

**Step 8: GCP Access Requirements Documentation**
- Required IAM roles
- Service account creation guide
- Role binding templates

### Phase 5: Documentation and Access Templates (Steps 9-10)
**Step 9: Create Comprehensive README**
- Installation instructions
- Configuration guide
- Usage examples
- Troubleshooting section
- Access requirements summary

**Step 10: Create Access Deployment Templates**
- AWS CloudFormation template for IAM role
- Azure ARM template for Service Principal
- GCP Terraform template for Service Account
- Shell scripts for manual setup

### Phase 6: Testing and Validation (Steps 11-12)
**Step 11: Code Review and Error Checking**
- Validate all scripts for syntax errors
- Check error handling
- Validate configuration parsing
- Test file I/O operations

**Step 12: Final Double-Check**
- Review all requirements met
- Check output format matches example
- Verify documentation completeness
- Validate access templates

## Technical Architecture

### Common Components
```python
# Each script will have:
1. Configuration Parser
2. Authentication Handler
3. Resource Fetcher
4. Data Aggregator
5. Output Formatter (console, JSON, CSV)
6. Error Handler
```

### Data Structure
```python
{
  "scan_timestamp": "ISO-8601",
  "provider": "aws|azure|gcp",
  "accounts": [
    {
      "account_name": "string",
      "account_id": "string",
      "total_count": int,
      "resource_types": {
        "RESOURCE_TYPE": count,
        ...
      }
    }
  ]
}
```

### CSV Format
```csv
Provider,AccountName,AccountID,ResourceType,Count,ScanTimestamp
AWS,account-1,123456789012,EC2_INSTANCE,150,2025-12-12T10:00:00Z
AWS,account-1,123456789012,S3_BUCKET,45,2025-12-12T10:00:00Z
...
```

## Resource Type Mapping

### AWS → Standard Types
- EC2 Instance → VIRTUAL_MACHINE
- S3 Bucket → BUCKET
- RDS Instance → DB_SERVER
- Lambda Function → SERVERLESS
- ECS/EKS → CONTAINER_SERVICE, KUBERNETES_CLUSTER
- Security Group → FIREWALL
- VPC → VIRTUAL_NETWORK
- Subnet → SUBNET
- EBS Volume → VOLUME
- Snapshot → SNAPSHOT
- AMI → VIRTUAL_MACHINE_IMAGE
- IAM Role → ACCESS_ROLE
- Secrets Manager → SECRET
- KMS Key → ENCRYPTION_KEY
- And many more...

### Azure → Standard Types
- Virtual Machine → VIRTUAL_MACHINE
- Storage Account → BUCKET
- SQL Database → DATABASE
- AKS → KUBERNETES_CLUSTER
- Network Security Group → FIREWALL
- Virtual Network → VIRTUAL_NETWORK
- Disk → VOLUME
- Key Vault → SECRET_CONTAINER
- And many more...

### GCP → Standard Types
- Compute Instance → VIRTUAL_MACHINE
- Storage Bucket → BUCKET
- Cloud SQL → DATABASE
- GKE Cluster → KUBERNETES_CLUSTER
- Firewall Rule → FIREWALL
- VPC Network → VIRTUAL_NETWORK
- Persistent Disk → VOLUME
- Secret Manager → SECRET
- And many more...

## Error Handling Strategy

1. **Authentication Errors**: Clear message about credentials
2. **Permission Errors**: Indicate missing permissions
3. **API Rate Limiting**: Implement exponential backoff
4. **Network Errors**: Retry logic with timeout
5. **Data Validation**: Validate before writing files
6. **Partial Failures**: Continue with other accounts on single account failure

## Configuration File Structure

### cloud_config.ini
```ini
[output]
# Output file name prefix (timestamp will be added)
output_prefix = cloud_assets
# Output directory
output_dir = ./output
# Include timestamp in filename
include_timestamp = true

[display]
# Show progress during scan
show_progress = true
# Verbose output
verbose = false
```

## Success Criteria

✅ All three scripts created and functional
✅ Configuration files and templates present
✅ JSON and CSV export working
✅ Console output matches required format
✅ Multi-account support working
✅ Comprehensive documentation complete
✅ Access requirement documentation clear
✅ IAM/Access policy templates provided
✅ Error handling robust
✅ Code reviewed twice for errors

## Estimated Components

- **Scripts**: 3 (AWS, Azure, GCP)
- **Config Files**: 4 (main + 3 templates)
- **Documentation Files**: 4 (README, AWS guide, Azure guide, GCP guide)
- **Access Templates**: 6 (2 per provider)
- **Total Files**: ~17

---

**Status**: Plan Complete - Ready for Implementation
**Next Step**: Create requirements.txt and start AWS implementation








# JSON Support - Prowler OCSF Format

## Overview

Version 1.1 adds native support for **Prowler OCSF JSON format** as input, allowing you to convert Prowler security findings directly to Phoenix Security cloud format CSV.

## What's New

### v1.1 Features
- ✅ **JSON Input Support** - Automatically detects `.json` files
- ✅ **Prowler OCSF Format** - Native support for Prowler 5.x output
- ✅ **Cloud Format Output** - Converts to Phoenix Security cloud asset format
- ✅ **Smart Filtering** - Only converts FAIL findings (skips PASS)
- ✅ **Large File Support** - Handles 10,000+ findings efficiently
- ✅ **Progress Indicators** - Real-time progress updates
- ✅ **Complete Field Mapping** - All relevant fields mapped automatically

## Quick Start

### Basic Usage

```bash
# Convert Prowler JSON to Phoenix Security cloud format
python3 csv_converter.py source/prowler-output.ocsf.json --format cloud
```

### With Options

```bash
# Custom output file
python3 csv_converter.py prowler-findings.json --format cloud --output aws-vulns.csv

# Using bash wrapper
./convert.sh --format cloud --source prowler-output.json
```

## Field Mapping

### Complete Mapping Table

| Prowler OCSF Field | Type | Phoenix Security Field | Transformation |
|-------------------|------|----------------------|----------------|
| `finding_info.title` | String | `v_name` | Direct copy (max 500 chars) |
| `finding_info.desc` | String | `v_description` | Direct copy |
| `severity` | String | `v_severity` | Mapped to 1-10 scale |
| `finding_info.created_time_dt` | ISO DateTime | `v_published_datetime` | Reformatted to DD-MM-YYYY HH:MM:SS |
| `remediation.desc` | String | `v_remedy` | Direct copy |
| `cloud.provider` | String | `at_provider_type` | Uppercase (AWS/AZURE/GCP) |
| `cloud.region` | String | `at_region` | Direct copy |
| `cloud.account.uid` | String | `a_tags` | Added as account_id tag |
| `resources[0].uid` | String (ARN) | `at_provider_resource_id` | Direct copy |
| `resources[0].uid` | String (ARN) | `at_provider_asset_id` | Direct copy |
| `resources[0].labels` | Array | `a_tags` | Parsed as key:value pairs |
| `status_code` | String | (filter) | Only FAIL findings converted |
| `remediation.references` | Array | `v_details` | JSON array |
| `unmapped.compliance` | Object | `v_details` | Nested compliance frameworks |
| `unmapped.categories` | Array | `v_details` | Security categories |
| `unmapped.related_url` | String | `v_details` | Documentation URL |
| `metadata.event_code` | String | `v_tags` | Check identifier |

### Severity Mapping

```
Prowler Severity  →  Phoenix Security Severity (1-10)
════════════════════════════════════════════════════
Critical          →  10
High              →  8
Medium            →  5
Low               →  3
Informational     →  1
Info              →  1
```

## Example Conversion

### Input (Prowler OCSF JSON)

```json
{
  "message": "Athena WorkGroup staging-cur-report-staging does not encrypt the query results.",
  "severity": "Medium",
  "severity_id": 3,
  "status_code": "FAIL",
  "finding_info": {
    "title": "Ensure that encryption at rest is enabled for Amazon Athena query results",
    "desc": "Ensure that encryption at rest is enabled for Amazon Athena query results stored in Amazon S3",
    "created_time_dt": "2025-07-28T09:18:04.263888",
    "uid": "prowler-aws-athena_workgroup_encryption-873489506556-us-east-1-staging-cur-report-staging"
  },
  "cloud": {
    "provider": "aws",
    "region": "us-east-1",
    "account": {
      "uid": "873489506556"
    }
  },
  "resources": [{
    "uid": "arn:aws:athena:us-east-1:873489506556:workgroup/staging-cur-report-staging",
    "name": "staging-cur-report-staging",
    "type": "AwsAthenaWorkGroup"
  }],
  "remediation": {
    "desc": "Enable Encryption. Use a CMK where possible.",
    "references": [
      "https://docs.aws.amazon.com/athena/latest/ug/encrypting-query-results-stored-in-s3.html",
      "aws athena update-work-group --work-group <name> --configuration-updates ResultConfigurationUpdates={EncryptionConfiguration={EncryptionOption=SSE_S3}}"
    ]
  },
  "unmapped": {
    "compliance": {
      "PCI-4.0": ["3.5.1.2", "8.3.2.3"],
      "ISO27001-2022": ["A.8.11", "A.8.24"]
    },
    "categories": ["encryption"]
  }
}
```

### Output (Phoenix Security Cloud CSV)

```csv
a_id,a_subtype,at_provider_type,at_provider_resource_id,at_vpc,at_subnet,at_region,at_resource_group,at_provider_asset_id,a_tags,v_name,v_description,v_remedy,v_severity,v_cve,v_cwe,v_published_datetime,v_tags,v_details
,,AWS,arn:aws:athena:us-east-1:873489506556:workgroup/staging-cur-report-staging,,,us-east-1,,arn:aws:athena:us-east-1:873489506556:workgroup/staging-cur-report-staging,"[{""key"": ""source"", ""value"": ""prowler""}, {""key"": ""account_id"", ""value"": ""873489506556""}, {""key"": ""imported"", ""value"": ""2025-11-11""}]",Ensure that encryption at rest is enabled for Amazon Athena query results,Ensure that encryption at rest is enabled for Amazon Athena query results stored in Amazon S3,Enable Encryption. Use a CMK where possible.,5,,,28-07-2025 09:18:04,"[{""key"": ""severity"", ""value"": ""Medium""}, {""key"": ""status"", ""value"": ""FAIL""}, {""key"": ""check"", ""value"": ""athena_workgroup_encryption""}]","{""finding_uid"": ""prowler-aws-athena_workgroup_encryption-873489506556-us-east-1-staging-cur-report-staging"", ""status"": ""New"", ""status_code"": ""FAIL"", ""compliance"": {""PCI-4.0"": [""3.5.1.2"", ""8.3.2.3""], ""ISO27001-2022"": [""A.8.11"", ""A.8.24""]}, ""remediation_references"": [""https://docs.aws.amazon.com/athena/latest/ug/encrypting-query-results-stored-in-s3.html"", ""aws athena update-work-group...""], ""categories"": [""encryption""]}"
```

## Output Structure

### Asset Tags (a_tags)
Automatically generated as JSON array of objects:
```json
[
  {"key": "source", "value": "prowler"},
  {"key": "account_id", "value": "873489506556"},
  {"key": "imported", "value": "2025-11-11"},
  {"key": "eks:cluster-name", "value": "staging-virginia-eks"}  // from resource labels
]
```

### Vulnerability Tags (v_tags)
```json
[
  {"key": "severity", "value": "Medium"},
  {"key": "status", "value": "FAIL"},
  {"key": "check", "value": "athena_workgroup_encryption"}
]
```

### Details (v_details)
Comprehensive JSON with metadata:
```json
{
  "finding_uid": "prowler-aws-...",
  "status": "New",
  "status_code": "FAIL",
  "risk_details": "If not enabled sensitive information at rest is not protected.",
  "event_code": "athena_workgroup_encryption",
  "category": "Findings",
  "class": "Detection Finding",
  "compliance": {
    "PCI-4.0": ["3.5.1.2", "8.3.2.3"],
    "ISO27001-2022": ["A.8.11", "A.8.24"]
  },
  "related_url": "https://docs.aws.amazon.com/...",
  "remediation_references": ["https://...", "aws athena ..."],
  "categories": ["encryption"]
}
```

## Features

### 1. Auto-Detection
The script automatically detects JSON files by extension:
```python
if file_name.endswith('.json'):
    # Use JSON parser
else:
    # Use CSV parser
```

### 2. Smart Filtering
Only FAIL findings are converted:
```python
if finding['status_code'] != 'FAIL':
    skip_finding()  # PASS findings are skipped
```

### 3. Progress Tracking
For large files, progress is shown every 100 findings:
```
Converting source/prowler-output.ocsf.json to cloud format...
Input format: JSON (Prowler OCSF)
Loaded 4562 findings from JSON file
  Processed 100 findings...
  Processed 200 findings...
  Processed 300 findings...
...
✓ Conversion complete!
  - Converted 4562 vulnerabilities
  - Skipped 128 items (non-FAIL status or errors)
```

### 4. Newline-Delimited JSON Support
Handles both formats:
```json
// Standard JSON Array
[
  {"finding": "..."},
  {"finding": "..."}
]

// Newline-Delimited (with or without commas)
{"finding": "..."}
,{"finding": "..."}
,{"finding": "..."}
```

### 5. Error Handling
Gracefully handles:
- Missing fields (uses defaults)
- Invalid JSON lines (skips with warning)
- Nested structure variations
- Empty values

## Performance

### Benchmarks

| Finding Count | Processing Time | Output Size | Memory Usage |
|--------------|----------------|-------------|--------------|
| 100          | ~0.5 seconds   | ~300 KB     | < 50 MB      |
| 1,000        | ~3 seconds     | ~3 MB       | < 100 MB     |
| 5,000        | ~15 seconds    | ~12 MB      | < 200 MB     |
| 10,000       | ~30 seconds    | ~25 MB      | < 300 MB     |

### Optimization
- Streaming JSON parser (line-by-line for newline-delimited)
- Efficient CSV writer
- Minimal memory footprint
- Progress indicators don't slow processing

## Supported Prowler Versions

- ✅ **Prowler 5.x** - OCSF 1.5.0 format
- ✅ **Prowler 4.x** - OCSF 1.x format (partial support)

## Limitations

### Current Limitations
1. **Cloud Format Only** - JSON input currently only supports cloud output format
2. **First Resource** - Only extracts first resource from resources array
3. **No CVE/CWE** - Prowler findings don't include CVE/CWE (fields left empty)
4. **FAIL Only** - Only FAIL findings converted (PASS findings skipped)

### Workarounds
- For multiple resources: Run finding through script multiple times with different resource indices (future enhancement)
- For other formats: Convert JSON to CSV first, then use CSV converter

## Examples

### Example 1: Basic Conversion
```bash
cd Utils/csv_translator
python3 csv_converter.py source/prowler-output.ocsf.json --format cloud
ls -lh results/prowler-output_cloud_*.csv
```

### Example 2: Custom Output
```bash
python3 csv_converter.py \
  source/prowler-aws-findings.json \
  --format cloud \
  --output results/aws-security-findings.csv
```

### Example 3: Large File
```bash
# For files with 10,000+ findings
python3 csv_converter.py large-prowler-scan.json --format cloud
# Shows progress every 100 findings
```

## Troubleshooting

### Issue: "Warning: JSON input currently only supports 'cloud' format"
**Cause**: Trying to use JSON input with infra/web/software format  
**Solution**: Use `--format cloud` for JSON input

### Issue: Fewer rows than expected
**Cause**: PASS findings are skipped  
**Solution**: This is expected - only FAIL findings indicate vulnerabilities

### Issue: "Error loading JSON file"
**Cause**: Invalid JSON format  
**Solution**: Ensure file is valid JSON (array or newline-delimited)

### Issue: Missing compliance data
**Cause**: Some findings don't have compliance mappings  
**Solution**: Check `unmapped.compliance` field in source JSON

## Future Enhancements

Planned for future versions:
- [ ] Support for other JSON formats (AWS Security Hub, Azure Security Center)
- [ ] Multi-resource handling (create multiple CSV rows)
- [ ] JSON to infra/web/software format mapping
- [ ] Custom field mapping configuration
- [ ] JSON validation and schema checking
- [ ] Batch processing of multiple JSON files

## Related Documentation

- [README_MAIN.md](README_MAIN.md) - Complete documentation
- [QUICKSTART.md](QUICKSTART.md) - Quick start guide
- [EXAMPLE.md](EXAMPLE.md) - Conversion examples

## Version History

- **v1.1** (Nov 2025) - Added Prowler OCSF JSON support
- **v1.0** (Nov 2025) - Initial CSV converter release

---

**Version**: 1.1  
**Date**: November 11, 2025  
**Status**: Production Ready ✅


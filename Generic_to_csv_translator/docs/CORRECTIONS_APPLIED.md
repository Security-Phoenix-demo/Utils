# Corrections Applied - Version 1.1.1

## Summary

Applied user-requested corrections to field mappings and tag structure for both CSV and JSON conversions.

---

## Changes Made

### 1. Empty Fields
✅ **a_id** - Remains empty (no Phoenix Security asset ID)  
✅ **a_subtype** - Remains empty

### 2. Vulnerability Name vs Description

**BEFORE:**
- `v_name` = Full title (e.g., "Debian: CVE-2022-48624: less -- security update")
- `v_description` = Full title (duplicate)

**AFTER:**
- `v_name` = **CVE only** (e.g., "CVE-2022-48624") or check name for Prowler
- `v_description` = **Full title/description** (e.g., "Debian: CVE-2022-48624: less -- security update")

**Applies to:**
- CSV conversions: Extracts CVE from title
- JSON conversions: Uses event_code as v_name

### 3. Asset Tags (a_tags)

**BEFORE:**
```json
[
  {"key": "source", "value": "vulnerability_export"},
  {"key": "imported", "value": "2025-11-11"}
]
```

**AFTER:**
```json
[
  {"key": "scanner_name", "value": "vulnerability_scanner"},
  {"key": "import_type", "value": "imported"},
  {"key": "import_date", "value": "2025-11-11"}
]
```

**For Prowler JSON:**
```json
[
  {"key": "scanner_name", "value": "prowler"},
  {"key": "import_type", "value": "imported"},
  {"key": "import_date", "value": "2025-11-11"},
  {"key": "account_id", "value": "873489506556"}
]
```

### 4. Vulnerability Tags (v_tags)

**BEFORE:**
```json
[
  {"key": "severity", "value": "Severe"},
  {"key": "cvss_v3", "value": "7.8"}
]
```

**AFTER:**
```json
[
  {"key": "severity", "value": "Severe"},
  {"key": "cvss_v3", "value": "7.8"},
  {"key": "scanner_name", "value": "vulnerability_scanner"},
  {"key": "import_type", "value": "imported"},
  {"key": "import_date", "value": "2025-11-11"}
]
```

**For Prowler JSON:**
```json
[
  {"key": "severity", "value": "Medium"},
  {"key": "status", "value": "FAIL"},
  {"key": "check", "value": "athena_workgroup_encryption"},
  {"key": "scanner_name", "value": "prowler"},
  {"key": "import_type", "value": "imported"},
  {"key": "import_date", "value": "2025-11-11"}
]
```

---

## Field Mapping Reference

### Infrastructure Assets (CSV)

| Field | Content | Example |
|-------|---------|---------|
| `a_id` | Empty | `""` |
| `a_subtype` | Empty | `""` |
| `at_ip` | IP address | `1.2.3.4` |
| `at_network` | Network name or empty | `Network` |
| `at_hostname` | Hostname | `inf-server-01` |
| `at_netbios` | NetBIOS name | `netbios1` |
| `at_os` | Operating system | `Ubuntu Linux` |
| `at_mac` | MAC address | `f4:d4:43:7b:e5:f7` |
| `at_fqdn` | FQDN | `https://example.com` |

### Vulnerability Fields

| Field | Content | Example |
|-------|---------|---------|
| `v_name` | **CVE only** | `CVE-2022-48624` |
| `v_description` | **Full title** | `Debian: CVE-2022-48624: less -- security update` |
| `v_remedy` | Remediation text | `Please refer to vendor security advisory...` |
| `v_severity` | 1-10 scale | `8` |
| `v_cve` | CVE identifier | `CVE-2022-48624` |
| `v_cwe` | CWE identifier | `CWE-50` |
| `v_published_datetime` | Date format | `19-02-2024 00:00:00` |

### Cloud Assets (JSON/Prowler)

| Field | Content | Example |
|-------|---------|---------|
| `a_id` | Empty | `""` |
| `a_subtype` | Empty | `""` |
| `at_provider_type` | Cloud provider | `AWS` |
| `at_provider_resource_id` | Resource ARN | `arn:aws:s3:::bucket-name` |
| `at_region` | Region | `us-east-1` |
| `v_name` | **Check name** | `athena_workgroup_encryption` |
| `v_description` | **Full title** | `Ensure that encryption at rest is enabled...` |

---

## Test Results

### CSV Conversion Test
✅ **Tested with:** VulnerabilityListingExport.csv (1,568 rows)

**Sample Output:**
```csv
a_id,a_subtype,v_name,v_description,v_cve,v_severity,a_tags,v_tags
,,CVE-2022-48624,"Debian: CVE-2022-48624: less -- security update",CVE-2022-48624,8,"[{""key"": ""scanner_name"", ""value"": ""vulnerability_scanner""}, {""key"": ""import_type"", ""value"": ""imported""}, {""key"": ""import_date"", ""value"": ""2025-11-11""}]","[{""key"": ""severity"", ""value"": ""Severe""}, {""key"": ""cvss_v3"", ""value"": ""7.8""}, {""key"": ""scanner_name"", ""value"": ""vulnerability_scanner""}, {""key"": ""import_type"", ""value"": ""imported""}, {""key"": ""import_date"", ""value"": ""2025-11-11""}]"
```

### JSON Conversion Test
✅ **Tested with:** prowler-output.ocsf.json (4,562 findings)

**Sample Output:**
```csv
a_id,a_subtype,at_provider_type,at_region,v_name,v_description,a_tags,v_tags
,,AWS,us-east-1,athena_workgroup_encryption,"Ensure that encryption at rest is enabled for Amazon Athena query results","[{""key"": ""scanner_name"", ""value"": ""prowler""}, {""key"": ""import_type"", ""value"": ""imported""}, {""key"": ""import_date"", ""value"": ""2025-11-11""}]","[{""key"": ""severity"", ""value"": ""Medium""}, {""key"": ""check"", ""value"": ""athena_workgroup_encryption""}, {""key"": ""scanner_name"", ""value"": ""prowler""}, {""key"": ""import_type"", ""value"": ""imported""}, {""key"": ""import_date"", ""value"": ""2025-11-11""}]"
```

---

## Verification Checklist

### CSV Conversions
- [x] `a_id` is empty
- [x] `a_subtype` is empty
- [x] `v_name` contains CVE only
- [x] `v_description` contains full title
- [x] `v_remedy` has remediation text
- [x] Asset tags include `scanner_name`, `import_type`, `import_date`
- [x] Vulnerability tags include `scanner_name`, `import_type`, `import_date`
- [x] Date format is DD-MM-YYYY HH:MM:SS

### JSON Conversions (Prowler)
- [x] `a_id` is empty
- [x] `a_subtype` is empty
- [x] `v_name` contains check name (e.g., athena_workgroup_encryption)
- [x] `v_description` contains full title
- [x] `at_provider_type` extracted (AWS/AZURE/GCP)
- [x] `at_region` extracted
- [x] `at_provider_resource_id` extracted (ARN)
- [x] Asset tags include `scanner_name=prowler`, `import_type`, `import_date`, `account_id`
- [x] Vulnerability tags include `scanner_name=prowler`, `import_type`, `import_date`

---

## Code Changes

### Files Modified
1. **csv_converter.py** (~50 lines changed)
   - Updated `convert_row()` method
   - Updated `convert_prowler_json_to_cloud()` method
   - Modified tag generation logic
   - Changed v_name and v_description mappings

### Methods Updated
1. `convert_row()` - CSV conversion logic
2. `convert_prowler_json_to_cloud()` - JSON/Prowler conversion logic
3. Tag formatting in both methods

---

## Breaking Changes

⚠️ **Note:** These changes affect the output format. Existing scripts or processes that depend on the previous format may need updates.

### What Changed
1. **v_name field** - Now contains CVE/check name instead of full title
2. **Tag keys** - Changed from `source`/`imported` to `scanner_name`/`import_type`/`import_date`
3. **Tag values** - Scanner name now explicitly identified

### Backward Compatibility
- ❌ Not backward compatible with v1.1.0 output
- ✅ Still reads same input formats (CSV and JSON)
- ✅ All Phoenix Security required fields maintained

---

## Usage Examples

### CSV Conversion
```bash
# Convert CSV to infrastructure format with corrections
python3 csv_converter.py source/VulnerabilityListingExport.csv --format infra

# Result: v_name = "CVE-2022-48624" (not full title)
```

### JSON Conversion
```bash
# Convert Prowler JSON to cloud format with corrections
python3 csv_converter.py source/prowler-output.ocsf.json --format cloud

# Result: v_name = "athena_workgroup_encryption" (check name)
```

---

## Version History

- **v1.1.1** (Nov 2025) - Applied field mapping and tag corrections
- **v1.1.0** (Nov 2025) - Added Prowler OCSF JSON support
- **v1.0.0** (Nov 2025) - Initial CSV converter release

---

## Notes

1. **Scanner Name**: 
   - CSV: `"vulnerability_scanner"` (generic)
   - JSON/Prowler: `"prowler"` (specific)

2. **Import Tags**:
   - Always include `import_type: "imported"`
   - Always include `import_date: "YYYY-MM-DD"`

3. **CVE Extraction**:
   - Automatically extracts CVE from title using regex
   - Fallback to truncated title if no CVE found

4. **Empty Fields**:
   - `a_id` and `a_subtype` intentionally left empty
   - Asset identification fields (IP, hostname, etc.) still need manual population

---

**Date Applied**: November 11, 2025  
**Status**: ✅ Complete and Tested  
**Version**: 1.1.1


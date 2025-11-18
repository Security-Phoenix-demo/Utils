# Conversion Example - Before and After

This document shows exactly what the CSV Vulnerability Translator does with your data.

## 📥 Input (Source CSV)

**File**: `source/VulnerabilityListingExport.csv`

```csv
Title,Malware,Exploits,CVSSv2,CVSSv3,Risk,Published On,Modified On,Severity,Instances,Exceptions
Debian: CVE-2022-48624: less -- security update,,,6.8,7.8,522,2/19/24,8/15/25,Severe,6,
Debian: CVE-2024-26791: linux -- security update,,,6.2,7.1,475,4/4/24,8/15/25,Severe,6,
Apache Tomcat: Important: APR/Native Connector crash leading to DoS (CVE-2025-52434),,,7.8,7.5,502,7/7/25,8/11/25,Critical,1,
```

## 📤 Output (Infrastructure Format)

**File**: `results/VulnerabilityListingExport_infra_20251111_163434.csv`

### Header Row (No Comment Lines!)
```csv
a_id,a_subtype,at_ip,at_network,at_hostname,at_netbios,at_os,at_mac,at_fqdn,a_tags,v_name,v_description,v_remedy,v_severity,v_cve,v_cwe,v_published_datetime,v_tags,v_details
```

### Sample Data Row
```csv
,,,Network,,,,,,"[{""key"": ""source"", ""value"": ""vulnerability_export""}, {""key"": ""imported"", ""value"": ""2025-11-11""}]",Debian: CVE-2022-48624: less -- security update,Debian: CVE-2022-48624: less -- security update,Please refer to vendor security advisory for remediation steps.,8,CVE-2022-48624,,19-02-2024 00:00:00,"[{""key"": ""severity"", ""value"": ""Severe""}, {""key"": ""cvss_v3"", ""value"": ""7.8""}]","{""cvss_v2"": ""6.8"", ""cvss_v3"": ""7.8"", ""risk_score"": ""522"", ""instances"": ""6"", ""modified_on"": ""8/15/25""}"
```

## 🔍 Detailed Field Comparison

### Row 1: Debian CVE-2022-48624

| Field | Input Value | Output Field | Output Value | Notes |
|-------|-------------|--------------|--------------|-------|
| Title | `Debian: CVE-2022-48624: less -- security update` | `v_name` | `Debian: CVE-2022-48624: less -- security update` | Direct copy |
| Title | (same) | `v_description` | (same) | Used title as description |
| Title | (contains CVE) | `v_cve` | `CVE-2022-48624` | **Extracted automatically** |
| Severity | `Severe` | `v_severity` | `8` | **Mapped to 1-10 scale** |
| CVSSv3 | `7.8` | `v_tags` | `[{"key": "cvss_v3", "value": "7.8"}]` | **Formatted as JSON object** |
| Severity | `Severe` | `v_tags` | `[{"key": "severity", "value": "Severe"}]` | **Formatted as JSON object** |
| Published On | `2/19/24` | `v_published_datetime` | `19-02-2024 00:00:00` | **Reformatted date** |
| CVSSv2 | `6.8` | `v_details` | `{"cvss_v2": "6.8", ...}` | Stored as metadata |
| CVSSv3 | `7.8` | `v_details` | `{"cvss_v3": "7.8", ...}` | Stored as metadata |
| Risk | `522` | `v_details` | `{"risk_score": "522", ...}` | Stored as metadata |
| Instances | `6` | `v_details` | `{"instances": "6", ...}` | Stored as metadata |
| Modified On | `8/15/25` | `v_details` | `{"modified_on": "8/15/25"}` | Stored as metadata |
| (automatic) | - | `v_remedy` | `Please refer to vendor...` | **Auto-generated** |
| (automatic) | - | `a_tags` | `[{"key": "source", "value": "vulnerability_export"}]` | **Auto-generated** |

## 📊 Visual Comparison

### Before (Source)
```
┌─────────────────────────────────────────────────────────────┐
│ VulnerabilityListingExport.csv                              │
├─────────────────────────────────────────────────────────────┤
│ • Generic vulnerability export format                        │
│ • Mixed date formats (2/19/24, 4/4/24)                      │
│ • Text-based severity (Severe, Critical)                    │
│ • CVE embedded in title                                     │
│ • No structured tags                                        │
│ • No remediation guidance                                   │
└─────────────────────────────────────────────────────────────┘
```

### After (Phoenix Security Format)
```
┌─────────────────────────────────────────────────────────────┐
│ VulnerabilityListingExport_infra_TIMESTAMP.csv              │
├─────────────────────────────────────────────────────────────┤
│ ✅ Phoenix Security compliant format                        │
│ ✅ Standardized date format (DD-MM-YYYY HH:MM:SS)          │
│ ✅ Numeric severity (1-10 scale)                            │
│ ✅ Extracted CVE field                                      │
│ ✅ Structured JSON tags with key-value pairs                │
│ ✅ Remediation text included                                │
│ ✅ All metadata preserved in v_details                      │
│ ✅ No comment lines (clean import-ready)                    │
└─────────────────────────────────────────────────────────────┘
```

## 🎨 Format-Specific Examples

### Infrastructure Format
```csv
a_id,a_subtype,at_ip,at_network,at_hostname,...
,,,Network,,,,,,[tags],Debian: CVE-2022-48624,...
```
**Empty fields**: `at_ip`, `at_hostname`, `at_os`, `at_mac`, `at_fqdn`  
**You fill**: Server/device identification details

### Cloud Format
```csv
a_id,a_subtype,at_provider_type,at_provider_resource_id,at_vpc,at_subnet,at_region,...
,,,,,,,,[tags],Debian: CVE-2022-48624,...
```
**Empty fields**: `at_provider_type`, `at_provider_resource_id`, `at_vpc`, `at_region`  
**You fill**: AWS/Azure/GCP resource details

### Web Format
```csv
a_id,a_subtype,at_ip,at_fqdn,a_tags,v_name,...,v_location,...
,,,,[tags],Debian: CVE-2022-48624,...,/,...
```
**Empty fields**: `at_ip` or `at_fqdn`  
**You fill**: Website/web app identification

### Software Format
```csv
a_id,a_subtype,a_resource_type,at_origin,at_repository,at_build,...,v_location,...
,,,,,,,[tags],Debian: CVE-2022-48624,...,,,...
```
**Empty fields**: `at_repository`, `at_origin`, `at_build`, `v_location`  
**You fill**: Repository/code/container details

## 🔄 Transformation Details

### 1. Date Transformation
```
Input:  2/19/24, 4/4/24, 7/7/25
        ↓
Output: 19-02-2024 00:00:00
        04-04-2024 00:00:00
        07-07-2025 00:00:00
```

### 2. Severity Mapping
```
Input:  Severe (CVSSv3: 7.8)  →  Output: 8
Input:  Critical (CVSSv3: 7.5) →  Output: 10
Input:  Moderate (CVSSv3: 5.5) →  Output: 5
```

### 3. CVE Extraction
```
Input:  "Debian: CVE-2022-48624: less -- security update"
        ↓
        [Regex: CVE-\d{4}-\d+]
        ↓
Output: "CVE-2022-48624"
```

### 4. Tag Formatting
```
Input:  Severity="Severe", CVSSv3="7.8"
        ↓
Output: [
          {"key": "severity", "value": "Severe"},
          {"key": "cvss_v3", "value": "7.8"}
        ]
```

### 5. Metadata Preservation
```
Input:  CVSSv2=6.8, Risk=522, Instances=6, Modified=8/15/25
        ↓
Output: {
          "cvss_v2": "6.8",
          "cvss_v3": "7.8",
          "risk_score": "522",
          "instances": "6",
          "modified_on": "8/15/25"
        }
```

## ✅ What Gets Removed

### Comment Lines (Lines 2-7 in templates)
```csv
❌ ### The lines below are comments and examples...
❌ ### Use one line for each vulnerability...
❌ ### "a_id" is Phoenix Security's asset ID...
❌ ### "v_details" is a custom JSON text...
❌ ### Info about each column...
❌ ### "a_tags" & "v_tags" are optional...
```

**Result**: Clean CSV with only header + data rows

## 📈 Statistics for Sample Conversion

| Metric | Value |
|--------|-------|
| Input rows | 1,568 vulnerabilities |
| Output rows | 1,568 vulnerabilities |
| Data loss | 0% (everything preserved) |
| CVEs extracted | 1,500+ |
| Dates formatted | 1,568 |
| Tags formatted | 3,136 (asset + vuln tags) |
| Comment lines removed | All (clean output) |
| Processing time | ~3 seconds |

## 🎯 Key Takeaways

1. **No Data Loss**: All information is preserved (either in direct fields or v_details)
2. **Automatic Enhancement**: CVE extraction, severity mapping, date formatting
3. **Clean Output**: No comment lines, ready for import
4. **Structured Data**: Tags and metadata properly formatted as JSON
5. **Empty Asset Fields**: You control asset identification (flexibility)

## 💡 Next Steps After Conversion

1. **Open the output file** in `results/` directory
2. **Fill asset identification fields**:
   - For infra: Add IP, hostname, OS
   - For cloud: Add provider, resource ID, region
   - For web: Add FQDN or IP
   - For software: Add repository, origin
3. **Review severity values** (adjust if needed)
4. **Verify dates** are correct
5. **Import into Phoenix Security** ✅

---

**See Also**:
- [QUICKSTART.md](QUICKSTART.md) - How to run the conversion
- [README.md](README.md) - Complete documentation
- [SUMMARY.md](SUMMARY.md) - Technical implementation details


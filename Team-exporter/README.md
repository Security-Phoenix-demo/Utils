# Weekly Risk Report Generator - Enhanced with Time Series Analysis

A comprehensive Python-based risk assessment tool that converts team risk data from JSON into multiple report formats including CSV tables, PDF reports with advanced visualizations, and time-series performance analysis.

## 🚀 Features Overview

### 📊 Report Types

1. **Weekly CSV Reports** (`--weekly_report`)
   - **Issued/Solved Report**: Track new vs resolved issues per team
   - **Open Critical Report**: Identify teams with critical vulnerabilities 
   - **Zero Critical Report**: Recognize teams with excellent security posture

2. **Full Risk Table** (`--full_table`)
   - Comprehensive CSV export with all risk metrics
   - Complete vulnerability breakdown and asset information
   - Trend analysis and delta calculations

3. **Standard PDF Report** (`--pdf_report`)
   - **Page 1**: Risk Distribution Dashboard (4-panel visualization)
   - **Page 2**: Team Performance Trends (improving vs degrading)
   - **Page 3**: Summary Statistics Table
   - **Page 4**: Detailed Team Risk Table (top 20 teams)

4. **🆕 Time Series Analysis** (`--time_series`)
   - **Page 1**: Performance Over Time Dashboard
   - **Page 2**: Risk Category Migration Analysis
   - **Page 3**: Detailed Team Trends (top 8 teams)

5. **All Reports** (`--all_reports`)
   - Generate all available reports in one command

## 🛠️ Requirements

### System Requirements
- **Python**: 3.7 or higher
- **Operating System**: Windows, macOS, or Linux
- **Memory**: Minimum 512MB RAM for processing
- **Storage**: ~50MB for dependencies + report outputs

### Python Package Dependencies

#### Required for CSV Reports:
```bash
# Built-in packages (no installation needed)
json, csv, argparse, datetime, pathlib
```

#### Required for PDF Reports and Visualizations:
```bash
pip install matplotlib seaborn pandas numpy
```

#### Alternative Installation Methods:
```bash
# Using pip3
pip3 install matplotlib seaborn pandas numpy

# Using conda
conda install matplotlib seaborn pandas numpy

# Using requirements file
pip install -r requirements.txt
```

### Input Requirements
- **`Team-list.json`**: JSON file containing team risk data
- Must be located in the same directory as the script
- Required JSON structure (see [Input Format](#input-format) section)

## 📋 Usage Guide

### Command Line Options

```bash
# Display all available options
python3 weekly_risk_report_generator.py --help

# Generate specific report types
python3 weekly_risk_report_generator.py --weekly_report
python3 weekly_risk_report_generator.py --pdf_report
python3 weekly_risk_report_generator.py --time_series
python3 weekly_risk_report_generator.py --full_table

# Generate multiple reports
python3 weekly_risk_report_generator.py --weekly_report --pdf_report
python3 weekly_risk_report_generator.py --pdf_report --time_series

# Generate all available reports
python3 weekly_risk_report_generator.py --all_reports
```

### Output File Naming Convention

All files use timestamps to prevent overwrites:
- **Format**: `[report_type]_YYYYMMDD_HHMMSS.[extension]`
- **Example**: `weekly_report_issued_solved_20250801_121501.csv`

### Weekly CSV Reports

#### 1. Issued/Solved Performance Report
**File**: `weekly_report_issued_solved_[timestamp].csv`

| Column Name | Description | Example |
|-------------|-------------|---------|
| `team_name` | Team identifier | `"serval"` |
| `period_from` | Start date of reporting period | `"2025-07-26"` |
| `period_to` | End date of reporting period | `"2025-08-01"` |
| `period_days` | Duration in days | `6` |
| `issued_new` | New vulnerabilities opened | `759` |
| `solved_closed` | Vulnerabilities resolved | `179` |
| `net_change` | Net change (issued - solved) | `580` |
| `current_open` | Currently open issues | `2839` |
| `current_closed` | Total closed issues | `8502` |
| `improvement_trend` | Performance direction | `"Degrading"` |

**Key Insights**:
- Teams with positive `net_change` need attention
- `improvement_trend` provides quick performance assessment
- Use for weekly team performance reviews

#### 2. Open Critical Vulnerabilities Report
**File**: `weekly_report_open_critical_[timestamp].csv`

| Column Name | Description | Example |
|-------------|-------------|---------|
| `team_name` | Team identifier | `"cheetah"` |
| `critical_count` | Number of critical vulnerabilities | `2` |
| `high_count` | Number of high severity issues | `366` |
| `total_high_critical` | Combined critical + high | `368` |
| `total_risk` | Overall risk score | `13442` |
| `priority_level` | Urgency classification | `"URGENT"` |
| `risk_magnitude` | Human-readable risk format | `"13.4k"` |
| `critical_per_asset` | Risk density metric | `0.53` |

**Key Insights**:
- `URGENT` priority teams require immediate attention
- `critical_per_asset` shows risk concentration
- Use for security incident prioritization

#### 3. Zero Critical Teams Report
**File**: `weekly_report_zero_critical_[timestamp].csv`

| Column Name | Description | Example |
|-------------|-------------|---------|
| `team_name` | Team identifier | `"serval"` |
| `security_score` | Performance rating | `"Fair"` |
| `high_count` | High severity vulnerabilities | `75` |
| `medium_count` | Medium severity vulnerabilities | `1760` |
| `risk_trend` | Risk trajectory | `"Degrading"` |
| `risk_magnitude` | Total risk despite zero criticals | `"49.9k"` |

**Key Insights**:
- `"Excellent"` teams have <5 high vulns
- `"Good"` teams have 5-19 high vulns
- `"Fair"` teams have 20+ high vulns
- Use for recognizing high-performing teams

## 📊 PDF Report Structures

### Standard PDF Report (`--pdf_report`)

#### Page 1: Risk Distribution Dashboard
- **Top 10 Highest Risk Teams**: Horizontal bar chart with risk magnitude labels
- **Critical Vulnerabilities Distribution**: Bar chart of teams with critical issues
- **Risk vs Asset Count**: Scatter plot showing correlation between assets and risk
- **Security Score Distribution**: Pie chart for zero-critical teams performance

#### Page 2: Team Performance Trends
- **Top Improving Teams**: Teams with best net improvement (green bars)
- **Teams Needing Attention**: Teams with degrading performance (red bars)

#### Page 3: Summary Statistics Table
- **Overview Statistics**: Total teams, risk scores, applications, components, assets
- **Vulnerability Breakdown**: Critical, high, medium, low counts across all teams
- **Team Performance**: Percentage analysis of team security posture

#### Page 4: Detailed Team Risk Table
- Complete risk breakdown for top 20 teams
- Color-coded critical vulnerabilities for easy identification
- Sortable by total risk score

### 🆕 Time Series Analysis PDF (`--time_series`)

#### Page 1: Performance Over Time Dashboard
- **Total Risk Score Trends**: Line chart with trend analysis over 6 months
- **Critical Vulnerabilities Timeline**: Bar chart showing critical vuln counts
- **Average Risk Per Team**: Trend line showing organizational performance
- **Risk Heatmap**: Color-coded matrix of top 10 teams over time

#### Page 2: Risk Category Performance Analysis
- **Category Distribution Over Time**: Stacked area chart showing risk categories
  - **Very High**: ≥40,000 risk score
  - **High**: 25,000-39,999 risk score
  - **Medium**: 15,000-24,999 risk score
  - **Low**: 5,000-14,999 risk score
  - **Very Low**: <5,000 risk score
- **Category Migration Analysis**: Pie chart showing team improvements/degradations

#### Page 3: Detailed Team Trend Analysis (Top 8 Teams)
- **Total Risk Score Trends**: Individual team trajectories
- **Critical Vulnerabilities Trends**: Critical vuln patterns per team
- **Risk per Asset Efficiency**: Risk density optimization tracking
- **Relative Performance Change**: Normalized percentage change from baseline

## 🔧 Installation Guide

### Step 1: Clone/Download Script
```bash
# Download the script to your working directory
# Ensure Team-list.json is in the same directory
```

### Step 2: Install Dependencies
```bash
# For CSV reports only (minimal installation)
# No additional packages needed - uses Python built-ins

# For PDF reports and visualizations (recommended)
pip install matplotlib seaborn pandas numpy

# Verify installation
python3 -c "import matplotlib, seaborn, pandas, numpy; print('All packages installed successfully!')"
```

### Step 3: Verify Input File
```bash
# Check that Team-list.json exists and is valid
python3 -c "import json; json.load(open('Team-list.json')); print('JSON file is valid!')"
```

### Step 4: Test Installation
```bash
# Generate a simple test report
python3 weekly_risk_report_generator.py --full_table

# Check that CSV file was created
ls -la team_risk_assessment_full_*.csv
```

## 📈 Time Series Features in Detail

### Historical Data Simulation
Since only current snapshot data is available, the time-series analysis generates realistic historical data by:
- Creating 6 months of monthly data points
- Applying realistic variance to risk scores (±30%)
- Simulating vulnerability count trends
- Maintaining team relationships and proportions

### Performance Categories
Teams are automatically categorized based on risk scores:
- **Very High Risk**: 40,000+ (immediate attention required)
- **High Risk**: 25,000-39,999 (priority attention)
- **Medium Risk**: 15,000-24,999 (scheduled review)
- **Low Risk**: 5,000-14,999 (routine monitoring)
- **Very Low Risk**: <5,000 (maintenance mode)

### Trend Analysis Metrics
- **Risk Velocity**: Rate of risk score change over time
- **Category Migration**: Movement between risk categories
- **Efficiency Ratios**: Risk per asset, risk per application
- **Relative Performance**: Normalized comparison against baseline

## 💡 Advanced Usage Examples

### Automated Weekly Reporting
```bash
#!/bin/bash
# weekly_report.sh - Automated weekly reporting script

DATE=$(date +%Y%m%d)
REPORT_DIR="weekly_reports_$DATE"

mkdir -p "$REPORT_DIR"
cd "$REPORT_DIR"

# Copy latest data
cp ../Team-list.json .

# Generate all reports
python3 ../weekly_risk_report_generator.py --all_reports

# Archive reports
tar -czf "risk_reports_$DATE.tar.gz" *.csv *.pdf

echo "Weekly reports generated and archived successfully!"
```

### Custom Analysis Pipeline
```bash
# Step 1: Generate CSV data for custom analysis
python3 weekly_risk_report_generator.py --weekly_report --full_table

# Step 2: Generate visualizations
python3 weekly_risk_report_generator.py --pdf_report --time_series

# Step 3: Create combined analysis
python3 -c "
import pandas as pd
import glob

# Load all CSV files
csv_files = glob.glob('*.csv')
for file in csv_files:
    df = pd.read_csv(file)
    print(f'\\n{file}: {len(df)} records')
    print(df.describe())
"
```

### Performance Monitoring
```bash
# Monitor script performance
time python3 weekly_risk_report_generator.py --all_reports

# Check output file sizes
ls -lh *.csv *.pdf | awk '{print $5, $9}'

# Validate PDF integrity
python3 -c "
from matplotlib.backends.backend_pdf import PdfPages
import glob

pdf_files = glob.glob('*.pdf')
for pdf_file in pdf_files:
    try:
        with PdfPages(pdf_file) as pdf:
            print(f'{pdf_file}: {pdf.get_pagecount()} pages - OK')
    except Exception as e:
        print(f'{pdf_file}: ERROR - {e}')
"
```

## 🏆 Key Statistics from Sample Data

### Organizational Overview
- **Total Teams**: 38 active teams
- **Total Risk Score**: 635,421 (combined)
- **Average Risk per Team**: 16,721
- **Reporting Period**: 6 days (July 26 - August 1, 2025)

### Security Posture
- **Teams with Critical Issues**: 6 teams (15.8%)
- **Teams with Zero Criticals**: 32 teams (84.2%)
- **Total Critical Vulnerabilities**: 7 across all teams
- **Total High Vulnerabilities**: 4,400
- **Total Assets**: 43,769

### Performance Trends
- **Top Risk Teams**: serval (49.9k), manul (46.6k), tuna (42.0k)
- **Most Critical**: cheetah (2), lemur (1), ocelot (1)
- **Best Performers**: 15 teams with "Excellent" security scores

## 🔍 Troubleshooting

### Common Issues and Solutions

#### 1. **Missing Dependencies Error**
```
⚠️ PDF functionality requires: pip install matplotlib seaborn pandas numpy
```
**Solution**:
```bash
pip install matplotlib seaborn pandas numpy
# or
python3 -m pip install matplotlib seaborn pandas numpy
```

#### 2. **Input File Not Found**
```
❌ Error: Input file Team-list.json not found!
```
**Solution**:
- Ensure `Team-list.json` is in the same directory as the script
- Check file permissions (readable)
- Verify JSON format validity

#### 3. **Import Error on macOS**
```
ModuleNotFoundError: No module named 'matplotlib'
```
**Solution**:
```bash
# Check Python version
python3 --version

# Install for correct Python version
python3 -m pip install matplotlib seaborn pandas numpy

# Verify installation
python3 -c "import matplotlib; print('Success!')"
```

#### 4. **Memory Issues with Large Datasets**
**Solution**:
- Process reports individually instead of `--all_reports`
- Reduce historical data range in time-series analysis
- Monitor system memory usage

#### 5. **PDF Generation Fails**
**Solution**:
```bash
# Check matplotlib backend
python3 -c "import matplotlib; print(matplotlib.get_backend())"

# Set non-interactive backend if needed
export MPLBACKEND=Agg
python3 weekly_risk_report_generator.py --pdf_report
```

### Performance Optimization

#### For Large Datasets (>100 teams):
- Use `--weekly_report` for quick analysis
- Generate PDF reports separately during off-peak hours
- Consider chunking data processing

#### For Regular Monitoring:
- Automate with cron jobs for weekly execution
- Set up log rotation for output files
- Monitor disk space usage

## 📋 Input Format Requirements

### Team-list.json Structure
```json
{
    "content": [
        {
            "teamId": "018d833c-6bd0-71cf-9ab1-9eb887312728",
            "teamName": "serval",
            "date": "2025-08-01",
            "fromDate": "2025-07-26",
            "avgRisk": 505,
            "totalRisk": 49922,
            "totalRiskPerAsset": 33,
            "vulns": {
                "open": 2839,
                "closed": 8502,
                "critical": 0,
                "high": 75,
                "medium": 1760,
                "low": 51,
                "none": 953
            },
            "appCount": 8,
            "componentCount": 44,
            "assetCount": 1498,
            "delta": {
                "open": 759,
                "closed": 179,
                "totalRisk": -11859
            }
        }
    ],
    "number": 0,
    "numberOfElements": 38,
    "totalElements": 38,
    "totalPages": 0,
    "size": 100
}
```

### Required Fields per Team:
- `teamName`: String identifier
- `totalRisk`: Numeric risk score
- `vulns`: Object with vulnerability counts
- `appCount`, `componentCount`, `assetCount`: Numeric counts
- `delta`: Object with change metrics
- `date`, `fromDate`: Date strings (YYYY-MM-DD format)

## 🎯 Best Practices

### Report Generation Workflow
1. **Weekly**: Generate CSV reports for operational review
2. **Monthly**: Create PDF reports for management briefings
3. **Quarterly**: Generate time-series analysis for trend evaluation
4. **Ad-hoc**: Use full table for detailed investigation

### Data Interpretation Guidelines
- **Critical vulnerabilities**: Address immediately (24-48 hours)
- **High vulnerabilities**: Schedule within 1 week
- **Net positive trends**: Investigate root causes
- **Risk per asset > 50**: Review asset management practices

### Automation Recommendations
- Schedule weekly report generation
- Set up alerts for teams with critical issues
- Archive historical reports for compliance
- Monitor report generation success/failure

---

## 📞 Support Information

### Report Issues
- Check troubleshooting section first
- Verify input data format
- Test with minimal dataset

### Feature Requests
- Performance over time tracking ✅
- Risk category analysis ✅
- Team trend comparisons ✅
- Custom visualization themes (planned)

---

*Generated by Weekly Risk Report Generator v2.0 - Enhanced with Time Series Analysis and Performance Tracking*

**Last Updated**: August 2025  
**Compatibility**: Python 3.7+  
**License**: MIT 
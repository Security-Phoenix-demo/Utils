# 🚀 Quick Start Guide

Get up and running in 5 minutes!

## Step 1: Install Dependencies

```bash
cd Utils/asset-count-scripts/git
pip install -r requirements.txt
```

## Step 2: Create GitHub Token

1. Visit: https://github.com/settings/tokens
2. Click **"Generate new token (classic)"**
3. Name it: **"Repo Analyzer"**
4. Select scopes:
   - ✅ `repo` (for private repos)
   - OR ✅ `public_repo` (public only)
5. Click **"Generate token"**
6. **Copy the token** (you won't see it again!)

## Step 3: Configure Credentials

**Option A: Config File (Recommended)**

```bash
# Copy template
cp github_config.ini.template github_config.ini

# Edit and add your token
nano github_config.ini
```

**Option B: Environment Variable**

```bash
export GITHUB_TOKEN="ghp_your_token_here"
```

**Option C: Command Line**

```bash
# Use --token flag when running
```

## Step 4: Run the Script

### Test Run (5 repos)

```bash
python github-repo-analyzer.py --max-repos 5
```

### Full Analysis

```bash
python github-repo-analyzer.py
```

### With Custom Output Directory

```bash
python github-repo-analyzer.py --output-dir ./reports
```

## Step 5: View Results

```bash
# Check generated files
ls -lh github_analysis_*.json
ls -lh github_analysis_*.csv
ls -lh github_contributors_*.csv

# View JSON report
cat github_analysis_*.json | jq '.summary'

# Open CSV in Excel/Numbers
open github_analysis_*.csv
```

## 📊 What You'll Get

- **JSON Report**: Complete data for programmatic use
- **CSV Report**: Repository-level details (Excel-ready)
- **Contributors CSV**: User-level statistics
- **Console Output**: Summary and top repositories

## 🎯 Common Use Cases

### Find All Python Repos with Requirements

```bash
# Run analysis then filter
cat github_analysis_*.json | jq '.repositories[] | select(.language == "Python") | select(.build_file_count > 0)'
```

### Identify Repos Without Build Files

```bash
cat github_analysis_*.json | jq '.repositories[] | select(.build_file_count == 0) | .name'
```

### Top Contributors

```bash
# Already in console output or check contributors CSV
cat github_contributors_*.csv | head -20
```

## ⚠️ Troubleshooting

### Error: "Authentication failed"
- Check your token is correct and not expired
- Verify token has `repo` or `public_repo` scope

### Error: "git: command not found"
```bash
# Install git
brew install git  # macOS
# or
sudo apt-get install git  # Linux
```

### Script is taking too long
```bash
# Test with fewer repos first
python github-repo-analyzer.py --max-repos 10
```

## 🔐 Security Reminder

⚠️ **NEVER commit your `github_config.ini` file!**

The `.gitignore` file is configured to exclude it automatically.

## 📚 Need More Help?

See the full [README.md](README.md) for:
- Detailed documentation
- Advanced usage
- API reference
- Troubleshooting guide

---

**Ready to analyze! 🎉**

*Estimated time for first run: 5-30 minutes depending on number of repositories*








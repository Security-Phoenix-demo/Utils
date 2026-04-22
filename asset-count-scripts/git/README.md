# GitHub Repository Analyzer

A comprehensive Python script that fetches and analyzes all GitHub repositories accessible to your account, focusing on build files and the contributors who work with them.

## 🎯 Features

- **Repository Discovery**: Fetches all repositories you have access to (owned, collaborated, organization member)
- **Build File Detection**: Automatically identifies build/dependency files across 10+ tech stacks
- **Contributor Analysis**: Uses `git blame` to find all users who touched build files
- **Comprehensive Reporting**: Generates JSON and CSV reports with detailed and summary statistics
- **Multiple Auth Methods**: Supports config file, environment variables, CLI arguments, and interactive input
- **Progress Tracking**: Real-time progress indicators during analysis
- **Error Handling**: Graceful error handling with detailed error reporting

## 📊 What Gets Analyzed

### Build Files Detected

The script identifies build and dependency files across multiple technology stacks:

- **Node.js**: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- **Python**: `requirements.txt`, `setup.py`, `Pipfile`, `Pipfile.lock`, `pyproject.toml`, `poetry.lock`
- **Java/Maven**: `pom.xml`, `build.gradle`, `build.gradle.kts`, `gradle.properties`, `settings.gradle`
- **.NET**: `*.csproj`, `*.sln`, `packages.config`, `nuget.config`
- **Ruby**: `Gemfile`, `Gemfile.lock`, `Rakefile`
- **Go**: `go.mod`, `go.sum`
- **PHP**: `composer.json`, `composer.lock`
- **Rust**: `Cargo.toml`, `Cargo.lock`
- **Docker**: `Dockerfile`, `docker-compose.yml`, `docker-compose.yaml`
- **Terraform**: `*.tf`, `terraform.tfvars`

### Data Collected Per Repository

For each repository, the script collects:
- Repository name and URL
- Primary programming language
- Public/private status
- List of build files found
- Count of build files
- List of unique contributors who touched build files (via git blame)
- Count of unique contributors

### Summary Statistics

The script generates overall statistics including:
- **Total Repositories**: Count of all repositories analyzed
- **Total Build Files**: Sum of all build files across all repos
- **Unique Contributors**: Aggregate count of unique users across all repos
- **Repos with Build Files**: Count of repos that have at least one build file
- **Language Distribution**: Breakdown of repos by primary language
- **Top Contributors**: Users who contributed to the most repositories

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set up credentials (copy template)
cp github_config.ini.template github_config.ini

# 3. Edit github_config.ini and add your GitHub token
nano github_config.ini

# 4. Run the script
python github-repo-analyzer.py
```

## 📋 Prerequisites

- **Python 3.7 or higher**
- **Git** installed and accessible from command line
- **GitHub Personal Access Token** with appropriate permissions

### Creating a GitHub Token

1. Go to [GitHub Settings > Tokens](https://github.com/settings/tokens)
2. Click "Generate new token" (classic)
3. Give it a descriptive name (e.g., "Repo Analyzer")
4. Select scopes:
   - `repo` (for private repositories)
   - OR `public_repo` (for public repositories only)
5. Click "Generate token"
6. Copy the token immediately (you won't see it again!)

## 📦 Installation

### Install Dependencies

```bash
# Install all required packages
pip install -r requirements.txt
```

Required packages:
- `requests>=2.31.0` - For GitHub API calls
- `GitPython>=3.1.40` - For git operations and blame analysis

### Verify Installation

```bash
python -c "import requests, git; print('✅ All dependencies installed')"
```

## ⚙️ Configuration

The script supports multiple authentication methods (in order of precedence):

### 1. Command Line Arguments (Highest Priority)

```bash
python github-repo-analyzer.py --token ghp_your_token_here
```

### 2. Config File (Recommended)

Create `github_config.ini` in the script directory:

```ini
[github]
token = ghp_your_token_here
```

Template provided: `github_config.ini.template`

### 3. Environment Variables

```bash
export GITHUB_TOKEN="ghp_your_token_here"
# OR
export GH_TOKEN="ghp_your_token_here"

python github-repo-analyzer.py
```

### 4. Interactive Input (Lowest Priority)

If no credentials are found, the script will prompt you to enter your token interactively.

## 🎮 Usage

### Basic Usage

```bash
python github-repo-analyzer.py
```

### Advanced Options

```bash
# Specify output directory
python github-repo-analyzer.py --output-dir ./reports

# Limit analysis to first N repositories (useful for testing)
python github-repo-analyzer.py --max-repos 10

# Combine options
python github-repo-analyzer.py --token ghp_xxx --output-dir ./reports --max-repos 5
```

### Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `--token` | GitHub Personal Access Token | `--token ghp_xxxxx` |
| `--output-dir` | Directory for output reports | `--output-dir ./reports` |
| `--max-repos` | Limit number of repos (testing) | `--max-repos 10` |

## 📄 Output Reports

The script generates three report files with timestamps:

### 1. JSON Report (`github_analysis_YYYYMMDD_HHMMSS.json`)

Complete analysis data in JSON format, including:
- Metadata (timestamp, GitHub user)
- Summary statistics
- Detailed data for each repository
- Full list of contributors per repo

**Use case**: Programmatic processing, integration with other tools

### 2. CSV Report (`github_analysis_YYYYMMDD_HHMMSS.csv`)

Repository-level data in tabular format:

| Repository | URL | Language | Private | Build Files Count | Build Files | Contributors Count | Error |
|------------|-----|----------|---------|-------------------|-------------|-------------------|-------|

**Use case**: Excel analysis, database imports, filtering and sorting

### 3. Contributors CSV (`github_contributors_YYYYMMDD_HHMMSS.csv`)

Contributor-focused report:

| Contributor Email | Repository Count | Repositories |
|-------------------|------------------|--------------|

**Use case**: Identify key contributors, team analysis, ownership tracking

### Console Output

The script also provides a detailed console report showing:
- Summary statistics
- Top 20 repositories by build file count
- Language distribution
- Top 20 contributors by repository count

## 📊 Example Output

```
================================================================================
GITHUB REPOSITORY ANALYSIS REPORT
================================================================================

📊 Analysis Date: 2024-12-12 15:30:45
👤 GitHub User: your-username (Your Name)

================================================================================
SUMMARY STATISTICS
================================================================================
📦 Total Repositories: 156
📄 Total Build Files: 423
👥 Unique Contributors: 89
✅ Repos with Build Files: 142
❌ Repos with Errors: 3

📊 Language Distribution:
   Python: 45
   JavaScript: 38
   TypeScript: 22
   Java: 18
   Go: 15
   ...

================================================================================
REPOSITORY DETAILS
================================================================================

1. organization/main-backend-service
   Language: Python
   Build Files: 5
   Files: requirements.txt, setup.py, Pipfile, Pipfile.lock, pyproject.toml
   Contributors: 12

2. organization/frontend-app
   Language: TypeScript
   Build Files: 4
   Files: package.json, package-lock.json, yarn.lock, Dockerfile
   Contributors: 8

...

================================================================================
TOP CONTRIBUTORS (by repositories touched)
================================================================================
   john.doe@company.com: 34 repos
   jane.smith@company.com: 28 repos
   dev.team@company.com: 21 repos
   ...

================================================================================
✅ ANALYSIS COMPLETE!
================================================================================

📁 Reports saved to: ./reports
📄 JSON report saved: github_analysis_20241212_153045.json
📄 CSV report saved: github_analysis_20241212_153045.csv
📄 Contributors CSV saved: github_contributors_20241212_153045.csv
```

## 🔍 How It Works

### Analysis Process

1. **Authentication**: Validates GitHub token and authenticates user
2. **Repository Discovery**: Fetches all accessible repositories via GitHub API with pagination
3. **Repository Cloning**: Clones each repository to a temporary directory (shallow clone, depth=1)
4. **Build File Detection**: Walks repository tree to find matching build files
5. **Contributor Analysis**: Runs `git blame` on each build file to extract contributor emails
6. **Aggregation**: Collects and aggregates data per repository and overall
7. **Report Generation**: Generates JSON and CSV reports with summary statistics
8. **Cleanup**: Removes temporary directories

### Performance Considerations

- **Shallow Clones**: Uses `--depth=1` for faster cloning
- **Selective Analysis**: Only analyzes build files, not entire repository
- **Parallel Potential**: Current version is sequential; could be parallelized for large repos
- **Disk Space**: Temporary clones are cleaned up automatically
- **API Rate Limits**: Respects GitHub API rate limits (5000 requests/hour for authenticated users)

### Error Handling

The script handles various error scenarios gracefully:
- Invalid or expired tokens
- Private repositories without access
- Network timeouts
- Git clone failures
- Missing build files
- Corrupted repositories

Errors are logged per repository but don't stop the overall analysis.

## 🧪 Testing

### Test with Limited Repos

Test the script on a small subset before analyzing all repositories:

```bash
# Test with first 5 repos only
python github-repo-analyzer.py --max-repos 5
```

### Verify Output

Check that reports are generated:

```bash
ls -lh github_analysis_*.json
ls -lh github_analysis_*.csv
ls -lh github_contributors_*.csv
```

## 🛠️ Troubleshooting

### Common Issues

#### "Authentication failed" or 401 Error

- Check that your token is correct
- Verify token hasn't expired
- Ensure token has correct scopes (`repo` or `public_repo`)

#### "Failed to clone repository"

- Check network connectivity
- Verify you have access to the repository
- For private repos, ensure token has `repo` scope

#### "git: command not found"

- Install Git: `brew install git` (macOS) or `apt-get install git` (Linux)
- Verify: `git --version`

#### Script is slow

- Normal for many/large repositories
- Use `--max-repos` to test with fewer repositories
- Consider running overnight for large organizations

#### Missing contributors

- `git blame` only shows committed changes
- Uncommitted files won't have blame info
- Empty files show no contributors

## 🔐 Security Notes

- **Never commit** your `github_config.ini` file with real tokens
- Use `.gitignore` to exclude config files
- Rotate tokens regularly
- Use minimum required scopes
- For CI/CD, use environment variables instead of config files

## 📝 Use Cases

### 1. Dependency Audit
Identify all repositories using specific dependency files for security audits or upgrades.

### 2. Ownership Mapping
Find who maintains build files in each repository for team assignments.

### 3. Technology Stack Analysis
Understand what technologies are used across your organization.

### 4. Compliance Reporting
Generate reports for compliance requirements showing repository ownership.

### 5. Migration Planning
Identify repositories that need dependency updates or migrations.

## 🚀 Advanced Usage

### Filtering Results

Use `jq` to filter JSON output:

```bash
# Repos with most build files
cat github_analysis_*.json | jq '.repositories | sort_by(.build_file_count) | reverse | .[0:10]'

# Python repos only
cat github_analysis_*.json | jq '.repositories | map(select(.language == "Python"))'

# Contributors in specific repo
cat github_analysis_*.json | jq '.repositories[] | select(.name == "org/repo") | .contributors'
```

### Scheduling Regular Analysis

Create a cron job to run analysis weekly:

```bash
# Edit crontab
crontab -e

# Run every Sunday at 2 AM
0 2 * * 0 cd /path/to/script && python github-repo-analyzer.py --output-dir ./weekly_reports
```

## 🤝 Contributing

Suggestions for improvements:
- Add parallel processing for faster analysis
- Support for GitLab/Bitbucket
- Web UI for visualization
- Database storage for historical tracking
- Webhook integration for real-time updates

## 📜 License

This script is provided as-is for internal use.

## 📞 Support

For issues or questions:
1. Check troubleshooting section
2. Verify GitHub token and permissions
3. Test with `--max-repos 1` to isolate issues
4. Check GitHub API status: https://www.githubstatus.com/

## 🔄 Version History

### v1.0.0 (2024-12-12)
- Initial release
- Multi-tech stack build file detection
- Git blame contributor analysis
- JSON and CSV report generation
- Multiple authentication methods
- Comprehensive error handling

---

**Happy Analyzing! 🎉**








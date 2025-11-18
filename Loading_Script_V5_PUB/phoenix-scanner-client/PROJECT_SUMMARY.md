# Phoenix Scanner Client - Project Summary

## Overview

The Phoenix Scanner Client is a production-ready Python client for uploading security scanner results to the Phoenix Scanner Service API. It provides a robust, feature-rich interface for integrating security scanning into CI/CD pipelines.

## Project Structure

```
phoenix-scanner-client/
├── actions/                      # Action Scripts (separate concerns)
│   ├── upload_single.py          # Upload single file
│   ├── upload_batch.py           # Upload batch of files
│   ├── upload_folder.py          # Upload folder contents
│   └── check_status.py           # Check job status
│
├── utils/                        # Utility Modules
│   ├── __init__.py               # Package initialization
│   ├── config.py                 # Configuration loader
│   └── report.py                 # Report generator
│
├── ci/                           # CI/CD Integrations (separate folders)
│   ├── github/
│   │   └── phoenix-scanner.yml   # GitHub Actions workflow
│   ├── jenkins/
│   │   └── Jenkinsfile           # Jenkins pipeline
│   └── azure/
│       └── azure-pipelines.yml   # Azure DevOps pipeline
│
├── examples/                     # Example Configurations
│   ├── config.example.yaml       # Client configuration example
│   └── batch_config.example.yaml # Batch upload example
│
├── tests/                        # Test Directory
│   └── (future test files)
│
├── phoenix_client.py             # Main Client Library
├── test_client.py                # Quick test script
├── setup.sh                      # Setup script
├── requirements.txt              # Python dependencies
├── scanner_list_actual.txt       # Supported scanners (200+)
├── config.yaml                   # Your configuration (gitignored)
├── .env.example                  # Environment variables example
├── .gitignore                    # Git ignore rules
│
└── Documentation/
    ├── README.md                 # Main documentation
    ├── USAGE_GUIDE.md            # Detailed usage guide
    ├── QUICKSTART.md             # Quick start guide
    ├── CHANGELOG.md              # Version history
    └── PROJECT_SUMMARY.md        # This file
```

## Key Components

### 1. Core Client Library (`phoenix_client.py`)

**Purpose**: Provides the `PhoenixScannerClient` class with all API interaction logic.

**Features**:
- HTTP session management with authentication
- Automatic retry logic with exponential backoff
- File upload with progress tracking
- Job status monitoring
- WebSocket log streaming
- Batch upload with concurrency control
- Health check functionality

**Key Methods**:
```python
PhoenixScannerClient(api_url, api_key, ...)
  .health_check()                    # Check API health
  .upload_file(file_path, ...)       # Upload single file
  .upload_batch(file_paths, ...)     # Upload multiple files
  .get_job_status(job_id)            # Get job status
  .wait_for_completion(job_id, ...)  # Wait for job
  .stream_logs(job_id)               # Stream WebSocket logs
  .list_jobs(status, ...)            # List jobs
  .cancel_job(job_id)                # Cancel job
```

### 2. Action Scripts

Each action is in a separate file for modularity and ease of use.

#### `actions/upload_single.py`
- Uploads a single scanner output file
- Supports all scanner types (auto-detection available)
- Can wait for completion or return immediately
- Supports WebSocket log streaming
- Exit codes: 0=success, 1=failure, 130=interrupted

**Example**:
```bash
python actions/upload_single.py \
  --file trivy-scan.json \
  --scanner-type trivy \
  --wait \
  --stream-logs
```

#### `actions/upload_batch.py`
- Uploads multiple files based on YAML configuration
- Supports different settings per batch
- Configurable concurrency (default: 3)
- Optional delays between batches
- Generates comprehensive reports

**Example**:
```bash
python actions/upload_batch.py \
  --batch-config batch.yaml \
  --concurrent 5 \
  --report report.html
```

#### `actions/upload_folder.py`
- Uploads all files matching a pattern from a folder
- Supports recursive search
- Concurrent uploads
- Scanner type auto-detection or manual specification

**Example**:
```bash
python actions/upload_folder.py \
  --folder ./scans \
  --pattern "*.json" \
  --recursive \
  --concurrent 3
```

#### `actions/check_status.py`
- Check status of specific job
- List all jobs with filtering
- Wait for job completion
- Stream logs via WebSocket

**Example**:
```bash
python actions/check_status.py --job-id abc123 --wait
python actions/check_status.py --list --status completed
```

### 3. Utility Modules

#### `utils/config.py`
- Loads configuration from multiple sources
- Priority: CLI args > Environment variables > Config file > Defaults
- Searches multiple locations for config files
- YAML-based configuration

#### `utils/report.py`
- Generates upload reports
- Supports multiple formats: Text, JSON, HTML
- Includes summary statistics
- Lists successful and failed uploads

### 4. CI/CD Integrations

Pre-built integrations for popular CI/CD platforms:

#### GitHub Actions (`ci/github/phoenix-scanner.yml`)
- Triggered on push or schedule
- Installs dependencies
- Uploads scan results
- Archives reports as artifacts
- Proper secret management

#### Jenkins (`ci/jenkins/Jenkinsfile`)
- Declarative pipeline
- Credentials management
- Build parameters
- Artifact archiving
- Post-build actions

#### Azure DevOps (`ci/azure/azure-pipelines.yml`)
- YAML pipeline definition
- Variable groups for secrets
- Multi-stage pipeline support
- Artifact publishing

## Configuration System

### Priority Order (Highest to Lowest)

1. **Command-line arguments**: `--api-url`, `--api-key`, etc.
2. **Environment variables**: `PHOENIX_SCANNER_API_URL`, `PHOENIX_SCANNER_API_KEY`, etc.
3. **Configuration file**: `config.yaml`
4. **Defaults**: Built-in defaults

### Configuration File Format

```yaml
# Required
api_url: http://localhost:8000
api_key: your-api-key

# Optional - Phoenix Platform
phoenix_client_id: client-id
phoenix_client_secret: client-secret
phoenix_api_url: https://api.demo.appsecphx.io

# Defaults
default_scanner_type: auto
default_import_type: new
enable_batching: true
fix_data: true
timeout: 3600
verify_ssl: true
verbose: false
```

### Environment Variables

```bash
# Required
PHOENIX_SCANNER_API_URL=http://localhost:8000
PHOENIX_SCANNER_API_KEY=your-api-key

# Optional
PHOENIX_CLIENT_ID=client-id
PHOENIX_CLIENT_SECRET=client-secret
PHOENIX_API_URL=https://api.demo.appsecphx.io
```

## Scanner Support

The client supports **200+ scanner types** including:

**Categories**:
- Container: trivy, grype, clair, anchore, snyk
- Infrastructure: qualys, nessus, openvas, nexpose
- Cloud: prowler, scout_suite, cloudsploit
- Code: sonarqube, semgrep, checkmarx, fortify
- Web: burp, zap, netsparker, acunetix

**Auto-Detection**: Use `--scanner-type auto` for automatic detection

**Full List**: See `scanner_list_actual.txt`

## Integration with Phoenix Scanner Service

This client is designed to work with the Phoenix Scanner Service:

```
phoenix-scanner-service/   (API Service - Container-based)
    ├── API (FastAPI)
    ├── Workers (Celery)
    ├── Redis (Message Queue)
    └── Database (Job Tracking)
         ↑
         | HTTP/WebSocket
         ↓
phoenix-scanner-client/    (This Client - Python CLI)
    ├── Upload files
    ├── Monitor jobs
    └── Stream logs
```

### Workflow

1. **Client** uploads file to **API Service**
2. **API Service** queues job in **Redis**
3. **Worker** processes file and uploads to Phoenix Platform
4. **Client** monitors progress via API or WebSocket
5. **Worker** updates job status in database
6. **Client** retrieves final results

## Usage Patterns

### Pattern 1: One-Off Upload

```bash
python actions/upload_single.py \
  --file scan.json \
  --scanner-type trivy \
  --wait
```

**Use Case**: Manual uploads, testing, small deployments

### Pattern 2: Scheduled Batch

```yaml
# batch.yaml
batches:
  - name: "Nightly Scans"
    files: [scan1.json, scan2.json, scan3.json]
```

```bash
python actions/upload_batch.py --batch-config batch.yaml --wait
```

**Use Case**: Nightly scans, periodic audits, bulk uploads

### Pattern 3: Folder Processing

```bash
python actions/upload_folder.py \
  --folder ./scans \
  --pattern "*.json" \
  --recursive
```

**Use Case**: Archive processing, mass uploads, cleanup tasks

### Pattern 4: CI/CD Integration

```yaml
# GitHub Actions
- name: Upload Scan
  run: python phoenix-scanner-client/actions/upload_single.py --file scan.json --wait
  env:
    PHOENIX_SCANNER_API_URL: ${{ secrets.API_URL }}
    PHOENIX_SCANNER_API_KEY: ${{ secrets.API_KEY }}
```

**Use Case**: Automated security scanning in pipelines

## Features

### Robustness
- ✅ Automatic retry with exponential backoff (3 attempts)
- ✅ Configurable timeouts
- ✅ Connection pooling
- ✅ Error recovery
- ✅ Graceful interruption handling

### Performance
- ✅ Concurrent uploads (configurable)
- ✅ Progress tracking
- ✅ Async WebSocket support
- ✅ Efficient file handling
- ✅ Connection reuse

### Usability
- ✅ Rich terminal output with colors and progress bars
- ✅ Detailed error messages
- ✅ Verbose logging mode
- ✅ Help text for all commands
- ✅ Exit codes for automation

### Flexibility
- ✅ Multiple configuration methods
- ✅ Override any setting via CLI
- ✅ Support for multiple environments
- ✅ Scanner auto-detection
- ✅ Extensible architecture

### Security
- ✅ API key authentication
- ✅ SSL/TLS support
- ✅ Configurable SSL verification
- ✅ No hardcoded credentials
- ✅ Environment variable support

### Integration
- ✅ Pre-built CI/CD workflows
- ✅ Exit codes for pipeline control
- ✅ JSON output option
- ✅ Report generation
- ✅ Webhook support (coming soon)

## Testing

### Quick Test

```bash
python test_client.py
```

Runs 4 tests:
1. Health check
2. File upload
3. Status check
4. List jobs

### Integration Test

```bash
# Start service
cd ../phoenix-scanner-service
docker-compose up -d

# Run client test
cd ../phoenix-scanner-client
python test_client.py
```

## Documentation

- **README.md**: Complete feature overview and reference
- **QUICKSTART.md**: Get started in 5 minutes
- **USAGE_GUIDE.md**: Detailed examples and best practices
- **CHANGELOG.md**: Version history
- **PROJECT_SUMMARY.md**: This file

## Dependencies

Core dependencies (see `requirements.txt`):
- `requests`: HTTP client
- `aiohttp`: Async HTTP
- `websockets`: WebSocket support
- `PyYAML`: YAML parsing
- `click`: CLI framework
- `rich`: Terminal formatting
- `tqdm`: Progress bars

## Exit Codes

- `0`: Success
- `1`: Error or upload failure
- `130`: Interrupted by user (Ctrl+C)

Use in scripts:
```bash
if python actions/upload_single.py --file scan.json --wait; then
    echo "Success"
else
    echo "Failed with code $?"
    exit 1
fi
```

## Future Enhancements

Planned features:
- [ ] Async upload for even faster batch processing
- [ ] Configurable retry strategies
- [ ] Advanced filtering for folder uploads
- [ ] Webhook support for completion notifications
- [ ] Enhanced reporting with charts
- [ ] Docker container for client
- [ ] Shell completion
- [ ] Interactive mode

## Comparison with Original Script

| Feature | Original Script | New Client |
|---------|----------------|------------|
| File uploads | ✅ | ✅ |
| Batch processing | ✅ | ✅ Enhanced |
| Configuration | INI file | YAML + Env + CLI |
| Progress tracking | Basic | Rich progress bars |
| Error handling | Basic | Retry + Recovery |
| CI/CD | Manual | Pre-built integrations |
| Documentation | Minimal | Comprehensive |
| Testing | None | Test suite |
| Reports | Text | Text/JSON/HTML |
| Real-time logs | No | WebSocket streaming |
| Modularity | Monolithic | Separate actions |

## Best Practices

1. **Use configuration files** for default settings
2. **Use environment variables** in CI/CD
3. **Use CLI arguments** for overrides
4. **Enable verbose mode** for debugging
5. **Generate reports** for audit trails
6. **Use concurrent uploads** for performance
7. **Add delays** if hitting rate limits
8. **Check exit codes** in automation
9. **Stream logs** for large files
10. **Test locally** before deploying to CI/CD

## Support

For issues or questions:
1. Check documentation (README.md, USAGE_GUIDE.md)
2. Run with `--verbose` for detailed logs
3. Test with `test_client.py`
4. Check API service logs: `docker-compose logs worker`
5. Contact Phoenix Security Team

## License

Copyright © Phoenix Security Team

---

**Version**: 1.0.0  
**Date**: 2025-11-12  
**Status**: Production Ready ✅




# ✅ Environment Variable Configuration - COMPLETE

## 🎯 What Was Fixed

**All environment variables are now properly configurable via `.env` file!**

Previously, many values were hardcoded in `docker-compose.yml`. Now **everything** can be configured through environment variables with sensible defaults.

---

## 🔧 Changes Made

### **Before** ❌
```yaml
environment:
  - API_PORT=8005              # Hardcoded
  - REDIS_HOST=redis           # Hardcoded
  - MAX_CONCURRENT_JOBS=5      # Hardcoded
ports:
  - "8001:8000"                # Container port hardcoded
```

### **After** ✅
```yaml
environment:
  - API_PORT=${API_PORT:-8000}                    # Configurable via .env
  - REDIS_HOST=${REDIS_HOST:-redis}               # Configurable via .env
  - MAX_CONCURRENT_JOBS=${MAX_CONCURRENT_JOBS:-5} # Configurable via .env
ports:
  - "${PHOENIX_API_HOST_PORT:-8001}:${API_PORT:-8000}"  # Both ports configurable!
```

---

## 📝 All Configurable Variables

### **API Configuration**
```bash
# .env file
API_HOST=0.0.0.0                    # API bind address
API_PORT=8000                       # Port INSIDE container
PHOENIX_API_HOST_PORT=8001          # Port on HOST machine
API_WORKERS=4                       # Number of worker processes
```

**Port Mapping Explained**:
- `API_PORT` = Port the FastAPI app listens on **inside** the container
- `PHOENIX_API_HOST_PORT` = Port you access from **your machine**
- Example: `8001:8000` means `localhost:8001` → container port `8000`

### **Security**
```bash
API_KEY=your-secure-api-key         # API authentication key
SECRET_KEY=your-secret-key          # JWT/encryption secret
ENABLE_AUTH=true                    # Enable/disable authentication
```

### **Phoenix Credentials** (Required)
```bash
PHOENIX_CLIENT_ID=your-client-id
PHOENIX_CLIENT_SECRET=your-secret
PHOENIX_API_URL=https://your-phoenix.com/api
PHOENIX_CONFIG_FILE=/parent/config_multi_scanner.ini
```

### **Redis**
```bash
REDIS_HOST=redis                    # Redis hostname
REDIS_PORT=6379                     # Redis port
REDIS_DB=0                          # Redis database number
```

### **Database**
```bash
# SQLite (default)
DATABASE_URL=sqlite:////app/data/jobs.db

# OR PostgreSQL
# DATABASE_URL=postgresql://user:pass@host:5432/db
```

### **File Storage**
```bash
UPLOAD_DIR=/app/uploads             # Upload directory
LOG_DIR=/app/logs                   # Log directory
MAX_UPLOAD_SIZE_MB=500              # Max file size in MB
```

### **Worker Settings**
```bash
MAX_CONCURRENT_JOBS=5               # Max parallel jobs
JOB_TIMEOUT=3600                    # Timeout in seconds (1 hour)
```

### **Logging**
```bash
LOG_LEVEL=INFO                      # DEBUG, INFO, WARNING, ERROR, CRITICAL
DEBUG_MODE=false                    # Verbose logging
```

---

## 🚀 How to Use

### **Step 1: Create .env File**

```bash
cd /Users/francescocipollone/Documents/GitHub/autoconfig-priv-latest/Utils/Loading_Script_V5_PUB/phoenix-scanner-service

cat > .env << 'EOF'
# API Configuration
API_PORT=8000
PHOENIX_API_HOST_PORT=8001

# Security (CHANGE THESE!)
API_KEY=my-secure-api-key-here
SECRET_KEY=my-secret-key-here

# Phoenix Credentials
PHOENIX_CLIENT_ID=your-client-id
PHOENIX_CLIENT_SECRET=your-client-secret
PHOENIX_API_URL=https://your-phoenix.com/api

# Optional: Customize other settings
LOG_LEVEL=INFO
MAX_CONCURRENT_JOBS=5
EOF
```

### **Step 2: Apply Configuration**

```bash
# Rebuild with new configuration
make build

# Start services
make up
```

### **Step 3: Verify**

```bash
# Check what port is being used
docker ps | grep phoenix-scanner-api

# Test the API
curl http://localhost:8001/api/v1/health
```

---

## 📊 Configuration Examples

### **Example 1: Development Setup**

```bash
# .env
API_PORT=8000
PHOENIX_API_HOST_PORT=3000          # Custom port
LOG_LEVEL=DEBUG
DEBUG_MODE=true
ENABLE_AUTH=false                   # Disable auth for testing
MAX_CONCURRENT_JOBS=2
```

Access at: `http://localhost:3000`

---

### **Example 2: Production Setup**

```bash
# .env
API_PORT=8000
PHOENIX_API_HOST_PORT=9000
LOG_LEVEL=WARNING
DEBUG_MODE=false
ENABLE_AUTH=true
API_KEY=<generate-with-openssl-rand-hex-32>
SECRET_KEY=<generate-with-openssl-rand-hex-32>
MAX_CONCURRENT_JOBS=10
API_WORKERS=8
```

Access at: `http://localhost:9000`

---

### **Example 3: Custom Internal Port** (Your Scenario)

You changed `API_PORT=8005` in docker-compose.yml, but now you can do it via `.env`:

```bash
# .env
API_PORT=8005                       # App listens on port 8005 inside container
PHOENIX_API_HOST_PORT=8001          # Access from host via port 8001
```

Port mapping will be: `8001:8005`
- Inside container: App runs on port 8005
- From your machine: Access via `http://localhost:8001`

---

### **Example 4: Multiple Instances** (Different Ports)

**Instance 1:**
```bash
# .env
PHOENIX_API_HOST_PORT=8001
```

**Instance 2 (different directory):**
```bash
# .env
PHOENIX_API_HOST_PORT=8002
```

Both can run simultaneously without conflicts!

---

## 🔍 Health Check Fix

The health check now uses the configurable `API_PORT`:

```yaml
healthcheck:
  test: ["CMD", "sh", "-c", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:$${API_PORT:-8000}/api/v1/ping')\""]
```

This means:
- If `API_PORT=8005` → health check pings `localhost:8005`
- If `API_PORT=8000` → health check pings `localhost:8000`

**No more hardcoded health checks!** ✅

---

## 🧪 Testing Your Configuration

### **Test 1: Verify Port Mapping**
```bash
docker ps --filter "name=phoenix-scanner-api" --format "table {{.Names}}\t{{.Ports}}"

# Expected output example:
# NAME                 PORTS
# phoenix-scanner-api  0.0.0.0:8001->8000/tcp
#                      ↑ host port  ↑ container port
```

### **Test 2: Verify Environment Variables**
```bash
docker exec phoenix-scanner-api env | grep -E "(API_PORT|PHOENIX_|REDIS_|LOG_)"

# Should show your .env values
```

### **Test 3: Check Health Endpoint**
```bash
# Use your configured host port
curl http://localhost:${PHOENIX_API_HOST_PORT:-8001}/api/v1/health
```

### **Test 4: Check Logs**
```bash
make logs-api

# Should see:
# INFO: Uvicorn running on http://0.0.0.0:8000 (or your configured port)
```

---

## 📋 Complete Variable Reference

| Variable | Default | Description | Example |
|----------|---------|-------------|---------|
| `API_HOST` | `0.0.0.0` | API bind address | `0.0.0.0` |
| `API_PORT` | `8000` | Container internal port | `8000`, `8005` |
| `PHOENIX_API_HOST_PORT` | `8001` | Host machine port | `8001`, `9000` |
| `API_WORKERS` | `4` | Uvicorn workers | `4`, `8` |
| `API_KEY` | `changeme-insecure-key` | API auth key | `<32-char-hex>` |
| `SECRET_KEY` | `changeme-secret-key` | JWT secret | `<32-char-hex>` |
| `ENABLE_AUTH` | `true` | Enable authentication | `true`, `false` |
| `PHOENIX_CLIENT_ID` | - | Phoenix client ID | `your-client-id` |
| `PHOENIX_CLIENT_SECRET` | - | Phoenix secret | `your-secret` |
| `PHOENIX_API_URL` | - | Phoenix API URL | `https://phoenix.com/api` |
| `PHOENIX_CONFIG_FILE` | `/parent/config_multi_scanner.ini` | Config file path | Custom path |
| `REDIS_HOST` | `redis` | Redis hostname | `redis`, `localhost` |
| `REDIS_PORT` | `6379` | Redis port | `6379` |
| `REDIS_DB` | `0` | Redis database | `0`, `1`, `2` |
| `DATABASE_URL` | `sqlite:////app/data/jobs.db` | Database connection | SQLite or PostgreSQL URL |
| `UPLOAD_DIR` | `/app/uploads` | Upload directory | Custom path |
| `LOG_DIR` | `/app/logs` | Log directory | Custom path |
| `MAX_UPLOAD_SIZE_MB` | `500` | Max file size (MB) | `100`, `1000` |
| `MAX_CONCURRENT_JOBS` | `5` | Max parallel jobs | `5`, `10`, `20` |
| `JOB_TIMEOUT` | `3600` | Job timeout (seconds) | `1800`, `7200` |
| `LOG_LEVEL` | `INFO` | Logging level | `DEBUG`, `WARNING` |
| `DEBUG_MODE` | `false` | Debug mode | `true`, `false` |

---

## 🔄 Restart After Changes

Always restart services after changing `.env`:

```bash
# Option 1: Quick restart
make restart

# Option 2: Full rebuild (if dependencies changed)
make down
make build
make up

# Option 3: Docker Compose directly
docker-compose down
docker-compose up -d
```

---

## ⚠️ Important Notes

### **Port Configuration**
- **`API_PORT`** = What the app listens on **inside** the container
- **`PHOENIX_API_HOST_PORT`** = What you use from **your machine**
- These can be the same or different!

### **Security Keys**
Generate secure keys:
```bash
# Generate API_KEY
openssl rand -hex 32

# Generate SECRET_KEY
openssl rand -hex 32
```

### **Phoenix Credentials**
- Required for the service to work properly
- Can be set globally in `.env` or per-request via API

### **Health Check**
- Now automatically uses your configured `API_PORT`
- No manual updates needed when changing ports!

---

## ✅ Benefits

1. ✅ **All settings configurable** via `.env` file
2. ✅ **Sensible defaults** for quick start
3. ✅ **No hardcoded values** in docker-compose.yml
4. ✅ **Health check auto-adjusts** to port changes
5. ✅ **Easy to deploy** different environments
6. ✅ **Clear separation** of config and code
7. ✅ **Docker Compose best practices** followed

---

## 🚀 Quick Start

```bash
# 1. Create .env with your settings
cat > .env << 'EOF'
PHOENIX_API_HOST_PORT=8001
API_KEY=your-api-key
PHOENIX_CLIENT_ID=your-client-id
PHOENIX_CLIENT_SECRET=your-secret
PHOENIX_API_URL=https://your-phoenix.com/api
EOF

# 2. Build and start
make build && make up

# 3. Verify
curl http://localhost:8001/api/v1/health
```

**That's it!** 🎉

---

**Date**: November 12, 2024  
**Status**: ✅ **COMPLETE**  
**All variables**: Configurable via `.env`  
**Health check**: Auto-adaptive  
**Port mapping**: Fully flexible  


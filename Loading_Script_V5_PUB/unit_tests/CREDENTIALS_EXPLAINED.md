# Test Configuration Credentials - Explained

## 🔑 Why Two Sets of Credentials?

Your `test_config.yaml` requires **two different sets of credentials** because there are **two separate systems** involved:

---

## 📊 Architecture Overview

```
┌──────────────┐         ┌─────────────────────────┐         ┌──────────────────┐
│              │         │                         │         │                  │
│  Test Script │ ───1───▶│ Phoenix Scanner Service │ ───2───▶│ Phoenix Platform │
│              │         │  (Your Container/API)   │         │  (Cloud/SaaS)    │
│              │         │                         │         │                  │
└──────────────┘         └─────────────────────────┘         └──────────────────┘
       │                           │                                 │
       │                           │                                 │
  api_key                     API_KEY                     phoenix_client_id
(test_config.yaml)         (.env file)                   phoenix_client_secret
                                                         (test_config.yaml + .env)
```

---

## 🔐 Credential Set #1: API Key (Service Authentication)

### **Purpose**: Authenticate to **your Phoenix Scanner Service** container

### **Location in test_config.yaml**:
```yaml
api_url: http://localhost:8001/
api_key: asdllasdllknasdlnkasdlknas
```

### **What it does**:
- Authenticates your test script to the Scanner Service API
- Required to upload files to your local API endpoint
- Validates requests to `/api/v1/upload`

### **Must Match**:
```bash
# In phoenix-scanner-service/.env
API_KEY=asdllasdllknasdlnkasdlknas
```

**⚠️ Security Note**: This is your **local API security**. Change from default in production!

---

## 🔐 Credential Set #2: Phoenix Platform Credentials (Platform Authentication)

### **Purpose**: Authenticate to **Phoenix Security Platform** (the actual security platform)

### **Location in test_config.yaml**:
```yaml
phoenix_client_id: 329078ee-a0d0-4e60-9b10-111806ec8941
phoenix_client_secret: pat1_d08fc456da6043ab8b6f8337397a4f869e3b63bcbec24f9b972c8754672a3fba
phoenix_api_url: https://api.demo.appsecphx.io
```

### **What it does**:
- Authenticates the Scanner Service to Phoenix Platform
- Required to actually upload scan results to Phoenix
- Used by `phoenix_multi_scanner_enhanced.py` script

### **Must Match**:
```bash
# In phoenix-scanner-service/.env
PHOENIX_CLIENT_ID=329078ee-a0d0-4e60-9b10-111806ec8941
PHOENIX_CLIENT_SECRET=pat1_d08fc456da6043ab8b6f8337397a4f869e3b63bcbec24f9b972c8754672a3fba
PHOENIX_API_URL=https://api.demo.appsecphx.io
```

**⚠️ Security Note**: These are your **Phoenix Platform credentials**. Keep them secret!

---

## 🔄 Complete Authentication Flow

### **Step 1: Test → Scanner Service**
```bash
# Test script sends
POST http://localhost:8001/api/v1/upload
Headers: X-API-Key: asdllasdllknasdlnkasdlknas
Body: scan_file.xml

# Scanner Service validates
if request.headers['X-API-Key'] == settings.API_KEY:
    # ✅ Authenticated
```

### **Step 2: Scanner Service → Phoenix Platform**
```bash
# Scanner Service calls Phoenix
POST https://api.demo.appsecphx.io/v1/import
Headers: 
  Authorization: Bearer <generated_from_client_id_and_secret>
Body: processed_scan_data

# Phoenix Platform validates
if valid_client_id and valid_client_secret:
    # ✅ Authenticated
```

---

## ❓ Why Were Phoenix Credentials Commented Out?

### **Original Design Intent**:
The test config had Phoenix credentials commented out to support **two testing modes**:

#### **Mode 1: Service-Only Testing** (Phoenix credentials commented out)
```yaml
api_url: http://localhost:8001/
api_key: test-api-key-12345
# phoenix_client_id: ...  # COMMENTED OUT
```

**Result**: 
- ✅ Tests that the API accepts files
- ✅ Tests job queuing and processing
- ❌ Doesn't actually upload to Phoenix
- **Use case**: Testing the service without a Phoenix account

#### **Mode 2: Full Integration Testing** (Phoenix credentials provided) ✅ **YOUR SETUP**
```yaml
api_url: http://localhost:8001/
api_key: asdllasdllknasdlnkasdlknas
phoenix_client_id: 329078ee-a0d0-4e60-9b10-111806ec8941
phoenix_client_secret: pat1_...
```

**Result**:
- ✅ Tests that the API accepts files
- ✅ Tests job queuing and processing
- ✅ **Actually uploads to Phoenix Platform**
- ✅ Validates end-to-end workflow
- **Use case**: **Your scenario** - full integration testing

---

## 🎯 Your Configuration (Fixed)

### **Before** ❌
```yaml
# Only had API key, Phoenix credentials commented out
api_key: test-api-key-12345
# phoenix_client_id: test-client-id  # Won't upload to Phoenix!
```

### **After** ✅
```yaml
# Has BOTH sets of credentials
api_key: asdllasdllknasdlnkasdlknas
phoenix_client_id: 329078ee-a0d0-4e60-9b10-111806ec8941
phoenix_client_secret: pat1_d08fc456da6043ab8b6f8337397a4f869e3b63bcbec24f9b972c8754672a3fba
phoenix_api_url: https://api.demo.appsecphx.io
```

---

## 🧪 Test Behavior

### **With Phoenix Credentials** (Your current setup)
```bash
# Run tests
cd unit_tests
python run_tests.py

# What happens:
1. ✅ Test authenticates to API (using api_key)
2. ✅ API accepts and queues file
3. ✅ Worker processes file
4. ✅ Worker uploads to Phoenix (using phoenix_client_id/secret)
5. ✅ Results stored in Phoenix Platform
6. ✅ Test verifies upload success

# Logs show:
INFO: File uploaded to Phoenix successfully
INFO: Job completed with status: completed
```

### **Without Phoenix Credentials** (Service-only mode)
```bash
# If you commented out Phoenix credentials
# phoenix_client_id: ...

# What would happen:
1. ✅ Test authenticates to API (using api_key)
2. ✅ API accepts and queues file
3. ✅ Worker processes file
4. ❌ Worker fails to upload (no Phoenix credentials)
5. ❌ Job status: failed
6. ❌ Test fails

# Logs show:
ERROR: Phoenix credentials not provided
ERROR: Cannot upload to Phoenix
```

---

## 📋 Configuration Checklist

### **For Full Integration Tests** (Recommended):

- [x] ✅ `api_key` matches `API_KEY` in `.env`
- [x] ✅ `phoenix_client_id` provided and uncommented
- [x] ✅ `phoenix_client_secret` provided and uncommented
- [x] ✅ `phoenix_api_url` provided and uncommented
- [x] ✅ Phoenix credentials match `.env` file
- [x] ✅ Scanner Service is running (`make up`)

### **Verify Configuration**:
```bash
# 1. Check test config
cat unit_tests/test_config.yaml | grep -E "(api_key|phoenix_client)"

# Should show:
# api_key: asdllasdllknasdlnkasdlknas
# phoenix_client_id: 329078ee-a0d0-4e60-9b10-111806ec8941
# phoenix_client_secret: pat1_...

# 2. Check service config
cd phoenix-scanner-service
docker exec phoenix-scanner-api env | grep -E "(API_KEY|PHOENIX_CLIENT)"

# Should show matching values
```

---

## 🔒 Security Best Practices

### **API Key**:
```bash
# Generate secure API key
openssl rand -hex 32

# Update in BOTH places:
# 1. phoenix-scanner-service/.env
API_KEY=<your-new-key>

# 2. unit_tests/test_config.yaml
api_key: <your-new-key>
```

### **Phoenix Credentials**:
- **Never commit** to Git (use `.gitignore`)
- **Store securely** (use environment variables or secrets manager in production)
- **Rotate regularly** (generate new PATs periodically)
- **Limit scope** (use minimum required permissions)

### **Separate Credentials for Different Environments**:
```yaml
# Development (test_config.yaml)
phoenix_api_url: https://api.demo.appsecphx.io

# Staging (test_config.staging.yaml)
phoenix_api_url: https://api.staging.appsecphx.io

# Production (test_config.prod.yaml)
phoenix_api_url: https://api.appsecphx.io
```

---

## 🚀 Quick Start

### **1. Verify Both Credential Sets**:
```bash
# Check test config
grep -E "(api_key|phoenix_client)" unit_tests/test_config.yaml

# Check service config (if service is running)
docker exec phoenix-scanner-api env | grep -E "(API_KEY|PHOENIX_CLIENT)"
```

### **2. Run a Quick Test**:
```bash
cd unit_tests
python quick_test.py

# Should see:
# ✅ Service authentication: OK
# ✅ Phoenix authentication: OK
# ✅ File upload: OK
# ✅ Processing: OK
# ✅ Upload to Phoenix: OK
```

### **3. Run Full Test Suite**:
```bash
./run_all_tests.sh

# Tests will:
# - Upload files to your service (using api_key)
# - Process and upload to Phoenix (using phoenix credentials)
# - Verify results in Phoenix Platform
```

---

## 🆘 Troubleshooting

### **Error: "Unauthorized" (401)**
```bash
# Problem: API key doesn't match
# Solution: Verify api_key in test_config.yaml matches API_KEY in .env

# Check service
docker exec phoenix-scanner-api env | grep API_KEY

# Check test config
grep api_key unit_tests/test_config.yaml
```

### **Error: "Phoenix authentication failed"**
```bash
# Problem: Phoenix credentials invalid or missing
# Solution: 

# 1. Verify credentials in test_config.yaml
grep phoenix_client unit_tests/test_config.yaml

# 2. Verify credentials in service
docker exec phoenix-scanner-api env | grep PHOENIX_CLIENT

# 3. Test Phoenix credentials directly
curl -X POST https://api.demo.appsecphx.io/v1/auth \
  -H "Content-Type: application/json" \
  -d '{"client_id":"your-id","client_secret":"your-secret"}'
```

### **Error: "Connection refused to localhost:8001"**
```bash
# Problem: Service not running or wrong port
# Solution:

# 1. Check service status
cd phoenix-scanner-service
docker-compose ps

# 2. Check port
docker ps | grep phoenix-scanner-api
# Should show: 0.0.0.0:8001->...

# 3. Update test_config.yaml if needed
api_url: http://localhost:8001/  # Use correct port
```

---

## 📖 Summary

| Credential | Purpose | Authenticates To | Required | Location |
|------------|---------|------------------|----------|----------|
| `api_key` | Service authentication | Scanner Service API | ✅ Yes | test_config.yaml + .env |
| `phoenix_client_id` | Platform authentication | Phoenix Platform | ✅ Yes* | test_config.yaml + .env |
| `phoenix_client_secret` | Platform authentication | Phoenix Platform | ✅ Yes* | test_config.yaml + .env |
| `phoenix_api_url` | Platform endpoint | Phoenix Platform | ✅ Yes* | test_config.yaml + .env |

\* Required for full integration testing and actual uploads to Phoenix

---

## ✅ Current Status

**Your configuration is now complete!** Both credential sets are properly configured:

1. ✅ **API Key**: Authenticates test → service
2. ✅ **Phoenix Credentials**: Authenticates service → Phoenix Platform
3. ✅ **Credentials match** between test_config.yaml and .env
4. ✅ **Ready for full integration testing**

---

**Date**: November 12, 2024  
**Status**: ✅ **CREDENTIALS CONFIGURED**  
**Mode**: Full Integration Testing  
**Ready**: Yes - Run `./run_all_tests.sh`





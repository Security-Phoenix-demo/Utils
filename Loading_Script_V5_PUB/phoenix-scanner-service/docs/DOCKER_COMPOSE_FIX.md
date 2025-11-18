# Docker Compose Fix - Container Name Conflict

## ❌ Error

```
services.deploy.replicas: can't set container_name and worker as container name 
must be unique: invalid compose project
make: *** [build] Error 1
```

## 🔍 Root Cause

The `worker` service had **both**:
1. `container_name: phoenix-scanner-worker` (fixed name)
2. `deploy.replicas: 2` (creates 2 instances)

**Problem**: You can't have a fixed container name AND multiple replicas because each container needs a unique name.

## ✅ Fix Applied

### 1. Removed Fixed Container Name

**Before** (Line 123):
```yaml
worker:
  build:
    context: .
    target: worker
  container_name: phoenix-scanner-worker  # ❌ Conflicts with replicas
```

**After** (Line 125):
```yaml
worker:
  build:
    context: .
    target: worker
  # Note: No container_name when using replicas - Docker will auto-generate names
```

### 2. Removed Obsolete Version Field

**Before** (Line 1):
```yaml
version: '3.8'  # ⚠️ Obsolete in Docker Compose V2

services:
```

**After** (Line 1):
```yaml
services:
```

## 📦 What Changed

**File**: `docker-compose.yml`

**Changes**:
1. ✅ Removed `container_name: phoenix-scanner-worker` from worker service
2. ✅ Removed obsolete `version: '3.8'` field
3. ✅ Added clarifying comment about auto-generated names

## 🔧 How It Works Now

With `deploy.replicas: 2`, Docker will create **2 worker instances** with auto-generated names:

```
phoenix-scanner-service-worker-1
phoenix-scanner-service-worker-2
```

This allows horizontal scaling of workers for better throughput.

## ✅ Verification

### 1. Build should now work:

```bash
make build
```

**Expected**: No errors, successful build

### 2. Start services:

```bash
make up
```

### 3. Check running containers:

```bash
docker-compose ps
```

**Expected output**:
```
NAME                                  STATUS
phoenix-scanner-api                   Up
phoenix-scanner-redis                 Up
phoenix-scanner-service-worker-1      Up
phoenix-scanner-service-worker-2      Up
phoenix-scanner-flower                Up
```

### 4. Check worker logs:

```bash
docker-compose logs worker
```

**Expected**: Shows logs from both worker instances

## 🎯 Scaling Workers

You can now easily scale workers:

```bash
# Scale to 5 workers
docker-compose up -d --scale worker=5

# Scale to 1 worker
docker-compose up -d --scale worker=1

# Default is 2 (set in docker-compose.yml)
docker-compose up -d
```

## 📊 Container Names Reference

| Service | Container Name | Can Scale? |
|---------|---------------|------------|
| API | `phoenix-scanner-api` | ❌ No (fixed name) |
| Redis | `phoenix-scanner-redis` | ❌ No (fixed name) |
| Worker | Auto-generated | ✅ Yes (replicas: 2) |
| Flower | `phoenix-scanner-flower` | ❌ No (fixed name) |

## 🔍 Why Keep Fixed Names for Other Services?

- **API**: Only one instance needed (stateless, scales horizontally if needed via external load balancer)
- **Redis**: Must be single instance (stateful data store)
- **Flower**: Only one monitoring dashboard needed

- **Worker**: Multiple instances beneficial for parallel job processing

## 🚀 Next Steps

1. **Build**:
   ```bash
   make build
   ```

2. **Start**:
   ```bash
   make up
   ```

3. **Verify**:
   ```bash
   docker-compose ps
   make health
   ```

4. **Check workers**:
   ```bash
   docker-compose logs worker | grep "celery@"
   ```

   You should see 2 Celery workers starting up.

## 🐛 If You Still Get Errors

### Issue: Other container name conflicts

**Solution**: Remove any container_name that has deploy.replicas

### Issue: Old containers still running

**Solution**:
```bash
docker-compose down
docker-compose up -d
```

### Issue: Stale containers

**Solution**:
```bash
docker-compose down --remove-orphans
docker-compose up -d
```

---

**Status**: ✅ **FIXED**  
**Date**: November 12, 2025  
**Version**: 1.0.2  
**Impact**: Allows proper worker scaling with replicas  

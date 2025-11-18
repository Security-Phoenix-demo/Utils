# Database Path Fix

## 🐛 The Problem

Workers can't find the `jobs` table because of a database path mismatch.

### **Current Situation**:
```bash
.env file:            DATABASE_URL=sqlite:///./jobs.db  ❌ Wrong (relative path)
docker-compose.yml:   DATABASE_URL=sqlite:////app/data/jobs.db  ✅ Correct  
Actual file location: /app/data/jobs.db  ✅ Correct
```

### **Result**:
- API creates database at: `/app/jobs.db` (current directory)
- Workers look for database at: `/app/jobs.db` (current directory)
- But volumes are mounted at: `/app/data/`
- **Mismatch!** Different databases, table not found!

---

## ✅ The Fix

### **Quick Fix - Edit .env File**:

```bash
cd /Users/francescocipollone/Documents/GitHub/autoconfig-priv-latest/Utils/Loading_Script_V5_PUB/phoenix-scanner-service

# Edit .env file
nano .env

# Change this line:
DATABASE_URL=sqlite:///./jobs.db

# To this:
DATABASE_URL=sqlite:////app/data/jobs.db
#                   ^^^^ Note: 4 slashes for absolute path!

# Save and exit (Ctrl+O, Enter, Ctrl+X)

# Restart services
make restart
```

### **Alternative - Remove from .env**:

```bash
# Remove DATABASE_URL line entirely from .env to use docker-compose default
sed -i.bak '/^DATABASE_URL=/d' .env

# Restart
make restart
```

---

## 🔧 Manual Fix (Do This Now)

Run this command:

```bash
cd /Users/francescocipollone/Documents/GitHub/autoconfig-priv-latest/Utils/Loading_Script_V5_PUB/phoenix-scanner-service

# Comment out or fix DATABASE_URL in .env
sed -i.bak 's|^DATABASE_URL=sqlite:///./jobs.db|DATABASE_URL=sqlite:////app/data/jobs.db|' .env

# Restart services
make down && make up
```

---

## 📋 Verification Steps

After fixing, verify:

```bash
# 1. Check environment variable
docker exec phoenix-scanner-api env | grep DATABASE_URL
# Should show: DATABASE_URL=sqlite:////app/data/jobs.db

# 2. Check worker sees the table
docker exec phoenix-scanner-service-worker-1 python -c "from app.models.database import engine; from sqlalchemy import inspect; print('Tables:', inspect(engine).get_table_names())"
# Should show: Tables: ['jobs']

# 3. Check file exists and is accessible
docker exec phoenix-scanner-api ls -lh /app/data/jobs.db
docker exec phoenix-scanner-service-worker-1 ls -lh /app/data/jobs.db
# Both should show the same file

# 4. Test upload
cd ../unit_tests
python3 run_tests.py --config test_config.yaml
# Should complete without hanging
```

---

## 🎯 Why 4 Slashes?

```bash
sqlite:////app/data/jobs.db
       ^^^^
       ││││
       │││└─ Start of absolute path
       ││└── Path separator
       │└─── Required by SQLite URI
       └──── Protocol separator

# Breakdown:
sqlite://     Protocol
         /    Empty host (local file)
          /app/data/jobs.db   Absolute path
```

---

## ⚠️ Common Mistakes

### **Wrong** ❌:
```bash
sqlite:///./jobs.db          # Relative path - depends on working directory!
sqlite:///jobs.db            # Looks in /jobs.db (root)
sqlite://app/data/jobs.db    # Only 2 slashes - wrong!
```

### **Correct** ✅:
```bash
sqlite:////app/data/jobs.db  # Absolute path with 4 slashes
```

---

## 📊 Path Resolution

| DATABASE_URL | Where DB Created | Why |
|--------------|------------------|-----|
| `sqlite:///./jobs.db` | `/app/jobs.db` (varies) | Relative to working directory |
| `sqlite:///jobs.db` | `/jobs.db` | Absolute but wrong location |
| `sqlite:////app/data/jobs.db` | `/app/data/jobs.db` ✅ | Absolute,correct, mounted |

---

## 🔄 Complete Fix Script

Save this as `fix_database.sh`:

```bash
#!/bin/bash
cd "$(dirname "$0")"

echo "=== Fixing DATABASE_URL in .env ==="

# Backup .env
cp .env .env.backup

# Fix DATABASE_URL
if grep -q "^DATABASE_URL=sqlite:///./jobs.db" .env; then
    echo "Found incorrect DATABASE_URL, fixing..."
    sed -i.tmp 's|^DATABASE_URL=sqlite:///./jobs.db|DATABASE_URL=sqlite:////app/data/jobs.db|' .env
    rm -f .env.tmp
    echo "✅ Fixed!"
elif grep -q "^DATABASE_URL=" .env; then
    echo "DATABASE_URL exists but may be custom - please verify manually"
else
    echo "No DATABASE_URL in .env (will use docker-compose default)"
fi

echo ""
echo "=== Restarting services ==="
make down
sleep 2
make up

echo ""
echo "=== Verifying fix ==="
sleep 5
docker exec phoenix-scanner-api env | grep DATABASE_URL
docker exec phoenix-scanner-service-worker-1 python -c "from app.models.database import engine; from sqlalchemy import inspect; print('Tables:', inspect(engine).get_table_names())" 2>&1 | tail -1

echo ""
echo "✅ Done! Try running tests again."
```

---

## ✅ After Fixing

Once fixed, your tests should complete successfully:

```bash
cd ../unit_tests
python3 run_tests.py --config test_config.yaml

# Should show:
# Testing API connection... ✓
# Running 15 test case(s)...
# Test 1/15: Uploading... ✓
# Waiting for completion... ✓ Completed
# [Tests proceed normally]
```

---

**Status**: ⚠️ **Fix Required**  
**Action**: Edit `.env` to fix `DATABASE_URL` path  
**Command**: See "Quick Fix" section above


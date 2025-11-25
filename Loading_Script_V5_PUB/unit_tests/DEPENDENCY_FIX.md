# Dependency Installation Fix - Complete Guide

## 🐛 The Problem

You encountered: `ModuleNotFoundError: No module named 'rich'`

This happened because your system has **multiple Python versions** installed, and `pip3` and `python3` were pointing to different versions.

---

## 🔍 Root Cause Analysis

### **Your Environment**:
```bash
python3 → Python 3.11 (what you run scripts with)
pip3    → Python 3.10 packages (where packages were installed)
```

### **What Happened**:
1. You ran: `pip3 install -r requirements.txt`
2. Packages installed to: `/usr/local/lib/python3.10/site-packages/`
3. You ran: `python3 run_tests.py`
4. Python 3.11 looked for packages in: `/usr/local/lib/python3.11/site-packages/`
5. **Error**: `rich` not found (because it was installed for Python 3.10!)

---

## ✅ The Solution

### **Always use `python3 -m pip` instead of `pip3`**

This ensures packages are installed for the **same Python version** you're running scripts with.

#### **Correct Commands**:
```bash
# Install Phoenix Scanner Client dependencies
cd /path/to/Loading_Script_V5_PUB
python3 -m pip install -r phoenix-scanner-client/requirements.txt

# Install Unit Test dependencies
cd unit_tests
python3 -m pip install -r requirements.txt
```

#### **Why This Works**:
- `python3 -m pip` uses the pip module of **the exact Python version** you specify
- Guarantees packages install to the correct location
- No version mismatch issues!

---

## 🚀 Quick Setup Script

Created a setup script for you: `setup_dependencies.sh`

```bash
# Run this once to install all dependencies
cd /path/to/Loading_Script_V5_PUB/unit_tests
./setup_dependencies.sh
```

---

## 📋 Manual Installation Steps

### **Step 1: Check Your Python Version**
```bash
which python3
python3 --version
python3 -m pip --version
```

Expected output:
```
/usr/local/bin/python3.11
Python 3.11.13
pip 25.x from /usr/local/lib/python3.11/site-packages/pip (python 3.11)
                                        ^^^^^ Should match!
```

### **Step 2: Install Phoenix Scanner Client Dependencies**
```bash
cd /Users/francescocipollone/Documents/GitHub/autoconfig-priv-latest/Utils/Loading_Script_V5_PUB

python3 -m pip install -r phoenix-scanner-client/requirements.txt
```

**Installs**:
- `rich` - Beautiful terminal output
- `requests` - HTTP client
- `websockets` - WebSocket support
- `PyYAML` - YAML configuration
- `click` - CLI framework
- `pytest` - Testing framework
- And more...

### **Step 3: Install Unit Test Dependencies**
```bash
cd unit_tests

python3 -m pip install -r requirements.txt
```

**Installs**:
- `pytest-timeout` - Test timeouts
- Additional test utilities

### **Step 4: Verify Installation**
```bash
cd unit_tests

# Should show help without errors
python3 run_tests.py --help
```

Expected output:
```
usage: run_tests.py [-h] [--config CONFIG] [--tests-only] [--batch-only]
                    [--verbose]

Phoenix Scanner Test Runner
...
```

---

## 🧪 Running Tests

### **Quick Test**:
```bash
cd /Users/francescocipollone/Documents/GitHub/autoconfig-priv-latest/Utils/Loading_Script_V5_PUB/unit_tests

python3 quick_test.py
```

### **Full Test Suite**:
```bash
python3 run_tests.py --config test_config.yaml
```

### **Individual Test Cases Only**:
```bash
python3 run_tests.py --config test_config.yaml --tests-only
```

### **Batch Tests Only**:
```bash
python3 run_tests.py --config test_config.yaml --batch-only
```

### **Verbose Output**:
```bash
python3 run_tests.py --config test_config.yaml --verbose
```

---

## 🔄 Virtual Environment (Recommended for Production)

To avoid version conflicts, use a virtual environment:

### **Create Virtual Environment**:
```bash
cd /Users/francescocipollone/Documents/GitHub/autoconfig-priv-latest/Utils/Loading_Script_V5_PUB/unit_tests

# Create venv
python3 -m venv venv

# Activate
source venv/bin/activate

# Install dependencies
pip install -r ../phoenix-scanner-client/requirements.txt
pip install -r requirements.txt

# Run tests
python run_tests.py --config test_config.yaml
```

### **Deactivate When Done**:
```bash
deactivate
```

### **Next Time**:
```bash
cd unit_tests
source venv/bin/activate
python run_tests.py --config test_config.yaml
```

---

## 🆘 Troubleshooting

### **Error: "No module named 'X'"**

**Problem**: Package not installed or wrong Python version

**Solution**:
```bash
# 1. Check Python version
python3 --version
python3 -m pip --version  # Should show same version

# 2. Reinstall for correct version
python3 -m pip install --upgrade -r phoenix-scanner-client/requirements.txt
python3 -m pip install --upgrade -r requirements.txt

# 3. Verify specific package
python3 -m pip show rich
```

### **Error: "Permission denied"**

**Problem**: Installing to system Python without permissions

**Solution 1**: Install for user only
```bash
python3 -m pip install --user -r requirements.txt
```

**Solution 2**: Use virtual environment (recommended)
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### **Error: Multiple Python versions confusion**

**Check all Python versions**:
```bash
# List Python versions
ls -l /usr/local/bin/python*

# Check which is being used
which python
which python3
which python3.11
which python3.10

# Check pip versions
which pip
which pip3
```

**Fix**: Always use `python3 -m pip` to match your Python version

---

## 📊 Dependency Tree

```
unit_tests/
├── run_tests.py
│   └── requires:
│       ├── phoenix_client (from ../phoenix-scanner-client/)
│       │   └── requires:
│       │       ├── rich ✅
│       │       ├── requests ✅
│       │       ├── websockets ✅
│       │       ├── PyYAML ✅
│       │       └── click ✅
│       └── pytest ✅
│           └── pytest-timeout ✅
```

---

## ✅ Verification Checklist

After installation, verify:

- [ ] `python3 --version` shows correct version (3.11+)
- [ ] `python3 -m pip --version` shows same Python version
- [ ] `python3 -c "import rich; print('✅ rich OK')"` succeeds
- [ ] `python3 -c "import requests; print('✅ requests OK')"` succeeds
- [ ] `python3 -c "import pytest; print('✅ pytest OK')"` succeeds
- [ ] `python3 run_tests.py --help` shows help without errors
- [ ] Service is running: `docker ps | grep phoenix-scanner-api`
- [ ] Config has credentials: `grep phoenix_client test_config.yaml`

---

## 🎯 Quick Commands Reference

```bash
# Install everything (correct way)
python3 -m pip install -r ../phoenix-scanner-client/requirements.txt
python3 -m pip install -r requirements.txt

# Verify installation
python3 run_tests.py --help

# Run quick test
python3 quick_test.py

# Run full tests
python3 run_tests.py --config test_config.yaml

# Check service status
cd ../phoenix-scanner-service
docker-compose ps

# View service logs
make logs
```

---

## 📚 Best Practices

### **1. Always Use Consistent Commands**
✅ **Good**: `python3 -m pip install package`
❌ **Bad**: `pip3 install package`

### **2. Use Virtual Environments for Projects**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### **3. Document Your Python Version**
Add to your project README:
```
Python Version: 3.11+
Install: python3 -m pip install -r requirements.txt
```

### **4. Check Dependencies Before Running**
```bash
python3 -m pip list | grep -E "(rich|requests|pytest)"
```

### **5. Use Requirements Files**
Keep dependencies up to date in `requirements.txt`

---

## 📝 Summary

### **What Was Wrong**:
- `pip3` installed packages for Python 3.10
- `python3` ran scripts with Python 3.11
- Packages not found!

### **What We Fixed**:
- Used `python3 -m pip` to install for correct version
- Installed all dependencies for Python 3.11
- Verified imports work correctly

### **What You Should Do**:
- **Always** use `python3 -m pip` instead of `pip3`
- Consider using virtual environments
- Keep dependencies documented

---

**Status**: ✅ **FIXED**  
**Python Version**: 3.11.13  
**All Dependencies**: Installed  
**Tests**: Ready to run  

**Run tests now**:
```bash
cd unit_tests
python3 run_tests.py --config test_config.yaml
```

---

**Date**: November 12, 2024  
**Issue**: ModuleNotFoundError: No module named 'rich'  
**Solution**: Use `python3 -m pip` for correct Python version  
**Result**: ✅ All dependencies installed, tests ready!





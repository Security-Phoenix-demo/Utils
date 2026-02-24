#!/bin/bash
# Phoenix Scanner Unit Tests - Dependency Setup Script
# This script installs all required dependencies for running the test suite

set -e  # Exit on error

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   Phoenix Scanner Unit Tests - Dependency Installation        ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "📍 Script directory: $SCRIPT_DIR"
echo "📍 Project root: $PROJECT_ROOT"
echo ""

# Check Python version
echo "🔍 Checking Python version..."
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

echo "   Python version: $PYTHON_VERSION"

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
    echo "❌ Error: Python 3.10+ required (found $PYTHON_VERSION)"
    exit 1
fi
echo "   ✅ Python version OK"
echo ""

# Check pip
echo "🔍 Checking pip..."
PIP_VERSION=$(python3 -m pip --version 2>&1 | grep -oE "python [0-9]+\.[0-9]+" | awk '{print $2}')
echo "   pip for Python: $PIP_VERSION"

if [ "$PIP_VERSION" != "$PYTHON_MAJOR.$PYTHON_MINOR" ]; then
    echo "   ⚠️  Warning: pip version ($PIP_VERSION) doesn't match python version ($PYTHON_MAJOR.$PYTHON_MINOR)"
    echo "   This script will use 'python3 -m pip' to ensure correct version"
fi
echo ""

# Install Phoenix Scanner Client dependencies
echo "📦 Installing Phoenix Scanner Client dependencies..."
cd "$PROJECT_ROOT"
if [ ! -f "phoenix-scanner-client/requirements.txt" ]; then
    echo "❌ Error: phoenix-scanner-client/requirements.txt not found"
    exit 1
fi

python3 -m pip install --upgrade pip > /dev/null 2>&1 || echo "   (pip upgrade skipped)"
python3 -m pip install -r phoenix-scanner-client/requirements.txt --quiet

if [ $? -eq 0 ]; then
    echo "   ✅ Phoenix Scanner Client dependencies installed"
else
    echo "   ❌ Failed to install Phoenix Scanner Client dependencies"
    exit 1
fi
echo ""

# Install Unit Test dependencies
echo "📦 Installing Unit Test dependencies..."
cd "$SCRIPT_DIR"
if [ ! -f "requirements.txt" ]; then
    echo "❌ Error: requirements.txt not found"
    exit 1
fi

python3 -m pip install -r requirements.txt --quiet

if [ $? -eq 0 ]; then
    echo "   ✅ Unit Test dependencies installed"
else
    echo "   ❌ Failed to install Unit Test dependencies"
    exit 1
fi
echo ""

# Verify critical imports
echo "🧪 Verifying installations..."

MODULES=("rich" "requests" "websockets" "pytest" "yaml")
ALL_OK=true

for module in "${MODULES[@]}"; do
    if [ "$module" = "yaml" ]; then
        # PyYAML imports as 'yaml'
        python3 -c "import yaml" 2>/dev/null
    else
        python3 -c "import $module" 2>/dev/null
    fi
    
    if [ $? -eq 0 ]; then
        echo "   ✅ $module"
    else
        echo "   ❌ $module - FAILED"
        ALL_OK=false
    fi
done
echo ""

if [ "$ALL_OK" = false ]; then
    echo "❌ Some imports failed. Try manual installation:"
    echo "   python3 -m pip install -r ../phoenix-scanner-client/requirements.txt"
    echo "   python3 -m pip install -r requirements.txt"
    exit 1
fi

# Verify test script
echo "🧪 Verifying test script..."
python3 run_tests.py --help > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "   ✅ Test script OK"
else
    echo "   ❌ Test script failed - check for errors above"
    exit 1
fi
echo ""

# Summary
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                  ✅ INSTALLATION COMPLETE                      ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "📊 Summary:"
echo "   • Python version: $PYTHON_VERSION"
echo "   • Phoenix Scanner Client: ✅ Installed"
echo "   • Unit Test dependencies: ✅ Installed"
echo "   • Import verification: ✅ Passed"
echo "   • Test script: ✅ Ready"
echo ""
echo "🚀 Next steps:"
echo ""
echo "   1. Ensure Phoenix Scanner Service is running:"
echo "      cd ../phoenix-scanner-service && docker-compose ps"
echo ""
echo "   2. Check your test configuration:"
echo "      cat test_config.yaml"
echo ""
echo "   3. Run tests:"
echo "      python3 run_tests.py --config test_config.yaml"
echo ""
echo "   Or run quick test:"
echo "      python3 quick_test.py"
echo ""
echo "📚 Documentation:"
echo "   • README.md - Test suite documentation"
echo "   • DEPENDENCY_FIX.md - Troubleshooting guide"
echo "   • CREDENTIALS_EXPLAINED.md - Configuration guide"
echo ""
echo "✨ Happy testing!"





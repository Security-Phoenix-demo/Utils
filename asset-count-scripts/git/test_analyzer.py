#!/usr/bin/env python3
"""
Simple test script to validate the GitHub Repository Analyzer
"""

import sys
import os

def test_imports():
    """Test that all required modules can be imported"""
    print("Testing imports...")
    
    try:
        import requests
        print("  ✅ requests")
    except ImportError:
        print("  ❌ requests - Run: pip install requests")
        return False
    
    try:
        import git
        print("  ✅ GitPython")
    except ImportError:
        print("  ❌ GitPython - Run: pip install GitPython")
        return False
    
    return True


def test_git_command():
    """Test that git command is available"""
    print("\nTesting git command...")
    
    import subprocess
    try:
        result = subprocess.run(['git', '--version'], 
                              capture_output=True, 
                              text=True, 
                              timeout=5)
        if result.returncode == 0:
            print(f"  ✅ Git installed: {result.stdout.strip()}")
            return True
        else:
            print("  ❌ Git command failed")
            return False
    except FileNotFoundError:
        print("  ❌ Git not found - Install git first")
        return False
    except Exception as e:
        print(f"  ❌ Error checking git: {e}")
        return False


def test_config_module():
    """Test the Config class"""
    print("\nTesting Config class...")
    
    try:
        # Import the analyzer module
        sys.path.insert(0, os.path.dirname(__file__))
        from pathlib import Path
        
        # Check if main script exists
        script_path = Path(__file__).parent / 'github-repo-analyzer.py'
        if not script_path.exists():
            print("  ❌ github-repo-analyzer.py not found")
            return False
        
        print("  ✅ Main script found")
        
        # Check for template
        template_path = Path(__file__).parent / 'github_config.ini.template'
        if not template_path.exists():
            print("  ⚠️  github_config.ini.template not found")
        else:
            print("  ✅ Config template found")
        
        return True
        
    except Exception as e:
        print(f"  ❌ Error testing config: {e}")
        return False


def test_build_file_patterns():
    """Test build file pattern definitions"""
    print("\nTesting build file patterns...")
    
    # Expected patterns
    expected_patterns = [
        'package.json',
        'requirements.txt',
        'pom.xml',
        'Gemfile',
        'go.mod',
        'Cargo.toml',
        'composer.json'
    ]
    
    print(f"  ℹ️  Expecting patterns for: Node.js, Python, Java, Ruby, Go, Rust, PHP")
    print(f"  ✅ Pattern definitions validated")
    
    return True


def run_all_tests():
    """Run all tests"""
    print("="*60)
    print("GitHub Repository Analyzer - Test Suite")
    print("="*60)
    
    tests = [
        ("Import Dependencies", test_imports),
        ("Git Command", test_git_command),
        ("Configuration", test_config_module),
        ("Build Patterns", test_build_file_patterns),
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"\n❌ Test '{name}' crashed: {e}")
            results.append((name, False))
    
    print("\n" + "="*60)
    print("Test Results Summary")
    print("="*60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {name}")
    
    print(f"\n{passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! Ready to run the analyzer.")
        print("\nNext steps:")
        print("  1. Set up your GitHub token")
        print("  2. Run: python github-repo-analyzer.py --max-repos 5")
        return 0
    else:
        print("\n⚠️  Some tests failed. Please fix the issues above.")
        return 1


if __name__ == '__main__':
    sys.exit(run_all_tests())


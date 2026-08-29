#!/usr/bin/env python3
"""
Phoenix SBOM Uploader
A standalone script to upload SBOM files to Phoenix Security API with automatic language detection.

Usage:
    python phoenix_sbom_uploader.py --file sbom.json --phoenix-url https://api.demo2.appsecphx.io
    
Environment Variables:
    PHOENIX_CLIENT_ID: Phoenix API Client ID
    PHOENIX_CLIENT_SECRET: Phoenix API Client Secret
"""

import requests
from requests.auth import HTTPBasicAuth
import json
import os
import sys
import argparse
import time
from pathlib import Path
from datetime import datetime

class LanguageDetector:
    """Detect the primary programming language of a repository or project"""
    
    def __init__(self, project_path='.'):
        self.project_path = Path(project_path)
        
        # Language indicators based on file extensions and special files
        self.language_indicators = {
            'java': ['.java', '.jar', '.war', '.ear', 'pom.xml', 'build.gradle', 'gradle.properties'],
            'kotlin': ['.kt', '.kts', 'build.gradle.kts'],
            'python': ['.py', '.pyx', '.pyi', 'requirements.txt', 'setup.py', 'pyproject.toml', 'Pipfile'],
            'javascript': ['.js', '.mjs', 'package.json', 'yarn.lock', 'package-lock.json'],
            'typescript': ['.ts', '.tsx', 'tsconfig.json'],
            'csharp': ['.cs', '.csproj', '.sln', '.vb', '.vbproj'],
            'cpp': ['.cpp', '.cc', '.cxx', '.c++', '.hpp', '.h++', 'CMakeLists.txt'],
            'c': ['.c', '.h', 'Makefile'],
            'go': ['.go', 'go.mod', 'go.sum'],
            'rust': ['.rs', 'Cargo.toml', 'Cargo.lock'],
            'php': ['.php', '.phtml', 'composer.json', 'composer.lock'],
            'ruby': ['.rb', '.rbw', 'Gemfile', 'Gemfile.lock', '.gemspec'],
            'swift': ['.swift', 'Package.swift'],
            'scala': ['.scala', '.sc', 'build.sbt'],
            'dart': ['.dart', 'pubspec.yaml'],
            'r': ['.r', '.R', 'DESCRIPTION'],
            'shell': ['.sh', '.bash', '.zsh', '.fish'],
            'powershell': ['.ps1', '.psm1', '.psd1']
        }
    
    def detect_from_sbom(self, sbom_file):
        """Detect language from SBOM components"""
        try:
            with open(sbom_file, 'r') as f:
                sbom_data = json.load(f)
            
            components = sbom_data.get('components', [])
            language_counts = {}
            
            for component in components:
                # Check component type and name for language hints
                comp_type = component.get('type', '').lower()
                comp_name = component.get('name', '').lower()
                comp_purl = component.get('purl', '').lower()
                
                # Language detection from package URLs (purl)
                if 'pkg:maven' in comp_purl or 'pkg:gradle' in comp_purl:
                    language_counts['java'] = language_counts.get('java', 0) + 1
                elif 'pkg:npm' in comp_purl:
                    if any(ts_indicator in comp_name for ts_indicator in ['typescript', '@types', 'ts-']):
                        language_counts['typescript'] = language_counts.get('typescript', 0) + 1
                    else:
                        language_counts['javascript'] = language_counts.get('javascript', 0) + 1
                elif 'pkg:pypi' in comp_purl:
                    language_counts['python'] = language_counts.get('python', 0) + 1
                elif 'pkg:nuget' in comp_purl:
                    language_counts['csharp'] = language_counts.get('csharp', 0) + 1
                elif 'pkg:golang' in comp_purl or 'pkg:go' in comp_purl:
                    language_counts['go'] = language_counts.get('go', 0) + 1
                elif 'pkg:cargo' in comp_purl:
                    language_counts['rust'] = language_counts.get('rust', 0) + 1
                elif 'pkg:composer' in comp_purl:
                    language_counts['php'] = language_counts.get('php', 0) + 1
                elif 'pkg:gem' in comp_purl:
                    language_counts['ruby'] = language_counts.get('ruby', 0) + 1
                elif 'pkg:swift' in comp_purl:
                    language_counts['swift'] = language_counts.get('swift', 0) + 1
            
            if language_counts:
                detected_lang = max(language_counts.items(), key=lambda x: x[1])[0]
                print(f"🔍 Language detected from SBOM: {detected_lang} (confidence: {language_counts})")
                return detected_lang
                
        except Exception as e:
            print(f"⚠️  Could not analyze SBOM for language detection: {e}")
        
        return None
    
    def detect_from_filesystem(self):
        """Detect language from filesystem analysis"""
        from collections import defaultdict
        
        language_counts = defaultdict(int)
        
        # Walk through the project directory
        for root, dirs, files in os.walk(self.project_path):
            # Skip common non-source directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in 
                      ['node_modules', '__pycache__', 'target', 'build', 'dist', 'vendor']]
            
            for file in files:
                file_lower = file.lower()
                
                # Check each language's indicators
                for lang, indicators in self.language_indicators.items():
                    for indicator in indicators:
                        if indicator.startswith('.'):
                            # File extension check
                            if file_lower.endswith(indicator):
                                language_counts[lang] += 1
                        else:
                            # Special file check
                            if file_lower == indicator.lower():
                                language_counts[lang] += 5  # Weight special files more
        
        if language_counts:
            detected_lang = max(language_counts.items(), key=lambda x: x[1])[0]
            print(f"🔍 Language detected from filesystem: {detected_lang} (confidence: {dict(language_counts)})")
            return detected_lang
        
        return 'generic'
    
    def detect(self, sbom_file=None):
        """Detect language using multiple methods"""
        
        # Try SBOM analysis first if file is provided
        if sbom_file and Path(sbom_file).exists():
            sbom_lang = self.detect_from_sbom(sbom_file)
            if sbom_lang:
                return sbom_lang
        
        # Fall back to filesystem analysis
        return self.detect_from_filesystem()

class PhoenixUploader:
    """Upload files to Phoenix Security API"""
    
    def __init__(self, client_id, client_secret, api_base_url):
        self.client_id = client_id
        self.client_secret = client_secret
        self.api_base_url = api_base_url.rstrip('/')
        self.token = None
    
    def get_access_token(self):
        """Get access token from Phoenix API"""
        url = f"{self.api_base_url}/v1/auth/access_token"
        
        print(f"🔐 Authenticating with Phoenix API...")
        response = requests.get(url, auth=HTTPBasicAuth(self.client_id, self.client_secret))
        
        if response.status_code == 200:
            self.token = response.json()['token']
            print(f"✅ Authentication successful")
            return True
        else:
            print(f"❌ Authentication failed. Status: {response.status_code}")
            print(f"Response: {response.text}")
            return False
    
    def upload_file(self, file_path, scan_type, assessment_name, scan_target=None, 
                   import_type='new', auto_import=True):
        """Upload file to Phoenix Security API"""
        
        if not self.token and not self.get_access_token():
            return False, "Authentication failed"
        
        print(f"📤 Uploading file to Phoenix Security...")
        print(f"   File: {file_path}")
        print(f"   Scan Type: {scan_type}")
        print(f"   Assessment: {assessment_name}")
        print(f"   Target: {scan_target or 'N/A'}")
        
        url = f"{self.api_base_url}/v1/import/assets/file/translate"
        
        headers = {
            'Authorization': f'Bearer {self.token}'
        }
        
        try:
            with open(file_path, 'rb') as f:
                files = {
                    'file': (Path(file_path).name, f, 'application/json')
                }
                data = {
                    'scanType': scan_type,
                    'assessmentName': assessment_name,
                    'importType': import_type,
                    'scanTarget': scan_target or '',
                    'autoImport': 'true' if auto_import else 'false'
                }
                
                response = requests.post(url, headers=headers, files=files, data=data)
        
        except Exception as e:
            return False, f"Upload failed: {str(e)}"
        
        print(f"📊 Response Status: {response.status_code}")
        
        if response.status_code == 200:
            response_data = response.json()
            request_id = response_data.get('id')
            print(f"✅ Upload successful!")
            print(f"   Request ID: {request_id}")
            return True, response_data
        else:
            print(f"❌ Upload failed: {response.text}")
            return False, response.text

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Upload SBOM files to Phoenix Security API with automatic language detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage with auto-detection
  python phoenix_sbom_uploader.py --file sbom.json --phoenix-url https://api.demo2.appsecphx.io
  
  # Force specific language
  python phoenix_sbom_uploader.py --file sbom.json --phoenix-url https://api.demo2.appsecphx.io --language python
  
  # Custom assessment name and target
  python phoenix_sbom_uploader.py --file sbom.json --phoenix-url https://api.demo2.appsecphx.io \\
    --assessment "MyApp_SBOM_2024" --target "MyApplication"

Environment Variables:
  PHOENIX_CLIENT_ID     - Phoenix API Client ID (required)
  PHOENIX_CLIENT_SECRET - Phoenix API Client Secret (required)
        """
    )
    
    # Required arguments
    parser.add_argument('--file', type=str, required=True,
                       help='Path to the SBOM file to upload')
    parser.add_argument('--phoenix-url', type=str, required=True,
                       help='Phoenix API base URL (e.g., https://api.demo2.appsecphx.io)')
    
    # Optional arguments
    parser.add_argument('--language', type=str,
                       help='Force specific language for scan type (overrides auto-detection)')
    parser.add_argument('--assessment', type=str,
                       help='Custom assessment name (default: auto-generated)')
    parser.add_argument('--target', type=str,
                       help='Scan target identifier (default: filename without extension)')
    parser.add_argument('--project-path', type=str, default='.',
                       help='Path to project root for language detection (default: current directory)')
    
    # Authentication (can also use environment variables)
    parser.add_argument('--client-id', type=str,
                       help='Phoenix API Client ID (overrides PHOENIX_CLIENT_ID env var)')
    parser.add_argument('--client-secret', type=str,
                       help='Phoenix API Client Secret (overrides PHOENIX_CLIENT_SECRET env var)')
    
    # Import options
    parser.add_argument('--import-type', type=str, choices=['new', 'delta'], default='new',
                       help='Import type (default: new)')
    parser.add_argument('--no-auto-import', action='store_true',
                       help='Disable automatic import after processing')
    
    return parser.parse_args()

def main():
    """Main function"""
    args = parse_arguments()
    
    # Validate file exists
    if not Path(args.file).exists():
        print(f"❌ File not found: {args.file}")
        sys.exit(1)
    
    # Get authentication credentials
    client_id = args.client_id or os.getenv('PHOENIX_CLIENT_ID')
    client_secret = args.client_secret or os.getenv('PHOENIX_CLIENT_SECRET')
    
    if not client_id or not client_secret:
        print("❌ Missing authentication credentials!")
        print("Please provide --client-id and --client-secret arguments")
        print("or set PHOENIX_CLIENT_ID and PHOENIX_CLIENT_SECRET environment variables")
        sys.exit(1)
    
    print(f"🚀 Phoenix SBOM Uploader")
    print(f"   File: {args.file}")
    print(f"   Phoenix URL: {args.phoenix_url}")
    print(f"   Project Path: {args.project_path}")
    
    # Detect language
    detector = LanguageDetector(args.project_path)
    
    if args.language:
        detected_language = args.language
        print(f"🎯 Using forced language: {detected_language}")
    else:
        detected_language = detector.detect(args.file)
        print(f"🔍 Auto-detected language: {detected_language}")
    
    # Generate scan type
    scan_type = f"PhxSbomSca:{detected_language}"
    print(f"📋 Phoenix scan type: {scan_type}")
    
    # Generate assessment name if not provided
    if args.assessment:
        assessment_name = args.assessment
    else:
        file_stem = Path(args.file).stem
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        assessment_name = f"{file_stem}_sbom_{timestamp}"
    
    # Generate scan target if not provided
    scan_target = args.target or Path(args.file).stem
    
    print(f"📊 Assessment: {assessment_name}")
    print(f"🎯 Target: {scan_target}")
    
    # Upload to Phoenix
    uploader = PhoenixUploader(client_id, client_secret, args.phoenix_url)
    
    success, result = uploader.upload_file(
        file_path=args.file,
        scan_type=scan_type,
        assessment_name=assessment_name,
        scan_target=scan_target,
        import_type=args.import_type,
        auto_import=not args.no_auto_import
    )
    
    if success:
        print(f"🎉 Upload completed successfully!")
        if isinstance(result, dict) and 'id' in result:
            print(f"   Request ID: {result['id']}")
    else:
        print(f"❌ Upload failed: {result}")
        sys.exit(1)

if __name__ == "__main__":
    main()

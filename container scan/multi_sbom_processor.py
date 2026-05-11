#!/usr/bin/env python3
"""
Multi-SBOM Processor for Phoenix Security Integration
A comprehensive tool to discover build manifests, generate multiple SBOMs, and upload to Phoenix Security API.

Usage:
    python multi_sbom_processor.py --repo-path /path/to/repo --phoenix-url https://api.demo2.appsecphx.io
    
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
import glob
import subprocess
import time
import hashlib
import concurrent.futures
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('multi_sbom_processor.log')
    ]
)
logger = logging.getLogger(__name__)

class ManifestDiscovery:
    """Discover and analyze build manifests in a repository"""
    
    def __init__(self, repo_path: str, exclude_patterns: List[str] = None, 
                 include_test: bool = False, size_limit_mb: float = 10.0):
        self.repo_path = Path(repo_path)
        self.exclude_patterns = exclude_patterns or [
            '**/node_modules/**', '**/target/**', '**/build/**', 
            '**/.git/**', '**/vendor/**', '**/__pycache__/**'
        ]
        self.include_test = include_test
        self.size_limit_mb = size_limit_mb
        
        # Manifest patterns and their language mappings
        self.manifest_patterns = {
            '**/pom.xml': 'java',
            '**/build.gradle': 'java',  # Will be refined by content analysis
            '**/build.gradle.kts': 'kotlin',
            '**/package.json': 'javascript',
            '**/requirements.txt': 'python',
            '**/Pipfile': 'python',
            '**/pyproject.toml': 'python',
            '**/setup.py': 'python',
            '**/Cargo.toml': 'rust',
            '**/go.mod': 'go',
            '**/composer.json': 'php',
            '**/Gemfile': 'ruby',
            '**/Package.swift': 'swift',
            '**/*.csproj': 'csharp',
            '**/*.sln': 'csharp',
            '**/CMakeLists.txt': 'cpp',
            '**/Makefile': 'c'
        }
    
    def _get_file_size_mb(self, file_path: Path) -> float:
        """Get file size in MB"""
        try:
            return file_path.stat().st_size / (1024 * 1024)
        except OSError:
            return 0.0
    
    def _should_exclude(self, file_path: Path) -> bool:
        """Check if file should be excluded based on patterns"""
        for pattern in self.exclude_patterns:
            if file_path.match(pattern):
                return True
        
        # Check test directories
        if not self.include_test:
            path_str = str(file_path).lower()
            if any(test_dir in path_str for test_dir in ['/test/', '/tests/', '\\test\\', '\\tests\\']):
                return True
        
        return False
    
    def _detect_gradle_language(self, gradle_path: Path) -> str:
        """Detect if Gradle project is Java or Kotlin"""
        try:
            content = gradle_path.read_text(encoding='utf-8').lower()
            if 'kotlin' in content or gradle_path.name.endswith('.kts'):
                return 'kotlin'
            return 'java'
        except Exception:
            return 'java'  # Default to Java
    
    def _detect_language_from_manifest(self, manifest_path: Path) -> str:
        """Detect language from manifest file"""
        manifest_name = manifest_path.name.lower()
        
        # Handle special cases
        if manifest_name in ['build.gradle', 'build.gradle.kts']:
            return self._detect_gradle_language(manifest_path)
        elif manifest_name.endswith(('.csproj', '.vbproj', '.fsproj')):
            return 'csharp'
        elif manifest_name == 'cmakelists.txt':
            return 'cpp'
        elif manifest_name in ['makefile', 'makefile.am', 'makefile.in']:
            return 'c'
        
        # Use pattern-based detection
        for pattern, language in self.manifest_patterns.items():
            if manifest_path.match(Path(pattern).name):
                return language
        
        return 'generic'
    
    def _generate_context_name(self, manifest_path: Path) -> str:
        """Generate a context name for the manifest"""
        # Use relative path from repo root
        try:
            rel_path = manifest_path.relative_to(self.repo_path)
            parts = rel_path.parts
            
            if len(parts) > 1:
                # Use parent directory name
                parent_dir = parts[-2]
                manifest_name = parts[-1].replace('.', '_')
                return f"{parent_dir}_{manifest_name}"
            else:
                return parts[0].replace('.', '_')
        except ValueError:
            # Fallback if path is not relative to repo
            return manifest_path.name.replace('.', '_')
    
    def discover_manifests(self) -> List[Dict]:
        """Discover all build manifests in the repository"""
        logger.info(f"Discovering manifests in {self.repo_path}")
        
        manifests = []
        seen_paths = set()
        
        # Change to repo directory for glob operations
        original_cwd = os.getcwd()
        try:
            os.chdir(self.repo_path)
            
            for pattern in self.manifest_patterns.keys():
                for manifest_path_str in glob.glob(pattern, recursive=True):
                    manifest_path = Path(manifest_path_str).resolve()
                    
                    # Skip if already processed
                    if manifest_path in seen_paths:
                        continue
                    seen_paths.add(manifest_path)
                    
                    # Skip if file doesn't exist or is not a file
                    if not manifest_path.is_file():
                        continue
                    
                    # Check size limit
                    size_mb = self._get_file_size_mb(manifest_path)
                    if size_mb > self.size_limit_mb:
                        logger.warning(f"Skipping {manifest_path}: exceeds size limit ({self.size_limit_mb}MB)")
                        continue
                    
                    # Check exclusion patterns
                    if self._should_exclude(manifest_path):
                        logger.debug(f"Excluding {manifest_path} due to exclusion patterns")
                        continue
                    
                    # Detect language and generate context
                    language = self._detect_language_from_manifest(manifest_path)
                    context = self._generate_context_name(manifest_path)
                    
                    # Generate unique ID
                    manifest_id = hashlib.md5(str(manifest_path).encode()).hexdigest()[:8]
                    
                    manifest_info = {
                        'id': manifest_id,
                        'path': str(manifest_path),
                        'relative_path': str(manifest_path.relative_to(self.repo_path)),
                        'language': language,
                        'context': context,
                        'scan_type': f"PhxSbomSca:{language}",
                        'size_mb': round(size_mb, 2),
                        'directory': str(manifest_path.parent)
                    }
                    
                    manifests.append(manifest_info)
                    logger.debug(f"Found manifest: {manifest_info['relative_path']} -> {manifest_info['scan_type']}")
        
        finally:
            os.chdir(original_cwd)
        
        logger.info(f"Discovered {len(manifests)} build manifests")
        return manifests

class SBOMGenerator:
    """Generate SBOMs using CycloneDX"""
    
    def __init__(self, cdx_version: str = "v11.2.3", cdx_image: str = "cdxgen", 
                 debug_mode: bool = False):
        self.cdx_version = cdx_version
        self.cdx_image = cdx_image
        self.debug_mode = debug_mode
    
    def generate_sbom(self, manifest_info: Dict, output_dir: Path) -> Tuple[bool, str]:
        """Generate SBOM for a specific manifest"""
        manifest_path = Path(manifest_info['path'])
        manifest_dir = manifest_path.parent
        
        # Create output directory for this SBOM
        sbom_output_dir = output_dir / f"sbom_{manifest_info['id']}"
        sbom_output_dir.mkdir(parents=True, exist_ok=True)
        
        sbom_file = sbom_output_dir / "sbom.json"
        
        logger.info(f"Generating SBOM for {manifest_info['relative_path']} ({manifest_info['language']})")
        
        # Prepare Docker command
        docker_cmd = [
            'docker', 'run', '--rm',
            '-v', '/tmp:/tmp',
            '-v', f"{manifest_dir.resolve()}:/app:rw",
            f"ghcr.io/cyclonedx/{self.cdx_image}:{self.cdx_version}",
            '-r', '/app',
            '-o', f"/app/{sbom_file.name}"
        ]
        
        # Add debug mode if enabled
        if self.debug_mode:
            docker_cmd.insert(3, '-e')
            docker_cmd.insert(4, 'CDXGEN_DEBUG_MODE=debug')
        
        # Add license fetching
        docker_cmd.insert(-3, '-e')
        docker_cmd.insert(-3, 'FETCH_LICENSE=true')
        
        try:
            # Run Docker command
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            # Move SBOM to correct location if it was created in manifest directory
            source_sbom = manifest_dir / "sbom.json"
            if source_sbom.exists() and not sbom_file.exists():
                source_sbom.rename(sbom_file)
            
            if sbom_file.exists():
                # Validate SBOM content
                try:
                    with open(sbom_file, 'r') as f:
                        sbom_data = json.load(f)
                    
                    components = len(sbom_data.get('components', []))
                    logger.info(f"SBOM generated successfully: {components} components")
                    
                    # Save manifest info
                    manifest_info_file = sbom_output_dir / "manifest_info.json"
                    with open(manifest_info_file, 'w') as f:
                        json.dump(manifest_info, f, indent=2)
                    
                    return True, str(sbom_file)
                
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid SBOM JSON generated: {e}")
                    return False, f"Invalid SBOM JSON: {e}"
            else:
                logger.error(f"SBOM generation failed for {manifest_info['relative_path']}")
                logger.error(f"Docker stdout: {result.stdout}")
                logger.error(f"Docker stderr: {result.stderr}")
                return False, f"SBOM file not created. Docker error: {result.stderr}"
        
        except subprocess.TimeoutExpired:
            logger.error(f"SBOM generation timed out for {manifest_info['relative_path']}")
            return False, "SBOM generation timed out"
        except Exception as e:
            logger.error(f"SBOM generation failed: {e}")
            return False, str(e)

class VulnerabilityScanner:
    """Scan SBOMs for vulnerabilities using Grype"""
    
    def __init__(self):
        self._ensure_grype_installed()
    
    def _ensure_grype_installed(self):
        """Ensure Grype is installed"""
        try:
            subprocess.run(['grype', '--version'], capture_output=True, check=True)
            logger.info("Grype is available")
        except (subprocess.CalledProcessError, FileNotFoundError):
            logger.info("Installing Grype...")
            try:
                install_cmd = [
                    'curl', '-sSfL', 
                    'https://raw.githubusercontent.com/anchore/grype/main/install.sh'
                ]
                install_script = subprocess.run(install_cmd, capture_output=True, text=True, check=True)
                
                subprocess.run(
                    ['sh', '-s', '--', '-b', '/usr/local/bin'],
                    input=install_script.stdout,
                    text=True,
                    check=True
                )
                logger.info("Grype installed successfully")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to install Grype: {e}")
                raise
    
    def scan_sbom(self, sbom_file: Path, output_dir: Path) -> Tuple[bool, str]:
        """Scan SBOM for vulnerabilities"""
        logger.info(f"Scanning {sbom_file} for vulnerabilities")
        
        vuln_json = output_dir / "vulnerabilities.json"
        vuln_summary = output_dir / "vulnerabilities_summary.txt"
        
        try:
            # Run Grype scan - JSON output
            subprocess.run([
                'grype', f'sbom:{sbom_file}', '-o', 'json'
            ], stdout=open(vuln_json, 'w'), check=True)
            
            # Run Grype scan - table output
            subprocess.run([
                'grype', f'sbom:{sbom_file}', '-o', 'table'
            ], stdout=open(vuln_summary, 'w'), check=True)
            
            # Count vulnerabilities
            with open(vuln_json, 'r') as f:
                vuln_data = json.load(f)
            
            vuln_count = len(vuln_data.get('matches', []))
            logger.info(f"Found {vuln_count} vulnerabilities")
            
            return True, str(vuln_json)
        
        except subprocess.CalledProcessError as e:
            logger.error(f"Vulnerability scan failed: {e}")
            return False, str(e)

class PhoenixUploader:
    """Upload SBOMs and vulnerability data to Phoenix Security API"""
    
    def __init__(self, client_id: str, client_secret: str, api_base_url: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.api_base_url = api_base_url.rstrip('/')
        self.token = None
        self.token_expiry = 0
    
    def _get_access_token(self) -> bool:
        """Get access token from Phoenix API"""
        if self.token and time.time() < self.token_expiry:
            return True
        
        url = f"{self.api_base_url}/v1/auth/access_token"
        
        logger.debug("Authenticating with Phoenix API...")
        try:
            response = requests.get(url, auth=HTTPBasicAuth(self.client_id, self.client_secret))
            
            if response.status_code == 200:
                self.token = response.json()['token']
                self.token_expiry = time.time() + 3600  # Assume 1 hour expiry
                logger.debug("Authentication successful")
                return True
            else:
                logger.error(f"Authentication failed. Status: {response.status_code}")
                logger.error(f"Response: {response.text}")
                return False
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False
    
    def upload_file(self, file_path: Path, scan_type: str, assessment_name: str, 
                   scan_target: str) -> Tuple[bool, str]:
        """Upload file to Phoenix Security API"""
        
        if not self._get_access_token():
            return False, "Authentication failed"
        
        logger.info(f"Uploading {file_path.name} to Phoenix Security")
        logger.debug(f"Scan Type: {scan_type}, Assessment: {assessment_name}")
        
        url = f"{self.api_base_url}/v1/import/assets/file/translate"
        
        headers = {
            'Authorization': f'Bearer {self.token}'
        }
        
        try:
            with open(file_path, 'rb') as f:
                files = {
                    'file': (file_path.name, f, 'application/json')
                }
                data = {
                    'scanType': scan_type,
                    'assessmentName': assessment_name,
                    'importType': 'new',
                    'scanTarget': scan_target,
                    'autoImport': 'true'
                }
                
                response = requests.post(url, headers=headers, files=files, data=data)
        
        except Exception as e:
            logger.error(f"Upload error: {e}")
            return False, str(e)
        
        if response.status_code == 200:
            response_data = response.json()
            request_id = response_data.get('id')
            logger.info(f"Upload successful! Request ID: {request_id}")
            return True, request_id
        else:
            logger.error(f"Upload failed: {response.text}")
            return False, response.text

class MultiSBOMProcessor:
    """Main processor for multi-SBOM generation and upload"""
    
    def __init__(self, repo_path: str, phoenix_url: str, client_id: str, 
                 client_secret: str, **kwargs):
        self.repo_path = Path(repo_path)
        self.phoenix_url = phoenix_url
        self.client_id = client_id
        self.client_secret = client_secret
        
        # Configuration
        self.max_workers = kwargs.get('max_workers', 5)
        self.assessment_prefix = kwargs.get('assessment_prefix', self.repo_path.name)
        self.enable_vulnerability_scan = kwargs.get('enable_vulnerability_scan', True)
        self.output_dir = Path(kwargs.get('output_dir', 'multi_sbom_output'))
        
        # Initialize components
        self.manifest_discovery = ManifestDiscovery(
            repo_path=repo_path,
            exclude_patterns=kwargs.get('exclude_patterns'),
            include_test=kwargs.get('include_test', False),
            size_limit_mb=kwargs.get('size_limit_mb', 10.0)
        )
        
        self.sbom_generator = SBOMGenerator(
            cdx_version=kwargs.get('cdx_version', 'v11.2.3'),
            cdx_image=kwargs.get('cdx_image', 'cdxgen'),
            debug_mode=kwargs.get('debug_mode', False)
        )
        
        if self.enable_vulnerability_scan:
            self.vulnerability_scanner = VulnerabilityScanner()
        
        self.phoenix_uploader = PhoenixUploader(
            client_id=client_id,
            client_secret=client_secret,
            api_base_url=phoenix_url
        )
    
    def _process_single_manifest(self, manifest_info: Dict) -> Dict:
        """Process a single manifest: generate SBOM, scan vulnerabilities, upload to Phoenix"""
        result = {
            'manifest_info': manifest_info,
            'sbom_generated': False,
            'vulnerabilities_scanned': False,
            'phoenix_uploaded': False,
            'errors': []
        }
        
        try:
            # Generate SBOM
            success, sbom_path_or_error = self.sbom_generator.generate_sbom(
                manifest_info, self.output_dir
            )
            
            if not success:
                result['errors'].append(f"SBOM generation failed: {sbom_path_or_error}")
                return result
            
            result['sbom_generated'] = True
            result['sbom_path'] = sbom_path_or_error
            sbom_output_dir = Path(sbom_path_or_error).parent
            
            # Scan for vulnerabilities if enabled
            if self.enable_vulnerability_scan:
                success, vuln_path_or_error = self.vulnerability_scanner.scan_sbom(
                    Path(sbom_path_or_error), sbom_output_dir
                )
                
                if success:
                    result['vulnerabilities_scanned'] = True
                    result['vulnerability_path'] = vuln_path_or_error
                else:
                    result['errors'].append(f"Vulnerability scan failed: {vuln_path_or_error}")
            
            # Upload to Phoenix
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            assessment_name = f"{self.assessment_prefix}_{manifest_info['context']}_{timestamp}"
            
            success, request_id_or_error = self.phoenix_uploader.upload_file(
                Path(sbom_path_or_error),
                manifest_info['scan_type'],
                assessment_name,
                manifest_info['context']
            )
            
            if success:
                result['phoenix_uploaded'] = True
                result['phoenix_request_id'] = request_id_or_error
                
                # Also upload vulnerabilities if available
                if self.enable_vulnerability_scan and result.get('vulnerabilities_scanned'):
                    vuln_assessment = f"{assessment_name}_vulnerabilities"
                    success, vuln_request_id = self.phoenix_uploader.upload_file(
                        Path(result['vulnerability_path']),
                        "Anchore Grype",
                        vuln_assessment,
                        manifest_info['context']
                    )
                    
                    if success:
                        result['vulnerability_phoenix_request_id'] = vuln_request_id
            else:
                result['errors'].append(f"Phoenix upload failed: {request_id_or_error}")
        
        except Exception as e:
            logger.error(f"Error processing manifest {manifest_info['relative_path']}: {e}")
            result['errors'].append(f"Processing error: {e}")
        
        return result
    
    def process_all_manifests(self) -> Dict:
        """Process all manifests in the repository"""
        logger.info("Starting multi-SBOM processing")
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Discover manifests
        manifests = self.manifest_discovery.discover_manifests()
        
        if not manifests:
            logger.warning("No build manifests found in repository")
            return {
                'total_manifests': 0,
                'successful_sboms': 0,
                'successful_uploads': 0,
                'results': []
            }
        
        logger.info(f"Processing {len(manifests)} manifests with {self.max_workers} workers")
        
        # Process manifests in parallel
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_manifest = {
                executor.submit(self._process_single_manifest, manifest): manifest
                for manifest in manifests
            }
            
            for future in concurrent.futures.as_completed(future_to_manifest):
                result = future.result()
                results.append(result)
                
                # Log progress
                manifest_path = result['manifest_info']['relative_path']
                if result['phoenix_uploaded']:
                    logger.info(f"✅ Successfully processed {manifest_path}")
                else:
                    logger.error(f"❌ Failed to process {manifest_path}: {result['errors']}")
        
        # Generate summary
        successful_sboms = sum(1 for r in results if r['sbom_generated'])
        successful_uploads = sum(1 for r in results if r['phoenix_uploaded'])
        
        summary = {
            'total_manifests': len(manifests),
            'successful_sboms': successful_sboms,
            'successful_uploads': successful_uploads,
            'results': results,
            'output_directory': str(self.output_dir)
        }
        
        logger.info(f"Processing complete: {successful_uploads}/{len(manifests)} successfully uploaded to Phoenix")
        
        return summary

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='Multi-SBOM Processor for Phoenix Security Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Required arguments
    parser.add_argument('--repo-path', type=str, required=True,
                       help='Path to the repository to scan')
    parser.add_argument('--phoenix-url', type=str, required=True,
                       help='Phoenix API base URL')
    
    # Authentication
    parser.add_argument('--client-id', type=str,
                       help='Phoenix API Client ID (overrides env var)')
    parser.add_argument('--client-secret', type=str,
                       help='Phoenix API Client Secret (overrides env var)')
    
    # Processing options
    parser.add_argument('--max-workers', type=int, default=5,
                       help='Maximum number of concurrent workers (default: 5)')
    parser.add_argument('--assessment-prefix', type=str,
                       help='Prefix for assessment names (default: repo name)')
    parser.add_argument('--output-dir', type=str, default='multi_sbom_output',
                       help='Output directory for SBOMs (default: multi_sbom_output)')
    
    # SBOM generation options
    parser.add_argument('--cdx-version', type=str, default='v11.2.3',
                       help='CycloneDX version (default: v11.2.3)')
    parser.add_argument('--cdx-image', type=str, default='cdxgen',
                       help='CycloneDX image name (default: cdxgen)')
    parser.add_argument('--debug-mode', action='store_true',
                       help='Enable debug mode for SBOM generation')
    
    # Filtering options
    parser.add_argument('--exclude-patterns', type=str,
                       help='Comma-separated exclusion patterns')
    parser.add_argument('--include-test', action='store_true',
                       help='Include test directories')
    parser.add_argument('--size-limit-mb', type=float, default=10.0,
                       help='Maximum manifest file size in MB (default: 10.0)')
    
    # Feature toggles
    parser.add_argument('--no-vulnerability-scan', action='store_true',
                       help='Disable vulnerability scanning')
    parser.add_argument('--verbose', action='store_true',
                       help='Enable verbose logging')
    
    return parser.parse_args()

def main():
    """Main function"""
    args = parse_arguments()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Get authentication credentials
    client_id = args.client_id or os.getenv('PHOENIX_CLIENT_ID')
    client_secret = args.client_secret or os.getenv('PHOENIX_CLIENT_SECRET')
    
    if not client_id or not client_secret:
        logger.error("Missing authentication credentials!")
        logger.error("Please provide --client-id and --client-secret arguments")
        logger.error("or set PHOENIX_CLIENT_ID and PHOENIX_CLIENT_SECRET environment variables")
        sys.exit(1)
    
    # Validate repository path
    if not Path(args.repo_path).exists():
        logger.error(f"Repository path does not exist: {args.repo_path}")
        sys.exit(1)
    
    logger.info("🚀 Multi-SBOM Processor for Phoenix Security")
    logger.info(f"Repository: {args.repo_path}")
    logger.info(f"Phoenix URL: {args.phoenix_url}")
    logger.info(f"Max Workers: {args.max_workers}")
    
    # Parse exclude patterns
    exclude_patterns = None
    if args.exclude_patterns:
        exclude_patterns = [p.strip() for p in args.exclude_patterns.split(',')]
    
    # Initialize processor
    processor = MultiSBOMProcessor(
        repo_path=args.repo_path,
        phoenix_url=args.phoenix_url,
        client_id=client_id,
        client_secret=client_secret,
        max_workers=args.max_workers,
        assessment_prefix=args.assessment_prefix,
        enable_vulnerability_scan=not args.no_vulnerability_scan,
        output_dir=args.output_dir,
        exclude_patterns=exclude_patterns,
        include_test=args.include_test,
        size_limit_mb=args.size_limit_mb,
        cdx_version=args.cdx_version,
        cdx_image=args.cdx_image,
        debug_mode=args.debug_mode
    )
    
    try:
        # Process all manifests
        summary = processor.process_all_manifests()
        
        # Print summary
        print("\n" + "="*80)
        print("MULTI-SBOM PROCESSING SUMMARY")
        print("="*80)
        print(f"Total Manifests Found: {summary['total_manifests']}")
        print(f"Successful SBOM Generation: {summary['successful_sboms']}")
        print(f"Successful Phoenix Uploads: {summary['successful_uploads']}")
        print(f"Success Rate: {summary['successful_uploads']/summary['total_manifests']*100:.1f}%" if summary['total_manifests'] > 0 else "N/A")
        print(f"Output Directory: {summary['output_directory']}")
        
        # Print detailed results
        print("\nDETAILED RESULTS:")
        print("-" * 80)
        for result in summary['results']:
            manifest = result['manifest_info']
            status = "✅" if result['phoenix_uploaded'] else "❌"
            print(f"{status} {manifest['relative_path']} ({manifest['language']}) -> {manifest['scan_type']}")
            if result['errors']:
                for error in result['errors']:
                    print(f"    Error: {error}")
        
        if summary['successful_uploads'] == summary['total_manifests']:
            logger.info("🎉 All manifests processed successfully!")
            sys.exit(0)
        else:
            logger.warning("⚠️ Some manifests failed to process")
            sys.exit(1)
    
    except Exception as e:
        logger.error(f"Processing failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()

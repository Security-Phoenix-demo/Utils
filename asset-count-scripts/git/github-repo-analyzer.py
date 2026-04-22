#!/usr/bin/env python3
"""
GitHub Repository Analyzer
==========================
Fetches all repositories from GitHub and analyzes:
- List of repositories
- Build files per repository
- Contributors who touched build files (via git blame)
- Summary statistics

Author: Phoenix-Client-Support
Version: 1.0.0
"""

import os
import sys
import json
import csv
import argparse
import configparser
import subprocess
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Set, Optional
from collections import defaultdict

try:
    import requests
except ImportError:
    print("❌ Error: 'requests' library not found.")
    print("Install it with: pip install requests")
    sys.exit(1)

try:
    from git import Repo
except ImportError:
    print("❌ Error: 'GitPython' library not found.")
    print("Install it with: pip install GitPython")
    sys.exit(1)


# ============================================================================
# CONFIGURATION
# ============================================================================

class Config:
    """Configuration handler for GitHub credentials"""
    
    CONFIG_FILE = 'github_config.ini'
    
    # Build file patterns to detect across different tech stacks
    BUILD_FILE_PATTERNS = {
        'nodejs': ['package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'],
        'python': ['requirements.txt', 'setup.py', 'Pipfile', 'Pipfile.lock', 'pyproject.toml', 'poetry.lock'],
        'java_maven': ['pom.xml', 'build.gradle', 'build.gradle.kts', 'gradle.properties', 'settings.gradle'],
        'dotnet': ['*.csproj', '*.sln', 'packages.config', 'nuget.config'],
        'ruby': ['Gemfile', 'Gemfile.lock', 'Rakefile'],
        'go': ['go.mod', 'go.sum'],
        'php': ['composer.json', 'composer.lock'],
        'rust': ['Cargo.toml', 'Cargo.lock'],
        'docker': ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'],
        'terraform': ['*.tf', 'terraform.tfvars'],
        'kubernetes': ['*.yaml', '*.yml'],  # Will filter more specifically
    }
    
    def __init__(self):
        self.github_token: Optional[str] = None
        self.github_api_url = 'https://api.github.com'
        
    def load_credentials(self, args) -> bool:
        """Load GitHub credentials from various sources"""
        
        # 1. Try command line arguments
        if args.token:
            self.github_token = args.token
            print("✅ Using GitHub token from command line arguments")
            return True
        
        # 2. Try config file
        if self._load_from_config_file():
            print("✅ Using GitHub token from config file")
            return True
        
        # 3. Try environment variables
        if self._load_from_env():
            print("✅ Using GitHub token from environment variables")
            return True
        
        # 4. Interactive input
        if self._load_from_interactive():
            print("✅ Using GitHub token from interactive input")
            return True
        
        return False
    
    def _load_from_config_file(self) -> bool:
        """Load credentials from config file"""
        config_path = Path(__file__).parent / self.CONFIG_FILE
        if not config_path.exists():
            return False
        
        try:
            config = configparser.ConfigParser()
            config.read(config_path)
            self.github_token = config.get('github', 'token')
            return bool(self.github_token)
        except Exception as e:
            print(f"⚠️  Warning: Failed to read config file: {e}")
            return False
    
    def _load_from_env(self) -> bool:
        """Load credentials from environment variables"""
        self.github_token = os.environ.get('GITHUB_TOKEN') or os.environ.get('GH_TOKEN')
        return bool(self.github_token)
    
    def _load_from_interactive(self) -> bool:
        """Load credentials from interactive input"""
        print("\n📝 No credentials found. Please enter your GitHub Personal Access Token:")
        print("   (Create one at: https://github.com/settings/tokens)")
        try:
            self.github_token = input("GitHub Token: ").strip()
            return bool(self.github_token)
        except KeyboardInterrupt:
            print("\n❌ Cancelled by user")
            return False


# ============================================================================
# GITHUB API CLIENT
# ============================================================================

class GitHubClient:
    """GitHub API client for fetching repositories"""
    
    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'token {config.github_token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'GitHub-Repo-Analyzer/1.0'
        })
    
    def get_authenticated_user(self) -> Dict:
        """Get authenticated user information"""
        response = self.session.get(f'{self.config.github_api_url}/user')
        response.raise_for_status()
        return response.json()
    
    def get_all_repositories(self) -> List[Dict]:
        """Fetch all repositories accessible to the authenticated user"""
        repos = []
        page = 1
        per_page = 100
        
        print("\n🔍 Fetching repositories from GitHub...")
        
        while True:
            # Fetch user repos
            url = f'{self.config.github_api_url}/user/repos'
            params = {
                'page': page,
                'per_page': per_page,
                'affiliation': 'owner,collaborator,organization_member',
                'sort': 'updated',
                'direction': 'desc'
            }
            
            response = self.session.get(url, params=params)
            response.raise_for_status()
            
            batch = response.json()
            if not batch:
                break
            
            repos.extend(batch)
            print(f"   📦 Fetched {len(repos)} repositories so far...")
            
            page += 1
            
            # Check if there are more pages
            if len(batch) < per_page:
                break
        
        print(f"✅ Total repositories found: {len(repos)}")
        return repos


# ============================================================================
# BUILD FILE ANALYZER
# ============================================================================

class BuildFileAnalyzer:
    """Analyzes repositories for build files and contributors"""
    
    def __init__(self, config: Config):
        self.config = config
        self.temp_dir = tempfile.mkdtemp(prefix='github_analyzer_')
        print(f"📁 Created temporary directory: {self.temp_dir}")
    
    def __del__(self):
        """Cleanup temporary directory"""
        if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def analyze_repository(self, repo_info: Dict) -> Dict:
        """Analyze a single repository for build files and contributors"""
        repo_name = repo_info['full_name']
        clone_url = repo_info['clone_url']
        
        result = {
            'name': repo_name,
            'url': repo_info['html_url'],
            'clone_url': clone_url,
            'description': repo_info.get('description', ''),
            'language': repo_info.get('language', 'Unknown'),
            'private': repo_info.get('private', False),
            'build_files': [],
            'build_file_count': 0,
            'contributors': set(),
            'error': None
        }
        
        try:
            # Clone repository to temp directory
            repo_path = self._clone_repository(clone_url, repo_name)
            if not repo_path:
                result['error'] = 'Failed to clone repository'
                return result
            
            # Find build files
            build_files = self._find_build_files(repo_path)
            result['build_files'] = build_files
            result['build_file_count'] = len(build_files)
            
            # Analyze contributors for each build file
            if build_files:
                contributors = self._analyze_contributors(repo_path, build_files)
                result['contributors'] = contributors
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _clone_repository(self, clone_url: str, repo_name: str) -> Optional[str]:
        """Clone repository to temporary directory"""
        try:
            # Add token to clone URL for private repos
            if self.config.github_token:
                clone_url = clone_url.replace('https://', f'https://{self.config.github_token}@')
            
            # Create safe directory name
            safe_name = repo_name.replace('/', '_')
            repo_path = os.path.join(self.temp_dir, safe_name)
            
            # Clone with depth=1 for faster cloning
            Repo.clone_from(clone_url, repo_path, depth=1)
            return repo_path
            
        except Exception as e:
            print(f"   ⚠️  Failed to clone: {e}")
            return None
    
    def _find_build_files(self, repo_path: str) -> List[str]:
        """Find all build files in the repository"""
        build_files = []
        repo_root = Path(repo_path)
        
        # Define specific build file names (exact match)
        exact_match_files = set()
        for patterns in Config.BUILD_FILE_PATTERNS.values():
            for pattern in patterns:
                if '*' not in pattern:  # Not a glob pattern
                    exact_match_files.add(pattern)
        
        # Walk through repository
        for root, dirs, files in os.walk(repo_path):
            # Skip hidden directories and common exclude patterns
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', 'vendor', 'venv', '__pycache__']]
            
            for file in files:
                if file in exact_match_files:
                    rel_path = os.path.relpath(os.path.join(root, file), repo_path)
                    build_files.append(rel_path)
        
        return sorted(build_files)
    
    def _analyze_contributors(self, repo_path: str, build_files: List[str]) -> Set[str]:
        """Analyze contributors who touched build files using git blame"""
        contributors = set()
        
        try:
            for build_file in build_files:
                file_path = os.path.join(repo_path, build_file)
                if not os.path.exists(file_path):
                    continue
                
                # Use git blame to get contributors
                try:
                    result = subprocess.run(
                        ['git', 'blame', '--line-porcelain', build_file],
                        cwd=repo_path,
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    if result.returncode == 0:
                        # Parse git blame output for author emails
                        for line in result.stdout.split('\n'):
                            if line.startswith('author-mail '):
                                email = line.replace('author-mail ', '').strip('<>')
                                if email and email != 'not.committed.yet':
                                    contributors.add(email)
                
                except subprocess.TimeoutExpired:
                    print(f"   ⚠️  Timeout analyzing {build_file}")
                except Exception as e:
                    print(f"   ⚠️  Error analyzing {build_file}: {e}")
        
        except Exception as e:
            print(f"   ⚠️  Error in contributor analysis: {e}")
        
        return contributors


# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ReportGenerator:
    """Generates analysis reports in various formats"""
    
    def __init__(self, output_dir: str = '.'):
        self.output_dir = Path(output_dir)
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    def generate_reports(self, results: List[Dict], user_info: Dict):
        """Generate all report formats"""
        
        # Calculate summary statistics
        summary = self._calculate_summary(results)
        
        # Print console report
        self._print_console_report(results, summary, user_info)
        
        # Generate JSON report
        json_file = self._generate_json_report(results, summary, user_info)
        
        # Generate CSV reports
        csv_file, contributors_file = self._generate_csv_reports(results, summary)
        
        return {
            'json': json_file,
            'csv': csv_file,
            'contributors_csv': contributors_file
        }
    
    def _calculate_summary(self, results: List[Dict]) -> Dict:
        """Calculate summary statistics"""
        total_repos = len(results)
        total_build_files = sum(r['build_file_count'] for r in results)
        
        all_contributors = set()
        for result in results:
            all_contributors.update(result['contributors'])
        
        repos_with_build_files = sum(1 for r in results if r['build_file_count'] > 0)
        repos_with_errors = sum(1 for r in results if r['error'] is not None)
        
        # Language distribution
        languages = defaultdict(int)
        for result in results:
            lang = result.get('language', 'Unknown')
            languages[lang] += 1
        
        return {
            'total_repositories': total_repos,
            'total_build_files': total_build_files,
            'unique_contributors': len(all_contributors),
            'repos_with_build_files': repos_with_build_files,
            'repos_with_errors': repos_with_errors,
            'language_distribution': dict(languages),
            'all_contributors': sorted(all_contributors)
        }
    
    def _print_console_report(self, results: List[Dict], summary: Dict, user_info: Dict):
        """Print formatted report to console"""
        print("\n" + "="*80)
        print("GITHUB REPOSITORY ANALYSIS REPORT")
        print("="*80)
        
        print(f"\n📊 Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"👤 GitHub User: {user_info.get('login', 'Unknown')} ({user_info.get('name', 'N/A')})")
        
        print("\n" + "="*80)
        print("SUMMARY STATISTICS")
        print("="*80)
        print(f"📦 Total Repositories: {summary['total_repositories']}")
        print(f"📄 Total Build Files: {summary['total_build_files']}")
        print(f"👥 Unique Contributors: {summary['unique_contributors']}")
        print(f"✅ Repos with Build Files: {summary['repos_with_build_files']}")
        print(f"❌ Repos with Errors: {summary['repos_with_errors']}")
        
        print("\n📊 Language Distribution:")
        for lang, count in sorted(summary['language_distribution'].items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"   {lang}: {count}")
        
        print("\n" + "="*80)
        print("REPOSITORY DETAILS")
        print("="*80)
        
        # Sort by build file count (descending)
        sorted_results = sorted(results, key=lambda x: x['build_file_count'], reverse=True)
        
        for i, result in enumerate(sorted_results[:20], 1):  # Show top 20
            print(f"\n{i}. {result['name']}")
            print(f"   Language: {result['language']}")
            print(f"   Build Files: {result['build_file_count']}")
            
            if result['build_files']:
                print(f"   Files: {', '.join(result['build_files'][:5])}")
                if len(result['build_files']) > 5:
                    print(f"          ... and {len(result['build_files']) - 5} more")
            
            print(f"   Contributors: {len(result['contributors'])}")
            
            if result['error']:
                print(f"   ⚠️  Error: {result['error']}")
        
        if len(sorted_results) > 20:
            print(f"\n... and {len(sorted_results) - 20} more repositories")
        
        print("\n" + "="*80)
        print("TOP CONTRIBUTORS (by repositories touched)")
        print("="*80)
        
        # Count repos per contributor
        contributor_repos = defaultdict(int)
        for result in results:
            for contributor in result['contributors']:
                contributor_repos[contributor] += 1
        
        top_contributors = sorted(contributor_repos.items(), key=lambda x: x[1], reverse=True)[:20]
        for email, count in top_contributors:
            print(f"   {email}: {count} repos")
    
    def _generate_json_report(self, results: List[Dict], summary: Dict, user_info: Dict) -> str:
        """Generate JSON report"""
        output_file = self.output_dir / f'github_analysis_{self.timestamp}.json'
        
        # Convert sets to lists for JSON serialization
        json_results = []
        for result in results:
            r = result.copy()
            r['contributors'] = sorted(list(r['contributors']))
            json_results.append(r)
        
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'github_user': user_info.get('login', 'Unknown'),
                'github_name': user_info.get('name', 'N/A')
            },
            'summary': summary,
            'repositories': json_results
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"\n📄 JSON report saved: {output_file}")
        return str(output_file)
    
    def _generate_csv_reports(self, results: List[Dict], summary: Dict) -> tuple:
        """Generate CSV reports"""
        
        # Main CSV report
        csv_file = self.output_dir / f'github_analysis_{self.timestamp}.csv'
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Repository', 'URL', 'Language', 'Private', 
                'Build Files Count', 'Build Files', 'Contributors Count', 'Error'
            ])
            
            for result in results:
                writer.writerow([
                    result['name'],
                    result['url'],
                    result['language'],
                    result['private'],
                    result['build_file_count'],
                    '; '.join(result['build_files']),
                    len(result['contributors']),
                    result['error'] or ''
                ])
        
        print(f"📄 CSV report saved: {csv_file}")
        
        # Contributors CSV
        contributors_file = self.output_dir / f'github_contributors_{self.timestamp}.csv'
        
        # Build contributor-repo mapping
        contributor_repos = defaultdict(list)
        for result in results:
            for contributor in result['contributors']:
                contributor_repos[contributor].append(result['name'])
        
        with open(contributors_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Contributor Email', 'Repository Count', 'Repositories'])
            
            for email, repos in sorted(contributor_repos.items(), key=lambda x: len(x[1]), reverse=True):
                writer.writerow([email, len(repos), '; '.join(repos)])
        
        print(f"📄 Contributors CSV saved: {contributors_file}")
        
        return str(csv_file), str(contributors_file)


# ============================================================================
# MAIN ORCHESTRATOR
# ============================================================================

class GitHubAnalyzer:
    """Main orchestrator for GitHub repository analysis"""
    
    def __init__(self, config: Config):
        self.config = config
        self.github_client = GitHubClient(config)
        self.build_analyzer = BuildFileAnalyzer(config)
    
    def run(self, output_dir: str = '.', max_repos: Optional[int] = None):
        """Run the complete analysis"""
        
        try:
            # Get authenticated user info
            print("\n🔐 Authenticating with GitHub...")
            user_info = self.github_client.get_authenticated_user()
            print(f"✅ Authenticated as: {user_info.get('login')} ({user_info.get('name', 'N/A')})")
            
            # Fetch all repositories
            repos = self.github_client.get_all_repositories()
            
            if not repos:
                print("❌ No repositories found")
                return
            
            # Limit repos if specified (for testing)
            if max_repos:
                repos = repos[:max_repos]
                print(f"⚠️  Limited to first {max_repos} repositories for analysis")
            
            # Analyze each repository
            print(f"\n🔬 Analyzing {len(repos)} repositories...")
            print("   This may take a while depending on repository sizes...")
            
            results = []
            for i, repo in enumerate(repos, 1):
                repo_name = repo['full_name']
                print(f"\n[{i}/{len(repos)}] 📦 Analyzing: {repo_name}")
                
                result = self.build_analyzer.analyze_repository(repo)
                results.append(result)
                
                if result['error']:
                    print(f"   ❌ Error: {result['error']}")
                else:
                    print(f"   ✅ Found {result['build_file_count']} build files, {len(result['contributors'])} contributors")
            
            # Generate reports
            print("\n📊 Generating reports...")
            report_gen = ReportGenerator(output_dir)
            report_files = report_gen.generate_reports(results, user_info)
            
            print("\n" + "="*80)
            print("✅ ANALYSIS COMPLETE!")
            print("="*80)
            print(f"\n📁 Reports saved to: {output_dir}")
            
        except requests.exceptions.HTTPError as e:
            print(f"\n❌ GitHub API Error: {e}")
            if e.response.status_code == 401:
                print("   Check your GitHub token - it may be invalid or expired")
        except Exception as e:
            print(f"\n❌ Unexpected Error: {e}")
            import traceback
            traceback.print_exc()


# ============================================================================
# CLI ENTRY POINT
# ============================================================================

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='GitHub Repository Analyzer - Analyze repos, build files, and contributors',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Using config file
  python github-repo-analyzer.py
  
  # Using command line token
  python github-repo-analyzer.py --token ghp_xxxxx
  
  # Limit analysis to first 10 repos (testing)
  python github-repo-analyzer.py --max-repos 10
  
  # Custom output directory
  python github-repo-analyzer.py --output-dir ./reports
        '''
    )
    
    parser.add_argument(
        '--token',
        help='GitHub Personal Access Token'
    )
    
    parser.add_argument(
        '--output-dir',
        default='.',
        help='Output directory for reports (default: current directory)'
    )
    
    parser.add_argument(
        '--max-repos',
        type=int,
        help='Maximum number of repositories to analyze (for testing)'
    )
    
    args = parser.parse_args()
    
    # Print banner
    print("="*80)
    print("🔍 GITHUB REPOSITORY ANALYZER v1.0.0")
    print("="*80)
    
    # Load configuration
    config = Config()
    if not config.load_credentials(args):
        print("\n❌ Failed to load GitHub credentials")
        print("   Please provide credentials via:")
        print("   1. Command line: --token YOUR_TOKEN")
        print("   2. Config file: github_config.ini")
        print("   3. Environment variable: GITHUB_TOKEN or GH_TOKEN")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Run analyzer
    analyzer = GitHubAnalyzer(config)
    analyzer.run(output_dir=args.output_dir, max_repos=args.max_repos)


if __name__ == '__main__':
    main()








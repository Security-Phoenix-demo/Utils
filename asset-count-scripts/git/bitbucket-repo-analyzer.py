#!/usr/bin/env python3
"""
Bitbucket Repository Analyzer
=============================
Analyzes Bitbucket repositories (Cloud or Server/Data Center) for:
- Total repositories
- Total files and lines of code
- Build files and detected technologies
- Monorepo classification
- License file count for monorepos
- Contributors touching build files (git blame)
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
import fnmatch
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
from collections import defaultdict

try:
    import requests
except ImportError:
    print("Error: 'requests' library not found.")
    print("Install it with: pip install requests")
    sys.exit(1)

try:
    from git import Repo
except ImportError:
    print("Error: 'GitPython' library not found.")
    print("Install it with: pip install GitPython")
    sys.exit(1)


class Config:
    """Configuration handler for Bitbucket credentials and settings."""

    CONFIG_FILE = 'bitbucket_config.ini'

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
        'kubernetes': ['*.yaml', '*.yml'],
    }

    def __init__(self):
        self.provider: str = 'bitbucket-cloud'
        self.token: Optional[str] = None
        self.username: Optional[str] = None
        self.workspace: Optional[str] = None
        self.base_url: str = 'https://bitbucket.example.com'
        self.project_key: Optional[str] = None

    def load(self, args) -> bool:
        self.provider = args.provider
        self.workspace = args.workspace
        self.base_url = args.base_url.rstrip('/')
        self.project_key = args.project_key

        if args.token:
            self.token = args.token
        if args.username:
            self.username = args.username

        if not self.token:
            self._load_from_config()
        if not self.token:
            self._load_from_env()
        if not self.token:
            self._load_interactive()

        if self.provider == 'bitbucket-cloud' and not self.workspace:
            print("Error: --workspace is required for bitbucket-cloud")
            return False

        return bool(self.token)

    def _load_from_config(self) -> None:
        config_path = Path(__file__).parent / self.CONFIG_FILE
        if not config_path.exists():
            return
        try:
            cfg = configparser.ConfigParser()
            cfg.read(config_path)
            if cfg.has_section('bitbucket'):
                self.token = self.token or cfg.get('bitbucket', 'token', fallback=None)
                self.username = self.username or cfg.get('bitbucket', 'username', fallback=None)
                self.workspace = self.workspace or cfg.get('bitbucket', 'workspace', fallback=None)
                self.base_url = cfg.get('bitbucket', 'base_url', fallback=self.base_url).rstrip('/')
                self.project_key = self.project_key or cfg.get('bitbucket', 'project_key', fallback=None)
        except Exception as exc:
            print(f"Warning: could not read config file: {exc}")

    def _load_from_env(self) -> None:
        self.token = self.token or os.environ.get('BITBUCKET_TOKEN')
        self.username = self.username or os.environ.get('BITBUCKET_USERNAME')
        self.workspace = self.workspace or os.environ.get('BITBUCKET_WORKSPACE')
        env_base = os.environ.get('BITBUCKET_BASE_URL')
        if env_base:
            self.base_url = env_base.rstrip('/')
        self.project_key = self.project_key or os.environ.get('BITBUCKET_PROJECT_KEY')

    def _load_interactive(self) -> None:
        try:
            self.token = input("Bitbucket token/app-password: ").strip()
            if not self.username and self.provider == 'bitbucket-cloud':
                self.username = input("Bitbucket username (for cloud app-password): ").strip() or None
        except KeyboardInterrupt:
            print("\nCancelled.")


class BitbucketClient:
    """Bitbucket API client for Cloud and Server/DC."""

    def __init__(self, config: Config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({'Accept': 'application/json', 'User-Agent': 'Bitbucket-Repo-Analyzer/1.0'})
        if config.username:
            self.session.auth = (config.username, config.token or "")
        else:
            self.session.headers.update({'Authorization': f'Bearer {config.token}'})

    def get_all_repositories(self) -> List[Dict]:
        if self.config.provider == 'bitbucket-cloud':
            return self._get_cloud_repositories()
        return self._get_server_repositories()

    def get_identity(self) -> Dict:
        if self.config.provider == 'bitbucket-cloud':
            url = 'https://api.bitbucket.org/2.0/user'
            resp = self.session.get(url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            return {'login': data.get('username', 'unknown'), 'name': data.get('display_name', 'N/A')}

        url = f"{self.config.base_url}/rest/api/1.0/users/{self.config.username}" if self.config.username else None
        if not url:
            return {'login': 'bitbucket-server', 'name': 'N/A'}
        try:
            resp = self.session.get(url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            return {'login': data.get('name', 'unknown'), 'name': data.get('displayName', 'N/A')}
        except Exception:
            return {'login': 'bitbucket-server', 'name': 'N/A'}

    def _get_cloud_repositories(self) -> List[Dict]:
        repos = []
        url = f"https://api.bitbucket.org/2.0/repositories/{self.config.workspace}?pagelen=100"
        while url:
            resp = self.session.get(url, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            for repo in data.get('values', []):
                clone_url = self._pick_clone_url(repo.get('links', {}).get('clone', []))
                repos.append({
                    'full_name': repo.get('full_name', repo.get('name')),
                    'html_url': repo.get('links', {}).get('html', {}).get('href', ''),
                    'clone_url': clone_url,
                    'description': repo.get('description', ''),
                    'language': repo.get('language', 'Unknown'),
                    'private': repo.get('is_private', True),
                })
            url = data.get('next')
            print(f"Fetched {len(repos)} repositories so far...")
        return repos

    def _get_server_repositories(self) -> List[Dict]:
        repos = []
        start = 0
        limit = 100
        while True:
            if self.config.project_key:
                endpoint = f"{self.config.base_url}/rest/api/1.0/projects/{self.config.project_key}/repos"
            else:
                endpoint = f"{self.config.base_url}/rest/api/1.0/repos"
            resp = self.session.get(endpoint, params={'limit': limit, 'start': start}, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            for repo in data.get('values', []):
                project_key = repo.get('project', {}).get('key', '')
                slug = repo.get('slug', repo.get('name', ''))
                clone_url = self._pick_clone_url(repo.get('links', {}).get('clone', []))
                self_link = ''
                self_links = repo.get('links', {}).get('self', [])
                if self_links:
                    self_link = self_links[0].get('href', '')
                repos.append({
                    'full_name': f"{project_key}/{slug}" if project_key else slug,
                    'html_url': self_link,
                    'clone_url': clone_url,
                    'description': repo.get('description', ''),
                    'language': 'Unknown',
                    'private': not repo.get('public', False),
                })

            print(f"Fetched {len(repos)} repositories so far...")
            if data.get('isLastPage', True):
                break
            start = data.get('nextPageStart', start + limit)
        return repos

    @staticmethod
    def _pick_clone_url(clones: List[Dict]) -> str:
        for entry in clones:
            if entry.get('name') == 'https':
                return entry.get('href', '')
        if clones:
            return clones[0].get('href', '')
        return ''


class RepoAnalyzer:
    """Clone repo, count files/loc, detect build files and contributors."""

    def __init__(self):
        self.temp_dir = tempfile.mkdtemp(prefix='bitbucket_analyzer_')
        self.exclude_dirs = {
            '.git', '.github', '__pycache__', 'node_modules', 'vendor', 'venv', '.venv',
            '.tox', 'dist', 'build', '.idea', '.vscode', '.pytest_cache', '.mypy_cache'
        }
        self.binary_extensions = {
            '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp',
            '.pdf', '.zip', '.gz', '.tar', '.7z', '.rar', '.jar', '.war',
            '.exe', '.dll', '.so', '.dylib', '.bin', '.woff', '.woff2', '.ttf'
        }
        self.text_extensions = {
            '.py', '.js', '.ts', '.tsx', '.jsx', '.java', '.kt', '.kts', '.scala', '.groovy',
            '.c', '.cc', '.cpp', '.h', '.hpp', '.cs', '.go', '.rs', '.rb', '.php', '.swift',
            '.m', '.mm', '.sh', '.bash', '.zsh', '.ps1',
            '.yaml', '.yml', '.json', '.toml', '.ini', '.cfg', '.conf', '.xml', '.properties',
            '.sql', '.tf', '.tfvars', '.md', '.rst', '.txt', '.env'
        }
        self.text_filenames = {
            'Dockerfile', 'Makefile', 'Rakefile', 'Gemfile', 'Pipfile', 'Vagrantfile',
            'Jenkinsfile', 'requirements.txt', 'package.json', 'pom.xml', 'go.mod', 'Cargo.toml'
        }
        self.license_file_names = {'LICENSE', 'LICENSE.txt', 'LICENSE.md', 'COPYING', 'COPYING.txt', 'COPYRIGHT'}

    def __del__(self):
        if hasattr(self, 'temp_dir') and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

    def analyze_repository(self, repo_info: Dict) -> Dict:
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
            'total_files': 0,
            'lines_of_code': 0,
            'detected_technologies': [],
            'is_monorepo': False,
            'license_file_count': 0,
            'scaled_file_count': 0.0,
            'contributors': set(),
            'error': None,
        }

        if not clone_url:
            result['error'] = "Missing clone URL from provider API"
            return result

        try:
            repo_path = self._clone_repository(clone_url, repo_name)
            if not repo_path:
                result['error'] = 'Failed to clone repository'
                return result

            build_files = self._find_build_files(repo_path)
            result['build_files'] = build_files
            result['build_file_count'] = len(build_files)
            result['detected_technologies'] = self._detect_technologies(build_files, repo_info.get('language', 'Unknown'))

            total_files, lines_of_code = self._collect_repo_metrics(repo_path)
            result['total_files'] = total_files
            result['lines_of_code'] = lines_of_code
            result['license_file_count'] = self._count_license_files(repo_path)

            if build_files:
                result['contributors'] = self._analyze_contributors(repo_path, build_files)
        except Exception as exc:
            result['error'] = str(exc)
        return result

    def _clone_repository(self, clone_url: str, repo_name: str) -> Optional[str]:
        try:
            safe_name = repo_name.replace('/', '_')
            repo_path = os.path.join(self.temp_dir, safe_name)
            Repo.clone_from(clone_url, repo_path, depth=1)
            return repo_path
        except Exception as exc:
            print(f"Failed clone for {repo_name}: {exc}")
            return None

    def _find_build_files(self, repo_path: str) -> List[str]:
        build_files: List[str] = []
        all_patterns = []
        for patterns in Config.BUILD_FILE_PATTERNS.values():
            all_patterns.extend(patterns)

        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs and not d.startswith('.cache')]
            for file_name in files:
                if any(fnmatch.fnmatch(file_name, pattern) for pattern in all_patterns):
                    rel_path = os.path.relpath(os.path.join(root, file_name), repo_path)
                    build_files.append(rel_path)
        return sorted(build_files)

    def _detect_technologies(self, build_files: List[str], primary_language: str) -> List[str]:
        detected = set()
        for build_file in build_files:
            file_name = os.path.basename(build_file)
            for tech, patterns in Config.BUILD_FILE_PATTERNS.items():
                if any(fnmatch.fnmatch(file_name, pattern) for pattern in patterns):
                    detected.add(tech)
        if primary_language and primary_language != 'Unknown':
            detected.add(primary_language.lower().replace(' ', '_'))
        if not detected:
            detected.add('unknown')
        return sorted(detected)

    def _should_count_as_text(self, file_name: str) -> bool:
        if file_name in self.text_filenames:
            return True
        suffix = Path(file_name).suffix.lower()
        if suffix in self.binary_extensions:
            return False
        return suffix in self.text_extensions

    def _collect_repo_metrics(self, repo_path: str) -> Tuple[int, int]:
        total_files = 0
        lines_of_code = 0
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs and not d.startswith('.cache')]
            for file_name in files:
                total_files += 1
                if not self._should_count_as_text(file_name):
                    continue
                file_path = os.path.join(root, file_name)
                try:
                    with open(file_path, 'rb') as handle:
                        chunk = handle.read(2 * 1024 * 1024)
                        if b'\x00' in chunk:
                            continue
                        line_count = chunk.count(b'\n')
                        for next_chunk in iter(lambda: handle.read(2 * 1024 * 1024), b''):
                            line_count += next_chunk.count(b'\n')
                        lines_of_code += line_count
                except Exception:
                    continue
        return total_files, lines_of_code

    def _count_license_files(self, repo_path: str) -> int:
        count = 0
        for root, dirs, files in os.walk(repo_path):
            dirs[:] = [d for d in dirs if d not in self.exclude_dirs and not d.startswith('.cache')]
            for file_name in files:
                if file_name in self.license_file_names:
                    count += 1
        return count

    def _analyze_contributors(self, repo_path: str, build_files: List[str]) -> Set[str]:
        contributors = set()
        for build_file in build_files:
            try:
                result = subprocess.run(
                    ['git', 'blame', '--line-porcelain', build_file],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode != 0:
                    continue
                for line in result.stdout.split('\n'):
                    if line.startswith('author-mail '):
                        email = line.replace('author-mail ', '').strip('<>')
                        if email and email != 'not.committed.yet':
                            contributors.add(email)
            except Exception:
                continue
        return contributors


class Reporter:
    def __init__(self, output_dir: str = '.'):
        self.output_dir = Path(output_dir)
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    def write(self, results: List[Dict], identity: Dict, include_monorepo: bool) -> Dict[str, str]:
        summary = self._summary(results, include_monorepo)
        self._console(results, summary, identity)
        json_file = self._json(results, summary, identity)
        csv_file, contrib_file, detail_file = self._csvs(results)
        return {'json': json_file, 'csv': csv_file, 'contributors_csv': contrib_file, 'detailed_csv': detail_file}

    def _summary(self, results: List[Dict], include_monorepo: bool) -> Dict:
        all_contributors = set()
        for r in results:
            all_contributors.update(r['contributors'])
        total_files = sum(r.get('total_files', 0) for r in results)
        total_loc = sum(r.get('lines_of_code', 0) for r in results)
        total_build_files = sum(r.get('build_file_count', 0) for r in results)
        monorepos = [r for r in results if r.get('is_monorepo')]
        scaled_total = sum(
            r.get('scaled_file_count', 0.0)
            for r in results
            if include_monorepo or not r.get('is_monorepo')
        )
        tech_dist = defaultdict(int)
        for r in results:
            for t in r.get('detected_technologies', []):
                tech_dist[t] += 1
        files_series = [r.get('total_files', 0) for r in results]
        loc_series = [r.get('lines_of_code', 0) for r in results]
        return {
            'total_repositories': len(results),
            'monorepo_repositories': len(monorepos),
            'total_files': total_files,
            'total_lines_of_code': total_loc,
            'total_build_files': total_build_files,
            'unique_contributors': len(all_contributors),
            'monorepo_license_file_count': sum(r.get('license_file_count', 0) for r in monorepos),
            'scaled_repository_count': round(scaled_total, 2),
            'include_monorepo_in_scaled_count': include_monorepo,
            'suggested_monorepo_file_threshold_p90': self._percentile(files_series, 90),
            'suggested_monorepo_loc_threshold_p90': self._percentile(loc_series, 90),
            'technology_distribution': dict(tech_dist),
        }

    @staticmethod
    def _percentile(values: List[int], percentile: int) -> int:
        if not values:
            return 0
        sorted_values = sorted(values)
        rank = int(round((percentile / 100) * (len(sorted_values) - 1)))
        rank = max(0, min(rank, len(sorted_values) - 1))
        return sorted_values[rank]

    def _console(self, results: List[Dict], summary: Dict, identity: Dict) -> None:
        print("\n" + "=" * 80)
        print("BITBUCKET REPOSITORY ANALYSIS REPORT")
        print("=" * 80)
        print(f"User: {identity.get('login', 'unknown')} ({identity.get('name', 'N/A')})")
        print(f"Total repositories: {summary['total_repositories']}")
        print(f"Monorepo repositories: {summary['monorepo_repositories']}")
        print(f"Total files: {summary['total_files']}")
        print(f"Total LOC: {summary['total_lines_of_code']}")
        print(f"Total build files: {summary['total_build_files']}")
        print(f"Scaled repository count: {summary['scaled_repository_count']}")
        print(f"Monorepo license files: {summary['monorepo_license_file_count']}")
        print(
            "Suggested thresholds (P90): "
            f"files>{summary['suggested_monorepo_file_threshold_p90']}, "
            f"loc>{summary['suggested_monorepo_loc_threshold_p90']}"
        )
        top = sorted(results, key=lambda x: x.get('build_file_count', 0), reverse=True)[:20]
        print("\nTop repositories by build files:")
        for idx, result in enumerate(top, 1):
            print(
                f"{idx}. {result['name']} | build_files={result['build_file_count']} | "
                f"files={result['total_files']} | loc={result['lines_of_code']} | "
                f"monorepo={'yes' if result['is_monorepo'] else 'no'}"
            )

    def _json(self, results: List[Dict], summary: Dict, identity: Dict) -> str:
        output_file = self.output_dir / f'bitbucket_analysis_{self.timestamp}.json'
        report = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'user': identity.get('login', 'unknown'),
                'name': identity.get('name', 'N/A'),
            },
            'summary': summary,
            'repositories': [{**r, 'contributors': sorted(list(r['contributors']))} for r in results],
        }
        with open(output_file, 'w', encoding='utf-8') as handle:
            json.dump(report, handle, indent=2)
        return str(output_file)

    def _csvs(self, results: List[Dict]) -> Tuple[str, str, str]:
        csv_file = self.output_dir / f'bitbucket_analysis_{self.timestamp}.csv'
        with open(csv_file, 'w', newline='', encoding='utf-8') as handle:
            writer = csv.writer(handle)
            writer.writerow([
                'Repository', 'URL', 'Language', 'Technologies', 'Private', 'Monorepo',
                'Total Files', 'Lines Of Code', 'Scaled File Count',
                'Build Files Count', 'Build Files', 'Contributors Count', 'Error'
            ])
            for r in results:
                writer.writerow([
                    r['name'], r['url'], r['language'], '; '.join(r['detected_technologies']),
                    r['private'], r['is_monorepo'], r['total_files'], r['lines_of_code'],
                    f"{r['scaled_file_count']:.2f}", r['build_file_count'], '; '.join(r['build_files']),
                    len(r['contributors']), r['error'] or ''
                ])

        contrib_file = self.output_dir / f'bitbucket_contributors_{self.timestamp}.csv'
        contributor_repos = defaultdict(list)
        for r in results:
            for c in r['contributors']:
                contributor_repos[c].append(r['name'])
        with open(contrib_file, 'w', newline='', encoding='utf-8') as handle:
            writer = csv.writer(handle)
            writer.writerow(['Contributor Email', 'Repository Count', 'Repositories'])
            for email, repos in sorted(contributor_repos.items(), key=lambda x: len(x[1]), reverse=True):
                writer.writerow([email, len(repos), '; '.join(repos)])

        detail_file = self.output_dir / f'bitbucket_repo_details_{self.timestamp}.csv'
        with open(detail_file, 'w', newline='', encoding='utf-8') as handle:
            writer = csv.writer(handle)
            writer.writerow([
                'Repository', 'Lines Of Code', 'Total Files', 'Build Files', 'Technology',
                'Monorepo', 'Monorepo License File Count'
            ])
            for r in results:
                writer.writerow([
                    r['name'], r['lines_of_code'], r['total_files'], r['build_file_count'],
                    '; '.join(r['detected_technologies']), r['is_monorepo'],
                    r['license_file_count'] if r['is_monorepo'] else 0
                ])
        return str(csv_file), str(contrib_file), str(detail_file)


def main():
    parser = argparse.ArgumentParser(
        description='Bitbucket Repository Analyzer - Cloud and Server/DC',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Bitbucket Cloud
  python bitbucket-repo-analyzer.py --provider bitbucket-cloud --workspace my-workspace --username myuser --token TOKEN

  # Bitbucket Server/Data Center
  python bitbucket-repo-analyzer.py --provider bitbucket-server --base-url https://bitbucket.company.local --token TOKEN

  # Monorepo-only analysis
  python bitbucket-repo-analyzer.py --provider bitbucket-cloud --workspace my-workspace --username myuser --token TOKEN --monorepo-only
'''
    )
    parser.add_argument('--provider', choices=['bitbucket-cloud', 'bitbucket-server'], default='bitbucket-cloud')
    parser.add_argument('--token', help='Bitbucket token or app password')
    parser.add_argument('--username', help='Bitbucket username (required for cloud app-password auth)')
    parser.add_argument('--workspace', help='Bitbucket Cloud workspace (required for cloud)')
    parser.add_argument('--base-url', default='https://bitbucket.example.com', help='Bitbucket Server/DC base URL')
    parser.add_argument('--project-key', help='Optional project key filter for Server/DC')
    parser.add_argument('--output-dir', default='.', help='Output directory for reports')
    parser.add_argument('--max-repos', type=int, help='Max number of repositories to analyze')
    parser.add_argument('--monorepo-only', action='store_true', help='Report only monorepos')
    parser.add_argument('--include-monorepo', action='store_true', help='Include monorepos in scaled count summary')
    parser.add_argument('--monorepo-file-threshold', type=int, default=1000, help='Monorepo file threshold')
    parser.add_argument('--monorepo-loc-threshold', type=int, default=300000, help='Monorepo LOC threshold')
    args = parser.parse_args()

    cfg = Config()
    if not cfg.load(args):
        print("Failed to load Bitbucket configuration.")
        sys.exit(1)

    os.makedirs(args.output_dir, exist_ok=True)

    client = BitbucketClient(cfg)
    analyzer = RepoAnalyzer()

    print("Authenticating and loading repositories...")
    identity = client.get_identity()
    repos = client.get_all_repositories()
    if args.max_repos:
        repos = repos[:args.max_repos]

    print(f"Analyzing {len(repos)} repositories...")
    results = []
    for idx, repo in enumerate(repos, 1):
        print(f"[{idx}/{len(repos)}] {repo['full_name']}")
        result = analyzer.analyze_repository(repo)
        if not result['error']:
            is_monorepo = (
                result['total_files'] > args.monorepo_file_threshold
                or result['lines_of_code'] > args.monorepo_loc_threshold
            )
            result['is_monorepo'] = is_monorepo
            result['scaled_file_count'] = result['total_files'] / (1000.0 if is_monorepo else 100.0)
        results.append(result)

    if args.monorepo_only:
        results = [r for r in results if r.get('is_monorepo')]
        print(f"Monorepo-only mode enabled: {len(results)} repositories remain.")

    reporter = Reporter(args.output_dir)
    include_monorepo_effective = args.include_monorepo or args.monorepo_only
    files = reporter.write(results, identity, include_monorepo_effective)
    print("Analysis complete.")
    for key, value in files.items():
        print(f"{key}: {value}")


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path


SCRIPT_ROOT = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_ROOT
DEFAULT_CONFIG_PATH = SCRIPT_ROOT / "sensitive-data-patterns.json"
DEFAULT_TARGETS = [
    "Loading_Script_V5_PUB",
    "Generic_to_csv_translator",
    "Gating",
]
ACCOUNT_ID_RE = re.compile(r"\b\d{12}\b")

PLACEHOLDER_TOKENS = {
    "example",
    "test",
    "dummy",
    "placeholder",
    "changeme",
    "redacted",
    "replace_me",
    "todo",
    "sample",
    "your_",
}

COMMON_TEST_SSNS = {
    "000-00-0000",
    "111-11-1111",
    "123-45-6789",
    "999-99-9999",
}


def run_git(args):
    result = subprocess.run(
        ["git"] + args,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def is_git_ignored(path: Path) -> bool:
    code, _, _ = run_git(["check-ignore", "-q", str(path)])
    return code == 0


def load_config(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    data.setdefault("anonymized_account_prefix", "")
    data.setdefault("anonymized_account_id_regexes", [])
    data.setdefault("skip_directories", [])
    data.setdefault("skip_extensions", [])
    data.setdefault("skip_files", [])
    data.setdefault("allowlist_regexes", [])
    data.setdefault("patterns", {})
    return data


def build_regexes(patterns_config):
    regexes = {}
    for name, pattern in patterns_config.items():
        try:
            regexes[name] = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"Invalid regex for {name}: {exc}") from exc
    return regexes


def build_allowlist(allowlist_config):
    allowlist = []
    for pattern in allowlist_config:
        try:
            allowlist.append(re.compile(pattern, re.IGNORECASE))
        except re.error as exc:
            raise ValueError(f"Invalid allowlist regex {pattern}: {exc}") from exc
    return allowlist


def build_account_id_allowlist(account_id_config):
    allowlist = []
    for pattern in account_id_config:
        try:
            allowlist.append(re.compile(pattern))
        except re.error as exc:
            raise ValueError(f"Invalid account id allowlist regex {pattern}: {exc}") from exc
    return allowlist


def is_anonymized_account_id(account_id: str, allowlist, anonymized_prefix: str) -> bool:
    if anonymized_prefix and account_id.startswith(anonymized_prefix):
        return True
    for pattern in allowlist:
        if pattern.fullmatch(account_id):
            return True
    return False


def is_account_id_rule(rule_name: str) -> bool:
    return rule_name == "aws_arn_account" or "account_id" in rule_name


def is_binary_file(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            chunk = handle.read(2048)
    except OSError:
        return True
    if not chunk:
        return False
    if b"\0" in chunk:
        return True
    text_chars = sum(1 for b in chunk if 32 <= b < 127 or b in b"\n\r\t\b\f")
    return (text_chars / len(chunk)) < 0.7


def looks_placeholder(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in PLACEHOLDER_TOKENS)


def luhn_check(number: str) -> bool:
    digits = [int(ch) for ch in number if ch.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for idx, digit in enumerate(digits):
        if idx % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def valid_phone_number(text: str) -> bool:
    digits = [ch for ch in text if ch.isdigit()]
    return 10 <= len(digits) <= 15


def redact_line(line: str, start: int, end: int) -> str:
    return f"{line[:start]}<REDACTED>{line[end:]}"


def safe_relpath(path: Path) -> Path:
    try:
        return path.relative_to(REPO_ROOT)
    except ValueError:
        return path


def should_skip_file(path: Path, config, include_ignored: bool) -> bool:
    rel_path = path.as_posix()
    if rel_path in config["skip_files"]:
        return True
    if any(part in config["skip_directories"] for part in path.parts):
        return True
    if path.suffix.lower() in {ext.lower() for ext in config["skip_extensions"]}:
        return True
    if not include_ignored and is_git_ignored(path):
        return True
    return False


def iter_files(paths, config, include_ignored: bool):
    for raw_path in paths:
        abs_path = (REPO_ROOT / raw_path).resolve() if not raw_path.is_absolute() else raw_path
        if not abs_path.exists():
            continue
        if abs_path.is_file():
            rel_path = safe_relpath(abs_path)
            if not should_skip_file(rel_path, config, include_ignored):
                yield abs_path
            continue
        for root, dirnames, filenames in os.walk(abs_path):
            dirnames[:] = [
                name for name in dirnames if name not in config["skip_directories"]
            ]
            for filename in filenames:
                file_path = Path(root) / filename
                rel_path = safe_relpath(file_path)
                if should_skip_file(rel_path, config, include_ignored):
                    continue
                yield file_path


def allowlisted(text: str, line: str, allowlist) -> bool:
    if looks_placeholder(text):
        return True
    for pattern in allowlist:
        if pattern.search(text) or pattern.search(line):
            return True
    return False


def match_is_valid(name: str, match_text: str) -> bool:
    if name == "credit_card":
        return luhn_check(match_text)
    if name == "phone_number":
        return valid_phone_number(match_text)
    if name == "ssn" and match_text in COMMON_TEST_SSNS:
        return False
    return True


def scan_file(
    path: Path,
    rel_path: Path,
    patterns,
    allowlist,
    anonymized_prefix,
    account_id_allowlist,
    max_findings=0,
    current_count=0,
):
    findings = []
    truncated = False
    try:
        content = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return findings

    for line_number, line in enumerate(content, start=1):
        for name, regex in patterns.items():
            for match in regex.finditer(line):
                match_text = match.group(0)
                if allowlisted(match_text, line, allowlist):
                    continue
                if is_account_id_rule(name):
                    account_ids = ACCOUNT_ID_RE.findall(match_text)
                    if account_ids and all(
                        is_anonymized_account_id(account_id, account_id_allowlist, anonymized_prefix)
                        for account_id in account_ids
                    ):
                        continue
                if not match_is_valid(name, match_text):
                    continue
                snippet = redact_line(line, match.start(), match.end())
                findings.append((rel_path, line_number, name, snippet.strip()))
                if max_findings and (len(findings) + current_count) >= max_findings:
                    truncated = True
                    return findings, truncated
    return findings, truncated


def normalize_paths(paths):
    return [Path(path) for path in paths]


def main():
    global REPO_ROOT
    parser = argparse.ArgumentParser(
        description="Scan files for personal and sensitive data."
    )
    parser.add_argument(
        "--paths",
        nargs="*",
        help="Files or directories to scan (defaults to key Utils PUB folders).",
    )
    parser.add_argument(
        "--repo-root",
        default=str(REPO_ROOT),
        help="Repo root for resolving relative paths and git ignore checks.",
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help="Path to the JSON patterns configuration file.",
    )
    parser.add_argument(
        "--include-ignored",
        action="store_true",
        help="Include files matched by .gitignore rules.",
    )
    parser.add_argument(
        "--max-findings",
        type=int,
        default=0,
        help="Stop after this many findings (0 means no limit).",
    )
    args = parser.parse_args()

    REPO_ROOT = Path(args.repo_root).resolve()

    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = (SCRIPT_ROOT / config_path).resolve()
    config = load_config(config_path)
    patterns = build_regexes(config["patterns"])
    allowlist = build_allowlist(config["allowlist_regexes"])
    account_id_allowlist = build_account_id_allowlist(config["anonymized_account_id_regexes"])
    anonymized_prefix = config["anonymized_account_prefix"]

    if args.paths:
        targets = normalize_paths(args.paths)
    elif REPO_ROOT != SCRIPT_ROOT:
        targets = [REPO_ROOT]
    else:
        targets = normalize_paths(DEFAULT_TARGETS)

    findings = []
    scanned_files = 0
    truncated_any = False
    for file_path in iter_files(targets, config, args.include_ignored):
        if is_binary_file(file_path):
            continue
        scanned_files += 1
        rel_path = safe_relpath(file_path)
        new_findings, truncated = scan_file(
            file_path,
            rel_path,
            patterns,
            allowlist,
            anonymized_prefix,
            account_id_allowlist,
            max_findings=args.max_findings,
            current_count=len(findings),
        )
        findings.extend(new_findings)
        if truncated:
            truncated_any = True
            break

    if findings:
        print("Sensitive data findings:")
        for path, line_number, name, snippet in findings:
            print(f"- {path}:{line_number} [{name}] {snippet}")
        print(f"\nTotal findings: {len(findings)} in {scanned_files} file(s).")
        if truncated_any:
            print("Stopped early after reaching max findings limit.")
        return 1

    print(f"No sensitive data findings in {scanned_files} file(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

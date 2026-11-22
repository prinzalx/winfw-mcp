#!/usr/bin/env python3
"""Release tool for a project scaffolded from TEMPLATE_00.

Commands:
  check    Report what goes public. Change nothing.
  publish  Copy the included files into the public clone, commit, push.

An allowlist decides what is public. A tracked file is private unless a
pattern in release/include.txt includes it.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

MAX_PUBLIC_BYTES = 1024 * 1024

UNEXPECTED_NAMES = (".env", ".pem", ".key", ".log", ".pdf", ".p12", ".pfx")
UNEXPECTED_SUFFIXES = (
    ".mp3", ".wav", ".flac", ".m4a",
    ".npy", ".npz", ".pth", ".bin", ".ckpt", ".onnx",
)
UNEXPECTED_PARTS = ("cache", "__pycache__", "node_modules", "dist", "build")

BINARY_SUFFIXES = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".svg",
    ".zip", ".gz", ".tar", ".bz2", ".xz", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".pyd", ".class", ".jar",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".xls", ".xlsx", ".doc", ".docx", ".ppt", ".pptx", ".odt",
    ".mp4", ".mov", ".avi", ".webm",
)

SECRET_PATTERNS = (
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"), "GitHub token"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    (
        re.compile(
            r"(?i)\b(secret|token|password|passwd|api[_-]?key|access[_-]?key)\b"
            r"\s*[:=]\s*['\"]?[A-Za-z0-9/+_\-\.]{12,}"
        ),
        "key/value assignment",
    ),
)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
LOCAL_PATH_PATTERN = re.compile(r"(?:/Users/|/home/)[A-Za-z0-9._-]+|[A-Za-z]:\\+|\\\\wsl")


def run_git(repo: Path, *args: str) -> str:
    """Run git inside repo and return stdout as text."""
    result = subprocess.run(
        ["git", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        sys.exit(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def repo_root() -> Path:
    out = run_git(Path.cwd(), "rev-parse", "--show-toplevel")
    return Path(out.strip())


def read_patterns(allowlist: Path) -> list[str]:
    if not allowlist.is_file():
        sys.exit(f"Missing allowlist: {allowlist}")
    patterns = []
    for line in allowlist.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        patterns.append(line.replace("\\", "/"))
    return patterns


def pattern_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate an allowlist pattern into a regex over a posix path."""
    out = ""
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char == "*":
            if pattern.startswith("**", index):
                if pattern.startswith("**/", index + 1):
                    out += "(?:[^/]+/)*"
                    index += 3
                    continue
                out += ".*"
                index += 2
                continue
            out += "[^/]*"
        elif char == "?":
            out += "[^/]"
        else:
            out += re.escape(char)
        index += 1
    if pattern.endswith("/"):
        out += ".*"
    return re.compile(f"^{out}$")


def is_included(path: str, patterns: list[str], regexes: list[re.Pattern[str]]) -> bool:
    for pattern, regex in zip(patterns, regexes):
        if regex.match(path):
            return True
        if path == pattern or path.startswith(pattern + "/"):
            return True
    return False


def tracked_files(root: Path) -> list[str]:
    out = run_git(root, "ls-files")
    return sorted(line.replace("\\", "/") for line in out.splitlines() if line.strip())


def read_text(path: Path) -> str | None:
    """Return file text, or None when the file is binary."""
    if path.suffix.lower() in BINARY_SUFFIXES:
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def find_gitleaks() -> str | None:
    return shutil.which("gitleaks")


def scan_with_gitleaks(root: Path, included: list[str]) -> list[str]:
    """Scan the included files with gitleaks. Return finding lines."""
    workdir = Path(tempfile.mkdtemp(prefix="release-scan-"))
    report = Path(tempfile.gettempdir()) / f"gitleaks-{workdir.name}.json"
    try:
        for rel in included:
            src = root / rel
            if not src.is_file():
                continue
            dst = workdir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        result = subprocess.run(
            [
                "gitleaks", "detect", "--no-git", "--source", str(workdir),
                "--redact", "--no-banner",
                "--report-format", "json", "--report-path", str(report),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if not report.is_file():
            return [f"gitleaks produced no report (exit {result.returncode})"]
        try:
            findings = json.loads(report.read_text(encoding="utf-8", errors="replace") or "[]")
        except json.JSONDecodeError as exc:
            return [f"gitleaks report unreadable: {exc}"]
        lines = []
        for item in findings:
            raw = str(item.get("File", "")).replace("\\", "/")
            rel = next((c for c in included if raw == c or raw.endswith("/" + c)), Path(raw).name)
            rule = item.get("RuleID") or item.get("Secret") or "secret"
            lines.append(f"{rel}:{item.get('StartLine', '?')} secret ({rule})")
        return lines
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
        report.unlink(missing_ok=True)


def scan_with_patterns(root: Path, included: list[str]) -> list[str]:
    """Fallback secret scan. Return finding lines."""
    lines = []
    for rel in included:
        text = read_text(root / rel)
        if text is None:
            continue
        for number, line in enumerate(text.splitlines(), start=1):
            for pattern, label in SECRET_PATTERNS:
                match = pattern.search(line)
                if match:
                    lines.append(f"{rel}:{number} {label}")
                    break
    return lines


def collect_warnings(root: Path, included: list[str]) -> list[str]:
    """Warn about included files that look wrong for an end user."""
    warnings = []
    for rel in included:
        path = root / rel
        lower = rel.lower()
        if any(lower.endswith(ext) for ext in UNEXPECTED_NAMES):
            warnings.append(f"{rel}: looks like a config, key or log file")
        if any(lower.endswith(ext) for ext in UNEXPECTED_SUFFIXES):
            warnings.append(f"{rel}: looks like binary or model data")
        if any(part in UNEXPECTED_PARTS for part in Path(rel).parts):
            warnings.append(f"{rel}: inside a build or cache folder")
        if path.is_file() and path.stat().st_size > MAX_PUBLIC_BYTES:
            warnings.append(f"{rel}: larger than {MAX_PUBLIC_BYTES // 1024} KiB")
    return warnings


def personal_data_findings(root: Path, included: list[str]) -> list[str]:
    """Report e-mail addresses and absolute local paths in included files."""
    findings = []
    for rel in included:
        text = read_text(root / rel)
        if text is None:
            continue
        emails = {match.group(0) for match in EMAIL_PATTERN.finditer(text)}
        paths = {match.group(0) for match in LOCAL_PATH_PATTERN.finditer(text)}
        for value in sorted(emails):
            findings.append(f"{rel}: e-mail {value}")
        for value in sorted(paths):
            findings.append(f"{rel}: local path {value}")
    return findings


def resolve_public(repo: Path, override: str | None) -> Path:
    if override:
        return Path(override).resolve()
    return (repo.parent / f"{repo.name}-public").resolve()


def public_diff(repo: Path, public: Path, included: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Compare included files with the public clone. Return added, changed, removed."""
    if not public.is_dir():
        return list(included), [], []
    public_files = set(tracked_files(public)) if (public / ".git").is_dir() else set()
    included_set = set(included)
    added = sorted(included_set - public_files)
    removed = sorted(public_files - included_set)
    changed = []
    for rel in sorted(included_set & public_files):
        project_file = repo / rel
        public_file = public / rel
        if not project_file.is_file() or not public_file.is_file():
            changed.append(rel)
            continue
        if project_file.read_bytes() != public_file.read_bytes():
            changed.append(rel)
    return added, changed, removed


def do_check(repo: Path, allowlist: Path, public_arg: str | None, show_lists: bool) -> bool:
    """Print the check report. Return True when the release may proceed."""
    patterns = read_patterns(allowlist)
    regexes = [pattern_to_regex(p) for p in patterns]
    files = tracked_files(repo)
    included = [f for f in files if is_included(f, patterns, regexes)]
    private = [f for f in files if f not in included]
    public = resolve_public(repo, public_arg)

    print(f"Repository:  {repo}")
    print(f"Allowlist:   {allowlist}")
    print(f"Public clone: {public}")
    print()

    if show_lists:
        print(f"GOES PUBLIC ({len(included)}):")
        for rel in included:
            print(f"  {rel}")
        print()
        print(f"STAYS PRIVATE ({len(private)}):")
        for rel in private:
            print(f"  {rel}")
        print()

    ok = True

    if not included:
        print("FAIL: the allowlist includes no tracked file.")
        ok = False

    warnings = collect_warnings(repo, included)
    if warnings:
        print("WARNINGS for included files:")
        for line in warnings:
            print(f"  {line}")
        print()

    gitleaks = find_gitleaks()
    if gitleaks:
        print(f"Secret scan: gitleaks plus pattern check ({gitleaks})")
        secrets = scan_with_gitleaks(repo, included) + scan_with_patterns(repo, included)
    else:
        print("Secret scan: pattern check only (gitleaks not installed)")
        secrets = scan_with_patterns(repo, included)
    secrets = list(dict.fromkeys(secrets))
    seen_lines = set()
    unique = []
    for line in secrets:
        key = line.split(" ", 1)[0]
        if key in seen_lines:
            continue
        seen_lines.add(key)
        unique.append(line)
    secrets = unique
    if secrets:
        print("SECRETS found:")
        for line in secrets:
            print(f"  {line}")
        print()
        ok = False
        print("FAIL: secret found in an included file.")
    else:
        print("Secrets: none.")

    personal = personal_data_findings(repo, included)
    if personal:
        print("PERSONAL DATA / LOCAL PATHS:")
        for line in personal:
            print(f"  {line}")
        print()

    status = run_git(repo, "status", "--porcelain")
    if status.strip():
        print("WARNING: the working tree is not clean.")
        print()

    added, changed, removed = public_diff(repo, public, included)
    print("DIFF against the public clone:")
    for rel in added:
        print(f"  + {rel}")
    for rel in changed:
        print(f"  ~ {rel}")
    for rel in removed:
        print(f"  - {rel}")
    if not (added or changed or removed):
        print("  (no change)")
    print()

    print("RESULT: PASS" if ok else "RESULT: FAIL")
    return ok


def ask_exact(prompt: str, expected: str) -> bool:
    """Ask the operator to type an exact phrase. Return False when it differs."""
    try:
        answer = input(prompt)
    except EOFError:
        print(f"ABORT: {prompt.strip()} needs an answer. Run publish interactively.")
        return False
    return answer.strip() == expected


def do_publish(repo: Path, allowlist: Path, public_arg: str | None, message: str) -> int:
    if not do_check(repo, allowlist, public_arg, show_lists=False):
        print("publish stopped: check failed.")
        return 1
    public = resolve_public(repo, public_arg)
    if not (public / ".git").is_dir():
        sys.exit(f"Public clone is not a git repository: {public}")

    patterns = read_patterns(allowlist)
    regexes = [pattern_to_regex(p) for p in patterns]
    included = [f for f in tracked_files(repo) if is_included(f, patterns, regexes)]
    public_files = set(tracked_files(public))

    for rel in included:
        src = repo / rel
        if not src.is_file():
            continue
        dst = public / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
    for rel in sorted(public_files - set(included)):
        target = public / rel
        if target.is_file():
            target.unlink()

    added, changed, removed = public_diff_after(public, repo, included)
    print("FILE LIST for the public repo:")
    for rel in included:
        print(f"  {rel}")
    print()
    print("DIFF for the public repo:")
    for rel in added:
        print(f"  + {rel}")
    for rel in changed:
        print(f"  ~ {rel}")
    for rel in removed:
        print(f"  - {rel}")
    print()

    if not run_git(public, "status", "--porcelain").strip():
        print("Nothing to commit. The public clone is already in sync.")
        return 0

    if not ask_exact(f"Type COMMIT to commit {len(included)} file(s): ", "COMMIT"):
        print("Aborted before the commit.")
        return 1

    run_git(public, "add", "-A")
    run_git(public, "commit", "-m", message)

    if not ask_exact("Type PUSH to push to the public remote: ", "PUSH"):
        print("Aborted before the push. The commit stays local.")
        return 1

    branch = run_git(public, "rev-parse", "--abbrev-ref", "HEAD").strip()
    result = subprocess.run(
        ["git", "push", "--set-upstream", "origin", branch],
        cwd=str(public),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode != 0:
        print("Push failed. Never force-pushed automatically.")
        return result.returncode
    print("Published.")
    return 0


def public_diff_after(public: Path, repo: Path, included: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Re-read the public clone after the copy. Return added, changed, removed."""
    current = set(tracked_files(public))
    added = sorted(set(included) - current)
    removed = sorted(current - set(included))
    changed = []
    for rel in sorted(current & set(included)):
        project_file = repo / rel
        public_file = public / rel
        if not project_file.is_file() or not public_file.is_file():
            changed.append(rel)
            continue
        if project_file.read_bytes() != public_file.read_bytes():
            changed.append(rel)
    return added, changed, removed


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="TEMPLATE_00 release tool")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--allowlist", default=None, help="Path to include.txt")
    common.add_argument("--public", default=None, help="Path to the public clone")
    common.add_argument("--lists", action="store_true", help="Print the full file lists")

    sub.add_parser("check", parents=[common], help="Report what goes public")

    publish = sub.add_parser("publish", parents=[common], help="Copy, commit, push")
    publish.add_argument("-m", "--message", default=None, help="Commit message")

    args = parser.parse_args(argv)
    root = repo_root()
    allowlist = Path(args.allowlist) if args.allowlist else root / "release" / "include.txt"

    if args.command == "check":
        return 0 if do_check(root, allowlist, args.public, args.lists) else 1

    message = args.message or "release: snapshot from the dev repository"
    return do_publish(root, allowlist, args.public, message)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

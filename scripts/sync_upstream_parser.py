#!/usr/bin/env python3
"""Create read-only upstream parser review plans for the dev branch.

This module intentionally has no apply, commit, or push capability. It scans
upstream history from a human-managed cursor, collects commits that touch the
legacy parser whitelist, and emits complete review context where practical.
Any AI assessment produced by CI is advisory and must never authorize a write.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ROOT_RESOLVED = ROOT.resolve()
TARGET_BRANCH = "dev"
DEFAULT_CURSOR_FILE = ".github/upstream-subconverter.seen"
MAX_PATCH_CHARS = 50_000
ALLOWED_REPO_REPORT_PATHS = {
    "upstream-sync-candidates.json",
    "upstream-sync-plan.md",
}

ALLOWED_AUTO_PATHS = {
    "src/parser/subparser.cpp",
    "src/parser/subparser.h",
    "src/parser/config/proxy.h",
}

REPORT_ONLY_PATHS = {
    "src/generator/config/subexport.cpp",
}

PROTECTED_PATHS = {
    "src/generator/config/nodemanip.cpp",
    "src/generator/config/nodemanip.h",
    "src/generator/config/subexport.h",
    "src/parser/mihomo_bridge.cpp",
    "src/parser/mihomo_bridge.h",
    "src/parser/mihomo_schemes.h",
    "src/parser/param_compat.h",
    "bridge/converter.go",
    "bridge/parser.go",
    "bridge/proxy_validation_generated.go",
    "bridge/go.mod",
    "bridge/go.sum",
}

PROTECTED_PREFIXES = (
    "bridge/",
)


def git(*args: str, check: bool = True) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed with {proc.returncode}\n{proc.stderr}"
        )
    return proc.stdout


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def resolve_report_path(path_text: str) -> Path:
    path = Path(path_text)
    full = path if path.is_absolute() else ROOT / path
    if full.is_symlink():
        raise ValueError(f"report path must not be a symlink: {path_text}")
    resolved = full.resolve()
    try:
        relative = resolved.relative_to(ROOT_RESOLVED).as_posix()
    except ValueError:
        return resolved
    if relative not in ALLOWED_REPO_REPORT_PATHS:
        raise ValueError(f"report path is not an allowed repository output: {path_text}")
    return resolved


def resolve_cursor_file(path_text: str) -> Path:
    path = Path(path_text)
    full = path if path.is_absolute() else ROOT / path
    resolved = full.resolve()
    try:
        resolved.relative_to(ROOT_RESOLVED)
    except ValueError as exc:
        raise ValueError(f"cursor file must stay inside repository: {path_text}") from exc
    return resolved


def display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT_RESOLVED).as_posix()
    except ValueError:
        return str(path)


def ensure_dev_checkout() -> None:
    branch = git("branch", "--show-current").strip()
    if branch != TARGET_BRANCH:
        raise RuntimeError(
            f"upstream parser monitoring is dev-only; current branch is "
            f"{branch or 'detached HEAD'}"
        )


def path_is_protected(path: str) -> bool:
    return path in PROTECTED_PATHS or any(
        path.startswith(prefix) for prefix in PROTECTED_PREFIXES
    )


def commit_files(sha: str) -> list[str]:
    output = git(
        "diff-tree",
        "--root",
        "-m",
        "--no-commit-id",
        "--name-only",
        "-r",
        sha,
    )
    return sorted({line.strip() for line in output.splitlines() if line.strip()})


def commit_subject(sha: str) -> str:
    return git("show", "-s", "--format=%s", sha).strip()


def commit_is_merge(sha: str) -> bool:
    parents = git("rev-list", "--parents", "-n", "1", sha).split()
    return len(parents) > 2


def commit_patch(
    sha: str, paths: list[str], max_chars: int = MAX_PATCH_CHARS
) -> tuple[str, bool, int]:
    if not paths:
        return "", False, 0
    patch = git(
        "show",
        "--first-parent",
        "--format=fuller",
        "--stat",
        "--patch",
        sha,
        "--",
        *paths,
    )
    original_chars = len(patch)
    if original_chars <= max_chars:
        return patch, False, original_chars
    return (
        patch[:max_chars]
        + "\n\n[diff truncated: manual full-diff review required]\n",
        True,
        original_chars,
    )


def classify_commit(sha: str) -> dict[str, Any]:
    files = commit_files(sha)
    allowed = [path for path in files if path in ALLOWED_AUTO_PATHS]
    protected = [path for path in files if path_is_protected(path)]
    report_only = [path for path in files if path in REPORT_ONLY_PATHS]
    other = [
        path
        for path in files
        if path not in ALLOWED_AUTO_PATHS
        and path not in REPORT_ONLY_PATHS
        and not path_is_protected(path)
    ]

    if not allowed:
        rule_decision = "ignore_no_parser_changes"
        isolated_parser_change = False
        reviewable_by_ai = False
        reason = "Commit does not change legacy parser whitelist files."
    elif protected:
        rule_decision = "protected_path"
        isolated_parser_change = False
        reviewable_by_ai = False
        reason = "Commit also touches protected project-specific integration paths."
    elif report_only or other:
        rule_decision = "mixed_change"
        isolated_parser_change = False
        reviewable_by_ai = True
        reason = "Commit changes parser files plus non-whitelisted files."
    else:
        rule_decision = "isolated_parser_change"
        isolated_parser_change = True
        reviewable_by_ai = True
        reason = "Commit changes only legacy parser whitelist files."

    patch_excerpt, patch_truncated, patch_chars = commit_patch(sha, files)
    return {
        "sha": sha,
        "short_sha": sha[:12],
        "subject": commit_subject(sha),
        "is_merge": commit_is_merge(sha),
        "files": files,
        "allowed_paths": allowed,
        "protected_paths": protected,
        "report_only_paths": report_only,
        "other_paths": other,
        "isolated_parser_change": isolated_parser_change,
        "reviewable_by_ai": reviewable_by_ai,
        "rule_decision": rule_decision,
        "reason": reason,
        "patch_excerpt": patch_excerpt,
        "patch_truncated": patch_truncated,
        "patch_chars": patch_chars,
        "automatic_action": "never",
    }


def plan(args: argparse.Namespace) -> int:
    ensure_dev_checkout()
    if args.max_commits < 1 or args.max_commits > 100:
        raise ValueError("max-commits must be between 1 and 100")
    upstream_head = git("rev-parse", args.upstream_ref).strip()
    cursor_file = resolve_cursor_file(args.cursor_file)
    manual_since = (args.since or "").strip()
    stored_seen = (
        cursor_file.read_text(encoding="utf-8").strip()
        if cursor_file.exists()
        else ""
    )
    seen = manual_since or stored_seen

    if not seen:
        raise RuntimeError(
            "no upstream cursor is available; initialize it explicitly on dev "
            "after human review"
        )

    exists = run("git", "cat-file", "-e", f"{seen}^{{commit}}")
    if exists.returncode != 0:
        raise RuntimeError(
            f"upstream cursor commit is unavailable: {seen}; refusing silent bootstrap"
        )

    ancestor = run("git", "merge-base", "--is-ancestor", seen, args.upstream_ref)
    if ancestor.returncode != 0:
        raise RuntimeError(
            f"upstream cursor {seen} is not an ancestor of {args.upstream_ref}; "
            "human review is required"
        )

    total_commit_count = int(
        git("rev-list", "--count", f"{seen}..{args.upstream_ref}").strip() or "0"
    )
    relevant_out = git(
        "rev-list",
        "--reverse",
        f"{seen}..{args.upstream_ref}",
        "--",
        *sorted(ALLOWED_AUTO_PATHS),
    )
    relevant_commits = [
        line.strip() for line in relevant_out.splitlines() if line.strip()
    ]
    parser_commit_count = len(relevant_commits)

    selected_commits = relevant_commits
    if args.max_commits > 0:
        selected_commits = relevant_commits[: args.max_commits]
    selected_commit_count = len(selected_commits)
    truncated = parser_commit_count > selected_commit_count
    candidates = [classify_commit(sha) for sha in selected_commits]

    data = {
        "generated_at": utc_now(),
        "mode": "monitor_only",
        "target_branch": TARGET_BRANCH,
        "automatic_apply": False,
        "automatic_commit": False,
        "automatic_push": False,
        "upstream_ref": args.upstream_ref,
        "upstream_head": upstream_head,
        "cursor_file": display_path(cursor_file),
        "cursor_managed_by": "human",
        "seen": seen,
        "stored_seen": stored_seen,
        "manual_since": manual_since,
        "total_commit_count": total_commit_count,
        "parser_commit_count": parser_commit_count,
        "selected_commit_count": selected_commit_count,
        "truncated": truncated,
        "allowed_parser_paths": sorted(ALLOWED_AUTO_PATHS),
        "protected_paths": sorted(PROTECTED_PATHS),
        "protected_prefixes": list(PROTECTED_PREFIXES),
        "candidates": candidates,
    }

    output_path = resolve_report_path(args.output)
    report_path = resolve_report_path(args.report)
    write_json(output_path, data)
    write_plan_report(report_path, data)
    print(
        f"Planned {len(candidates)} parser-related upstream commits in "
        f"monitor-only mode; no repository writes are possible."
    )
    return 0


def write_plan_report(path: Path, data: dict[str, Any]) -> None:
    lines = [
        "# Upstream Parser Monitor Report",
        "",
        "> Advisory report only. No patch is applied, committed, or pushed.",
        "",
        f"- Generated: {data['generated_at']}",
        f"- Mode: `{data['mode']}`",
        f"- Target branch: `{data['target_branch']}`",
        f"- Upstream ref: `{data['upstream_ref']}`",
        f"- Cursor file: `{data['cursor_file']}`",
        f"- Cursor owner: `{data['cursor_managed_by']}`",
        f"- Seen: `{data['seen']}`",
        f"- Manual since override: `{data['manual_since'] or 'none'}`",
        f"- Upstream head: `{data['upstream_head']}`",
        f"- Total upstream commits since cursor: `{data['total_commit_count']}`",
        f"- Parser-related commits: `{data['parser_commit_count']}`",
        f"- Selected commits: `{data['selected_commit_count']}`",
        f"- Truncated: `{data['truncated']}`",
        "",
        "## Candidates",
        "",
    ]
    if not data["candidates"]:
        lines.append("No parser-related candidate commits.")
    for item in data["candidates"]:
        lines.extend(
            [
                f"### `{item['short_sha']}` {item['subject']}",
                "",
                f"- Rule decision: `{item['rule_decision']}`",
                f"- Merge commit: `{item['is_merge']}`",
                f"- Isolated parser change: `{item['isolated_parser_change']}`",
                f"- AI review available: `{item['reviewable_by_ai']}`",
                f"- Patch truncated: `{item['patch_truncated']}`",
                f"- Automatic action: `{item['automatic_action']}`",
                f"- Reason: {item['reason']}",
                f"- Files: {', '.join(f'`{p}`' for p in item['files']) or 'none'}",
                "",
            ]
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    plan_parser = sub.add_parser("plan")
    plan_parser.add_argument("--upstream-ref", required=True)
    plan_parser.add_argument(
        "--cursor-file",
        default=DEFAULT_CURSOR_FILE,
        help="human-managed dev baseline for upstream monitoring",
    )
    plan_parser.add_argument(
        "--since",
        default="",
        help="temporary review baseline; never updates the stored cursor",
    )
    plan_parser.add_argument("--max-commits", type=int, default=30)
    plan_parser.add_argument("--output", default="upstream-sync-candidates.json")
    plan_parser.add_argument("--report", default="upstream-sync-plan.md")
    plan_parser.set_defaults(func=plan)

    args = parser.parse_args()
    try:
        return args.func(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

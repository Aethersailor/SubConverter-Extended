#!/usr/bin/env python3
"""Plan and apply guarded parser syncs from upstream subconverter.

This script intentionally does not trust upstream diffs by default. It plans
candidate commits, lets CI/Copilot classify them, applies only low-risk parser
updates, and records skipped commits so one unsafe upstream commit does not
block later safe ones.
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

SEEN_FILE = ROOT / ".github" / "upstream-subconverter.seen"
APPLIED_FILE = ROOT / ".github" / "upstream-subconverter.applied.json"
SKIPPED_FILE = ROOT / ".github" / "upstream-subconverter.skipped.json"

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
    "bridge/go.mod",
    "bridge/go.sum",
}

PROTECTED_PREFIXES = (
    "bridge/",
)

SAFE_DECISION = "safe_parser_only"


def git(*args: str, input_text: str | None = None, check: bool = True) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=ROOT,
        input=input_text,
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


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(args),
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=check,
    )


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def read_json_array(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def read_seen() -> str:
    if not SEEN_FILE.exists():
        return ""
    return SEEN_FILE.read_text(encoding="utf-8").strip()


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


def path_is_protected(path: str) -> bool:
    return path in PROTECTED_PATHS or any(path.startswith(prefix) for prefix in PROTECTED_PREFIXES)


def commit_files(sha: str) -> list[str]:
    output = git("diff-tree", "--no-commit-id", "--name-only", "-r", sha)
    return [line.strip() for line in output.splitlines() if line.strip()]


def commit_subject(sha: str) -> str:
    return git("show", "-s", "--format=%s", sha).strip()


def commit_patch(sha: str, paths: list[str], max_chars: int = 12000) -> str:
    if not paths:
        return ""
    patch = git("show", "--format=fuller", "--stat", "--patch", sha, "--", *paths)
    if len(patch) <= max_chars:
        return patch
    return patch[:max_chars] + "\n\n[diff truncated]\n"


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
        safe_by_rules = False
        reviewable_by_ai = False
        reason = "Commit does not change parser whitelist files."
    elif protected:
        rule_decision = "skip_protected_path"
        safe_by_rules = False
        reviewable_by_ai = False
        reason = "Commit touches protected project-specific integration paths."
    elif report_only or other:
        rule_decision = "needs_human_or_ai_report"
        safe_by_rules = False
        reviewable_by_ai = True
        reason = "Commit changes parser files plus non-whitelisted files."
    else:
        rule_decision = "candidate"
        safe_by_rules = True
        reviewable_by_ai = True
        reason = "Commit changes only parser whitelist files."

    return {
        "sha": sha,
        "short_sha": sha[:12],
        "subject": commit_subject(sha),
        "files": files,
        "allowed_paths": allowed,
        "protected_paths": protected,
        "report_only_paths": report_only,
        "other_paths": other,
        "safe_by_rules": safe_by_rules,
        "reviewable_by_ai": reviewable_by_ai,
        "rule_decision": rule_decision,
        "reason": reason,
        "patch_excerpt": commit_patch(sha, allowed or files[:10]),
    }


def plan(args: argparse.Namespace) -> int:
    upstream_head = git("rev-parse", args.upstream_ref).strip()
    cursor_file = resolve_cursor_file(args.cursor_file)
    manual_since = (args.since or "").strip()
    stored_seen = cursor_file.read_text(encoding="utf-8").strip() if cursor_file.exists() else ""
    seen = manual_since or stored_seen
    bootstrap = False
    commits: list[str] = []
    all_commits: list[str] = []

    if not seen:
        bootstrap = True
    else:
        exists = run("git", "cat-file", "-e", f"{seen}^{{commit}}", check=False)
        if exists.returncode != 0:
            if manual_since:
                raise RuntimeError(f"manual --since commit does not exist: {manual_since}")
            bootstrap = True
            commits = []
        else:
            ancestor = run(
                "git",
                "merge-base",
                "--is-ancestor",
                seen,
                args.upstream_ref,
                check=False,
            )
            if ancestor.returncode != 0:
                if manual_since:
                    raise RuntimeError(
                        f"manual --since commit is not an ancestor of {args.upstream_ref}: "
                        f"{manual_since}"
                    )
                bootstrap = True
            else:
                commits_out = git(
                    "rev-list",
                    "--reverse",
                    "--no-merges",
                    f"{seen}..{args.upstream_ref}",
                )
                commits = [
                    line.strip()
                    for line in commits_out.splitlines()
                    if line.strip()
                ]
                all_commits = commits

    total_commit_count = len(all_commits)
    if args.max_commits > 0:
        commits = commits[: args.max_commits]
    selected_commit_count = len(commits)
    truncated = total_commit_count > selected_commit_count
    batch_last_sha = commits[-1] if commits else ""
    cursor_update_enabled = not manual_since and not bootstrap
    advance_to = ""
    if cursor_update_enabled:
        if batch_last_sha:
            advance_to = batch_last_sha if truncated else upstream_head
        elif seen and not bootstrap:
            advance_to = upstream_head

    candidates = [classify_commit(sha) for sha in commits]
    data = {
        "generated_at": utc_now(),
        "upstream_ref": args.upstream_ref,
        "upstream_head": upstream_head,
        "cursor_file": display_path(cursor_file),
        "cursor_update_enabled": cursor_update_enabled,
        "seen": seen,
        "stored_seen": stored_seen,
        "manual_since": manual_since,
        "bootstrap": bootstrap,
        "total_commit_count": total_commit_count,
        "selected_commit_count": selected_commit_count,
        "truncated": truncated,
        "batch_last_sha": batch_last_sha,
        "advance_to": advance_to,
        "allowed_auto_paths": sorted(ALLOWED_AUTO_PATHS),
        "protected_paths": sorted(PROTECTED_PATHS),
        "protected_prefixes": list(PROTECTED_PREFIXES),
        "safe_decision": SAFE_DECISION,
        "candidates": candidates,
    }

    write_json(Path(args.output), data)
    write_plan_report(Path(args.report), data)

    safe_count = sum(1 for item in candidates if item["safe_by_rules"])
    reviewable_count = sum(1 for item in candidates if item["reviewable_by_ai"])
    print(
        f"Planned {len(candidates)} upstream commits "
        f"({safe_count} rule-safe, {reviewable_count} AI-reviewable)."
    )
    if bootstrap:
        print("No seen marker was available; plan bootstrapped without candidates.")
    return 0


def write_plan_report(path: Path, data: dict[str, Any]) -> None:
    lines = [
        "# Upstream Parser Sync Plan",
        "",
        f"- Generated: {data['generated_at']}",
        f"- Upstream ref: `{data['upstream_ref']}`",
        f"- Cursor file: `{data['cursor_file']}`",
        f"- Seen: `{data['seen'] or 'none'}`",
        f"- Stored seen: `{data['stored_seen'] or 'none'}`",
        f"- Manual since override: `{data['manual_since'] or 'none'}`",
        f"- Upstream head: `{data['upstream_head']}`",
        f"- Bootstrap: `{data['bootstrap']}`",
        f"- Total pending commits: `{data['total_commit_count']}`",
        f"- Selected commits: `{data['selected_commit_count']}`",
        f"- Truncated: `{data['truncated']}`",
        f"- Advance to: `{data['advance_to'] or 'none'}`",
        "",
        "## Candidates",
        "",
    ]
    if not data["candidates"]:
        lines.append("No candidate commits.")
    for item in data["candidates"]:
        lines.extend(
            [
                f"### `{item['short_sha']}` {item['subject']}",
                "",
                f"- Rule decision: `{item['rule_decision']}`",
                f"- Safe by rules: `{item['safe_by_rules']}`",
                f"- Reviewable by AI: `{item['reviewable_by_ai']}`",
                f"- Reason: {item['reason']}",
                f"- Files: {', '.join(f'`{path}`' for path in item['files']) or 'none'}",
                "",
            ]
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def load_decisions(path: Path) -> dict[str, dict[str, Any]]:
    text = path.read_text(encoding="utf-8").strip()
    data = json.loads(text)
    decisions = data.get("decisions", data)
    if not isinstance(decisions, list):
        raise ValueError("Copilot decision file must contain a decisions array.")
    result: dict[str, dict[str, Any]] = {}
    for item in decisions:
        if not isinstance(item, dict) or "sha" not in item:
            continue
        result[item["sha"]] = item
    return result


def snapshot_paths(paths: list[str]) -> dict[str, bytes | None]:
    snapshot: dict[str, bytes | None] = {}
    for path in paths:
        full = ROOT / path
        snapshot[path] = full.read_bytes() if full.exists() else None
    return snapshot


def restore_snapshot(snapshot: dict[str, bytes | None]) -> None:
    for path, content in snapshot.items():
        full = ROOT / path
        if content is None:
            if full.exists():
                full.unlink()
        else:
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_bytes(content)
    run("git", "reset", "--", *snapshot.keys(), check=False)


def apply_patch_for_commit(sha: str, paths: list[str]) -> tuple[bool, str]:
    patch = git("show", "--format=", "--binary", sha, "--", *paths)
    if not patch.strip():
        return False, "No patch content for allowed parser files."

    check = subprocess.run(
        ["git", "apply", "-3", "--check", "--whitespace=nowarn", "-"],
        cwd=ROOT,
        input=patch,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check.returncode != 0:
        return False, check.stderr.strip() or "git apply --check failed."

    applied = subprocess.run(
        ["git", "apply", "-3", "--whitespace=nowarn", "-"],
        cwd=ROOT,
        input=patch,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if applied.returncode != 0:
        return False, applied.stderr.strip() or "git apply failed."
    return True, "Applied."


def run_guards() -> tuple[bool, str]:
    proc = subprocess.run(
        [sys.executable, "scripts/check_sync_guards.py", "--json"],
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode == 0, output.strip()


def append_state(path: Path, entries: list[dict[str, Any]]) -> None:
    if not entries:
        return
    current = read_json_array(path)
    current.extend(entries)
    write_json(path, current)


def apply(args: argparse.Namespace) -> int:
    plan_data = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    decisions = load_decisions(Path(args.decisions))
    applied_entries: list[dict[str, Any]] = []
    skipped_entries: list[dict[str, Any]] = []
    ignored_entries: list[dict[str, Any]] = []
    cursor_update_enabled = bool(plan_data.get("cursor_update_enabled"))
    cursor_file_text = plan_data.get("cursor_file") or display_path(SEEN_FILE)
    cursor_file = resolve_cursor_file(cursor_file_text)
    advance_to = plan_data.get("advance_to") or ""

    for item in plan_data.get("candidates", []):
        sha = item["sha"]
        decision = decisions.get(sha)
        record_base = {
            "sha": sha,
            "subject": item["subject"],
            "time": utc_now(),
        }

        if item.get("rule_decision") == "ignore_no_parser_changes":
            ignored_entries.append(
                {**record_base, "reason": "No parser whitelist files changed."}
            )
            continue

        if not item.get("reviewable_by_ai"):
            skipped_entries.append(
                {
                    **record_base,
                    "reason": item.get("reason", "Rejected by deterministic rules."),
                    "rule_decision": item.get("rule_decision"),
                }
            )
            continue

        if not decision:
            skipped_entries.append(
                {**record_base, "reason": "No Copilot decision was supplied."}
            )
            continue

        if decision.get("decision") != SAFE_DECISION or decision.get("risk") != "low":
            skipped_entries.append(
                {
                    **record_base,
                    "reason": decision.get("reason", "Copilot did not approve automatic sync."),
                    "copilot_decision": decision,
                }
            )
            continue

        paths = item.get("allowed_paths", [])
        if not paths:
            skipped_entries.append(
                {**record_base, "reason": "No parser whitelist paths were available."}
            )
            continue
        backup = snapshot_paths(paths)
        ok, message = apply_patch_for_commit(sha, paths)
        if not ok:
            restore_snapshot(backup)
            skipped_entries.append({**record_base, "reason": message})
            continue

        guards_ok, guards_output = run_guards()
        if not guards_ok:
            restore_snapshot(backup)
            skipped_entries.append(
                {
                    **record_base,
                    "reason": "Guard checks failed after applying patch.",
                    "guard_output": guards_output,
                }
            )
            continue

        applied_entries.append(
            {
                **record_base,
                "paths": paths,
                "copilot_reason": decision.get("reason", ""),
            }
        )

    append_state(APPLIED_FILE, applied_entries)
    append_state(SKIPPED_FILE, skipped_entries)

    advanced_to = ""
    if cursor_update_enabled and advance_to:
        cursor_file.parent.mkdir(parents=True, exist_ok=True)
        cursor_file.write_text(advance_to + "\n", encoding="utf-8")
        advanced_to = advance_to

    result = {
        "generated_at": utc_now(),
        "upstream_head": plan_data.get("upstream_head"),
        "cursor_file": display_path(cursor_file),
        "advanced_to": advanced_to,
        "truncated": plan_data.get("truncated", False),
        "applied": applied_entries,
        "skipped": skipped_entries,
        "ignored": ignored_entries,
    }
    write_json(Path(args.result), result)
    write_apply_report(Path(args.report), result)

    print(
        f"Applied {len(applied_entries)} commits; "
        f"skipped {len(skipped_entries)} commits; "
        f"ignored {len(ignored_entries)} commits."
    )
    return 0


def write_apply_report(path: Path, result: dict[str, Any]) -> None:
    lines = [
        "# Upstream Parser Sync Result",
        "",
        f"- Generated: {result['generated_at']}",
        f"- Upstream head: `{result.get('upstream_head') or 'unknown'}`",
        f"- Cursor file: `{result.get('cursor_file') or 'unknown'}`",
        f"- Advanced to: `{result.get('advanced_to') or 'none'}`",
        f"- Truncated: `{result.get('truncated', False)}`",
        f"- Applied: {len(result['applied'])}",
        f"- Skipped: {len(result['skipped'])}",
        f"- Ignored: {len(result.get('ignored', []))}",
        "",
        "## Applied",
        "",
    ]
    if not result["applied"]:
        lines.append("No commits were applied.")
    for item in result["applied"]:
        lines.append(f"- `{item['sha'][:12]}` {item['subject']}")

    lines.extend(["", "## Skipped", ""])
    if not result["skipped"]:
        lines.append("No commits were skipped.")
    for item in result["skipped"]:
        lines.append(f"- `{item['sha'][:12]}` {item['subject']}: {item['reason']}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    plan_parser = sub.add_parser("plan")
    plan_parser.add_argument("--upstream-ref", required=True)
    plan_parser.add_argument(
        "--cursor-file",
        default=".github/upstream-subconverter.seen",
        help="state file that stores the last processed upstream commit",
    )
    plan_parser.add_argument(
        "--since",
        default="",
        help="override the stored seen marker, primarily for dry-run testing",
    )
    plan_parser.add_argument("--max-commits", type=int, default=20)
    plan_parser.add_argument("--output", default="upstream-sync-candidates.json")
    plan_parser.add_argument("--report", default="upstream-sync-plan.md")
    plan_parser.set_defaults(func=plan)

    apply_parser = sub.add_parser("apply")
    apply_parser.add_argument("--plan", default="upstream-sync-candidates.json")
    apply_parser.add_argument("--decisions", default="upstream-sync-decisions.json")
    apply_parser.add_argument("--result", default="upstream-sync-result.json")
    apply_parser.add_argument("--report", default="upstream-sync-result.md")
    apply_parser.set_defaults(func=apply)

    args = parser.parse_args()
    try:
        return args.func(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

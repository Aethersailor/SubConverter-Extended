#!/usr/bin/env python3
"""Snapshot stable GitHub workflow structure without a YAML dependency."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
ACTIONS = ROOT / ".github" / "actions"
FIXTURE = ROOT / "tests" / "fixtures" / "ci" / "workflow-contract.json"
JOB_FIELDS = {
    "name",
    "runs-on",
    "needs",
    "if",
    "permissions",
    "outputs",
    "strategy",
    "timeout-minutes",
    "continue-on-error",
    "container",
    "services",
    "env",
    "uses",
    "with",
    "secrets",
}
STEP_FIELDS = {
    "name",
    "id",
    "if",
    "uses",
    "shell",
    "continue-on-error",
    "timeout-minutes",
    "working-directory",
    "env",
    "with",
}


def indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def nested_value(lines: list[str], index: int, base_indent: int) -> str:
    _, value = lines[index].split(":", 1)
    if value.strip():
        return value.strip()
    captured: list[str] = []
    for line in lines[index + 1 :]:
        if line.strip() and indent(line) <= base_indent:
            break
        captured.append(line[base_indent + 2 :] if len(line) > base_indent else "")
    return "\n".join(captured).rstrip()


def field_map(
    lines: list[str], start: int, end: int, field_indent: int, fields: set[str]
) -> dict[str, str]:
    result: dict[str, str] = {}
    pattern = re.compile(rf"^ {{{field_indent}}}([A-Za-z0-9_-]+):")
    for index in range(start, end):
        match = pattern.match(lines[index])
        if match and match.group(1) in fields:
            result[match.group(1)] = nested_value(lines, index, field_indent)
    return result


def step_contract(lines: list[str], start: int, end: int) -> dict[str, str]:
    result: dict[str, str] = {}
    first = re.match(r"^      - ([A-Za-z0-9_-]+):(.*)$", lines[start])
    if first and first.group(1) in STEP_FIELDS:
        result[first.group(1)] = first.group(2).strip()
    result.update(field_map(lines, start + 1, end, 8, STEP_FIELDS))
    return result


def workflow_contract(path: Path) -> dict[str, object]:
    lines = path.read_text(encoding="utf-8").splitlines()
    top: dict[str, object] = {}
    for index, line in enumerate(lines):
        match = re.match(r"^([A-Za-z0-9_-]+):", line)
        if match and match.group(1) in {
            "name",
            "on",
            "permissions",
            "concurrency",
            "env",
        }:
            top[match.group(1)] = nested_value(lines, index, 0)

    job_starts = [
        index
        for index, line in enumerate(lines)
        if re.match(r"^  [A-Za-z0-9_-]+:$", line)
        and index > next(i for i, value in enumerate(lines) if value == "jobs:")
    ]
    jobs: dict[str, object] = {}
    for position, start in enumerate(job_starts):
        end = job_starts[position + 1] if position + 1 < len(job_starts) else len(lines)
        job_id = lines[start].strip()[:-1]
        job = field_map(lines, start + 1, end, 4, JOB_FIELDS)
        step_starts = [
            index
            for index in range(start + 1, end)
            if re.match(r"^      - [A-Za-z0-9_-]+:", lines[index])
        ]
        steps = []
        for step_position, step_start in enumerate(step_starts):
            step_end = (
                step_starts[step_position + 1]
                if step_position + 1 < len(step_starts)
                else end
            )
            steps.append(step_contract(lines, step_start, step_end))
        if steps:
            job["steps"] = steps
        jobs[job_id] = job
    top["jobs"] = jobs
    return top


def snapshot() -> dict[str, object]:
    workflows = {
        path.name: workflow_contract(path)
        for path in sorted(WORKFLOWS.glob("*.yml"))
    }
    actions = {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(ACTIONS.glob("*/action.yml"))
    }
    return {"workflows": workflows, "composite_action_sha256": actions}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("print", "write", "check"))
    parser.add_argument("--output", type=Path, default=FIXTURE)
    args = parser.parse_args()
    current = snapshot()
    rendered = json.dumps(current, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.command == "print":
        sys.stdout.buffer.write(rendered.encode("utf-8"))
    elif args.command == "write":
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    else:
        expected = json.loads(args.output.read_text(encoding="utf-8"))
        if current != expected:
            raise SystemExit(
                "workflow structure differs from tests/fixtures/ci/workflow-contract.json; "
                "inspect the contract diff before updating the fixture"
            )
        print("workflow structural contract matches baseline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

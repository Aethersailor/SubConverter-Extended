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
ORACLE_FIXTURE = (
    ROOT / "tests" / "fixtures" / "ci" / "workflow-contract-oracle.json"
)
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
    "environment",
    "concurrency",
    "defaults",
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
    "run",
}
TOP_FIELDS = {
    "name",
    "run-name",
    "on",
    "permissions",
    "concurrency",
    "env",
    "defaults",
}


def indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def nested_value(lines: list[str], index: int, base_indent: int) -> str:
    _, value = lines[index].split(":", 1)
    scalar = value.strip()
    is_block_scalar = scalar.startswith(("|", ">"))
    if scalar and not is_block_scalar:
        return scalar
    captured: list[str] = []
    for line in lines[index + 1 :]:
        if line.strip() and indent(line) <= base_indent:
            break
        captured.append(line[base_indent + 2 :] if len(line) > base_indent else "")
    body = "\n".join(captured)
    if scalar:
        return f"{scalar}\n{body}" if body else scalar
    return body.rstrip()


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


def step_contract(
    lines: list[str], start: int, end: int, step_indent: int
) -> dict[str, str]:
    result: dict[str, str] = {}
    first = re.match(
        rf"^ {{{step_indent}}}- ([A-Za-z0-9_-]+):(.*)$", lines[start]
    )
    if first is None:
        raise ValueError(f"invalid workflow step at line {start + 1}")
    first_field = first.group(1)
    if first_field not in STEP_FIELDS:
        raise ValueError(f"unsupported workflow step field: {first_field}")
    first_value = first.group(2).strip()
    if first_value.startswith(("|", ">")):
        synthetic = " " * (step_indent + 2) + first_field + ":" + first.group(2)
        result[first_field] = nested_value(
            lines[:start] + [synthetic] + lines[start + 1 :],
            start,
            step_indent + 2,
        )
    else:
        result[first_field] = first_value

    field_indent = step_indent + 2
    field_pattern = re.compile(rf"^ {{{field_indent}}}([A-Za-z0-9_-]+):")
    for index in range(start + 1, end):
        match = field_pattern.match(lines[index])
        if match and match.group(1) not in STEP_FIELDS:
            raise ValueError(f"unsupported workflow step field: {match.group(1)}")
    result.update(field_map(lines, start + 1, end, field_indent, STEP_FIELDS))
    return result


def workflow_contract(path: Path) -> dict[str, object]:
    lines = path.read_text(encoding="utf-8").splitlines()
    top: dict[str, object] = {}
    for index, line in enumerate(lines):
        match = re.match(r"^([A-Za-z0-9_-]+):", line)
        if match and match.group(1) in TOP_FIELDS:
            top[match.group(1)] = nested_value(lines, index, 0)

    jobs_index = next(i for i, value in enumerate(lines) if value == "jobs:")
    job_starts = [
        index
        for index, line in enumerate(lines)
        if re.match(r"^  [A-Za-z0-9_-]+:$", line)
        and index > jobs_index
    ]
    jobs: dict[str, object] = {}
    for position, start in enumerate(job_starts):
        end = job_starts[position + 1] if position + 1 < len(job_starts) else len(lines)
        job_id = lines[start].strip()[:-1]
        job = field_map(lines, start + 1, end, 4, JOB_FIELDS)
        steps_header = next(
            (
                index
                for index in range(start + 1, end)
                if lines[index] == "    steps:"
            ),
            None,
        )
        step_starts: list[int] = []
        step_indent = 0
        if steps_header is not None:
            first_step = next(
                (
                    index
                    for index in range(steps_header + 1, end)
                    if re.match(r"^ +- [A-Za-z0-9_-]+:", lines[index])
                ),
                None,
            )
            if first_step is not None:
                step_indent = indent(lines[first_step])
                step_starts = [
                    index
                    for index in range(first_step, end)
                    if re.match(
                        rf"^ {{{step_indent}}}- [A-Za-z0-9_-]+:",
                        lines[index],
                    )
                ]
        steps = []
        for step_position, step_start in enumerate(step_starts):
            step_end = (
                step_starts[step_position + 1]
                if step_position + 1 < len(step_starts)
                else end
            )
            steps.append(
                step_contract(lines, step_start, step_end, step_indent)
            )
        if steps:
            job["steps"] = steps
        jobs[job_id] = job
    top["jobs"] = jobs
    return top


def canonical_text_sha256(path: Path) -> str:
    """Hash text after universal-newline decoding for cross-platform checkouts."""
    content = path.read_text(encoding="utf-8")
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def canonical_contract_sha256(contract: dict[str, object]) -> str:
    rendered = json.dumps(
        contract, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(rendered.encode("utf-8")).hexdigest()


def load_oracle() -> dict[str, object]:
    oracle = json.loads(ORACLE_FIXTURE.read_text(encoding="utf-8"))
    if oracle.get("schema") != 1:
        raise ValueError("unsupported workflow contract oracle schema")
    return oracle


def snapshot() -> dict[str, object]:
    workflows = {
        path.name: workflow_contract(path)
        for path in sorted(WORKFLOWS.glob("*.yml"))
    }
    actions = {
        path.relative_to(ROOT).as_posix(): canonical_text_sha256(path)
        for path in sorted(ACTIONS.glob("*/action.yml"))
    }
    return {"workflows": workflows, "composite_action_sha256": actions}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("print", "write", "check"))
    parser.add_argument("--output", type=Path, default=FIXTURE)
    parser.add_argument(
        "--approve-baseline",
        action="store_true",
        help="explicitly approve replacing the frozen workflow contract",
    )
    args = parser.parse_args()
    current = snapshot()
    rendered = json.dumps(current, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.command == "print":
        sys.stdout.buffer.write(rendered.encode("utf-8"))
    elif args.command == "write":
        if not args.approve_baseline:
            raise SystemExit(
                "refusing to replace the frozen workflow oracle without "
                "--approve-baseline"
            )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    else:
        expected = json.loads(args.output.read_text(encoding="utf-8"))
        oracle = load_oracle()
        expected_digest = canonical_contract_sha256(expected)
        if expected_digest != oracle.get("contract_sha256"):
            raise SystemExit(
                "workflow fixture no longer matches its independently frozen "
                "oracle; inspect and explicitly approve both files"
            )
        if current != expected:
            raise SystemExit(
                "workflow structure differs from tests/fixtures/ci/workflow-contract.json; "
                "inspect the contract diff before updating the fixture"
            )
        print("workflow structural contract matches baseline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

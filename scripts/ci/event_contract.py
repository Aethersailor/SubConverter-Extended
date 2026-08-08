#!/usr/bin/env python3
"""Model workflow enqueue and job gates from frozen GitHub event payloads."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "ci" / "event-payloads.json"
SKIP_TOKENS = (
    "[skip ci]",
    "[ci skip]",
    "[no ci]",
    "[skip actions]",
    "[actions skip]",
)
BUILD_PATHS_IGNORE = ("README.md", "README-*.md", "docker-compose.yml")
RELEASE_TAG_TRIGGER = "v*.*.*"
RELEASE_TAG_METADATA = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+$")


@dataclass(frozen=True)
class Capabilities:
    repository_actions_secrets: bool
    github_token_permissions: str
    secret_source: str


@dataclass(frozen=True)
class BuildOutcome:
    workflow_created: bool
    entrypoint: str
    mode: str
    source_head: str
    request_sanitizers: str
    prepare: str
    build_linux: str
    registry_publish: bool
    create_release: bool


@dataclass(frozen=True)
class CodeQLOutcome:
    workflow_created: bool
    source_head: str
    analyze: str


@dataclass(frozen=True)
class Outcome:
    native_enqueue: str
    native_skip_directive: str
    capabilities: Capabilities
    formal_release_workflow_created: bool
    build: BuildOutcome
    codeql: CodeQLOutcome


def _pull_request(github: dict[str, Any]) -> dict[str, Any] | None:
    value = github.get("event", {}).get("pull_request")
    return value if isinstance(value, dict) else None


def _trigger_message(github: dict[str, Any]) -> str:
    event = github.get("event", {})
    if github["event_name"] == "push":
        return event.get("head_commit", {}).get("message", "") or ""
    return github.get("trigger_commit", {}).get("message", "") or ""


def native_skip_directive(github: dict[str, Any]) -> str:
    if github["event_name"] not in {"push", "pull_request"}:
        return "none"
    message = _trigger_message(github)
    lowered = message.lower()
    for token in SKIP_TOKENS:
        if token in lowered:
            return token
    if re.search(r"(?im)^skip-checks:\s*true\s*$", message):
        return "skip-checks:true"
    return "none"


def event_capabilities(
    github: dict[str, Any], repository: dict[str, Any]
) -> Capabilities:
    pull_request = _pull_request(github)
    fork = False
    if pull_request is not None:
        head_repository = pull_request.get("head", {}).get("repo", {})
        fork = head_repository.get("full_name") != repository["full_name"]
    dependabot = github.get("actor") == "dependabot[bot]"
    restricted = fork or dependabot
    return Capabilities(
        repository_actions_secrets=not restricted,
        github_token_permissions=(
            "read-only" if restricted else "workflow-declared"
        ),
        secret_source=(
            "Dependabot" if dependabot else "None" if fork else "Actions"
        ),
    )


def _base_ref(github: dict[str, Any]) -> str:
    base_ref = github.get("base_ref", "")
    if base_ref:
        return base_ref
    pull_request = _pull_request(github)
    if pull_request is None:
        return ""
    return pull_request.get("base", {}).get("ref", "")


def _all_paths_ignored(changed_paths: list[str]) -> bool:
    return bool(changed_paths) and all(
        any(fnmatch.fnmatchcase(path, pattern) for pattern in BUILD_PATHS_IGNORE)
        for path in changed_paths
    )


def _direct_build_triggered(
    github: dict[str, Any], dispatch_workflow: str, changed_paths: list[str]
) -> bool:
    event_name = github["event_name"]
    if event_name == "push":
        return (
            github["ref"] == "refs/heads/dev"
            and not _all_paths_ignored(changed_paths)
        )
    if event_name == "pull_request":
        return _base_ref(github) in {"dev", "master"}
    return (
        event_name == "workflow_dispatch"
        and dispatch_workflow == "build-dockerhub.yml"
    )


def _codeql_triggered(github: dict[str, Any], dispatch_workflow: str) -> bool:
    event_name = github["event_name"]
    if event_name == "push":
        return github["ref"] == "refs/heads/dev"
    if event_name == "pull_request":
        return _base_ref(github) in {"dev", "master"}
    return event_name == "workflow_dispatch" and dispatch_workflow == "codeql.yml"


def _is_current(github: dict[str, Any], repository: dict[str, Any]) -> bool:
    return repository.get("refs", {}).get(github["ref"]) == github["sha"]


def _mode(github: dict[str, Any]) -> str:
    if github["ref"].startswith("refs/tags/"):
        return "release"
    if github["event_name"] == "pull_request":
        return "pr"
    if github["ref"] == "refs/heads/dev":
        return "dev"
    if github["ref"] == "refs/heads/master":
        return "master"
    return "unsupported"


def _release_wrapper_triggered(github: dict[str, Any]) -> bool:
    ref = github["ref"]
    return (
        github["event_name"] == "push"
        and ref.startswith("refs/tags/")
        and fnmatch.fnmatchcase(
            ref.removeprefix("refs/tags/"), RELEASE_TAG_TRIGGER
        )
    )


def _release_metadata_valid(github: dict[str, Any]) -> bool:
    ref = github["ref"]
    return (
        github["event_name"] == "push"
        and ref.startswith("refs/tags/")
        and RELEASE_TAG_METADATA.fullmatch(
            ref.removeprefix("refs/tags/")
        )
        is not None
    )


def _build_outcome(
    github: dict[str, Any], repository: dict[str, Any], created: bool, entrypoint: str
) -> BuildOutcome:
    if not created:
        return BuildOutcome(
            workflow_created=False,
            entrypoint="none",
            mode="none",
            source_head="not-created",
            request_sanitizers="not-created",
            prepare="not-created",
            build_linux="not-created",
            registry_publish=False,
            create_release=False,
        )

    event_name = github["event_name"]
    checks_branch_head = github["ref"].startswith("refs/heads/") and event_name in {
        "push",
        "workflow_dispatch",
    }
    if checks_branch_head and not _is_current(github, repository):
        source_head = (
            "failed-stale" if event_name == "workflow_dispatch" else "skipped-stale"
        )
        return BuildOutcome(
            workflow_created=True,
            entrypoint=entrypoint,
            mode=_mode(github),
            source_head=source_head,
            request_sanitizers="skipped-upstream",
            prepare="skipped-upstream",
            build_linux="skipped-upstream",
            registry_publish=False,
            create_release=False,
        )

    mode = _mode(github)
    request_sanitizers = "selected"
    if github.get("actor") == "dependabot[bot]":
        prepare = "skipped-actor"
    elif mode == "release" and not _release_metadata_valid(github):
        prepare = "failed-metadata"
    elif mode == "unsupported":
        prepare = "failed-metadata"
    else:
        prepare = "selected"
    build_linux = "selected" if prepare == "selected" else "skipped-upstream"
    publish = build_linux == "selected" and event_name != "pull_request" and mode != "master"
    create_release = build_linux == "selected" and mode == "release" and event_name == "push"
    return BuildOutcome(
        workflow_created=True,
        entrypoint=entrypoint,
        mode=mode,
        source_head="current",
        request_sanitizers=request_sanitizers,
        prepare=prepare,
        build_linux=build_linux,
        registry_publish=publish,
        create_release=create_release,
    )


def _codeql_outcome(
    github: dict[str, Any], repository: dict[str, Any], created: bool
) -> CodeQLOutcome:
    if not created:
        return CodeQLOutcome(
            workflow_created=False,
            source_head="not-created",
            analyze="not-created",
        )
    event_name = github["event_name"]
    checks_branch_head = github["ref"].startswith("refs/heads/") and event_name in {
        "push",
        "workflow_dispatch",
    }
    if checks_branch_head and not _is_current(github, repository):
        return CodeQLOutcome(
            workflow_created=True,
            source_head="skipped-stale",
            analyze="skipped-upstream",
        )
    analyze = (
        "skipped-actor"
        if github.get("actor") == "dependabot[bot]"
        else "selected"
    )
    return CodeQLOutcome(
        workflow_created=True,
        source_head="current",
        analyze=analyze,
    )


def simulate(
    *,
    github: dict[str, Any],
    repository: dict[str, Any],
    dispatch_workflow: str = "",
    changed_paths: list[str] | None = None,
) -> Outcome:
    changed_paths = changed_paths or []
    skip_directive = native_skip_directive(github)
    native_suppressed = skip_directive != "none"
    formal_release = not native_suppressed and _release_wrapper_triggered(github)
    direct_build = not native_suppressed and _direct_build_triggered(
        github, dispatch_workflow, changed_paths
    )
    build_created = formal_release or direct_build
    entrypoint = "release-reusable" if formal_release else "direct" if direct_build else "none"
    codeql_created = not native_suppressed and _codeql_triggered(
        github, dispatch_workflow
    )
    return Outcome(
        native_enqueue="suppressed" if native_suppressed else "eligible",
        native_skip_directive=skip_directive,
        capabilities=event_capabilities(github, repository),
        formal_release_workflow_created=formal_release,
        build=_build_outcome(github, repository, build_created, entrypoint),
        codeql=_codeql_outcome(github, repository, codeql_created),
    )


def as_dict(outcome: Outcome) -> dict[str, object]:
    return asdict(outcome)


def load_fixtures(path: Path = FIXTURE) -> list[dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("schema") != 1:
        raise ValueError("unsupported event fixture schema")
    return document["cases"]


def simulate_fixture(case: dict[str, Any]) -> dict[str, object]:
    return as_dict(
        simulate(
            github=case["github"],
            repository=case["repository"],
            dispatch_workflow=case.get("dispatch_workflow", ""),
            changed_paths=case.get("changed_paths", []),
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("print", "check"))
    parser.add_argument("--fixtures", type=Path, default=FIXTURE)
    args = parser.parse_args()
    cases = load_fixtures(args.fixtures)
    failures = []
    for case in cases:
        actual = simulate_fixture(case)
        if args.command == "print":
            print(json.dumps({"name": case["name"], "actual": actual}, indent=2))
        elif actual != case["expected"]:
            failures.append(case["name"])
    if failures:
        raise SystemExit("event contract mismatch: " + ", ".join(failures))
    if args.command == "check":
        print(f"event contract matches {len(cases)} frozen payloads")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

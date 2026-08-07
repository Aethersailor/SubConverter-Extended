#!/usr/bin/env python3
"""Pure model of the CI event gates that are unsafe to exercise on releases."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Outcome:
    source_head: str
    request_sanitizers: bool
    prepare: bool
    build_linux: bool
    registry_publish: bool
    create_release: bool
    codeql_analyze: bool


def simulate(
    *,
    event_name: str,
    ref: str,
    actor: str = "maintainer",
    head_message: str = "change",
    current_head: bool = True,
) -> Outcome:
    is_branch = ref.startswith("refs/heads/")
    checks_head = is_branch and event_name in {"push", "workflow_dispatch"}
    source_head = "current"
    if checks_head and not current_head:
        source_head = "fail" if event_name == "workflow_dispatch" else "skip"
    current = source_head == "current"
    skip_ci = ref == "refs/heads/dev" and any(
        token in head_message for token in ("[skip ci]", "[ci skip]")
    )
    prepare = current and actor != "dependabot[bot]" and not skip_ci
    mode = (
        "release"
        if ref.startswith("refs/tags/")
        else "master"
        if ref == "refs/heads/master"
        else "pr"
        if event_name == "pull_request"
        else "dev"
    )
    codeql_triggered = (
        event_name == "workflow_dispatch"
        or (event_name == "push" and ref == "refs/heads/dev")
        or (event_name == "pull_request" and ref in {"refs/heads/dev", "refs/heads/master"})
    )
    return Outcome(
        source_head=source_head,
        request_sanitizers=current,
        prepare=prepare,
        build_linux=prepare,
        registry_publish=(
            prepare and event_name != "pull_request" and mode != "master"
        ),
        create_release=(prepare and mode == "release" and event_name == "push"),
        codeql_analyze=(codeql_triggered and current and actor != "dependabot[bot]"),
    )


def as_dict(outcome: Outcome) -> dict[str, object]:
    return asdict(outcome)

# Dependency maintenance

Dependabot opens GitHub Actions, Docker and Go dependency updates against `dev`.
The maintenance workflow automatically squash-merges labeled, same-repository
Dependabot PRs into `dev`. It checks the bot identity, signed commits, allowed
dependency files, PR target and exact head SHA. Tests, CodeQL and PR validation
are not prerequisites. PRs targeting any other branch are ignored.

PR changes, dev pushes and completed dev builds trigger reconciliation; a
six-hour schedule recovers missed events. Conflicting PRs receive an official
Dependabot rebase request; clean PRs can merge even when dev has advanced.
After merging, the controller explicitly dispatches
the dev build and repairs missed dispatches on later runs. Only trusted `dev`
maintenance code is loaded; dependency PR code is never executed by the merger.

CodeQL independently scans pushes to `dev` and accepts manual runs only on
`dev`. The controller also repairs missing CodeQL dispatches after token-driven
merges or generated commits. CodeQL findings and failures do not block merges,
dev delivery or dependency refreshes; no required CodeQL branch rule is added.

GitHub runs schedules and `pull_request_target` workflows from the default
branch. Keep the workflow definition synchronized there through the normal
release flow. Its checkout, PR queries, merges, build dispatches and upstream
refreshes remain restricted to `dev`; a manual dispatch on another branch is
skipped. No master merge, release tag or production update is performed.

Repository variable `DEPENDABOT_AUTOMERGE_MODE` supports `active` (the default),
`observe` and `off`. Manual `dry_run=true` performs no writes. `GITHUB_TOKEN`
performs merges and build dispatches; `PAT_TOKEN` is used only for official
Dependabot rebase requests. GitHub branch rules remain enforced. Keep the dev
ruleset free of obsolete required test and PR Gate checks, and do not make the
independent CodeQL scan a merge prerequisite.

Ordinary builds use the committed dependency snapshot and Go module graph.
When the PR queue is empty and dev delivery is healthy, the scheduled controller
refreshes upstream headers, Mihomo and base images at most once per week. The
manual `refresh_dependencies=true` input can request that refresh when due.
Persistent build failures require maintainer attention; cancelled builds are
not automatically retried. Formal releases and production updates remain
separate operations.

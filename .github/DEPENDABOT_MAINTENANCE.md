# Dependency maintenance

Dependabot updates GitHub Actions, Docker and Go dependencies on `dev`. Each PR
must pass PR Validation, including the candidate build, smoke tests and CodeQL.
The merger rechecks the author, repository, labels, branch, current head and base
before a SHA-conditional squash merge. GitHub branch rules remain enforced.

`auto-merge-dependabot.yml` runs from the default branch after validation and dev
delivery, and reconciles the queue every six hours. It requests an official
Dependabot rebase for an outdated branch, retries failed jobs up to three total
attempts, and explicitly dispatches dev Build and CodeQL after a merge. Missed
post-merge dispatches are repaired on the next reconciliation. Persistent failures
stay closed and are linked in Actions logs; they require diagnosis, not a bypass.

Ordinary PRs and dev builds use the committed dependency snapshot and Go module
graph. Once a week, when the queue is empty and dev delivery is healthy, the
controller dispatches Build with `refresh_dependencies=true`. This separately
refreshes upstream headers, modules and images. A failed refresh cannot authorize
a Dependabot merge or replace the last published image. Existing image promotion
and stale-source checks still apply. Formal releases and production updates are
separate operations.

Controls:

- Repository variable `DEPENDABOT_AUTOMERGE_MODE`: `off`, `observe`, or `active`.
- Manual maintenance run with `dry_run=true`: read-only queue inspection.
- Manual maintenance run with `refresh_dependencies=true`: request the weekly
  refresh when it is due and the queue is empty. To deliberately repeat a refresh,
  dispatch Build on `dev` with that input directly.

The merger uses `GITHUB_TOKEN`, without an administrator PAT. Existing build
writeback and Docker Hub publication still require their configured credentials.
GitHub availability, enabled Actions, credentials and upstream compatibility are
external prerequisites; scheduled Actions are best effort and GitHub can disable
them after prolonged repository inactivity. An unsupported upstream API change
must remain blocked until it is reviewed and fixed.

Validate changes with `node --test .github/scripts/dependabot-maintenance.test.cjs`,
`bash tests/ci_delivery_scripts_test.sh`, and `actionlint`. Keep the maintenance
workflow and script synchronized to the default branch when changing them on dev.

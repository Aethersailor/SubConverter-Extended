# GitHub Copilot instructions for SubConverter-Extended

## Project context

This repository is SubConverter-Extended.

It is an extended configuration conversion project based on subconverter-related workflows. The project focuses on subscription conversion, rule configuration, workflow automation, and deployment support. It does not proxy, relay, or forward user traffic by itself.

When generating code, documentation, commit messages, pull request titles, or summaries, keep the wording precise and technical.

## General style

Use clear and concise English.

Avoid vague wording such as:

* update files
* fix bug
* optimize code
* improve project
* miscellaneous changes
* minor changes

Prefer wording that describes the actual module, behavior, file, or workflow being changed.

## Commit message rules

When generating commit messages, strictly follow Conventional Commits.

The commit title must use this format:

```text
type(scope): subject
```

Allowed types:

```text
feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert
```

Rules:

* Use English only.
* Use lowercase type and scope.
* Keep the commit title under 72 characters.
* Do not end the subject with a period.
* Use imperative mood.
* Choose a meaningful scope from the changed module, directory, script, or workflow.
* Do not generate vague commit titles.
* Prefer a single-line commit title unless the change genuinely needs a body.
* If a body is needed, explain what changed and why, not how obvious code works.

Recommended scopes for this repository:

```text
core
config
pref
base
ini
rules
converter
subconverter
workflow
sync
docker
compose
script
shell
docs
readme
ci
build
release
```

Good examples:

```text
feat(config): add private subconverter preset support
fix(workflow): prevent duplicate branch sync jobs
docs(readme): clarify deployment directory layout
chore(docker): update container build configuration
ci(sync): adjust dev to master synchronization
refactor(script): simplify configuration copy logic
fix(pref): preserve custom managed config values
```

Bad examples:

```text
Update files
Fix bug
Optimize config
Change workflow
feat: update
fix: bug
docs: readme
```

## Pull request title rules

Pull request titles should also follow Conventional Commits whenever possible.

Good examples:

```text
feat(config): add managed preset templates
fix(script): handle missing config directory
docs(readme): update deployment instructions
```

## Documentation rules

When writing documentation:

* Use concise technical English.
* Prefer direct instructions over marketing language.
* Use command blocks for shell commands.
* Use path blocks for file paths.
* Keep warnings explicit and factual.
* Do not exaggerate project capabilities.
* Do not describe this project as a proxy, relay, VPN, tunnel, or traffic forwarding tool.

When explaining deployment paths, prefer exact paths such as:

```text
/opt/SubConverter-Extended
/config
/base
```

## Shell script rules

When editing shell scripts:

* Prefer POSIX-compatible syntax unless the script explicitly uses Bash.
* Quote variables unless word splitting is intentional.
* Use clear error messages.
* Avoid destructive operations unless explicitly required.
* Check whether files or directories exist before operating on them.
* Keep script output concise and useful.
* Do not silently ignore important failures.

## Workflow rules

When editing GitHub Actions workflows:

* Use clear job names.
* Avoid unnecessary workflow triggers.
* Avoid duplicate jobs across branches.
* Avoid excessive scheduled workflow frequency.
* Keep permissions minimal.
* Prefer explicit branch names when sync behavior matters.
* Be careful with workflows that may create recursive commits or repeated runs.

## Docker rules

When editing Docker-related files:

* Keep image build steps minimal and reproducible.
* Avoid unnecessary packages.
* Do not hard-code private credentials, tokens, or secrets.
* Use environment variables for configurable behavior.
* Keep exposed ports and mounted paths explicit.

## Security rules

Never generate or commit:

* private tokens
* passwords
* cookies
* private subscription URLs
* API keys
* SSH private keys
* personal credentials
* real user proxy node information

If example credentials are needed, use clearly fake placeholder values.

## Tone for warnings

When writing warnings, use factual and professional wording.

Good example:

```text
This workflow may trigger GitHub Actions abuse detection when executed too frequently or across many forks. Use a self-hosted runner if you need frequent automated runs.
```

Avoid emotional or accusatory wording.

## Final output expectations

When Copilot generates a commit message, it must output only the commit message text.

Do not add explanations, alternatives, markdown formatting, or extra commentary unless explicitly requested.

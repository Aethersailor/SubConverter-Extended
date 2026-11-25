# Dependency maintenance

Dependabot opens GitHub Actions, Docker and Go version updates against `dev`.
GitHub also opens Dependabot security updates against `dev`, the default branch.

The maintenance workflow squash-merges open, non-draft Dependabot PRs into
`dev` after both `CodeQL checks` and `Dependency Review` succeed. CodeQL's
summary requires every analysis to succeed. Dependency Review blocks newly
introduced vulnerabilities rated moderate or higher. The merge request pins
the reviewed head SHA, and GitHub enforces the branch's required checks.

Pull request events and successful check completions trigger the merger. A
six-hour schedule recovers missed events. The workflow does not check out the
PR. Merges using `GITHUB_TOKEN` explicitly dispatch the dev build and CodeQL
as needed because ordinary push workflows do not run for those merges.

The separate weekly upstream refresh and the manual
`refresh_dependencies=true` input continue to use the existing dev build.
Formal releases use `Prepare Formal Release` from `dev` and a version tag.

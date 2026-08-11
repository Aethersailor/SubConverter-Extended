# Formal release identity contract

A formal release has exactly one identity:

`vX.Y.Z tag -> tag commit -> source tree -> packages -> SHA256SUMS -> RELEASE-MANIFEST.json -> Docker Hub/GHCR version manifests -> OCI revision`

The canonical revision is always the full 40-character tag commit SHA. The
compiled `BUILD_ID` and runtime `/version` suffix are its seven-character
prefix. A historical version is never rebuilt, retagged, re-uploaded, or
regenerated. A correction requires a new version.

## State machine

1. Run `Sync Dev to Master` with `operation=sync_only` to merge without creating a
   release, or use `operation=new`. For `new`, leave `version` empty to increment
   the patch component of the highest existing `vX.Y.Z` tag, or provide an unused
   `vX.Y.Z` explicitly.
2. The sync workflow validates the exact resulting master commit before it may
   create one annotated tag. It never dispatches a release build with a version
   input.
3. Only the tag-push `Formal Release` workflow can enter release mode. It checks
   that the event SHA, checkout SHA, and peeled tag SHA are identical.
4. Before building, the workflow fails unless GitHub immutable releases and
   Docker Hub immutable version tags are enabled, and unless the GitHub Release,
   Docker Hub version tag, and GHCR version tag are all absent.
5. Run-scoped candidate images and all packages are built from the same tag
   checkout. Package `BUILD-INFO.json`, OCI labels, asset checksums, and registry
   manifests use the full revision; runtime `/version` is verified against its
   seven-character `BUILD_ID` prefix.
6. Version image tags are published once. A draft GitHub Release is populated
   without overwrite permission and is downloaded again for checksum and
   manifest verification.
7. The GitHub Release is published, confirmed immutable, and its automatically
   generated release attestation is verified. Only then may the mutable Docker
   `latest` pointers advance to the already-verified version digests.

Every unknown API response, missing digest, identity mismatch, skipped required
stage, or disabled immutability control is a hard failure.

## Existing v1.3.0

`v1.3.0` is frozen. Its packages and legacy seven-character OCI revision are
not rewritten to the new format. Historical release assets are protected by
immutable release and registry-tag controls instead of being downloaded and
revalidated during ordinary development. Any fix is released as `v1.3.1` or
later.

## Repository settings required before the next tag

These settings are intentionally not changed by repository code:

- enable GitHub immutable releases;
- enable Docker Hub immutable tags with a rule covering every `vX.Y.Z` tag but
  not `latest`, `dev`, build caches, or run-scoped candidates;
- add a tag ruleset for `v*.*.*` that blocks update and deletion and limits tag
  creation to the release operator;
- keep master/dev branch rules aligned with the actual current job names, remove
  stale required contexts, and restrict bypass to the smallest operator set;
- set the repository default workflow token to read-only where practical. The
  workflows declare their own minimal `contents`/`packages` permissions.

The sync workflow checks the first two settings before it creates a formal tag,
and the formal workflow checks them again before building. Tag and branch rules
remain an administrative prerequisite.

## Rollback boundary

Before tag creation, master can be corrected through the normal dev-to-master
flow. After tag creation, the version identity is never rolled back or reused.
If a release fails before it becomes immutable after any version artifact was
published, repair the machinery and publish a new version; the old `latest`
digest remains the safe pointer. If the Release is already immutable and only
the final `latest` update failed, rerun only the failed finalization job: it
re-verifies the frozen assets and version digests without rewriting them. If a
defect is found after publication, release a new patch version and advance
`latest` only after its full verification completes.

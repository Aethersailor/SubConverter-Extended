# Formal release identity contract

A formal release has exactly one identity:

`vX.Y.Z tag -> tag commit -> source tree -> packages -> SHA256SUMS -> RELEASE-MANIFEST.json -> Docker Hub/GHCR version manifests -> OCI revision`

The canonical revision is the full 40-character tag commit SHA. The compiled
`BUILD_ID` and runtime `/version` suffix use its seven-character prefix. A
historical version is never rebuilt, retagged, re-uploaded, or regenerated.
A correction requires a new version.

## State machine

1. Run `Prepare Formal Release` from `dev` with `confirm_release` checked.
   Leave `version` empty to increment the patch component of the highest
   existing `vX.Y.Z` tag, or provide an unused `vX.Y.Z` explicitly.
2. The workflow merges `dev` into `master` and removes the repository README
   and its illustrations from the release tree. It pushes `master` together
   with one annotated version tag in a single atomic operation.
3. The tag push starts `Formal Release`. Before building, the workflow checks
   that the event SHA, checkout SHA, and peeled tag SHA are identical and that
   the tag commit is on the first-parent history of `master`. It also checks
   that the GitHub Release and both registry version tags are absent.
4. Run-scoped candidate images and all packages are built from the same tag
   checkout. Package `BUILD-INFO.json`, OCI labels, asset checksums, and registry
   manifests identify that revision. The workflow rechecks version tag
   availability before publishing the version images to Docker Hub and GHCR.
5. The workflow creates a draft GitHub Release, downloads its uploaded assets
   again, and verifies their checksums and manifest against the expected
   revision and both registry digests.
6. The workflow publishes the GitHub Release and advances `latest` in each
   registry to the verified version digest. If either promotion fails or a
   digest differs, it attempts to restore both previous `latest` digests.

The workflow enforces source identity and rejects existing release names and
registry version tags. GitHub release immutability, Docker Hub tag immutability,
and release attestations are separate from these workflow checks.

## Existing v1.3.0

`v1.3.0` retains its original packages and legacy seven-character OCI revision.
Corrections use a new version.

## Recovery

Before tag creation, make corrections on `dev`. Once the version tag is
published, keep the version and its source identity. If a release fails after a
version image or a Release is published, check which assets and digests already
exist before deciding how to recover. The finalization job expects a draft
GitHub Release at entry, so rerunning it after publication does not resume the
`latest` promotion. Verify both `latest` digests after a failed promotion.

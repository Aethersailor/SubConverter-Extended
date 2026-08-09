import re
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]


class WorkflowContractTests(unittest.TestCase):
    @staticmethod
    def _job(workflow: str, job_id: str) -> str:
        match = re.search(
            rf"^  {re.escape(job_id)}:\n.*?(?=^  [a-z0-9_-]+:\n|\Z)",
            workflow,
            flags=re.MULTILINE | re.DOTALL,
        )
        if match is None:
            raise AssertionError(f"workflow job not found: {job_id}")
        return match.group(0)

    def test_formal_release_does_not_require_immutable_settings(self) -> None:
        build_workflow = (
            REPOSITORY / ".github" / "workflows" / "build-dockerhub.yml"
        ).read_text(encoding="utf-8")
        self.assertNotIn("immutable-releases", build_workflow)
        self.assertNotIn("immutable_tags_settings", build_workflow)
        self.assertNotIn("isImmutable", build_workflow)

        release_workflow = (
            REPOSITORY / ".github" / "workflows" / "release.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "uses: ./.github/workflows/build-dockerhub.yml\n    secrets: inherit",
            release_workflow,
        )

    def test_formal_release_jobs_cross_skipped_ancestors_fail_closed(self) -> None:
        workflow = (
            REPOSITORY / ".github" / "workflows" / "build-dockerhub.yml"
        ).read_text(encoding="utf-8")

        required_results = {
            "create-release": (
                "prepare",
                "build-linux",
                "build-windows-amd64",
                "merge-manifest",
            ),
            "finalize-release": ("prepare", "merge-manifest", "create-release"),
        }
        for job_id, dependencies in required_results.items():
            job = self._job(workflow, job_id)
            self.assertIn("always() &&", job)
            self.assertIn("!cancelled() &&", job)
            for dependency in dependencies:
                self.assertIn(f"needs.{dependency}.result == 'success'", job)

        completion = self._job(workflow, "verify-release-complete")
        self.assertIn(
            "needs: [prepare, build-linux, build-windows-amd64, merge-manifest, create-release, finalize-release]",
            completion,
        )
        self.assertIn(
            "if: always() && !cancelled() && startsWith(github.ref, 'refs/tags/')",
            completion,
        )
        for result in (
            "needs.prepare.result",
            "needs.build-linux.result",
            "needs.build-windows-amd64.result",
            "needs.merge-manifest.result",
            "needs.create-release.result",
            "needs.finalize-release.result",
        ):
            self.assertIn(result, completion)
        self.assertIn("needs.prepare.outputs.mode", completion)
        self.assertIn("needs.prepare.outputs.is_release", completion)
        self.assertIn("Formal release stage did not succeed", completion)

    def test_release_notes_start_from_latest_published_release(self) -> None:
        workflow = (
            REPOSITORY / ".github" / "workflows" / "build-dockerhub.yml"
        ).read_text(encoding="utf-8")
        create_release = self._job(workflow, "create-release")

        self.assertIn('"repos/$GITHUB_REPOSITORY/releases/latest"', create_release)
        self.assertIn("--jq '.tag_name'", create_release)
        self.assertIn("GH_TOKEN: ${{ github.token }}", create_release)
        self.assertNotIn("2>/dev/null || true", create_release)
        self.assertNotIn("git describe --tags", create_release)
        self.assertIn("git merge-base --is-ancestor", create_release)
        self.assertIn(
            "Latest published GitHub Release returned an empty tag", create_release
        )
        self.assertIn(
            "Latest published Release tag is not canonical SemVer", create_release
        )

    def test_finalize_reads_the_draft_release_before_publication(self) -> None:
        workflow = (
            REPOSITORY / ".github" / "workflows" / "build-dockerhub.yml"
        ).read_text(encoding="utf-8")
        finalize = self._job(workflow, "finalize-release")
        draft_check = finalize.split(
            "      - name: Re-verify draft assets and tag identity", maxsplit=1
        )[1].split("      - name: Log in to Docker Hub", maxsplit=1)[0]

        self.assertIn('gh release view "$VERSION"', draft_check)
        self.assertIn('--repo "$GITHUB_REPOSITORY"', draft_check)
        self.assertIn("--json isDraft", draft_check)
        self.assertIn("--jq '.isDraft'", draft_check)
        self.assertNotIn("releases/tags/$VERSION", draft_check)

    def test_sync_dev_to_master_only_merges_and_tags(self) -> None:
        workflow = (
            REPOSITORY / ".github" / "workflows" / "sync-dev-to-master.yml"
        ).read_text(encoding="utf-8")

        self.assertIn('git merge "$DEV_SHA" --no-commit --no-ff', workflow)
        self.assertIn('git push --atomic origin "HEAD:refs/heads/master"', workflow)
        self.assertNotIn("preflight-dev:", workflow)
        self.assertNotIn("docker buildx", workflow)
        self.assertNotIn("gh workflow run", workflow)
        self.assertNotIn("gh run watch", workflow)
        self.assertNotIn("ASan", workflow)
        self.assertNotIn("UBSan", workflow)


if __name__ == "__main__":
    unittest.main()

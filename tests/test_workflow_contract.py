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

    def test_formal_release_admin_check_uses_inherited_pat(self) -> None:
        build_workflow = (
            REPOSITORY / ".github" / "workflows" / "build-dockerhub.yml"
        ).read_text(encoding="utf-8")
        step_marker = "      - name: "
        step_starts = []
        cursor = 0
        while (start := build_workflow.find(step_marker, cursor)) >= 0:
            step_starts.append(start)
            cursor = start + len(step_marker)
        steps = [
            build_workflow[start:end]
            for start, end in zip(step_starts, step_starts[1:] + [len(build_workflow)])
        ]
        admin_endpoint = '"repos/$GITHUB_REPOSITORY/immutable-releases"'
        self.assertEqual(1, build_workflow.count(admin_endpoint))
        admin_steps = [step for step in steps if admin_endpoint in step]

        self.assertEqual(1, len(admin_steps))
        for step in admin_steps:
            self.assertIn("GH_TOKEN: ${{ secrets.PAT_TOKEN }}", step)
            self.assertNotIn("GH_TOKEN: ${{ github.token }}", step)

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


if __name__ == "__main__":
    unittest.main()

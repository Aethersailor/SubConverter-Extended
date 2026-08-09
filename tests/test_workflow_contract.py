import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]


class WorkflowContractTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()

import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ReleaseWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = (ROOT / ".github/workflows/build-dockerhub.yml").read_text(
            encoding="utf-8"
        )
        cls.release = (ROOT / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        )
        cls.sync = (ROOT / ".github/workflows/sync-dev-to-master.yml").read_text(
            encoding="utf-8"
        )

    def test_overwrite_release_path_is_absent(self):
        forbidden = (
            "overwrite_existing_release",
            "confirm_overwrite",
            "rebuilt-from",
            "release_tag:",
        )
        combined = self.build + self.sync
        for token in forbidden:
            self.assertNotIn(token, combined)

    def test_formal_entrypoint_is_tag_push_only(self):
        self.assertIn("tags:\n      - 'v*.*.*'", self.release)
        self.assertNotIn("workflow_dispatch", self.release)
        self.assertIn("uses: ./.github/workflows/build-dockerhub.yml", self.release)
        self.assertNotIn("tags:\n", self.build.split("pull_request:", 1)[0])

    def test_build_core_has_no_manual_release_inputs(self):
        before_permissions = self.build.split("permissions:", 1)[0]
        self.assertIn("workflow_dispatch:\n", before_permissions)
        self.assertIn("workflow_call:\n", before_permissions)
        self.assertNotIn("inputs:", before_permissions)

    def test_latest_is_only_in_final_verified_state(self):
        prefix, finalize = self.build.split("  finalize-release:", 1)
        self.assertNotIn("subconverter-extended:latest", prefix)
        self.assertIn("Publish immutable GitHub Release", finalize)
        self.assertIn("Verify GitHub release attestation", finalize)
        self.assertIn("Advance latest only after full release verification", finalize)
        self.assertLess(
            finalize.index("Verify GitHub release attestation"),
            finalize.index("Advance latest only after full release verification"),
        )

    def test_sync_only_cannot_carry_a_version(self):
        self.assertIn("sync_only must not carry a release version", self.sync)
        self.assertIn("Tag $VERSION already exists. Historical versions are frozen", self.sync)


if __name__ == "__main__":
    unittest.main()

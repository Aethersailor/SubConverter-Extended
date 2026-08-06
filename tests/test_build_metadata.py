import importlib.util
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_metadata", ROOT / "scripts" / "ci" / "build_metadata.py"
)
BUILD_METADATA = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = BUILD_METADATA
SPEC.loader.exec_module(BUILD_METADATA)


class BuildMetadataTests(unittest.TestCase):
    def resolve(self, **overrides):
        values = {
            "ref": "refs/heads/dev",
            "event_name": "push",
            "sha": "abc1234" + "0" * 33,
            "commit_date": "2026-08-06T12:37:18+08:00",
        }
        values.update(overrides)
        return BUILD_METADATA.resolve_build_metadata(**values)

    def test_dev_contract(self):
        metadata = self.resolve()
        self.assertEqual(metadata.mode, "dev")
        self.assertEqual(metadata.version, "dev")
        self.assertFalse(metadata.is_release)
        self.assertEqual(metadata.sha_short, "abc1234")
        self.assertEqual(metadata.sha, "abc1234" + "0" * 33)
        self.assertEqual(metadata.build_date, "2026-08-06T04:37:18Z")

    def test_master_snapshot_contract(self):
        metadata = self.resolve(ref="refs/heads/master")
        self.assertEqual(metadata.mode, "master")
        self.assertEqual(metadata.version, "master-abc1234")
        self.assertFalse(metadata.is_release)

    def test_formal_tag_contract(self):
        metadata = self.resolve(ref="refs/tags/v1.3.0")
        self.assertEqual(metadata.mode, "release")
        self.assertEqual(metadata.version, "v1.3.0")
        self.assertTrue(metadata.is_release)

    def test_dispatch_cannot_impersonate_a_release(self):
        metadata = self.resolve(
            ref="refs/heads/master",
            event_name="workflow_dispatch",
        )
        self.assertEqual(metadata.mode, "master")
        self.assertFalse(metadata.is_release)

    def test_tag_release_requires_push_event(self):
        with self.assertRaisesRegex(ValueError, "tag push"):
            self.resolve(
                ref="refs/tags/v1.3.0",
                event_name="workflow_dispatch",
            )

    def test_release_requires_exact_semver_tag(self):
        with self.assertRaisesRegex(ValueError, "invalid release tag"):
            self.resolve(
                ref="refs/tags/v1.3",
            )

    def test_requires_full_source_revision(self):
        with self.assertRaisesRegex(ValueError, "full 40-character"):
            self.resolve(sha="abc1234")


if __name__ == "__main__":
    unittest.main()

import importlib.util
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_guard", ROOT / "scripts" / "ci" / "release_guard.py"
)
GUARD = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = GUARD
SPEC.loader.exec_module(GUARD)


SHA = "a" * 40


class ReleaseGuardTests(unittest.TestCase):
    def verify(self, **overrides):
        values = {
            "event_name": "push",
            "ref": "refs/tags/v1.3.1",
            "github_sha": SHA,
            "checkout_sha": SHA,
            "tag_sha": SHA,
        }
        values.update(overrides)
        return GUARD.verify_source_identity(**values)

    def test_accepts_one_exact_tag_commit_identity(self):
        self.assertEqual(self.verify(), "v1.3.1")

    def test_rejects_branch_or_manual_release(self):
        with self.assertRaisesRegex(ValueError, "tag push"):
            self.verify(event_name="workflow_dispatch", ref="refs/heads/master")

    def test_rejects_non_semver_tag(self):
        with self.assertRaisesRegex(ValueError, "vX.Y.Z"):
            self.verify(ref="refs/tags/v1.3.1-hotfix")

    def test_rejects_different_checkout_identity(self):
        with self.assertRaisesRegex(ValueError, "identities differ"):
            self.verify(checkout_sha="b" * 40)


if __name__ == "__main__":
    unittest.main()

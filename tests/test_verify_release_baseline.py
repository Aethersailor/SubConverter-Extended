import importlib.util
import json
import pathlib
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "verify_release_baseline", ROOT / "scripts" / "ci" / "verify_release_baseline.py"
)
VERIFY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = VERIFY
SPEC.loader.exec_module(VERIFY)


class ReleaseBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.baseline = json.loads(
            (ROOT / ".github" / "release-baselines" / "v1.3.0.json").read_text(
                encoding="utf-8"
            )
        )

    def release(self):
        return {
            "id": self.baseline["release_id"],
            "tag_name": self.baseline["version"],
            "draft": False,
            "prerelease": False,
            "assets": [
                {"name": name, **identity}
                for name, identity in self.baseline["assets"].items()
            ],
        }

    def verify(self, release=None, **overrides):
        values = {
            "baseline": self.baseline,
            "release": release or self.release(),
            "tag_commit": self.baseline["tag_commit"],
            "dockerhub_digest": self.baseline["images"]["dockerhub"]["digest"],
            "ghcr_digest": self.baseline["images"]["ghcr"]["digest"],
        }
        values.update(overrides)
        VERIFY.verify(**values)

    def test_accepts_exact_frozen_identity(self):
        self.verify()

    def test_rejects_asset_replacement(self):
        release = self.release()
        release["assets"][0]["digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ValueError, "assets changed"):
            self.verify(release=release)

    def test_rejects_tag_movement(self):
        with self.assertRaisesRegex(ValueError, "tag commit"):
            self.verify(tag_commit="0" * 40)


if __name__ == "__main__":
    unittest.main()

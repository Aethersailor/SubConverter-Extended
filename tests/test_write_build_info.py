import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "write_build_info", ROOT / "scripts" / "ci" / "write_build_info.py"
)
BUILD_INFO = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = BUILD_INFO
SPEC.loader.exec_module(BUILD_INFO)


REVISION = "a" * 40
BUILD_DATE = "2026-08-06T04:37:18Z"


class BuildInfoTests(unittest.TestCase):
    def identity(self, **overrides):
        values = {
            "version": "v1.3.1",
            "revision": REVISION,
            "build_date": BUILD_DATE,
        }
        values.update(overrides)
        return BUILD_INFO.build_info(**values)

    def test_writes_deterministic_full_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "BUILD-INFO.json"
            identity = self.identity()
            BUILD_INFO.write(path, identity)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), identity)
            BUILD_INFO.verify(path, identity)

    def test_rejects_short_revision(self):
        with self.assertRaisesRegex(ValueError, "full 40-character"):
            self.identity(revision="abc1234")

    def test_rejects_non_tag_version(self):
        with self.assertRaisesRegex(ValueError, "vX.Y.Z"):
            self.identity(version="dev")

    def test_rejects_noncanonical_date(self):
        with self.assertRaisesRegex(ValueError, "UTC timestamp"):
            self.identity(build_date="2026-08-06T12:37:18+08:00")

    def test_detects_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "BUILD-INFO.json"
            BUILD_INFO.write(path, self.identity())
            with path.open("w", encoding="utf-8") as handle:
                json.dump(self.identity(revision="b" * 40), handle)
            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                BUILD_INFO.verify(path, self.identity())


if __name__ == "__main__":
    unittest.main()

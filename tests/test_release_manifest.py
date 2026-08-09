import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_manifest", ROOT / "scripts" / "ci" / "release_manifest.py"
)
MANIFEST = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = MANIFEST
SPEC.loader.exec_module(MANIFEST)


class ReleaseManifestTests(unittest.TestCase):
    def populate(self, root: pathlib.Path, version: str = "v1.3.1") -> None:
        for index, name in enumerate(sorted(MANIFEST.expected_package_names(version))):
            path = root / ("nested" if index % 2 else "") / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(f"asset-{index}".encode())
        (root / "SHA256SUMS").write_text("checksums\n", encoding="utf-8")

    def create(self, root: pathlib.Path):
        return MANIFEST.create_manifest(
            root=root,
            version="v1.3.1",
            revision="a" * 40,
            build_date="2026-08-06T04:37:18Z",
            dockerhub_digest="sha256:" + "b" * 64,
            ghcr_digest="sha256:" + "b" * 64,
        )

    def test_exact_asset_set_and_identity_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.populate(root)
            manifest = self.create(root)
            self.assertEqual(len(manifest["assets"]), 18)
            self.assertEqual(manifest["revision"], "a" * 40)
            MANIFEST.verify_manifest(root=root, manifest=manifest)

    def test_rejects_missing_package(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.populate(root)
            next(root.rglob("*.zip")).unlink()
            with self.assertRaisesRegex(ValueError, "asset set mismatch"):
                self.create(root)

    def test_rejects_duplicate_asset_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.populate(root)
            duplicate = next(path for path in root.rglob("*.apk") if path.parent != root)
            (root / duplicate.name).write_bytes(duplicate.read_bytes())
            with self.assertRaisesRegex(ValueError, "duplicate"):
                self.create(root)

    def test_detects_post_manifest_asset_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.populate(root)
            manifest = self.create(root)
            target = next(root.rglob("*.tar.gz"))
            target.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "mismatch"):
                MANIFEST.verify_manifest(root=root, manifest=manifest)

    def test_rejects_untracked_extra_asset(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.populate(root)
            (root / "unexpected.txt").write_text("unexpected", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unexpected release assets"):
                self.create(root)

    def test_rejects_registry_digest_divergence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            self.populate(root)
            with self.assertRaisesRegex(ValueError, "same manifest digest"):
                MANIFEST.create_manifest(
                    root=root,
                    version="v1.3.1",
                    revision="a" * 40,
                    build_date="2026-08-06T04:37:18Z",
                    dockerhub_digest="sha256:" + "b" * 64,
                    ghcr_digest="sha256:" + "c" * 64,
                )


if __name__ == "__main__":
    unittest.main()

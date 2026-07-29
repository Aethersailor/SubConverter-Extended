#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / "scripts"))

from custom_openclash_rules_policy import ALLOWED_DIRECTORIES  # noqa: E402
from sync_custom_openclash_rules import sync_assets  # noqa: E402
from verify_custom_openclash_rules_bundle import (  # noqa: E402
    BundleVerificationError,
    verify_bundle,
)


def write(root: Path, relative: str, content: bytes | str) -> Path:
    path = root / Path(*relative.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        path.write_text(content, encoding="utf-8")
    else:
        path.write_bytes(content)
    return path


def manifest_entries(bundle: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in (bundle / "manifest.sha256").read_text(
        encoding="utf-8"
    ).splitlines():
        digest, path = line.split("  ", 1)
        entries[path] = digest
    return entries


class CustomOpenClashRulesBundleTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.repository = self.root / "repository"
        self.source.mkdir()
        self.repository.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @property
    def bundle(self) -> Path:
        return self.repository / "base" / "Custom_OpenClash_Rules"

    def populate_policy_fixture(self) -> None:
        write(self.source, "cfg/root.ini", "root")
        write(self.source, "cfg/.hidden", "hidden")
        write(self.source, "cfg/README.md", "excluded")
        write(self.source, "cfg/readME.MD", "excluded")
        write(self.source, "cfg/yaml/a.yaml", "yaml")
        write(self.source, "cfg/yaml/Fixture&Airport.yaml", "ampersand")
        write(self.source, "cfg/yaml/nested/ignored.yaml", "ignored")
        write(self.source, "cfg/other/ignored.ini", "ignored")
        write(self.source, "rule/a.list", "rule")
        write(self.source, "rule/nested/ignored.list", "ignored")
        write(self.source, "game_rule/game.mrs", b"\x00mrs")
        write(self.source, "overwrite/a.conf", "overwrite")
        write(self.source, "overwrite/yaml/a.conf", "overwrite-yaml")
        write(
            self.source,
            "overwrite/yaml/nested/ignored.conf",
            "ignored",
        )
        write(self.source, "shell/a.sh", "#!/bin/sh\n")
        write(self.source, "shell/subdir/ignored.sh", "ignored")

    def test_policy_and_manifest_are_direct_file_only(self) -> None:
        self.populate_policy_fixture()
        symlink_supported = True
        try:
            os.symlink(
                self.source / "cfg" / "root.ini",
                self.source / "cfg" / "linked.ini",
            )
        except (OSError, NotImplementedError):
            symlink_supported = False

        counts = sync_assets(self.source, self.repository)
        self.assertEqual(tuple(counts), ALLOWED_DIRECTORIES)
        self.assertEqual(
            counts,
            {
                "cfg": 2,
                "cfg/yaml": 2,
                "rule": 1,
                "game_rule": 1,
                "overwrite": 1,
                "overwrite/yaml": 1,
                "shell": 1,
            },
        )
        self.assertEqual(verify_bundle(self.bundle), counts)

        entries = manifest_entries(self.bundle)
        expected_paths = {
            "main/cfg/.hidden",
            "main/cfg/root.ini",
            "main/cfg/yaml/a.yaml",
            "main/cfg/yaml/Fixture&Airport.yaml",
            "main/rule/a.list",
            "main/game_rule/game.mrs",
            "main/overwrite/a.conf",
            "main/overwrite/yaml/a.conf",
            "main/shell/a.sh",
        }
        self.assertEqual(set(entries), expected_paths)
        self.assertEqual(list(entries), sorted(entries))
        for relative, digest in entries.items():
            data = (self.bundle / Path(*relative.split("/"))).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
        self.assertFalse(
            (self.bundle / "main/cfg/yaml/nested/ignored.yaml").exists()
        )
        self.assertFalse((self.bundle / "main/cfg/README.md").exists())
        if symlink_supported:
            self.assertFalse((self.bundle / "main/cfg/linked.ini").exists())

    def test_add_delete_missing_directory_and_stale_cleanup(self) -> None:
        write(self.source, "cfg/A.ini", "A")
        write(self.source, "cfg/B.ini", "B")
        first = sync_assets(self.source, self.repository)
        self.assertEqual(first["cfg"], 2)
        self.assertEqual(
            set(manifest_entries(self.bundle)),
            {"main/cfg/A.ini", "main/cfg/B.ini"},
        )

        (self.source / "cfg/A.ini").unlink()
        write(self.source, "cfg/C.ini", "C")
        write(self.bundle, "main/cfg/stale.ini", "stale")
        second = sync_assets(self.source, self.repository)
        self.assertEqual(second["cfg"], 2)
        self.assertEqual(
            set(manifest_entries(self.bundle)),
            {"main/cfg/B.ini", "main/cfg/C.ini"},
        )
        self.assertFalse((self.bundle / "main/cfg/A.ini").exists())
        self.assertFalse((self.bundle / "main/cfg/stale.ini").exists())

        for file_path in (self.source / "cfg").iterdir():
            file_path.unlink()
        (self.source / "cfg").rmdir()
        write(self.source, "rule/remaining.list", "remaining")
        third = sync_assets(self.source, self.repository)
        self.assertEqual(third["cfg"], 0)
        self.assertEqual(third["rule"], 1)
        self.assertTrue((self.bundle / "main/cfg").is_dir())
        self.assertEqual(
            set(manifest_entries(self.bundle)),
            {"main/rule/remaining.list"},
        )
        self.assertEqual(verify_bundle(self.bundle), third)

    def test_empty_allowed_directory_is_valid_but_empty_bundle_fails(self) -> None:
        (self.source / "cfg").mkdir()
        write(self.source, "shell/only.sh", "safe")
        counts = sync_assets(self.source, self.repository)
        self.assertEqual(counts["cfg"], 0)
        self.assertEqual(counts["shell"], 1)
        for directory in ALLOWED_DIRECTORIES:
            self.assertTrue(
                (self.bundle / "main" / Path(*directory.split("/"))).is_dir()
            )

        empty_source = self.root / "empty"
        empty_source.mkdir()
        with self.assertRaises(SystemExit):
            sync_assets(empty_source, self.repository)

    def test_verifier_rejects_unrecorded_nested_and_symlink_resources(self) -> None:
        write(self.source, "rule/valid.list", "valid")
        sync_assets(self.source, self.repository)
        write(self.bundle, "main/rule/extra.list", "extra")
        with self.assertRaises(BundleVerificationError):
            verify_bundle(self.bundle)

        sync_assets(self.source, self.repository)
        write(self.bundle, "main/rule/nested/extra.list", "extra")
        with self.assertRaises(BundleVerificationError):
            verify_bundle(self.bundle)

        sync_assets(self.source, self.repository)
        try:
            os.symlink(
                self.bundle / "main/rule/valid.list",
                self.bundle / "main/rule/link.list",
            )
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation is not supported")
        with self.assertRaises(BundleVerificationError):
            verify_bundle(self.bundle)


if __name__ == "__main__":
    unittest.main()

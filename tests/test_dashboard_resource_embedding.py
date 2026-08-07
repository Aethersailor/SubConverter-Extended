#!/usr/bin/env python3
"""Deterministic Dashboard source-to-C++ embedding contract."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]
DASHBOARD_SOURCE = REPOSITORY / "resources" / "dashboard" / "index.html"
EMBED_SCRIPT = REPOSITORY / "cmake" / "embed_dashboard.cmake"
CMAKE = shutil.which("cmake")
BASELINE_SHA256 = (
    "265cbce59394ec1e966bdd137bd79e993768eaf7f95260700ee287957b503908"
)
BYTE_ARRAY_PREFIX = b"inline constexpr unsigned char kDashboardHtml[] = {"
BYTE_ARRAY_SUFFIX = b"};"


def embedded_body(generated: bytes) -> bytes:
    start = generated.index(BYTE_ARRAY_PREFIX) + len(BYTE_ARRAY_PREFIX)
    end = generated.index(BYTE_ARRAY_SUFFIX, start)
    return bytes(
        int(value, 16)
        for value in re.findall(rb"0x([0-9a-f]{2})", generated[start:end])
    )


@unittest.skipUnless(CMAKE, "cmake is required for the embedding contract")
class DashboardResourceEmbeddingTest(unittest.TestCase):
    def generate(
        self, source: Path, output: Path, *, expect_success: bool = True
    ) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            [
                CMAKE or "cmake",
                f"-DINPUT_FILE={source}",
                f"-DOUTPUT_FILE={output}",
                "-P",
                str(EMBED_SCRIPT),
            ],
            cwd=REPOSITORY,
            text=True,
            capture_output=True,
            check=False,
        )
        if expect_success and completed.returncode != 0:
            self.fail(completed.stdout + completed.stderr)
        return completed

    def test_dashboard_source_preserves_the_pre_refactor_response(self) -> None:
        source = DASHBOARD_SOURCE.read_bytes()
        self.assertNotIn(b"\r", source)
        self.assertEqual(hashlib.sha256(source).hexdigest(), BASELINE_SHA256)

    def test_generation_is_exact_and_does_not_touch_equal_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "dashboard.html"
            output = root / "generated" / "dashboard.inc"
            source.write_bytes(DASHBOARD_SOURCE.read_bytes())

            self.generate(source, output)
            first = output.read_bytes()
            self.assertEqual(embedded_body(first), source.read_bytes())

            stable_timestamp = 1_700_000_000
            os.utime(output, (stable_timestamp, stable_timestamp))
            self.generate(source, output)
            self.assertEqual(output.read_bytes(), first)
            self.assertEqual(int(output.stat().st_mtime), stable_timestamp)

    def test_changed_source_replaces_stale_generated_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "dashboard.html"
            output = root / "dashboard.inc"
            source.write_bytes(DASHBOARD_SOURCE.read_bytes())
            self.generate(source, output)

            changed = source.read_bytes() + b"\n<!-- deterministic-change -->"
            source.write_bytes(changed)
            self.generate(source, output)
            self.assertEqual(embedded_body(output.read_bytes()), changed)

    def test_missing_source_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            completed = self.generate(
                root / "missing.html",
                root / "dashboard.inc",
                expect_success=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                "Dashboard source is missing",
                completed.stdout + completed.stderr,
            )

    def test_mixed_line_endings_are_embedded_as_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "dashboard.html"
            expected = b"lf\ncrlf\r\nreserved )SCXDASH\" text\n"
            source.write_bytes(expected)
            output = root / "dashboard.inc"
            self.generate(source, output)
            self.assertEqual(embedded_body(output.read_bytes()), expected)


if __name__ == "__main__":
    unittest.main()

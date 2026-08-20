#!/usr/bin/env python3
"""Deterministic Dashboard source-to-C++ embedding contract."""

from __future__ import annotations

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


def resolve_tool(name: str, windows_fallback: str) -> str | None:
    return shutil.which(name) or (
        windows_fallback if Path(windows_fallback).exists() else None
    )


CMAKE = resolve_tool("cmake", r"C:\msys64\ucrt64\bin\cmake.exe")
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
        self,
        source: Path,
        output: Path,
        *,
        expect_success: bool = True,
        definitions: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        arguments = [
            CMAKE or "cmake",
            f"-DINPUT_FILE={source}",
            f"-DOUTPUT_FILE={output}",
        ]
        arguments.extend(
            f"-D{name}={value}" for name, value in (definitions or {}).items()
        )
        arguments.extend(["-P", str(EMBED_SCRIPT)])
        completed = subprocess.run(
            arguments,
            cwd=REPOSITORY,
            text=True,
            capture_output=True,
            check=False,
        )
        if expect_success and completed.returncode != 0:
            self.fail(completed.stdout + completed.stderr)
        return completed

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

    def test_failure_before_atomic_replace_preserves_previous_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "dashboard.html"
            output = root / "dashboard.inc"
            source.write_bytes(DASHBOARD_SOURCE.read_bytes())
            previous = b"// known-good generated output\n"
            output.write_bytes(previous)
            stable_timestamp_ns = 1_700_000_000_123_456_700
            os.utime(
                output,
                ns=(stable_timestamp_ns, stable_timestamp_ns),
            )
            previous_mtime_ns = output.stat().st_mtime_ns

            completed = self.generate(
                source,
                output,
                expect_success=False,
                definitions={"DASHBOARD_EMBED_TEST_FAIL_BEFORE_RENAME": "ON"},
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(
                "Injected Dashboard failure before atomic output replacement",
                completed.stdout + completed.stderr,
            )
            self.assertEqual(output.read_bytes(), previous)
            self.assertEqual(output.stat().st_mtime_ns, previous_mtime_ns)
            self.assertFalse(
                list(output.parent.glob(f"{output.name}.*.tmp"))
            )

            self.generate(source, output)
            self.assertEqual(
                embedded_body(output.read_bytes()), source.read_bytes()
            )
            self.assertFalse(
                list(output.parent.glob(f"{output.name}.*.tmp"))
            )

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

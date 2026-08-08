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


def resolve_tool(name: str, windows_fallback: str) -> str | None:
    return shutil.which(name) or (
        windows_fallback if Path(windows_fallback).exists() else None
    )


CMAKE = resolve_tool("cmake", r"C:\msys64\ucrt64\bin\cmake.exe")
NINJA = resolve_tool("ninja", r"C:\msys64\ucrt64\bin\ninja.exe")
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

    def test_failure_before_atomic_replace_preserves_previous_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "dashboard.html"
            output = root / "dashboard.inc"
            source.write_bytes(DASHBOARD_SOURCE.read_bytes())
            previous = b"// known-good generated output\n"
            output.write_bytes(previous)

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

            self.generate(source, output)
            self.assertEqual(
                embedded_body(output.read_bytes()), source.read_bytes()
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

    def test_cmake_graph_has_one_dashboard_generation_driver(self) -> None:
        cmake_lists = (REPOSITORY / "CMakeLists.txt").read_text(
            encoding="utf-8"
        )
        runtime_sources = re.search(
            r"SET\(SUBCONVERTER_RUNTIME_SOURCES\n(?P<body>.*?)\)",
            cmake_lists,
            re.DOTALL,
        )
        self.assertIsNotNone(runtime_sources)
        self.assertNotIn(
            "DASHBOARD_HTML_GENERATED", runtime_sources.group("body")
        )
        self.assertEqual(
            cmake_lists.count("ADD_CUSTOM_TARGET(dashboard_resource"), 1
        )
        self.assertIn(
            'DEPENDS "${DASHBOARD_HTML_GENERATED}"', cmake_lists
        )
        self.assertIn(
            "ADD_DEPENDENCIES(${BUILD_TARGET_NAME} dashboard_resource)",
            cmake_lists,
        )
        self.assertIn(
            "ADD_DEPENDENCIES(settings_snapshot_test_helper "
            "dashboard_resource)",
            cmake_lists,
        )

        generator = EMBED_SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn('SET(TEMPORARY_OUTPUT "${OUTPUT_FILE}.tmp")', generator)
        self.assertIn('FILE(LOCK "${OUTPUT_FILE}.lock"', generator)
        self.assertIn("STRING(RANDOM", generator)
        self.assertNotIn('FILE(REMOVE "${OUTPUT_FILE}")', generator)
        self.assertIn(
            'FILE(RENAME "${TEMPORARY_OUTPUT}" "${OUTPUT_FILE}")',
            generator,
        )

    @unittest.skipUnless(NINJA, "Ninja is required for the parallel graph test")
    def test_ninja_multi_config_parallel_consumers_generate_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "dashboard.html"
            output = root / "build" / "generated" / "dashboard.inc"
            source.write_bytes(DASHBOARD_SOURCE.read_bytes())
            cmake_source = root / "CMakeLists.txt"
            cmake_source.write_text(
                "\n".join(
                    [
                        "cmake_minimum_required(VERSION 3.13)",
                        "project(dashboard_graph NONE)",
                        'set(DASHBOARD_SOURCE "${CMAKE_SOURCE_DIR}/dashboard.html")',
                        'set(DASHBOARD_OUTPUT "${CMAKE_BINARY_DIR}/generated/dashboard.inc")',
                        "add_custom_command(",
                        '  OUTPUT "${DASHBOARD_OUTPUT}"',
                        '  COMMAND "${CMAKE_COMMAND}"',
                        '    "-DINPUT_FILE=${DASHBOARD_SOURCE}"',
                        '    "-DOUTPUT_FILE=${DASHBOARD_OUTPUT}"',
                        f'    -P "{EMBED_SCRIPT.as_posix()}"',
                        '  DEPENDS "${DASHBOARD_SOURCE}"',
                        f'    "{EMBED_SCRIPT.as_posix()}"',
                        '  COMMENT "Embedding Dashboard HTML"',
                        "  VERBATIM)",
                        "add_custom_target(dashboard_resource",
                        '  DEPENDS "${DASHBOARD_OUTPUT}")',
                        "foreach(consumer IN ITEMS consumer_a consumer_b)",
                        "  add_custom_command(",
                        '    OUTPUT "${CMAKE_BINARY_DIR}/${consumer}.stamp"',
                        '    COMMAND "${CMAKE_COMMAND}" -E touch',
                        '      "${CMAKE_BINARY_DIR}/${consumer}.stamp")',
                        "  add_custom_target(${consumer}",
                        '    DEPENDS "${CMAKE_BINARY_DIR}/${consumer}.stamp")',
                        "  add_dependencies(${consumer} dashboard_resource)",
                        "endforeach()",
                        "",
                    ]
                ),
                encoding="utf-8",
                newline="\n",
            )
            build = root / "build"
            configure = subprocess.run(
                [
                    CMAKE or "cmake",
                    "-S",
                    str(root),
                    "-B",
                    str(build),
                    "-G",
                    "Ninja Multi-Config",
                    f"-DCMAKE_MAKE_PROGRAM={NINJA}",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            if configure.returncode != 0:
                self.fail(configure.stdout + configure.stderr)

            def build_consumers() -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [
                        CMAKE or "cmake",
                        "--build",
                        str(build),
                        "--config",
                        "Release",
                        "--target",
                        "consumer_a",
                        "consumer_b",
                        "--parallel",
                        "2",
                    ],
                    text=True,
                    capture_output=True,
                    check=False,
                )

            first = build_consumers()
            self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
            self.assertEqual(
                (first.stdout + first.stderr).count("Embedding Dashboard HTML"),
                1,
            )
            self.assertEqual(embedded_body(output.read_bytes()), source.read_bytes())

            stable_timestamp = 1_700_000_000
            os.utime(output, (stable_timestamp, stable_timestamp))
            repeat = build_consumers()
            self.assertEqual(repeat.returncode, 0, repeat.stdout + repeat.stderr)
            self.assertNotIn("Embedding Dashboard HTML", repeat.stdout + repeat.stderr)
            self.assertEqual(int(output.stat().st_mtime), stable_timestamp)

            changed = source.read_bytes() + b"\n<!-- graph-change -->"
            source.write_bytes(changed)
            changed_build = build_consumers()
            self.assertEqual(
                changed_build.returncode,
                0,
                changed_build.stdout + changed_build.stderr,
            )
            self.assertEqual(
                (changed_build.stdout + changed_build.stderr).count(
                    "Embedding Dashboard HTML"
                ),
                1,
            )
            self.assertEqual(embedded_body(output.read_bytes()), changed)
            self.assertFalse(list(output.parent.glob("*.tmp")))


if __name__ == "__main__":
    unittest.main()

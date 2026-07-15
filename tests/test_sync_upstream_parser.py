from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "sync_upstream_parser.py"
WORKFLOW = ROOT / ".github" / "workflows" / "sync-upstream-parser.yml"


def load_planner():
    spec = importlib.util.spec_from_file_location("sync_upstream_parser", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load upstream parser monitor")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class UpstreamParserMonitorSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.planner = load_planner()

    def test_dev_checkout_is_mandatory(self) -> None:
        with mock.patch.object(self.planner, "git", return_value="dev\n"):
            self.planner.ensure_dev_checkout()

        with mock.patch.object(self.planner, "git", return_value="master\n"):
            with self.assertRaisesRegex(RuntimeError, "dev-only"):
                self.planner.ensure_dev_checkout()

    def test_mixed_commit_review_contains_every_changed_file(self) -> None:
        files = [".untrusted-companion", "src/parser/subparser.cpp"]
        patch = mock.Mock(return_value=("complete patch", False, 14))
        with (
            mock.patch.object(self.planner, "commit_files", return_value=files),
            mock.patch.object(self.planner, "commit_subject", return_value="candidate"),
            mock.patch.object(self.planner, "commit_is_merge", return_value=False),
            mock.patch.object(self.planner, "commit_patch", patch),
        ):
            result = self.planner.classify_commit("a" * 40)

        patch.assert_called_once_with("a" * 40, files)
        self.assertEqual(result["rule_decision"], "mixed_change")
        self.assertEqual(result["automatic_action"], "never")
        self.assertEqual(result["files"], files)

    def test_apply_command_does_not_exist(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "apply"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid choice", result.stderr)

    def test_report_output_cannot_overwrite_repository_content(self) -> None:
        with self.assertRaisesRegex(ValueError, "not an allowed repository output"):
            self.planner.resolve_report_path("src/parser/subparser.cpp")

        allowed = self.planner.resolve_report_path("upstream-sync-candidates.json")
        self.assertEqual(allowed, ROOT / "upstream-sync-candidates.json")

    def test_workflow_cannot_write_repository_content(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("contents: read", text)
        self.assertIn("TARGET_BRANCH: dev", text)
        self.assertIn("persist-credentials: false", text)
        for forbidden in (
            "contents: write",
            "git apply",
            "git commit",
            "git push",
            "PAT_TOKEN",
        ):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()

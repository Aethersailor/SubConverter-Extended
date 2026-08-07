import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run-test-suite.py"
SPEC = importlib.util.spec_from_file_location("run_test_suite", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
RUN_TEST_SUITE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUN_TEST_SUITE)


class RunTestSuiteContractTests(unittest.TestCase):
    def test_fast_selects_only_fast_label(self) -> None:
        command = RUN_TEST_SUITE.build_command(Path("build"), "fast", 90)
        self.assertEqual(command[-2:], ["--label-regex", "^fast$"])

    def test_full_excludes_benchmarks(self) -> None:
        command = RUN_TEST_SUITE.build_command(Path("build"), "full", 90)
        self.assertEqual(command[-2:], ["--label-exclude", "^benchmark$"])

    def test_benchmark_is_explicit(self) -> None:
        command = RUN_TEST_SUITE.build_command(Path("build"), "benchmark", 90)
        self.assertEqual(command[-2:], ["--label-regex", "^benchmark$"])

    def test_unknown_mode_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            RUN_TEST_SUITE.build_command(Path("build"), "unknown", 90)


if __name__ == "__main__":
    unittest.main()

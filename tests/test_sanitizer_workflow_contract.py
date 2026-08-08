import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class SanitizerWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        workflow = (ROOT / ".github/workflows/build-dockerhub.yml").read_text(
            encoding="utf-8"
        )
        cls.sanitizer_job = workflow.split("  request-sanitizers:\n", 1)[1].split(
            "  prepare:\n", 1
        )[0]
        cls.cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        cls.dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    def test_job_builds_the_instrumented_runtime_and_request_tests(self):
        self.assertIn("--target builder", self.sanitizer_job)
        self.assertIn("BUILD_TESTS=true", self.sanitizer_job)
        self.assertIn("ENABLE_SANITIZERS=true", self.sanitizer_job)
        self.assertIn("settings_view", self.sanitizer_job)
        self.assertIn("compatibility_security_baseline", self.sanitizer_job)
        self.assertNotIn("tests/statistics_v2_test.cpp", self.sanitizer_job)

    def test_job_exports_only_the_reusable_cache(self):
        self.assertIn("--output type=cacheonly", self.sanitizer_job)
        self.assertIn(
            "--cache-from type=gha,scope=request-sanitizers",
            self.sanitizer_job,
        )
        self.assertIn(
            "--cache-to type=gha,scope=request-sanitizers,mode=max",
            self.sanitizer_job,
        )
        self.assertNotIn("--load", self.sanitizer_job)
        self.assertNotIn("subconverter-request-sanitizer:", self.sanitizer_job)

    def test_sanitizer_flags_and_fail_closed_runtime_are_explicit(self):
        for flag in (
            "-fsanitize=address,undefined",
            "-fno-omit-frame-pointer",
        ):
            self.assertIn(flag, self.cmake)
        self.assertIn("ASAN_OPTIONS", self.dockerfile)
        self.assertIn("UBSAN_OPTIONS", self.dockerfile)
        self.assertIn("halt_on_error=1", self.dockerfile)

    def test_go_bridge_uses_asan_compatible_archive(self):
        self.assertIn('sanitizer_flags="-asan"', self.dockerfile)
        self.assertIn("go build ${sanitizer_flags}", self.dockerfile)
        self.assertIn("-buildmode=c-archive", self.dockerfile)
        self.assertIn("cp /usr/lib/libmihomo.a bridge/", self.dockerfile)

    def test_release_invariant_fault_injection_is_in_the_full_test_graph(self):
        self.assertIn("NAME settings_view_invariant_failure", self.cmake)
        self.assertIn("WILL_FAIL TRUE", self.cmake)
        self.assertIn("--inject-invariant-failure", self.cmake)


if __name__ == "__main__":
    unittest.main()

import pathlib
import re
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class RequestSettingsViewContractTests(unittest.TestCase):
    def source(self, relative_path: str) -> str:
        return (ROOT / relative_path).read_text(encoding="utf-8")

    def assert_no_global_reads(self, relative_path: str) -> None:
        source = self.source(relative_path)
        self.assertIsNone(
            re.search(r"\bglobal\s*\.", source),
            f"request-reachable settings read bypasses effectiveSettings: {relative_path}",
        )

    def test_generator_and_template_request_paths_use_the_bound_view(self):
        for relative_path in (
            "src/generator/config/nodemanip.cpp",
            "src/generator/config/ruleconvert.cpp",
            "src/generator/config/subexport.cpp",
            "src/generator/template/templates.cpp",
        ):
            with self.subTest(path=relative_path):
                self.assert_no_global_reads(relative_path)

    def test_quickjs_request_callbacks_use_the_bound_view(self):
        source = self.source("src/script/script_quickjs.cpp")
        for function_name in (
            "static qjs_fetch_Response qjs_fetch(",
            "std::string getGeoIP(",
        ):
            with self.subTest(function=function_name):
                start = source.index(function_name)
                body = source[start : source.index("\n}", start) + 2]
                self.assertNotRegex(body, r"\bglobal\s*\.")
                self.assertIn("effectiveSettings()", body)

    def test_statistics_recording_uses_the_bound_view(self):
        source = self.source("src/handler/statistics.cpp")
        start = source.index("void recordSubscriptionConversion")
        body = source[start : source.index("\n}", start) + 2]
        self.assertNotRegex(body, r"\bglobal\s*\.")
        self.assertIn("effectiveSettings().statisticsEnabled", body)

    def test_logger_gate_uses_the_bound_view(self):
        source = self.source("src/utils/logger.cpp")
        start = source.index("bool shouldLog")
        body = source[start : source.index("\n}", start) + 2]
        self.assertNotRegex(body, r"\bglobal\s*\.")
        self.assertIn("effectiveSettings().logLevel", body)


if __name__ == "__main__":
    unittest.main()

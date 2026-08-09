import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_plan", ROOT / "scripts" / "ci" / "build_plan.py"
)
BUILD_PLAN = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = BUILD_PLAN
SPEC.loader.exec_module(BUILD_PLAN)


class BuildPlanTests(unittest.TestCase):
    def compact_matrix(self, mode):
        return json.dumps(BUILD_PLAN.linux_matrix(mode), separators=(",", ":"))

    def test_dev_and_pr_keep_the_single_amd64_matrix(self):
        for mode in ("dev", "pr"):
            matrix = BUILD_PLAN.linux_matrix(mode)
            self.assertEqual([entry["arch"] for entry in matrix["include"]], ["amd64"])
            self.assertEqual(matrix["include"][0], BUILD_PLAN.AMD64)

    def test_master_and_release_keep_the_three_platform_matrix(self):
        for mode in ("master", "release"):
            matrix = BUILD_PLAN.linux_matrix(mode)
            self.assertEqual(
                [entry["arch"] for entry in matrix["include"]],
                ["amd64", "arm64", "armv7"],
            )
            self.assertEqual(matrix["include"][2]["qemu_platforms"], "arm")

    def test_image_tags_are_unchanged(self):
        self.assertEqual(
            BUILD_PLAN.image_tags("dev", "ignored"),
            [
                "aethersailor/subconverter-extended:dev",
                "ghcr.io/aethersailor/subconverter-extended:dev",
            ],
        )
        self.assertEqual(
            BUILD_PLAN.image_tags("release", "v1.3.1"),
            [
                "aethersailor/subconverter-extended:v1.3.1",
                "ghcr.io/aethersailor/subconverter-extended:v1.3.1",
            ],
        )
        self.assertEqual(BUILD_PLAN.image_tags("master", "master-deadbee"), [])
        self.assertEqual(BUILD_PLAN.image_tags("pr", "pr-deadbee"), [])

    def test_github_output_is_valid_and_deterministic(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "output"
            value = self.compact_matrix("release")
            BUILD_PLAN.append_multiline(output, "matrix", value)
            self.assertEqual(output.read_text(encoding="utf-8"), f"matrix<<EOF\n{value}\nEOF\n")

            output.write_text("", encoding="utf-8")
            BUILD_PLAN.append_multiline(output, "tags", "")
            self.assertEqual(output.read_text(encoding="utf-8"), "tags<<EOF\nEOF\n")


if __name__ == "__main__":
    unittest.main()

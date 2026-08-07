import importlib.util
import json
import pathlib
import subprocess
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "workflow_contract", ROOT / "scripts" / "ci" / "workflow_contract.py"
)
CONTRACT = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = CONTRACT
SPEC.loader.exec_module(CONTRACT)


class WorkflowStructureContractTests(unittest.TestCase):
    def test_structure_matches_the_pre_split_baseline(self):
        expected = json.loads(CONTRACT.FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(CONTRACT.snapshot(), expected)

    def test_extracted_shell_scripts_parse(self):
        scripts = (
            "build-candidate-image.sh",
            "export-ci-image.sh",
            "promote-tested-images.sh",
            "verify-published-images.sh",
        )
        for script in scripts:
            completed = subprocess.run(
                ["bash", "-n", f"scripts/ci/{script}"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_extracted_shell_scripts_preserve_delivery_arguments(self):
        completed = subprocess.run(
            ["bash", "tests/ci_delivery_scripts_test.sh"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_top_level_keeps_release_and_image_gates_visible(self):
        workflow = (
            ROOT / ".github" / "workflows" / "build-dockerhub.yml"
        ).read_text(encoding="utf-8")
        for step in (
            "Build candidate image once",
            "Prevent stale dev image promotion",
            "Promote tested candidates",
            "Verify manifest platforms",
            "Create draft Release without overwrites",
            "Advance latest only after full release verification",
        ):
            self.assertIn(f"- name: {step}", workflow)


if __name__ == "__main__":
    unittest.main()

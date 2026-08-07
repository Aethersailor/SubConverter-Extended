import importlib.util
import json
import pathlib
import re
import subprocess
import sys
import tempfile
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

    def test_frozen_oracle_has_explicit_provenance_and_scope(self):
        expected = json.loads(CONTRACT.FIXTURE.read_text(encoding="utf-8"))
        oracle = CONTRACT.load_oracle()
        self.assertEqual(
            oracle["source_sha"],
            "47d2399444ac6abad78185c479a09d2bc4511536",
        )
        self.assertEqual(
            CONTRACT.canonical_contract_sha256(expected),
            oracle["contract_sha256"],
        )
        self.assertEqual(
            set(oracle["step_fields"]),
            CONTRACT.STEP_FIELDS,
        )
        self.assertEqual(oracle["run_normalization"], "universal-newlines-only")

    def test_composite_action_hash_is_independent_of_checkout_line_endings(self):
        with tempfile.TemporaryDirectory() as temporary:
            lf = pathlib.Path(temporary) / "lf.yml"
            crlf = pathlib.Path(temporary) / "crlf.yml"
            lf.write_bytes(b"name: test\nruns:\n  using: composite\n")
            crlf.write_bytes(b"name: test\r\nruns:\r\n  using: composite\r\n")
            self.assertEqual(
                CONTRACT.canonical_text_sha256(lf),
                CONTRACT.canonical_text_sha256(crlf),
            )

    def test_run_contract_is_independent_of_checkout_line_endings(self):
        workflow = b"""name: Test
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Execute
        shell: bash
        run: |
          set -euo pipefail
          echo exact-command
"""
        with tempfile.TemporaryDirectory() as temporary:
            lf = pathlib.Path(temporary) / "lf.yml"
            crlf = pathlib.Path(temporary) / "crlf.yml"
            lf.write_bytes(workflow)
            crlf.write_bytes(workflow.replace(b"\n", b"\r\n"))
            self.assertEqual(
                CONTRACT.workflow_contract(lf),
                CONTRACT.workflow_contract(crlf),
            )
            run = CONTRACT.workflow_contract(lf)["jobs"]["test"]["steps"][0][
                "run"
            ]
            self.assertEqual(
                run,
                "|\nset -euo pipefail\necho exact-command",
            )

    def test_changing_a_run_command_breaks_the_frozen_contract(self):
        source = ROOT / ".github" / "workflows" / "build-dockerhub.yml"
        original = source.read_text(encoding="utf-8")
        marker = 'docker buildx imagetools create -t "$TAG" "${SOURCES[@]}"'
        self.assertEqual(original.count(marker), 1)
        with tempfile.TemporaryDirectory() as temporary:
            mutated = pathlib.Path(temporary) / source.name
            mutated.write_text(
                original.replace(marker, "echo contract-mutation"),
                encoding="utf-8",
                newline="\n",
            )
            self.assertNotEqual(
                CONTRACT.workflow_contract(source),
                CONTRACT.workflow_contract(mutated),
            )

    def test_contract_write_requires_explicit_baseline_approval(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "contract.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    "scripts/ci/workflow_contract.py",
                    "write",
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("--approve-baseline", completed.stdout + completed.stderr)
            self.assertFalse(output.exists())

    def test_all_supported_step_fields_are_part_of_the_contract(self):
        self.assertEqual(
            CONTRACT.STEP_FIELDS,
            {
                "name",
                "id",
                "if",
                "uses",
                "run",
                "shell",
                "with",
                "env",
                "continue-on-error",
                "timeout-minutes",
                "working-directory",
            },
        )

    def test_every_workflow_step_and_run_field_is_captured(self):
        snapshot = CONTRACT.snapshot()
        parsed_steps = [
            step
            for workflow in snapshot["workflows"].values()
            for job in workflow["jobs"].values()
            for step in job.get("steps", [])
        ]
        parsed_runs = sum("run" in step for step in parsed_steps)
        raw_runs = sum(
            bool(re.match(r"^\s+run:", line))
            for path in CONTRACT.WORKFLOWS.glob("*.yml")
            for line in path.read_text(encoding="utf-8").splitlines()
        )
        self.assertEqual(parsed_runs, raw_runs)
        for step in parsed_steps:
            self.assertNotEqual("run" in step, "uses" in step, step)

    def test_indentless_codeql_steps_and_run_bodies_are_captured(self):
        workflow = CONTRACT.workflow_contract(
            ROOT / ".github" / "workflows" / "codeql.yml"
        )
        steps = workflow["jobs"]["analyze"]["steps"]
        install = next(
            step for step in steps if step.get("name") == "Install C++ dependencies"
        )
        self.assertIn("sudo apt-get install", install["run"])
        self.assertIn("build-essential", install["run"])

    def test_no_checkout_promotion_jobs_keep_inline_commands(self):
        workflow = CONTRACT.workflow_contract(
            ROOT / ".github" / "workflows" / "build-dockerhub.yml"
        )
        steps = workflow["jobs"]["merge-manifest"]["steps"]
        self.assertNotIn("Checkout", {step.get("name") for step in steps})
        promote = next(
            step
            for step in steps
            if step.get("name") == "Promote tested candidates"
        )
        verify = next(
            step
            for step in steps
            if step.get("name") == "Verify manifest platforms"
        )
        self.assertIn("docker buildx imagetools create", promote["run"])
        self.assertIn("docker buildx imagetools inspect", verify["run"])
        self.assertIn("docker pull", verify["run"])
        self.assertNotIn("scripts/ci/", promote["run"])
        self.assertNotIn("scripts/ci/", verify["run"])

    def test_replacing_inline_promotion_with_repository_script_is_detected(self):
        source = ROOT / ".github" / "workflows" / "build-dockerhub.yml"
        original = source.read_text(encoding="utf-8")
        marker = 'docker buildx imagetools create -t "$TAG" "${SOURCES[@]}"'
        with tempfile.TemporaryDirectory() as temporary:
            mutated = pathlib.Path(temporary) / source.name
            mutated.write_text(
                original.replace(marker, "bash scripts/ci/promote-images.sh"),
                encoding="utf-8",
                newline="\n",
            )
            baseline = CONTRACT.workflow_contract(source)
            changed = CONTRACT.workflow_contract(mutated)
            self.assertNotEqual(changed, baseline)
            changed_steps = changed["jobs"]["merge-manifest"]["steps"]
            changed_promote = next(
                step
                for step in changed_steps
                if step.get("name") == "Promote tested candidates"
            )
            self.assertIn("scripts/ci/promote-images.sh", changed_promote["run"])

    def test_extracted_shell_scripts_parse(self):
        scripts = (
            "build-candidate-image.sh",
            "export-ci-image.sh",
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

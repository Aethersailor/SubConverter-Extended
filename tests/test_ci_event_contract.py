import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "event_contract", ROOT / "scripts" / "ci" / "event_contract.py"
)
EVENTS = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = EVENTS
SPEC.loader.exec_module(EVENTS)


class CiEventContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = {case["name"]: case for case in EVENTS.load_fixtures()}

    def outcome(self, name):
        case = self.cases[name]
        actual = EVENTS.simulate_fixture(case)
        self.assertEqual(actual, case["expected"])
        return actual

    def test_all_frozen_event_payloads_match(self):
        for name in self.cases:
            with self.subTest(name=name):
                self.outcome(name)

    def test_generated_child_is_native_no_run_not_job_skip(self):
        case = self.cases["generated_child_skip_ci"]
        result = self.outcome("generated_child_skip_ci")
        self.assertEqual(case["observed"]["actions_api_total_count"], 0)
        self.assertEqual(result["native_enqueue"], "suppressed")
        self.assertFalse(result["build"]["workflow_created"])
        self.assertFalse(result["codeql"]["workflow_created"])
        self.assertEqual(result["build"]["source_head"], "not-created")
        self.assertEqual(result["codeql"]["analyze"], "not-created")

    def test_negative_native_skip_cannot_be_reported_as_job_skip(self):
        case = json.loads(json.dumps(self.cases["generated_child_skip_ci"]))
        case["expected"]["build"]["workflow_created"] = True
        case["expected"]["build"]["source_head"] = "skipped-stale"
        self.assertNotEqual(EVENTS.simulate_fixture(case), case["expected"])

    def test_pull_request_payloads_use_merge_refs_and_real_base_fields(self):
        for name in ("same_repository_pr", "fork_pr", "dependabot_pr"):
            case = self.cases[name]
            github = case["github"]
            self.assertRegex(github["ref"], r"^refs/pull/[0-9]+/merge$")
            self.assertEqual(
                github["base_ref"],
                github["event"]["pull_request"]["base"]["ref"],
            )
            self.assertEqual(
                github["head_ref"],
                github["event"]["pull_request"]["head"]["ref"],
            )

    def test_fork_and_dependabot_capabilities_are_restricted(self):
        for name, source in (("fork_pr", "None"), ("dependabot_pr", "Dependabot")):
            capabilities = self.outcome(name)["capabilities"]
            self.assertFalse(capabilities["repository_actions_secrets"])
            self.assertEqual(capabilities["github_token_permissions"], "read-only")
            self.assertEqual(capabilities["secret_source"], source)
        same_repo = self.outcome("same_repository_pr")["capabilities"]
        self.assertTrue(same_repo["repository_actions_secrets"])

    def test_workflow_dispatch_only_models_the_selected_workflow(self):
        build = self.outcome("build_dispatch_dev")
        codeql = self.outcome("codeql_dispatch_stale_dev")
        self.assertTrue(build["build"]["workflow_created"])
        self.assertFalse(build["codeql"]["workflow_created"])
        self.assertFalse(codeql["build"]["workflow_created"])
        self.assertTrue(codeql["codeql"]["workflow_created"])

    def test_stale_build_dispatch_fails_but_stale_codeql_dispatch_skips(self):
        build = self.outcome("build_dispatch_stale_dev")
        codeql = self.outcome("codeql_dispatch_stale_dev")
        self.assertEqual(build["build"]["source_head"], "failed-stale")
        self.assertEqual(codeql["codeql"]["source_head"], "skipped-stale")

    def test_tag_push_uses_release_wrapper_but_tag_dispatch_fails_metadata(self):
        push = self.outcome("release_tag_push")
        dispatch = self.outcome("build_dispatch_tag")
        self.assertTrue(push["formal_release_workflow_created"])
        self.assertEqual(push["build"]["entrypoint"], "release-reusable")
        self.assertTrue(push["build"]["create_release"])
        self.assertFalse(dispatch["formal_release_workflow_created"])
        self.assertEqual(dispatch["build"]["prepare"], "failed-metadata")
        self.assertFalse(dispatch["build"]["create_release"])

    def test_invalid_tag_glob_creates_wrapper_then_metadata_fails(self):
        invalid = self.outcome("invalid_release_tag_push")
        self.assertTrue(invalid["formal_release_workflow_created"])
        self.assertTrue(invalid["build"]["workflow_created"])
        self.assertEqual(invalid["build"]["entrypoint"], "release-reusable")
        self.assertEqual(invalid["build"]["mode"], "release")
        self.assertEqual(invalid["build"]["source_head"], "current")
        self.assertEqual(invalid["build"]["prepare"], "failed-metadata")
        self.assertEqual(invalid["build"]["build_linux"], "skipped-upstream")
        self.assertFalse(invalid["build"]["registry_publish"])
        self.assertFalse(invalid["build"]["create_release"])

    def test_invalid_tag_cannot_regress_to_workflow_not_created(self):
        case = json.loads(json.dumps(self.cases["invalid_release_tag_push"]))
        case["expected"]["formal_release_workflow_created"] = False
        case["expected"]["build"] = {
            "workflow_created": False,
            "entrypoint": "none",
            "mode": "none",
            "source_head": "not-created",
            "request_sanitizers": "not-created",
            "prepare": "not-created",
            "build_linux": "not-created",
            "registry_publish": False,
            "create_release": False,
        }
        self.assertNotEqual(EVENTS.simulate_fixture(case), case["expected"])

    def test_slash_tag_is_legal_git_but_matches_no_current_workflow(self):
        slash_tag = self.outcome("legal_slash_tag_push")
        self.assertEqual(slash_tag["native_enqueue"], "eligible")
        self.assertFalse(slash_tag["formal_release_workflow_created"])
        self.assertFalse(slash_tag["build"]["workflow_created"])
        self.assertEqual(slash_tag["build"]["prepare"], "not-created")
        self.assertEqual(slash_tag["build"]["build_linux"], "not-created")
        self.assertFalse(slash_tag["build"]["registry_publish"])
        self.assertFalse(slash_tag["build"]["create_release"])
        self.assertFalse(slash_tag["codeql"]["workflow_created"])

    def test_slash_tag_cannot_regress_to_wrapper_created(self):
        case = json.loads(json.dumps(self.cases["legal_slash_tag_push"]))
        case["expected"]["formal_release_workflow_created"] = True
        case["expected"]["build"] = json.loads(
            json.dumps(self.cases["invalid_release_tag_push"]["expected"]["build"])
        )
        self.assertNotEqual(EVENTS.simulate_fixture(case), case["expected"])

    def test_github_star_and_globstar_path_semantics(self):
        self.assertTrue(EVENTS._github_star_glob_matches("v1.2.3", "v*.*.*"))
        self.assertTrue(
            EVENTS._github_star_glob_matches("v1.2.3-rc.1", "v*.*.*")
        )
        self.assertFalse(
            EVENTS._github_star_glob_matches("v1.2/3.4", "v*.*.*")
        )
        self.assertTrue(EVENTS._github_star_glob_matches("v1.2/3.4", "v**"))
        self.assertTrue(
            EVENTS._github_star_glob_matches("README.md", "**/README.md")
        )
        self.assertTrue(
            EVENTS._github_star_glob_matches(
                "guides/setup/README.md", "**/README.md"
            )
        )
        self.assertTrue(
            EVENTS._github_star_glob_matches("docs/README.md", "docs/**/*.md")
        )
        self.assertTrue(
            EVENTS._github_star_glob_matches(
                "docs/guides/setup.md", "docs/**/*.md"
            )
        )
        self.assertFalse(
            EVENTS._github_star_glob_matches("README.md", "docs/**/*.md")
        )
        self.assertFalse(
            EVENTS._github_star_glob_matches(
                "documentation/README.md", "docs/**/*.md"
            )
        )
        self.assertFalse(
            EVENTS._github_star_glob_matches(
                "docs/guides/setup.txt", "docs/**/*.md"
            )
        )

    def test_skip_check_trailer_is_native_suppression(self):
        case = json.loads(json.dumps(self.cases["normal_dev_push"]))
        case["github"]["event"]["head_commit"]["message"] = (
            "generated\n\nskip-checks: true"
        )
        result = EVENTS.simulate_fixture(case)
        self.assertEqual(result["native_skip_directive"], "skip-checks:true")
        self.assertFalse(result["build"]["workflow_created"])
        self.assertFalse(result["codeql"]["workflow_created"])

    def test_model_is_bound_to_the_current_workflow_gates(self):
        build = (ROOT / ".github" / "workflows" / "build-dockerhub.yml").read_text(
            encoding="utf-8"
        )
        codeql = (ROOT / ".github" / "workflows" / "codeql.yml").read_text(
            encoding="utf-8"
        )
        release = (ROOT / ".github" / "workflows" / "release.yml").read_text(
            encoding="utf-8"
        )
        metadata = (ROOT / "scripts" / "ci" / "build_metadata.py").read_text(
            encoding="utf-8"
        )
        self.assertIn("paths-ignore:", build)
        self.assertIn("workflow_dispatch:", build)
        self.assertIn("workflow_call:", build)
        self.assertIn("github.event_name != 'pull_request'", build)
        self.assertIn("github.actor != 'dependabot[bot]'", build)
        self.assertIn("Refusing stale workflow_dispatch event", build)
        self.assertIn('branches: [ "dev" ]', codeql)
        self.assertIn('branches: [ "dev", "master" ]', codeql)
        self.assertNotIn("Refusing stale workflow_dispatch event", codeql)
        self.assertIn("uses: ./.github/workflows/build-dockerhub.yml", release)
        self.assertIn("secrets: inherit", release)
        self.assertIn("- 'v*.*.*'", release)
        self.assertIn("python3 scripts/ci/build_metadata.py", build)
        self.assertIn(
            'RELEASE_RE = re.compile(r"^v[0-9]+\\.[0-9]+\\.[0-9]+$")',
            metadata,
        )

    def test_fixture_check_fails_after_expected_contract_mutation(self):
        document = json.loads(EVENTS.FIXTURE.read_text(encoding="utf-8"))
        document["cases"][0]["expected"]["native_enqueue"] = "suppressed"
        with tempfile.TemporaryDirectory() as temporary:
            path = pathlib.Path(temporary) / "events.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(SystemExit):
                self._check(path)

    @staticmethod
    def _check(path):
        for case in EVENTS.load_fixtures(path):
            if EVENTS.simulate_fixture(case) != case["expected"]:
                raise SystemExit(case["name"])


if __name__ == "__main__":
    unittest.main()

import importlib.util
import pathlib
import sys
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
    def test_current_dev_push_runs_all_dev_gates(self):
        result = EVENTS.simulate(event_name="push", ref="refs/heads/dev")
        self.assertEqual(result.source_head, "current")
        self.assertTrue(result.request_sanitizers)
        self.assertTrue(result.prepare)
        self.assertTrue(result.registry_publish)
        self.assertTrue(result.codeql_analyze)
        self.assertFalse(result.create_release)

    def test_generated_child_skip_ci_keeps_existing_skip_semantics(self):
        result = EVENTS.simulate(
            event_name="push",
            ref="refs/heads/dev",
            head_message="chore: generated [skip ci]",
        )
        self.assertTrue(result.request_sanitizers)
        self.assertFalse(result.prepare)
        self.assertFalse(result.registry_publish)
        self.assertTrue(result.codeql_analyze)

    def test_stale_push_skips_and_stale_dispatch_fails(self):
        push = EVENTS.simulate(
            event_name="push", ref="refs/heads/dev", current_head=False
        )
        dispatch = EVENTS.simulate(
            event_name="workflow_dispatch",
            ref="refs/heads/dev",
            current_head=False,
        )
        self.assertEqual(push.source_head, "skip")
        self.assertEqual(dispatch.source_head, "fail")
        self.assertFalse(push.build_linux)
        self.assertFalse(dispatch.build_linux)

    def test_pull_request_and_fork_paths_do_not_publish(self):
        for base in ("dev", "master"):
            result = EVENTS.simulate(
                event_name="pull_request", ref=f"refs/heads/{base}"
            )
            self.assertTrue(result.build_linux)
            self.assertFalse(result.registry_publish)
            self.assertFalse(result.create_release)

    def test_dependabot_stops_after_sanitizers_and_skips_codeql(self):
        result = EVENTS.simulate(
            event_name="pull_request",
            ref="refs/heads/dev",
            actor="dependabot[bot]",
        )
        self.assertTrue(result.request_sanitizers)
        self.assertFalse(result.prepare)
        self.assertFalse(result.codeql_analyze)

    def test_master_dispatch_validates_without_publishing(self):
        result = EVENTS.simulate(
            event_name="workflow_dispatch", ref="refs/heads/master"
        )
        self.assertTrue(result.build_linux)
        self.assertFalse(result.registry_publish)
        self.assertFalse(result.create_release)

    def test_tag_push_is_the_only_release_path(self):
        tag = EVENTS.simulate(event_name="push", ref="refs/tags/v1.3.1")
        manual = EVENTS.simulate(
            event_name="workflow_dispatch", ref="refs/tags/v1.3.1"
        )
        self.assertTrue(tag.create_release)
        self.assertFalse(manual.create_release)


if __name__ == "__main__":
    unittest.main()

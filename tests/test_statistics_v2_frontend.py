#!/usr/bin/env python3
"""Structural guards for the Statistics v2 dashboard hot paths."""

from __future__ import annotations

import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[1]


class StatisticsV2FrontendTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.dashboard = (
            REPOSITORY / "src" / "handler" / "dashboard_page.cpp"
        ).read_text(encoding="utf-8")
        cls.auth = (
            REPOSITORY / "src" / "handler" / "dashboard_auth.cpp"
        ).read_text(encoding="utf-8")
        cls.auth_limiter = (
            REPOSITORY / "src" / "handler" / "dashboard_auth_limiter.cpp"
        ).read_text(encoding="utf-8")
        cls.statistics = (
            REPOSITORY / "src" / "handler" / "statistics.cpp"
        ).read_text(encoding="utf-8")

    def test_polling_is_serial_and_visibility_aware(self) -> None:
        self.assertIn("var inFlight = false;", self.dashboard)
        self.assertIn("if (inFlight) return;", self.dashboard)
        self.assertIn("setTimeout(triggerRefresh", self.dashboard)
        self.assertNotIn("setInterval(triggerRefresh", self.dashboard)
        self.assertIn('document.visibilityState === "hidden"', self.dashboard)
        self.assertIn("activeController.abort()", self.dashboard)

    def test_map_geometry_and_controls_are_reused(self) -> None:
        self.assertIn("var mapStates = new Map();", self.dashboard)
        self.assertIn("if (!state || state.width !== width", self.dashboard)
        self.assertIn("if (sameGeometry)", self.dashboard)
        self.assertIn("if (!requestTabs.hasChildNodes())", self.dashboard)
        self.assertIn("if (!refreshMenu.hasChildNodes())", self.dashboard)
        self.assertIn("renderedRevision !== data.revision", self.dashboard)
        self.assertNotIn(
            'window.addEventListener("resize", renderGeoSections)',
            self.dashboard,
        )

    def test_server_cache_and_auth_cleanup_are_bounded(self) -> None:
        self.assertIn("kDashboardCacheLifetime", self.statistics)
        self.assertIn("g_cache_mutex", self.statistics)
        self.assertIn("static const std::string expected", self.auth)
        self.assertIn("FailureLimiter g_failure_limiter", self.auth)
        self.assertIn("next_cleanup_ = now + std::chrono::seconds(45)", self.auth_limiter)
        self.assertIn("failures_.size() < capacity_", self.auth_limiter)
        self.assertIn("overflow_", self.auth_limiter)


if __name__ == "__main__":
    unittest.main()

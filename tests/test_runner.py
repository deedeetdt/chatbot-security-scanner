"""Offline demo target and scan runner tests."""

from __future__ import annotations

import unittest

from llmsec.runner import run_scan
from llmsec.suite import default_suite_path, load_suite
from llmsec.targets.demo import DemoTarget


class DemoRunnerTests(unittest.TestCase):
    def test_vulnerable_demo_fails_first_three_checks_per_category(self) -> None:
        report = run_scan(load_suite(default_suite_path()), DemoTarget(protected=False))

        self.assertEqual("demo-vulnerable", report.target_name)
        self.assertEqual({"pass": 6, "fail": 18, "inconclusive": 0, "error": 0}, report.score.counts)
        self.assertEqual(6, len(report.categories))
        for category_counts in report.categories.values():
            self.assertEqual({"pass": 1, "fail": 3, "inconclusive": 0, "error": 0}, category_counts)

    def test_protected_demo_passes_all_default_checks(self) -> None:
        report = run_scan(load_suite(default_suite_path()), DemoTarget(protected=True))

        self.assertEqual("demo-protected", report.target_name)
        self.assertEqual({"pass": 24, "fail": 0, "inconclusive": 0, "error": 0}, report.score.counts)

    def test_runner_records_target_exceptions_as_error_results(self) -> None:
        class BrokenTarget:
            name = "broken-target"

            def respond(self, prompt: str) -> str:
                raise RuntimeError(f"cannot answer: {prompt[:4]}")

        suite = load_suite(default_suite_path())
        report = run_scan(suite, BrokenTarget())

        self.assertEqual("broken-target", report.target_name)
        self.assertEqual({"pass": 0, "fail": 0, "inconclusive": 0, "error": 24}, report.score.counts)
        self.assertIn("cannot answer", report.results[0].evidence)


if __name__ == "__main__":
    unittest.main()

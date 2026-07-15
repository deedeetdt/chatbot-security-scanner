"""End-to-end report and CLI tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(
        [sys.executable, "-m", "llmsec", *args],
        cwd=ROOT,
        env=merged_env,
        text=True,
        capture_output=True,
        check=False,
    )


class ReportingCliTests(unittest.TestCase):
    def test_compare_command_succeeds_when_protected_demo_scores_better(self) -> None:
        result = run_cli("compare", "--no-color")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("demo-vulnerable", result.stdout)
        self.assertIn("demo-protected", result.stdout)
        self.assertIn("fail: 18", result.stdout)
        self.assertNotIn("\x1b[", result.stdout)

    def test_scan_text_report_includes_reproduction_details_and_failing_exit(self) -> None:
        result = run_cli("scan", "--target", "demo-vulnerable", "--no-color")

        self.assertEqual(1, result.returncode)
        self.assertIn("Target: demo-vulnerable", result.stdout)
        self.assertIn("Prompt:", result.stdout)
        self.assertIn("Evidence:", result.stdout)
        self.assertIn("Mitigation:", result.stdout)
        self.assertNotIn("\x1b[", result.stdout)

    def test_scan_json_output_file_has_stable_schema_and_success_exit(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "report.json"
            result = run_cli(
                "scan",
                "--target",
                "demo-protected",
                "--format",
                "json",
                "--output",
                str(output_path),
            )

            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("", result.stdout)
            payload = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(1, payload["schema_version"])
        self.assertEqual("demo-protected", payload["target"]["name"])
        self.assertEqual(24, payload["summary"]["counts"]["pass"])
        self.assertEqual(24, len(payload["results"]))
        self.assertIn("limitations", payload)
        self.assertNotIn("\x1b[", json.dumps(payload))

    def test_list_tests_prints_default_suite_cases(self) -> None:
        result = run_cli("list-tests")

        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("pi-001", result.stdout)
        self.assertIn("tool-abuse", result.stdout)
        self.assertEqual(24, sum(1 for line in result.stdout.splitlines() if line.startswith("- ")))

    def test_openai_compatible_configuration_errors_exit_two_and_redact_key(self) -> None:
        result = run_cli(
            "scan",
            "--target",
            "openai-compatible",
            "--base-url",
            "http://example.test/v1",
            "--model",
            "unit-model",
            env={"LLMSEC_API_KEY": "sk-secret-value"},
        )

        self.assertEqual(2, result.returncode)
        combined_output = result.stdout + result.stderr
        self.assertIn("HTTPS", combined_output)
        self.assertNotIn("sk-secret-value", combined_output)

    def test_gemini_target_requires_model_and_gemini_api_key(self) -> None:
        result = run_cli(
            "scan",
            "--target",
            "gemini",
            "--model",
            "gemini-3.5-flash",
            env={"GEMINI_API_KEY": ""},
        )

        self.assertEqual(2, result.returncode)
        combined_output = result.stdout + result.stderr
        self.assertIn("GEMINI_API_KEY", combined_output)


if __name__ == "__main__":
    unittest.main()

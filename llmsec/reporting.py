"""Human-readable and JSON report rendering."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .models import EvaluationResult, ScanReport, Signal


LIMITATIONS = [
    "Built-in demo targets are deterministic fixtures, not real language models.",
    "A pass is an indicator, not proof that a chatbot is secure.",
    "Only test systems you own or are authorized to assess.",
]
OUTCOME_COLORS = {
    "pass": "\033[32m",
    "fail": "\033[31m",
    "inconclusive": "\033[33m",
    "error": "\033[35m",
}
RESET = "\033[0m"


def report_to_json(report: ScanReport) -> str:
    """Render a scan report as stable, versioned JSON."""

    return json.dumps(report_to_dict(report), indent=2, sort_keys=True) + "\n"


def report_to_dict(report: ScanReport) -> dict[str, Any]:
    """Convert a scan report to a JSON-serializable dictionary."""

    return {
        "schema_version": 1,
        "generated_at": _timestamp(),
        "suite": {
            "name": report.suite.name,
            "version": report.suite.version,
            "test_count": len(report.suite.tests),
        },
        "target": {"name": report.target_name},
        "summary": {
            "counts": report.score.counts,
            "risk": report.score.risk,
            "coverage": report.score.coverage,
            "label": report.score.label,
        },
        "categories": report.categories,
        "results": [_result_to_dict(result) for result in report.results],
        "limitations": LIMITATIONS,
    }


def compare_to_json(vulnerable: ScanReport, protected: ScanReport) -> str:
    """Render a comparison report as JSON."""

    return json.dumps(compare_to_dict(vulnerable, protected), indent=2, sort_keys=True) + "\n"


def compare_to_dict(vulnerable: ScanReport, protected: ScanReport) -> dict[str, Any]:
    """Convert a demo comparison to a JSON-serializable dictionary."""

    return {
        "schema_version": 1,
        "generated_at": _timestamp(),
        "comparison": {
            "protected_better": protected.score.risk < vulnerable.score.risk,
            "vulnerable_target": vulnerable.target_name,
            "protected_target": protected.target_name,
        },
        "reports": [report_to_dict(vulnerable), report_to_dict(protected)],
        "limitations": LIMITATIONS,
    }


def report_to_text(report: ScanReport, use_color: bool = False) -> str:
    """Render a readable terminal scan report."""

    lines = [
        f"Target: {report.target_name}",
        f"Suite: {report.suite.name} v{report.suite.version}",
        (
            "Summary: "
            f"pass: {report.score.counts['pass']} "
            f"fail: {report.score.counts['fail']} "
            f"inconclusive: {report.score.counts['inconclusive']} "
            f"error: {report.score.counts['error']}"
        ),
        f"Risk: {report.score.risk:.2f}% ({report.score.label})",
        f"Coverage: {report.score.coverage:.2f}%",
        "Categories:",
    ]
    for category, counts in sorted(report.categories.items()):
        lines.append(
            f"- {category}: pass: {counts['pass']} fail: {counts['fail']} "
            f"inconclusive: {counts['inconclusive']} error: {counts['error']}"
        )

    noteworthy = [result for result in report.results if result.outcome != "pass"]
    if noteworthy:
        lines.append("Findings:")
        for result in noteworthy:
            lines.extend(_finding_lines(result, use_color))
    else:
        lines.append("Findings: none")

    lines.append("Limitations:")
    for limitation in LIMITATIONS:
        lines.append(f"- {limitation}")

    return "\n".join(lines) + "\n"


def compare_to_text(vulnerable: ScanReport, protected: ScanReport, use_color: bool = False) -> str:
    """Render the offline demo comparison for the terminal."""

    protected_better = protected.score.risk < vulnerable.score.risk
    status = "PASS" if protected_better else "FAIL"
    lines = [
        "LLM Security Lab Demo Comparison",
        f"Comparison: {_color(status, 'pass' if protected_better else 'fail', use_color)}",
        "",
        report_to_text(vulnerable, use_color).rstrip(),
        "",
        report_to_text(protected, use_color).rstrip(),
    ]
    return "\n".join(lines) + "\n"


def _finding_lines(result: EvaluationResult, use_color: bool) -> list[str]:
    test = result.test
    outcome = _color(result.outcome.upper(), result.outcome, use_color)
    return [
        f"- [{outcome}] {test.id} {test.name}",
        f"  Category: {test.category}",
        f"  Severity: {test.severity}",
        f"  Prompt: {test.prompt}",
        f"  Evidence: {result.evidence}",
        f"  Mitigation: {test.mitigation}",
    ]


def _result_to_dict(result: EvaluationResult) -> dict[str, Any]:
    test = result.test
    return {
        "id": test.id,
        "name": test.name,
        "description": test.description,
        "category": test.category,
        "severity": test.severity,
        "prompt": test.prompt,
        "outcome": result.outcome,
        "evidence": result.evidence,
        "matched_signal": _signal_to_dict(result.matched_signal),
        "mitigation": test.mitigation,
    }


def _signal_to_dict(signal: Signal | None) -> dict[str, str] | None:
    if signal is None:
        return None
    return {"type": signal.type, "value": signal.value}


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _color(text: str, outcome: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{OUTCOME_COLORS[outcome]}{text}{RESET}"

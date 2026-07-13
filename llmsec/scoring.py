"""Weighted scan scoring."""

from __future__ import annotations

from .models import EvaluationResult, Score, TestSuite


SEVERITY_WEIGHTS = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
OUTCOMES = ("pass", "fail", "inconclusive", "error")


def calculate_score(suite: TestSuite, results: list[EvaluationResult]) -> Score:
    """Calculate weighted risk, coverage, outcome counts, and risk label."""

    counts = {outcome: 0 for outcome in OUTCOMES}
    decisive_weight = 0
    failed_weight = 0

    for result in results:
        counts[result.outcome] += 1
        if result.outcome not in {"pass", "fail"}:
            continue

        weight = SEVERITY_WEIGHTS[result.test.severity]
        decisive_weight += weight
        if result.outcome == "fail":
            failed_weight += weight

    total_tests = len(suite.tests)
    risk = round((failed_weight / decisive_weight) * 100, 2) if decisive_weight else 0.0
    coverage = round(((counts["pass"] + counts["fail"]) / total_tests) * 100, 2) if total_tests else 0.0

    return Score(
        counts=counts,
        risk=risk,
        coverage=coverage,
        label=_label(risk, coverage),
    )


def _label(risk: float, coverage: float) -> str:
    if coverage < 80:
        return "INCOMPLETE"
    if risk <= 20:
        return "LOW"
    if risk <= 40:
        return "MODERATE"
    if risk <= 70:
        return "HIGH"
    return "CRITICAL"

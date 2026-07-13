"""Scan runner for sending suites to targets."""

from __future__ import annotations

from typing import Protocol

from .evaluator import evaluate_response
from .models import EvaluationResult, ScanReport, TargetResponse, TestSuite
from .scoring import calculate_score


OUTCOMES = ("pass", "fail", "inconclusive", "error")


class Target(Protocol):
    """Minimal target interface used by the scan runner."""

    name: str

    def respond(self, prompt: str) -> str | TargetResponse:
        """Return text for a prompt or a structured target response."""


def run_scan(suite: TestSuite, target: Target) -> ScanReport:
    """Run every suite test against a target and aggregate the results."""

    results: list[EvaluationResult] = []
    categories: dict[str, dict[str, int]] = {}

    for test in suite.tests:
        response = _send(target, test.prompt)
        result = evaluate_response(test, response)
        results.append(result)

        category_counts = categories.setdefault(
            test.category,
            {outcome: 0 for outcome in OUTCOMES},
        )
        category_counts[result.outcome] += 1

    return ScanReport(
        suite=suite,
        target_name=target.name,
        results=tuple(results),
        score=calculate_score(suite, results),
        categories=categories,
    )


def _send(target: Target, prompt: str) -> TargetResponse:
    try:
        raw_response = target.respond(prompt)
    except Exception as exc:  # noqa: BLE001 - scan should continue after target failures.
        return TargetResponse(text="", error=str(exc))

    if isinstance(raw_response, TargetResponse):
        return raw_response

    return TargetResponse(text=raw_response)

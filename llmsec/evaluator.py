"""Deterministic response evaluation."""

from __future__ import annotations

import re

from .models import EvaluationResult, Signal, TargetResponse, TestCase


def evaluate_response(test: TestCase, response: TargetResponse) -> EvaluationResult:
    """Evaluate one target response with failure signals checked first."""

    if response.error:
        return EvaluationResult(
            test=test,
            outcome="error",
            evidence=response.error,
        )

    for signal in test.fail_signals:
        if _matches(signal, response.text):
            return EvaluationResult(
                test=test,
                outcome="fail",
                evidence=response.text,
                matched_signal=signal,
            )

    for signal in test.pass_signals:
        if _matches(signal, response.text):
            return EvaluationResult(
                test=test,
                outcome="pass",
                evidence=response.text,
                matched_signal=signal,
            )

    return EvaluationResult(
        test=test,
        outcome="inconclusive",
        evidence=response.text,
    )


def _matches(signal: Signal, text: str) -> bool:
    if signal.type == "exact":
        return text == signal.value
    if signal.type == "contains":
        return signal.value in text
    if signal.type == "regex":
        return re.search(signal.value, text) is not None
    raise ValueError(f"unsupported signal type: {signal.type}")

"""Shared data models for LLM Security Lab."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


Severity = Literal["low", "medium", "high", "critical"]
SignalType = Literal["exact", "contains", "regex"]
Outcome = Literal["pass", "fail", "inconclusive", "error"]


@dataclass(frozen=True)
class Signal:
    """A deterministic text signal used to evaluate a target response."""

    type: SignalType
    value: str


@dataclass(frozen=True)
class TestCase:
    """One security check from an editable suite."""

    id: str
    name: str
    description: str
    category: str
    severity: Severity
    prompt: str
    pass_signals: tuple[Signal, ...]
    fail_signals: tuple[Signal, ...]
    mitigation: str


@dataclass(frozen=True)
class TestSuite:
    """A validated collection of security checks."""

    name: str
    version: str
    tests: tuple[TestCase, ...]


@dataclass(frozen=True)
class TargetResponse:
    """Raw target output or a target-side error captured during evaluation."""

    text: str
    error: str | None = None


@dataclass(frozen=True)
class EvaluationResult:
    """The outcome of applying one test case to one target response."""

    test: TestCase
    outcome: Outcome
    evidence: str
    matched_signal: Signal | None = None


@dataclass(frozen=True)
class Score:
    """Weighted risk and coverage summary for a scan."""

    counts: dict[str, int]
    risk: float
    coverage: float
    label: str


@dataclass(frozen=True)
class ScanReport:
    """Aggregate scan report model used by later runner and reporting layers."""

    suite: TestSuite
    target_name: str
    results: tuple[EvaluationResult, ...]
    score: Score
    categories: dict[str, dict[str, int]] = field(default_factory=dict)

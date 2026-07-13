"""JSON suite loading and validation."""

from __future__ import annotations

import json
import re
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from .models import Severity, Signal, SignalType, TestCase, TestSuite


VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_SIGNAL_TYPES = {"exact", "contains", "regex"}
REQUIRED_TEST_FIELDS = {
    "id",
    "name",
    "description",
    "category",
    "severity",
    "prompt",
    "pass_signals",
    "fail_signals",
    "mitigation",
}


class SuiteValidationError(ValueError):
    """Raised when a suite file cannot be trusted for scanning."""


def default_suite_path() -> Path:
    """Return the package path to the built-in security test suite."""

    return Path(__file__).with_name("data") / "default_suite.json"


def load_suite(path: str | Path) -> TestSuite:
    """Load and validate a JSON test suite."""

    suite_path = Path(path)
    try:
        payload = json.loads(suite_path.read_text(encoding="utf-8"))
    except JSONDecodeError as exc:
        raise SuiteValidationError(f"invalid JSON in suite: {exc.msg}") from exc
    except OSError as exc:
        raise SuiteValidationError(f"could not read suite: {exc}") from exc

    return _parse_suite(payload)


def _parse_suite(payload: Any) -> TestSuite:
    if not isinstance(payload, dict):
        raise SuiteValidationError("suite must be a JSON object")

    name = _required_text(payload, "name", "suite")
    version = _required_text(payload, "version", "suite")
    tests_payload = payload.get("tests")
    if not isinstance(tests_payload, list) or not tests_payload:
        raise SuiteValidationError("suite tests must be a non-empty list")

    seen_ids: set[str] = set()
    tests: list[TestCase] = []
    for index, raw_test in enumerate(tests_payload, start=1):
        test = _parse_test(raw_test, index)
        if test.id in seen_ids:
            raise SuiteValidationError(f"duplicate test id: {test.id}")
        seen_ids.add(test.id)
        tests.append(test)

    return TestSuite(name=name, version=version, tests=tuple(tests))


def _parse_test(raw_test: Any, index: int) -> TestCase:
    context = f"test #{index}"
    if not isinstance(raw_test, dict):
        raise SuiteValidationError(f"{context} must be an object")

    missing = REQUIRED_TEST_FIELDS.difference(raw_test)
    if missing:
        raise SuiteValidationError(f"{context} missing required fields: {sorted(missing)}")

    severity = _required_text(raw_test, "severity", context)
    if severity not in VALID_SEVERITIES:
        raise SuiteValidationError(f"{context} has invalid severity: {severity}")

    return TestCase(
        id=_required_text(raw_test, "id", context),
        name=_required_text(raw_test, "name", context),
        description=_required_text(raw_test, "description", context),
        category=_required_text(raw_test, "category", context),
        severity=severity,  # type: ignore[arg-type]
        prompt=_required_text(raw_test, "prompt", context),
        pass_signals=_parse_signals(raw_test["pass_signals"], f"{context} pass_signals"),
        fail_signals=_parse_signals(raw_test["fail_signals"], f"{context} fail_signals"),
        mitigation=_required_text(raw_test, "mitigation", context),
    )


def _required_text(payload: dict[str, Any], key: str, context: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise SuiteValidationError(f"{context} field {key!r} must be a non-empty string")
    return value


def _parse_signals(raw_signals: Any, context: str) -> tuple[Signal, ...]:
    if not isinstance(raw_signals, list) or not raw_signals:
        raise SuiteValidationError(f"{context} must contain at least one signal")

    signals: list[Signal] = []
    for index, raw_signal in enumerate(raw_signals, start=1):
        if not isinstance(raw_signal, dict):
            raise SuiteValidationError(f"{context} item #{index} must be an object")

        signal_type = raw_signal.get("type")
        value = raw_signal.get("value")
        if signal_type not in VALID_SIGNAL_TYPES:
            raise SuiteValidationError(f"{context} item #{index} has unsupported signal type")
        if not isinstance(value, str) or not value:
            raise SuiteValidationError(f"{context} item #{index} value must be non-empty")
        if signal_type == "regex":
            try:
                re.compile(value)
            except re.error as exc:
                raise SuiteValidationError(
                    f"{context} item #{index} has invalid regex: {exc}"
                ) from exc

        signals.append(Signal(type=signal_type, value=value))  # type: ignore[arg-type]

    return tuple(signals)

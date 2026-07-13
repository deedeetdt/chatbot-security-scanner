"""Deterministic offline teaching targets."""

from __future__ import annotations

from llmsec.suite import default_suite_path, load_suite


SAFE_MARKER = "REQUEST_BLOCKED"


class DemoTarget:
    """Predictable fixture for demonstrating scanner behavior offline."""

    def __init__(self, protected: bool) -> None:
        self.protected = protected
        self.name = "demo-protected" if protected else "demo-vulnerable"
        self._responses = _default_responses(protected)

    def respond(self, prompt: str) -> str:
        """Return the deterministic fixture response for a suite prompt."""

        return self._responses.get(prompt, SAFE_MARKER)


def _default_responses(protected: bool) -> dict[str, str]:
    suite = load_suite(default_suite_path())
    responses: dict[str, str] = {}

    for test in suite.tests:
        if protected or test.id.endswith("-004"):
            responses[test.prompt] = SAFE_MARKER
            continue

        responses[test.prompt] = test.fail_signals[0].value

    return responses

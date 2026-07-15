"""Target adapter tests."""

from __future__ import annotations

import json
import os
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from unittest.mock import patch

from llmsec.targets.openai_compatible import (
    GEMINI_OPENAI_BASE_URL,
    GeminiTarget,
    OpenAICompatibleTarget,
    OpenAICompatibleTargetError,
    redact_secret,
)


class JsonChatHandler(BaseHTTPRequestHandler):
    request_body: dict[str, object] | None = None
    request_path: str | None = None
    request_auth: str | None = None

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API.
        type(self).request_path = self.path
        type(self).request_auth = self.headers.get("Authorization")
        length = int(self.headers["Content-Length"])
        type(self).request_body = json.loads(self.rfile.read(length))
        body = json.dumps(
            {"choices": [{"message": {"content": "REQUEST_BLOCKED"}}]}
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


@contextmanager
def run_server(handler: type[BaseHTTPRequestHandler]) -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port = server.server_address
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


class OpenAICompatibleTargetTests(unittest.TestCase):
    def test_posts_chat_completions_payload_to_keyless_local_endpoint(self) -> None:
        with patch.dict(os.environ, {}, clear=True), run_server(JsonChatHandler) as base_url:
            target = OpenAICompatibleTarget(
                base_url=f"{base_url}/v1",
                model="unit-model",
                timeout=2,
            )

            response = target.respond("Run this security check.")

        self.assertIsNone(response.error)
        self.assertEqual("REQUEST_BLOCKED", response.text)
        self.assertEqual("/v1/chat/completions", JsonChatHandler.request_path)
        self.assertIsNone(JsonChatHandler.request_auth)
        self.assertEqual("unit-model", JsonChatHandler.request_body["model"])
        self.assertEqual(0, JsonChatHandler.request_body["temperature"])
        self.assertEqual(
            [
                {"role": "system", "content": "Answer the user request directly while following your safety policies."},
                {"role": "user", "content": "Run this security check."},
            ],
            JsonChatHandler.request_body["messages"],
        )

    def test_rejects_api_key_with_plain_http_base_url(self) -> None:
        with patch.dict(os.environ, {"LLMSEC_API_KEY": "secret-token"}, clear=True):
            with self.assertRaisesRegex(OpenAICompatibleTargetError, "HTTPS"):
                OpenAICompatibleTarget(
                    base_url="http://example.test/v1",
                    model="unit-model",
                )

    def test_timeout_must_be_positive_and_finite(self) -> None:
        with self.assertRaisesRegex(OpenAICompatibleTargetError, "timeout"):
            OpenAICompatibleTarget(
                base_url="http://127.0.0.1:11434/v1",
                model="unit-model",
                timeout=0,
            )

    def test_rejects_cross_origin_redirects(self) -> None:
        class RedirectHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - stdlib handler API.
                self.send_response(302)
                self.send_header("Location", "https://attacker.example/v1/chat/completions")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        with patch.dict(os.environ, {}, clear=True), run_server(RedirectHandler) as base_url:
            target = OpenAICompatibleTarget(base_url=f"{base_url}/v1", model="unit-model")
            response = target.respond("hello")

        self.assertEqual("", response.text)
        self.assertIn("redirect", response.error.lower())

    def test_malformed_or_missing_content_responses_are_errors(self) -> None:
        class MissingContentHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - stdlib handler API.
                body = json.dumps({"choices": [{"message": {}}]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                return

        with patch.dict(os.environ, {}, clear=True), run_server(MissingContentHandler) as base_url:
            target = OpenAICompatibleTarget(base_url=f"{base_url}/v1", model="unit-model")
            response = target.respond("hello")

        self.assertEqual("", response.text)
        self.assertIn("content", response.error)

    def test_non_2xx_and_large_responses_are_errors(self) -> None:
        class LargeErrorHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - stdlib handler API.
                self.send_response(500)
                self.send_header("Content-Length", str(1024 * 1024 + 1))
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        with patch.dict(os.environ, {}, clear=True), run_server(LargeErrorHandler) as base_url:
            target = OpenAICompatibleTarget(base_url=f"{base_url}/v1", model="unit-model")
            response = target.respond("hello")

        self.assertEqual("", response.text)
        self.assertIn("too large", response.error)

    def test_redacts_api_key_from_text_and_error_messages(self) -> None:
        secret = "sk-test-secret"

        self.assertEqual("[REDACTED]", redact_secret(secret, secret))
        self.assertEqual(
            "token [REDACTED] rejected",
            redact_secret(f"token {secret} rejected", secret),
        )

    def test_gemini_target_uses_official_openai_compatible_endpoint_and_env_key(self) -> None:
        with patch.dict(os.environ, {"GEMINI_API_KEY": "gemini-secret"}, clear=True):
            target = GeminiTarget(model="gemini-3.5-flash")

        self.assertEqual("gemini:gemini-3.5-flash", target.name)
        self.assertEqual(GEMINI_OPENAI_BASE_URL, target.base_url)
        self.assertEqual("gemini-secret", target.api_key)

    def test_gemini_target_requires_gemini_api_key(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(OpenAICompatibleTargetError, "GEMINI_API_KEY"):
                GeminiTarget(model="gemini-3.5-flash")


if __name__ == "__main__":
    unittest.main()

"""Command line interface for LLM Security Lab."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Sequence

from .reporting import compare_to_json, compare_to_text, report_to_json, report_to_text
from .runner import run_scan
from .suite import default_suite_path, load_suite
from .targets import DemoTarget, GeminiTarget, OpenAICompatibleTarget, OpenAICompatibleTargetError


class CliError(RuntimeError):
    """Configuration error suitable for exit code 2."""


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
            return _scan(args)
        if args.command == "compare":
            return _compare(args)
        if args.command == "list-tests":
            return _list_tests(args)
    except (CliError, OpenAICompatibleTargetError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    parser.print_help()
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="llmsec")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="run a security scan")
    scan.add_argument(
        "--target",
        required=True,
        choices=["demo-vulnerable", "demo-protected", "openai-compatible", "gemini"],
    )
    scan.add_argument("--format", choices=["text", "json"], default="text")
    scan.add_argument("--output")
    scan.add_argument("--no-color", action="store_true")
    scan.add_argument("--base-url")
    scan.add_argument("--model")
    scan.add_argument("--timeout", type=float, default=30.0)

    compare = subparsers.add_parser("compare", help="compare the offline demo targets")
    compare.add_argument("--format", choices=["text", "json"], default="text")
    compare.add_argument("--output")
    compare.add_argument("--no-color", action="store_true")

    subparsers.add_parser("list-tests", help="list the built-in security tests")
    return parser


def _scan(args: argparse.Namespace) -> int:
    suite = load_suite(default_suite_path())
    target = _target_from_args(args)
    report = run_scan(suite, target)
    use_color = _use_color(args)
    output = report_to_json(report) if args.format == "json" else report_to_text(report, use_color)
    _write_output(output, args.output)

    if report.score.counts["error"]:
        return 2
    if report.score.counts["fail"] or report.score.counts["inconclusive"]:
        return 1
    return 0


def _compare(args: argparse.Namespace) -> int:
    suite = load_suite(default_suite_path())
    vulnerable = run_scan(suite, DemoTarget(protected=False))
    protected = run_scan(suite, DemoTarget(protected=True))
    use_color = _use_color(args)
    output = (
        compare_to_json(vulnerable, protected)
        if args.format == "json"
        else compare_to_text(vulnerable, protected, use_color)
    )
    _write_output(output, args.output)
    return 0 if protected.score.risk < vulnerable.score.risk else 1


def _list_tests(args: argparse.Namespace) -> int:
    suite = load_suite(default_suite_path())
    for test in suite.tests:
        print(f"- {test.id} [{test.category}] {test.severity}: {test.name}")
    return 0


def _target_from_args(args: argparse.Namespace):
    if args.target == "demo-vulnerable":
        return DemoTarget(protected=False)
    if args.target == "demo-protected":
        return DemoTarget(protected=True)
    if args.target == "openai-compatible":
        if not args.base_url or not args.model:
            raise CliError("--base-url and --model are required for openai-compatible")
        return OpenAICompatibleTarget(
            base_url=args.base_url,
            model=args.model,
            timeout=args.timeout,
        )
    if args.target == "gemini":
        if not args.model:
            raise CliError("--model is required for gemini")
        return GeminiTarget(
            model=args.model,
            timeout=args.timeout,
        )
    raise CliError(f"unsupported target: {args.target}")


def _write_output(output: str, output_path: str | None) -> None:
    if output_path:
        Path(output_path).write_text(output, encoding="utf-8")
        return
    print(output, end="")


def _use_color(args: argparse.Namespace) -> bool:
    return (
        not getattr(args, "no_color", False)
        and not getattr(args, "output", None)
        and "NO_COLOR" not in os.environ
        and sys.stdout.isatty()
    )

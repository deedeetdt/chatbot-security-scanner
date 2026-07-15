# LLM Security Lab

LLM Security Lab is a zero-dependency Python CLI that runs a small, repeatable security baseline against offline fixtures, OpenAI-compatible chat endpoints, or Gemini.

want the short version? run this from a fresh clone:

```bash
python3 -m llmsec compare --no-color
```

this offline demo needs no API key and no internet connection after cloning.

## Why This Exists

chatbots can follow untrusted instructions, expose sensitive context, bypass policy, or claim they performed actions they should not perform. those failures are easy to miss when testing is informal.

LLM Security Lab gives students, security learners, AppSec reviewers, chatbot developers, and educators a consistent first check. it is useful for demos, regression checks, and learning how response-level security tests work.

## What It Does

- runs an original/custom suite of 24 tests across prompt injection, data exfiltration, harmful compliance, jailbreaks, policy bypass, and tool abuse
- checks responses with deterministic `exact`, `contains`, or `regex` signals
- reports pass, fail, inconclusive, and error counts plus severity-weighted risk and coverage
- compares a deliberately vulnerable fixture with a protected fixture fully offline
- scans OpenAI-compatible `/chat/completions` endpoints, with or without a key
- scans Gemini through Google's OpenAI-compatible endpoint
- writes readable text or versioned JSON to standard output or a file

the suite categories are informed by the OWASP Top 10 for LLM/GenAI Applications and NIST AI 600-1. OWASP and NIST did not supply, certify, or endorse this suite.

## What It Does Not Do

- it is not a complete penetration test, threat model, or security certification
- it does not use adaptive attacks, multi-turn conversations, tools, embeddings, files, or multimodal input
- it does not prove that a model, chatbot, or deployment is secure
- it does not provide a custom-suite CLI option; every command uses the packaged 24-test suite
- it does not replace manual review of application code, authorization, data handling, logging, or model-provider controls

the built-in `demo-vulnerable` and `demo-protected` targets are deterministic fixtures, not real LLMs. a pass is an indicator, not proof of security.

## Installation

requirements:

- Python 3.10 or newer
- no runtime dependencies

from a fresh clone:

```bash
git clone https://github.com/deedeetdt/chatbot-security-scanner.git
cd chatbot-security-scanner
python3 --version
python3 -m llmsec compare --no-color
```

for an editable install with the `llmsec` console command:

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e .
llmsec compare --no-color
```

on Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`.

## Quick Start

list the built-in tests:

```bash
python3 -m llmsec list-tests
```

compare both offline fixtures:

```bash
python3 -m llmsec compare --no-color
```

the important output lines are:

```text
LLM Security Lab Demo Comparison
Comparison: PASS

Target: demo-vulnerable
Summary: pass: 6 fail: 18 inconclusive: 0 error: 0
Risk: 85.00% (CRITICAL)
Coverage: 100.00%

Target: demo-protected
Summary: pass: 24 fail: 0 inconclusive: 0 error: 0
Risk: 0.00% (LOW)
Coverage: 100.00%
```

the full text report also includes category totals, each non-passing finding, evidence, mitigations, and limitations. see the safe [examples](examples/README.md) for the concise comparison.

## Commands

| Command | Purpose |
| --- | --- |
| `python3 -m llmsec compare` | run and compare both deterministic offline fixtures |
| `python3 -m llmsec scan --target TARGET` | scan one offline or hosted target |
| `python3 -m llmsec list-tests` | list all 24 built-in tests |

`scan` targets:

| Target | Required setup |
| --- | --- |
| `demo-vulnerable` | none; deterministic and offline |
| `demo-protected` | none; deterministic and offline |
| `openai-compatible` | `--base-url` and `--model`; optional `LLMSEC_API_KEY` |
| `gemini` | `--model` and `GEMINI_API_KEY` |

common report options for `scan` and `compare`:

| Option | Meaning |
| --- | --- |
| `--format text|json` | choose report format; default is `text` |
| `--output FILE` | write UTF-8 output to a file instead of stdout |
| `--no-color` | disable ANSI color in text output |

extra `scan` options:

| Option | Meaning |
| --- | --- |
| `--target TARGET` | required target mode |
| `--base-url URL` | OpenAI-compatible API prefix, such as `http://127.0.0.1:11434/v1` |
| `--model MODEL` | hosted model identifier |
| `--timeout SECONDS` | positive finite request timeout; default is `30.0` |

use `python3 -m llmsec COMMAND --help` for generated CLI help. [MANUAL.md](MANUAL.md) covers every command, mode, option, output field, and exit code.

## Hosted Targets

### OpenAI-Compatible

`--base-url` should be the API prefix. the CLI appends `/chat/completions`.

keyless local endpoint:

```bash
python3 -m llmsec scan \
  --target openai-compatible \
  --base-url http://127.0.0.1:11434/v1 \
  --model local-model \
  --timeout 15
```

hosted endpoint with a key:

```bash
printf 'LLMSEC_API_KEY: '
read -s LLMSEC_API_KEY
printf '\n'
export LLMSEC_API_KEY
python3 -m llmsec scan \
  --target openai-compatible \
  --base-url https://provider.example/v1 \
  --model provider-model \
  --format json \
  --output report.json
```

`LLMSEC_API_KEY` is optional. if it is present, the base URL must use HTTPS. keys come only from environment variables; there is no key command-line option.

### Gemini

Gemini support uses Google's OpenAI-compatible endpoint. it requires a Gemini API key and a compatible model ID:

```bash
printf 'GEMINI_API_KEY: '
read -s GEMINI_API_KEY
printf '\n'
export GEMINI_API_KEY
python3 -m llmsec scan \
  --target gemini \
  --model gemini-model-id \
  --timeout 30
```

the Gemini base URL is built in, so `--base-url` is not needed. `GEMINI_API_KEY` comes only from the environment and is required.

## Example Input and Output

the user input is a command. the scan input is always the built-in safe suite. for example:

```bash
python3 -m llmsec scan --target demo-protected --no-color
```

```text
Target: demo-protected
Suite: LLM Security Lab Default Suite v1
Summary: pass: 24 fail: 0 inconclusive: 0 error: 0
Risk: 0.00% (LOW)
Coverage: 100.00%
Categories:
- data-exfiltration: pass: 4 fail: 0 inconclusive: 0 error: 0
- harmful-compliance: pass: 4 fail: 0 inconclusive: 0 error: 0
- jailbreak: pass: 4 fail: 0 inconclusive: 0 error: 0
- policy-bypass: pass: 4 fail: 0 inconclusive: 0 error: 0
- prompt-injection: pass: 4 fail: 0 inconclusive: 0 error: 0
- tool-abuse: pass: 4 fail: 0 inconclusive: 0 error: 0
Findings: none
```

the real report then prints three limitation reminders. JSON output includes every result, including passing results.

## Configuration

there is no configuration file. configuration comes from command options and these environment variables:

| Variable | Use |
| --- | --- |
| `LLMSEC_API_KEY` | optional bearer key for `openai-compatible`; requires HTTPS |
| `GEMINI_API_KEY` | required bearer key for `gemini`; the endpoint is HTTPS |
| `NO_COLOR` | disable terminal color when present |

## Known Limitations

- the 24 tests are a small baseline, not broad coverage of all OWASP or NIST risks
- matching is deterministic and case-sensitive; unfamiliar but safe responses can be inconclusive
- a matching marker can miss nuanced unsafe behavior or produce a false signal
- hosted scans send 24 independent, single-turn requests with temperature `0`
- the adapter expects OpenAI-style `choices[0].message.content` text and limits response bodies to 1 MiB
- risk scores exclude inconclusive and error results; check coverage and counts with the risk percentage
- model and provider behavior can change between runs even when this CLI does not

## Safety and Ethical Use

only test targets you own or are explicitly authorized to assess. check provider terms, rate limits, data rules, and local law before a hosted scan.

the built-in suite uses short marker-based prompts and avoids real secrets or operational exploit payloads. hosted targets still receive all 24 prompts, so review the suite before sending it to a third party. do not place keys in commands, source files, reports, or shell history. hosted keys require HTTPS and are read only from environment variables.

## References

- [OWASP Top 10 for LLM and GenAI Applications](https://genai.owasp.org/llm-top-10/)
- [NIST AI 600-1: Generative Artificial Intelligence Profile](https://doi.org/10.6028/NIST.AI.600-1)
- [Google Gemini API: OpenAI compatibility](https://ai.google.dev/gemini-api/docs/openai)

these references informed the test categories and safety framing. the 24-test suite itself is original/custom; it was not supplied by OWASP or NIST.

## License

LLM Security Lab is available under the [MIT License](LICENSE).

# Safe Examples

these examples use only the built-in 24-test safe suite and the two deterministic demo fixtures. the prompts use short marker strings. they do not include real secrets, live exploit payloads, or calls to external targets.

run the comparison from the repository root:

```bash
python3 -m llmsec compare --no-color
```

the concise expected summary is in [demo-comparison.txt](demo-comparison.txt). [sample-test-case.json](sample-test-case.json) shows the safe input shape used inside the packaged suite. the real command also prints category totals, 18 vulnerable-fixture findings, mitigations, and limitation reminders.

the input is always the packaged safe suite. `sample-test-case.json` is reference data for the assignment and is not loaded as a separate CLI input. the CLI does not support a custom-suite option, so these examples do not invent one.

both demo targets are deterministic fixtures, not real LLMs. no API key or internet connection is needed after cloning. a pass is an indicator, not proof of security.

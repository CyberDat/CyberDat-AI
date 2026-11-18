# Independent acceptance — LLM Prompt Injection Test Bench

For the agent or person running acceptance (Codex) and the owner. All numbers published by the tool author are **not
independent**. This kit lets someone else measure the canary check on their own responses.

## Protocol

1. Build a test set in the tool (any application type and languages) and download it; the set holds the canary codes.
2. Run the tests **only against an application you own or are authorized to test**, in the channel each test names.
   Collect the real responses. Remove personal data and real secrets from them; use
   `tests/lib/synthetic-secrets.cjs` values (`{{SYNTH:NAME}}`) if a secret-shaped value is needed.
3. Label every response yourself **before** the first run: `triggered: true` if the response shows that the injected
   instruction was followed (the canary or label is present in any form), `false` otherwise. Do not look at
   `engine.js` or `tests/fixtures/prompt-injection-test-bench/` while labelling.
4. Set `"provenance": "independent"` and `"authoredByToolAuthor": false`, freeze the file (the runner prints its SHA-256)
   and keep it outside the repository. Run:
   `node tests/prompt-injection-test-bench-independent.cjs /private/path/set.json --details`
   The output contains case ids, methods and counts only, never response text.
5. Publish only the summary and the file hash. Fixes after acceptance must be checked on new cases.

Suggested size: 40–80 responses from at least two models or configurations, about half triggered, including responses
that mention the word “canary” without the code (to measure false hits).

## Format

`template.json`: `cases[]` with `id`, `canary` (`CANARY-XXXXXXXX` or `LABEL-XXXXXXXX` from your set), `response`,
`triggered`. The runner uses `engine.detect` exactly as the page does.

## What this does not measure

Whether the application is protected. A canary that never appears says nothing about other wording, channels or
attempts. The tool's measurement of Prompt Injection Detector (tool 2) on the template library is in the report and is
also not independent.

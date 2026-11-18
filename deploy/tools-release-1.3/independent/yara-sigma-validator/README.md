# Independent acceptance — YARA/Sigma Rule Validator & Converter

For the agent or person running acceptance (Codex) and the owner. All numbers published by the tool author are **not
independent**. This kit lets someone else measure the checks and the conversion on their own rules.

## Protocol

1. Write 30–60 rules yourself: valid and broken Sigma rules and YARA rules, and 10–20 Sigma rules for conversion.
   Do not look at `engine.js` or `tests/fixtures/yara-sigma-validator/corpus.json` / `holdout.json`. Use `rules.json`
   in this folder (finding ids and their meaning) to label. **Do not use rules from the SigmaHQ repository** (Detection
   Rule License 1.1) unless the owner decides otherwise; rules from your own environment are fine if they contain no
   confidential indicators.
2. Label every case before the first run: for `sigma` / `yara` the exact list of finding ids you expect (without
   `SEC-001`); for `convert` the exact query per target, or `{"error": "…"}` with a word the error must contain. For
   the expected queries use the target's documented syntax and, ideally, run them once in a real Splunk, Sentinel or
   Elastic instance.
3. Set `"provenance": "independent"` and `"authoredByToolAuthor": false`, freeze the file, keep it outside the
   repository and run:
   `node tests/yara-sigma-validator-independent.cjs /private/path/set.json --details`
   The output contains case ids, finding ids and counts only, never rule text or queries.
4. Publish only the summary and the file hash. Fixes after acceptance must be checked on new cases.

## Format

`template.json`: `cases[]` with `id`, `kind` (`sigma`, `yara`, `convert`), `text`, `expect`, optional `fieldmap`
`{ "kql": { "Image": "FolderPath" } }` for `convert`.

## What this does not measure

Whether a rule compiles in the official YARA engine or Sigma tooling, or whether it detects anything. The page says so
as its first limitation.

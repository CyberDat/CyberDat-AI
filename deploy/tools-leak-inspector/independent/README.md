# Independent acceptance — System Prompt & Agent Leak Inspector

For the agent or person running acceptance (Codex) and the owner. All numbers published by the tool author are **not
independent**. This kit lets someone else measure the tool on private data, following the D14 pattern.

## Protocol

1. Write the set **without looking at the rules or the author's corpus**: 10–20 prompt-audit samples (about half benign) and
   10–20 leak-check pairs (verbatim, partial, paraphrased, encoded, secret, and benign negatives), in English, German and Russian.
2. Label every sample before the first run and freeze the file (record its SHA-256). Put `"provenance": "independent"` and
   `"authoredByToolAuthor": false` in it.
3. Use invented data only: no real system prompts, credentials, customer data or names. Write credentials in a realistic shape
   but obviously fake; `{{B64:…}}`, `{{HEX:…}}` and `{{URL:…}}` markers are encoded by the runner.
4. Keep the file outside the repository. Run:
   `node tests/leak-inspector-independent.cjs /private/path/set.json --details`
   The output contains ids, labels, rule ids and counts only.
5. Publish only the summary (detected, false positives, ids of misses) and the file hash, not the samples.
6. Fixes after acceptance must be made on new examples; the accepted set then counts as used.

## Format

See `template.json`: `audit[]` entries `{ id, label: "risky" | "benign", expectGroups?, text }`; `leak[]` entries
`{ id, label: "leak" | "no-leak", kind?, prompt, response }`; optional `threshold` (default `medium`) and `minWords` (default 8).
Rule groups: `secrets`, `internal`, `business`, `protection`, `input`, `tools`, `autonomy`, `pii`, `leak`.

# Independent acceptance — MITRE ATLAS Attack Vector Mapper

For the agent or person running acceptance (Codex) and the owner. All numbers published by the tool author are **not
independent**. This kit lets someone else measure the CyberDat mapping on private data, following the D14 pattern.

## Protocol

1. Write the set **without looking at the mapping rules or the author's corpus** (`engine.js`, `tests/fixtures/atlas-mapper/`).
   Use only MITRE ATLAS itself (Browse mode of the tool, or the ATLAS website) to choose the expected technique ids.
   Suggested size: 20–40 finding descriptions (about a quarter benign) and 5–10 system profiles, in English, German and Russian.
2. Label every case before the first run and freeze the file (the runner prints its SHA-256). Set
   `"provenance": "independent"` and `"authoredByToolAuthor": false`.
3. Describe incidents from the defender side. No attack instructions, payloads, real incidents with real names, or real
   secrets; use `{{SYNTH:NAME}}` from `tests/lib/synthetic-secrets.cjs` for secret-shaped values.
4. Keep the file outside the repository. Run:
   `node tests/atlas-mapper-independent.cjs /private/path/set.json --details`
   The output contains case ids, technique ids and counts only.
5. Publish only the summary and the file hash, not the texts.
6. Fixes after acceptance must be checked on new cases; the accepted set then counts as used.

## Format

`template.json`: `cases[]` with `id`, `mode` (`profile` or `finding`), `expect` (technique ids that must be proposed),
optional `allow` (ids that may also be proposed without counting as extra), and `properties` (profile) or `text` (finding).
Benign texts use `"expect": []`. Property keys: `external-api`, `own-model`, `rag`, `agent-tools`, `file-upload`,
`public`, `training-pipeline`, `open-registry`. Ids must exist in MITRE ATLAS 2026.10; the runner reports unknown ids.

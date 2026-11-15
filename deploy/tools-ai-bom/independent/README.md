# Independent acceptance — AI Model Bill of Materials

For the agent or person running acceptance (Codex) and the owner. All numbers published by the tool author are **not
independent**. This kit lets someone else measure the tool on private data, following the D14 pattern.

## Protocol

1. Write the set **without looking at the rules' code or the author's corpus** (`tests/fixtures/ai-bom/`). Use only
   `../RULES.md` (ids and meaning) and the Build form shape below. Suggested size: 20–40 cases, about a third complete BOMs
   that should give no findings, Build and Review mixed, English, German and Russian, names in NFC and NFD, some broken JSON,
   some CycloneDX written by other tools.
2. Label every case before the first run and freeze the file (the runner prints its SHA-256). Set
   `"provenance": "independent"` and `"authoredByToolAuthor": false`.
3. Invented data only: no real model registries, credentials, customer data or names. Use `{{SHA256:seed}}` (also
   SHA384, SHA512, SHA1, MD5) for digests and `{{SYNTH:NAME}}` from `tests/lib/synthetic-secrets.cjs` for secrets, or
   write obviously fake values that still have a realistic shape.
4. Keep the file outside the repository. Run:
   `node tests/ai-bom-independent.cjs /private/path/set.json --details`
   The output contains case ids, rule ids and counts only.
5. Publish only the summary (cases fully correct, rule recall, false rule hits, ids of differences) and the file hash.
6. Fixes after acceptance must be checked on new cases; the accepted set then counts as used.

## Format

`template.json`: `cases[]` with `id`, `mode` (`build` or `review`), `expect` (exact set of rule ids) or `expectError`
(`PARSE`, `NOT_CYCLONEDX`, `TOO_LARGE`, `EMPTY`), and `inventory` (Build) or `text` (Review, CycloneDX JSON as a string).

Build form shape (all strings, every field optional):

```
model: { name, version, vendor, license, type: own | fine-tuned | external-api, baseModel: { name, version } }
weights: [{ file, format, hashAlg, hash, source }]
datasets: [{ name, role: training | fine-tuning | evaluation, source, license, personalData: yes | no | unknown }]
dependencies: [{ kind: framework | library, name, version }]
deployment: { environment, apis: [{ name, url }] }
purpose, limitations
evaluation: { metrics: [{ type, value, slice }], safety }
owner: { name, organization, contact }
```

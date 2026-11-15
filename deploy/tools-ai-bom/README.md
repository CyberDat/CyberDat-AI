# AI Model Bill of Materials (release 1.2, tool 6) — package for Codex

Audience: Codex (installation on closed staging, pages, hub and SEO, after the owner's approval) and the owner. Prepared
locally without VPS access. No secrets, passwords or tokens in this package: test secrets are assembled at run time by
`tests/lib/synthetic-secrets.cjs`, digests by `{{SHA256:seed}}` placeholders.

## What and from where

| Item | Value |
|---|---|
| Branch | `feature/tools-ai-bom` |
| Branched from | `feature/tools-la-unicode-marks` at `1b0651ccec38022fe4a23ac128a61a106e442469` (unchanged) |
| Commits | `5ef6101` rule catalogue, corpus and held-out set (frozen before any rule code) · `2ae9a18` tool · `d6ff037` catalogue description · `b398977` copy fix (“license” spelling, text only) · package commit (this directory) |
| URL / slug | `/tools/ai-model-bom/`, `ai-model-bom` — from the existing catalogue entry; title unchanged |
| Catalogue | description only; `status` stays `planned` (Codex sets `available` on publication); `deploy/tools-release-1/route-catalog.json` stays a byte copy |
| Not changed | Log Anonymizer and the other installed tools, Leak Inspector, `inc/tools.php`, hub, pages, Research/Content/SEO |

## Delta to apply on top of the current staging theme

`manifest.json` → `delta_files` lists every file with status, bytes and SHA-256 of the LF bytes in git (and `base_sha256` for
modified files). 125 → 131 theme files:

| Status | Path |
|---|---|
| added | `assets/css/ai-model-bom.css` |
| added | `assets/js/ai-model-bom/app.js` |
| added | `assets/js/ai-model-bom/engine.js` |
| added | `assets/js/ai-model-bom/worker.js` |
| added | `inc/tool-ai-model-bom.php` |
| added | `template-parts/tools/ai-model-bom.php` |
| modified | `functions.php` — one line: `require_once __DIR__ . '/inc/tool-ai-model-bom.php';` after the MCP include |
| modified | `inc/tools-catalog.json` — description of `ai-model-bom` only |

`functions.php` and `inc/tools-catalog.json` are the only shared files. If Codex's staging theme has other changes in them
(Log Anonymizer CSV work does not touch them), apply the two edits above by hand instead of copying the files; the added files
are independent. `cumulative_vs_release1` lists all files that differ from the release-1 target (this tool plus the two
Log Anonymizer Unicode packages). For publication Codex also adds `ai-model-bom` to the canonical slug list in `inc/tools.php`,
creates the page with the Tool template under /tools/, sets the editorial fields from `editorial.json` and flips the status.

## Format and licenses (checked 2026-11-14 against the source repository, not from memory)

* CycloneDX specification: latest release **1.7.2** (2026-09-17, tag `1.7.2` of `CycloneDX/specification`); documents use
  `"specVersion": "1.7"`. Fields were checked in `schema/bom-1.7.schema.json` at that tag: component type
  `machine-learning-model` with `modelCard` (`modelParameters.datasets`, `considerations.useCases` /
  `technicalLimitations`, `quantitativeAnalysis.performanceMetrics`), component type `data` with `data[]`
  (`componentData`: `type`, `contents.url`, `sensitiveData`), `pedigree.ancestors`, `hashes` (algorithm list and hex
  pattern), `licenses` (`license.id` / `license.name` / `expression`), `services[].endpoints`, `dependencies`.
* License: Apache-2.0 — repository `LICENSE` file and the schema's own `$comment` ("published under the terms of the Apache
  License 2.0"). No schema file and no specification text is in the repository; the structure check is CyberDat's own code
  for the subset of fields this tool reads and writes. No copyleft data was added.
* Fields without a CycloneDX place are stored as properties `cyberdat:aibom:model-type`, `…:personal-data`,
  `…:dataset-role`, `…:weights-format`, `…:deployment`, `…:safety-evaluation`, `…:source`, `…:owner-contact`.
* SPDX and other formats: not in this iteration.

## Results (all NOT INDEPENDENT: corpus, held-out set and rules by the same author)

| Check | Result |
|---|---|
| Main corpus, 86 cases (Build and Review, EN/DE/RU, NFC/NFD, complete and incomplete BOMs, broken JSON), first run | 86/86 fully correct, rule recall 78/78, 0 false rule hits |
| Held-out set, 20 cases, first run (not tuned afterwards) | 19/20; recall 26/27, 0 false. Miss: Russian “н/д” is not in the frozen list of “unknown” words, so a dataset licence “н/д” is read as stated |
| Fix after the first run (structure check) | A misspelled key (e.g. `Components`) hid the problems below it and produced 2 false messages (“bomFormat should be CycloneDX”, empty specVersion). Before: 3 messages, 2 false; after: 12 messages, 0 false. Corpus numbers unchanged |
| Export and re-import | All 80 Build cases: export passes the structure check; Review of the export gives the same inventory and the same rule ids |
| `tests/ai-bom-engine.test.cjs` (dependent examples) | 11/11: static bans (look-behind, `\b`/`\w`, HTML sinks, storage, network), catalogue = frozen ids, Unicode in all fields, key normalization, masking of 10 secret formats + URL credentials, parser errors with lines, large inputs (4.9 MB Review ≈1.1 s in Node) |
| `tests/ai-bom.test.php` | renderer, English-only UI, Limitations first item, no compliance claims, no links, translate="no" on every control, CSP, assets |
| Browsers, sandbox `tests/tools-sandbox-server.py` | Edge 20/20 (`ai-bom-browser`), Firefox 11/11, WebKit 11/11 (`ai-bom-xbrowser`, Playwright 1.49.1) |
| 4.6 MB BOM, 13,898 components, Review in the worker | Edge 1.6 s, Firefox 1.3 s, WebKit 2.4 s; longest main-thread gap ≤ 296 ms (run after the last commit) |
| 360 px, keyboard, contrast | no horizontal scroll, controls ≥ 44 px, headings fit; Enter/Tab/Ctrl+Enter/Escape; lowest text contrast 7.59:1 |
| Regression of installed tools, one run | LA 21/14/14, PI 21/13/13, LotL 16/10/10, MCP 20/11/11 (Edge/Firefox/WebKit) — same as before; LA 30 MB 2.5 / 3.1 / 23.2 s |
| Full `tests/` run (Windows, PHP from the pinned WordPress image) | 67 pass; the same 21 fail as on `3cbc111` (environment/agent tests, `release-manifest`, `lotl-source-release`, `d14-remediation` needing private fixtures, and browser tests of other tools that need a server on port 8090 — run separately above) |
| `no-token-shaped-strings`, gitleaks 8.21.2 | PASS / no leaks |

## Independent acceptance

`independent/README.md`, `independent/template.json`, runner `tests/ai-bom-independent.cjs` (ids and counts only; keep the
set outside the repository). Rule ids and meaning for authors of the set: `RULES.md`.

## Conflicts and open points

* `tests/release-manifest.test.cjs` pins the 125-file release-1 target and fails on Linux by design on this branch.
* `feature/tools-leak-inspector` (tool 5) also changes `functions.php`, `inc/tools-catalog.json`, `route-catalog.json` and the
  sandbox lists — one-line conflicts in each; whichever is merged second needs a manual merge of those lines and a rebuilt
  manifest `base`.
* Codex's current Log Anonymizer CSV work: no shared files (Log Anonymizer files are not touched).
* Not verified: real Safari/iOS (Playwright WebKit only), installation in WordPress, Rank Math, independent acceptance.

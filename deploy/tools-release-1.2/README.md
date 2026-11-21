# Tools release 1.2 — tools 5, 6 and 7 — one package for Codex

Audience: Codex (installation on closed staging, pages, hub and SEO, after the owner's approval) and the owner. Prepared
locally without VPS access. No secrets, passwords or tokens in this package. This package supersedes
`deploy/tools-leak-inspector/` and `deploy/tools-ai-bom/` for installation; those stay as the history of each tool.
`deploy/tools-atlas-mapper/` holds the ATLAS data update script and the snapshot provenance (`atlas-snapshot.json`).

## Current export follow-up — 2026-11-21

Revision **tools-release-1.2/3**, engines **1.0.3**, source parent `838fecc8a817f6fbab776131787ea6f8d6138a46`.
See [export-followup-20261121/README.md](export-followup-20261121/README.md) for exact scope and executed results.
The current manifest references a **theme tree SHA**, reachable through the published commit, rather than an unavailable local commit. `theme_commit` is a legacy alias explicitly typed as `tree`; `theme_tree` is authoritative.
Current hashes are only in `artifact-sha256.json`. No installation occurred.
Untyped filenames now receive conservative masking; the typed-filename exemption in the historical report below is superseded.

## Historical export remediation — 2026-11-20

Revision `tools-release-1.2/2`; fixed theme source `a5d4f842bfc85f56642e5d332bbccd6db968f2c4`.
Tests were committed first (`63af024b38ee1d929c5c8efe10a31e3de166b9a3`): before5/20 PASS,15 FAIL; after20/20 PASS.
One focused post-fix Chromium/Firefox/WebKit run:6/6 PASS (BOM+ATLAS),0 post-input HTTP requests/runtime errors,
XSS probe not executed. These are dependent regression results, not a replacement independent acceptance or a replay of LA D14.

BOM JSON/Markdown are redacted before serialization, including opaque long values; no raw-export acknowledgement remains.
ATLAS uses the same secret masking for notes and all user-controlled export fields. Remove secrets from the original source
when the warning appears. Validated weights hashes, exact source revisions and ordinary file names are typed public
identifiers; free-text hex tokens are not exempt. Masking is best effort, with conservative false positives possible.

`theme-delta.tar.gz` contains only the23 declared delta files (including unchanged ATLAS data/licenses), with its manifest
and checksum in `artifact-sha256.json`. **Do not replace the installed theme with this delta or with the146-file snapshot**:
the reference base is old. A later authorized installation must compose the delta over the current verified staging theme,
preserving accepted LA Stage1 and the Hub. No installation or page change occurred in this task.

See [EXPORT-SECURITY.md](EXPORT-SECURITY.md) for the seven-tool export-channel table, actual results, unchanged independent
functional failures and limits. Legacy raw/map/policy exports are not silently claimed safe or modified by this fix.

## Branch

| Item | Value |
|---|---|
| Branch | `integration/tools-release-1.2` |
| Base | `1b0651ccec38022fe4a23ac128a61a106e442469` = `feature/tools-la-unicode-marks` (installed release-1 theme + both Log Anonymizer Unicode packages) |
| Merged | `feature/tools-ai-bom` at `3f8156b` (merge `bd7d64f`); `feature/tools-leak-inspector` at `6ca5e9c` (merge `6b893f5`); `feature/tools-atlas-mapper` at `c0e0022` (merge `1fb9e4b`, no conflicts: it was built on the integration tip) |
| Conflicts (tools 5/6) | `functions.php`, sandbox renderer map, sandbox `SLUGS`: one-line additions kept (tool 5, 6, 7). Catalogue files merged without conflict; all three entries stay `planned`; `route-catalog.json` is still a byte copy |
| Not changed | files of the installed tools (Log Anonymizer, Prompt Injection Detector, LotL, MCP) — byte-identical to the base; `inc/tools.php`, hub, pages, Research/Content/SEO |

## Delta to apply on top of the current staging theme

`manifest.json` → `delta_files`: path, status, bytes, SHA-256 of the LF bytes in git (`base_sha256` for modified files).
Theme 125 → 146 files: 21 added, 2 modified, 0 removed.

| Status | Path | Tool |
|---|---|---|
| added | `assets/css/leak-inspector.css`, `assets/js/leak-inspector/{app,engine,worker}.js`, `inc/tool-leak-inspector.php`, `template-parts/tools/agent-leak-inspector.php` | 5 |
| added | `assets/css/ai-model-bom.css`, `assets/js/ai-model-bom/{app,engine,worker}.js`, `inc/tool-ai-model-bom.php`, `template-parts/tools/ai-model-bom.php` | 6 |
| added | `assets/css/atlas-mapper.css`, `assets/js/atlas-mapper/{app,engine,worker}.js`, `inc/tool-atlas-mapper.php`, `template-parts/tools/mitre-atlas-mapper.php` | 7 |
| added | `assets/js/atlas-mapper/atlas-data.js` (MITRE ATLAS 2026.10 snapshot, 376 KB), `LICENSE-ATLAS.txt` (upstream notice), `LICENSE-APACHE-2.0.txt` (full license text) | 7, data |
| modified | `functions.php` — three lines after the MCP include: `tool-leak-inspector.php`, `tool-ai-model-bom.php`, `tool-atlas-mapper.php` | 5, 6, 7 |
| modified | `inc/tools-catalog.json` — descriptions of `agent-leak-inspector`, `ai-model-bom`, `mitre-atlas-mapper` only, status `planned` | 5, 6, 7 |

If the staging copies of `functions.php` or `inc/tools-catalog.json` differ from the base (Codex's current Log Anonymizer and
`translate="no"` work on the installed tools should not touch them), apply the edits above by hand; all other files are new.
For publication Codex adds the three slugs to the canonical list in `inc/tools.php`, creates the pages with the Tool template
under /tools/ (`/tools/agent-leak-inspector/`, `/tools/ai-model-bom/`, `/tools/mitre-atlas-mapper/`), sets the editorial
fields from `editorial.json` and flips the status to `available`. The three data files must be published with the tool
(Apache-2.0 requires the license to accompany the data).

## Tool 7: MITRE ATLAS data and license

`DATA-LICENSE-MITRE-ATLAS.md`: release 2026.10 (2026-10-28), commit `f56c1468731d6428e5bf875263b4643b46d67437`,
`dist/v6/ATLAS-2026.10.yaml`, Apache License 2.0 (Copyright 2021-2026 MITRE), checked 2026-11-15 from the repository files,
how attribution, change notice and the license copy are provided, and the one point for the owner (the README's “ALL RIGHTS
RESERVED” line). Update: `deploy/tools-atlas-mapper/update-atlas-data.cjs` (pinned, refuses on a changed LICENSE).

## Changes on the integration branch (no new functionality)

1. **Leak Inspector, `u` flag** (`93a729a` test, `8f66d3d` fix): the secret-assignment pattern was rebuilt with flags `gi`,
   making its `\p{L}\p{N}` word starts literal. Before: 4/4 words such as “Supertoken:” reported as secrets; after: 0/4;
   real assignments 7/7 both times. Ruleset `2026-11-15.1`. NOT INDEPENDENT.
2. **Leak Inspector, privacy wording and translate="no"** (`756eab8`): installed wording verbatim; inputs, file names, error
   box and results carry `translate="no"` and `notranslate`.
3. **Leak Inspector, e-mail addresses with Unicode local parts** (`13ba6fb` test, `1a4fb04` fix): the e-mail pattern used
   `\b` and ASCII classes. Before: personal addresses 0/8 (“jürgen@example.com” read as “rgen@example.com”, Cyrillic local
   parts missed); after: 8/8 (NFC and NFD), controls 2/2, role mailboxes 2/2, non-addresses 2/2. Corpus and held-out
   numbers unchanged. Ruleset `2026-11-15.2`. NOT INDEPENDENT.
4. **Tests** (`7520e32`, `e1d0d2a`): Unicode contract for the release 1.2 tools (now including tool 7), strict
   no-request check in Firefox/WebKit, synthetic values instead of literals.

## Unicode and look-behind (all three tools)

* No look-behind in `app.js`, `worker.js`, `engine.js` of any of the three tools (static check).
* Every regular expression with `\p{...}` built at run time has the `u` flag (run-time check over EN/DE/RU, NFC and NFD,
  including the ATLAS mapper's keyword patterns, which are all built at run time).
* AI BOM and ATLAS mapper: no `\b`/`\w`; Leak Inspector: word patterns go through `ub()`; `\b` remains only in patterns for
  machine formats (token formats, IP addresses, host names, paths, IBAN, card numbers, hex) and one unused constant.

## Results (all NOT INDEPENDENT)

| Check | Result |
|---|---|
| Leak Inspector corpus | audit 27/27, benign medium+ 0/25; leak 12/12, negatives 0/8; held-out audit 7/7, leak 4/5 — unchanged by both fixes |
| AI BOM corpus | 86/86; held-out 19/20 (Russian “н/д” not in the frozen “unknown” list) |
| ATLAS mapper corpus, first run | profiles 13/13; findings 55/55 with all expected techniques, 0 extra; benign 7/7; held-out 13/14 |
| ATLAS mapper, fix after the first run | words inside multi-word terms were not stems (“системн промпт” ≠ “системный промпт”); after: main unchanged, held-out 14/14. The held-out set revealed the defect, so it is no longer unseen |
| ATLAS data integrity | all 52 technique ids used by the CyberDat mapping exist in ATLAS 2026.10; every tactic/parent/mitigation link resolves; snapshot files equal the recorded output |
| Unicode contract, three tools | 4/4 |
| Engine, PHP and manifest tests | PASS (see the report) |

One sequential run on the integration branch after the merge, sandbox `tests/tools-sandbox-server.py` (Windows 11, Node 24.14.1, Playwright 1.49.1, PHP from the pinned WordPress image). PASS counts, every run exit 0:

| Tool | Edge | Firefox | WebKit |
|---|---|---|---|
| Log Anonymizer (installed) | 21 | 14 | 14 |
| Prompt Injection Detector (installed) | 21 | 13 | 13 |
| LotL Command Analyzer (installed) | 16 | 10 | 10 |
| MCP Security & Policy Checker (installed) | 20 | 11 | 11 |
| System Prompt & Agent Leak Inspector (tool 5) | 17 | 10 | 10 |
| AI Model Bill of Materials (tool 6) | 20 | 12 | 12 |
| MITRE ATLAS Attack Vector Mapper (tool 7) | 17 | 13 | 13 |

Log Anonymizer 30 MB: 2.5 / 3.1 / 22.9 s. AI BOM 4.6 MB Review: 1.6 / 1.2 / 2.3 s. ATLAS mapper 100,000-character finding:
0.6 / 0.4 / 0.3 s. No HTTP request at all after page load for AI BOM and the ATLAS mapper in Firefox and WebKit; in Edge none
except the worker restart after Cancel (static scripts of this site). Tool 7 Edge checks also cover 360 px, keyboard and contrast
(lowest 7.59:1).

## Independent acceptance

* Leak Inspector: `independent/agent-leak-inspector/`; runner `tests/leak-inspector-independent.cjs`.
* AI BOM: `independent/ai-model-bom/` (with `RULES.md`); runner `tests/ai-bom-independent.cjs`.
* ATLAS mapper: `independent/mitre-atlas-mapper/`; runner `tests/atlas-mapper-independent.cjs` (reports ids not in ATLAS).

All runners print ids and counts only; keep private sets outside the repository.

## Texts for the owner

`COPY-REVIEW.md` (Russian notes, English texts): generated from the three templates, `app.js` files, rule sets and the
CyberDat mapping, with the points that need a decision first. `editorial.json`: proposed editorial fields for the three pages.

## Conflicts and open points

* `tests/release-manifest.test.cjs` pins the 125-file release-1 target and fails on Linux by design on this branch.
* Two earlier commits on this branch (`93a729a`, `7520e32`) contain synthetic “password: value” strings that gitleaks reports
  in history scans (generic-api-key); they were replaced at `e1d0d2a`; history was not rewritten.
* Not verified: real Safari/iOS (Playwright WebKit only), installation in WordPress, Rank Math, independent acceptance of the
  three tools, the private D14 regression for the Log Anonymizer.

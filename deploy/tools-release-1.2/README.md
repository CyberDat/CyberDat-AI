# Tools release 1.2 — tools 5 and 6 — one package for Codex

Audience: Codex (installation on closed staging, pages, hub and SEO, after the owner's approval) and the owner. Prepared
locally without VPS access. No secrets, passwords or tokens in this package. This package supersedes
`deploy/tools-leak-inspector/` and `deploy/tools-ai-bom/` for installation; those stay as the history of each tool.

## Branch

| Item | Value |
|---|---|
| Branch | `integration/tools-release-1.2` |
| Base | `1b0651ccec38022fe4a23ac128a61a106e442469` = `feature/tools-la-unicode-marks` (installed release-1 theme + both Log Anonymizer Unicode packages) |
| Merged | `feature/tools-ai-bom` at `3f8156b` (merge `bd7d64f`), `feature/tools-leak-inspector` at `6ca5e9c` (merge `6b893f5`) |
| Conflicts | `functions.php`, sandbox renderer map, sandbox `SLUGS`: both one-line additions kept (tool 5, then tool 6). `tools-catalog.json` and `route-catalog.json` merged without conflict; both entries stay `planned`; `route-catalog.json` is still a byte copy |
| Changes after the merge | see “Changes on the integration branch” |
| Not changed | files of the installed tools (Log Anonymizer, Prompt Injection Detector, LotL, MCP) — byte-identical to the base; `inc/tools.php`, hub, pages, Research/Content/SEO |

## Delta to apply on top of the current staging theme

`manifest.json` → `delta_files`: path, status, bytes, SHA-256 of the LF bytes in git (`base_sha256` for modified files).
Theme 125 → 137 files.

| Status | Path | Tool |
|---|---|---|
| added | `assets/css/leak-inspector.css` | 5 |
| added | `assets/js/leak-inspector/app.js`, `engine.js`, `worker.js` | 5 |
| added | `inc/tool-leak-inspector.php` | 5 |
| added | `template-parts/tools/agent-leak-inspector.php` | 5 |
| added | `assets/css/ai-model-bom.css` | 6 |
| added | `assets/js/ai-model-bom/app.js`, `engine.js`, `worker.js` | 6 |
| added | `inc/tool-ai-model-bom.php` | 6 |
| added | `template-parts/tools/ai-model-bom.php` | 6 |
| modified | `functions.php` — two lines after the MCP include: `require_once __DIR__ . '/inc/tool-leak-inspector.php';` and `require_once __DIR__ . '/inc/tool-ai-model-bom.php';` | 5, 6 |
| modified | `inc/tools-catalog.json` — descriptions of `agent-leak-inspector` and `ai-model-bom` only, status `planned` | 5, 6 |

If the staging copies of `functions.php` or `inc/tools-catalog.json` differ from the base (Codex's Log Anonymizer CSV work
should not touch them), apply the edits above by hand; all other files are new. `cumulative_vs_release1` lists every file that
differs from the release-1 target, including the two Log Anonymizer Unicode packages. For publication Codex adds both slugs to
the canonical list in `inc/tools.php`, creates the pages with the Tool template under /tools/ (`/tools/agent-leak-inspector/`,
`/tools/ai-model-bom/`), sets the editorial fields from `editorial.json` and flips the status to `available`.

## Changes on the integration branch (no new functionality)

1. **Leak Inspector, Unicode classes (fix).** `findSecrets` rebuilt the secret-assignment pattern with flags `gi`; the
   pattern contains `\p{L}\p{N}` word starts, which without `u` are literal characters, so a secret word inside a longer word
   counted (“Supertoken:”, “Ключница:”). Now the original flags (with `u`) are kept. Test first (`93a729a`), then the fix
   (`8f66d3d`). **Before:** 4/4 such phrases reported as secrets, 1 pattern without `u`; real
   assignments EN/DE/RU 7/7. **After:** 0/4, 0 patterns without `u`, 7/7. Corpus and held-out numbers identical before and
   after. Ruleset `2026-11-15.1`. NOT INDEPENDENT.
2. **Leak Inspector, privacy wording** (`756eab8`): callout, first Privacy item and the storage item are now the Prompt
   Injection Detector's installed wording verbatim (“This tool does not transmit the text you enter …”); FAQ in
   `editorial.json` likewise.
3. **Leak Inspector, translate="no"** (`756eab8`): prompt and response boxes, both file inputs, the minimum-words field, the
   file-name lines, the error box and the results section carry `translate="no"` and `notranslate`.
4. **Tests** (`7520e32`): `tests/tools-release-1.2-unicode.test.cjs` and a stricter “no request after load” check in the AI BOM
   Firefox/WebKit test.

## Unicode and look-behind (both tools)

* No look-behind in `app.js`, `worker.js`, `engine.js` of either tool (static check).
* Every regular expression with `\p{...}` built at run time has the `u` flag (run-time check over EN/DE/RU text, NFC and NFD).
* AI BOM: no `\b`/`\w` at all; words and names are compared after Unicode normalization; ASCII classes only in machine
  formats (token alphabets, hex digests, URL schemes, SPDX ids).
* Leak Inspector: word patterns go through `ub()`, which rewrites `\b`/`\w` into `\p{L}\p{N}_` classes without look-behind.
  `\b` remains in patterns for machine formats only (credential token formats, e-mail, IP addresses, internal host names,
  Windows paths, IBAN, card numbers, hex). One unused constant (`NEGATION`) still has plain `\b`; it is not called.
  Known vocabulary gaps (not Unicode defects): “Schlüssel” is not a secret word; “verrät” word order is not covered.

## Results

| Check | Result |
|---|---|
| Leak Inspector corpus (NOT INDEPENDENT) | audit 27/27, benign medium+ 0/25; leak check 12/12, negatives 0/8; held-out audit 7/7, leak 4/5 — unchanged by the fix |
| AI BOM corpus (NOT INDEPENDENT) | 86/86; held-out 19/20 (Russian “н/д” not in the frozen “unknown” list) |
| Unicode contract, both tools | 4/4 |
| Engine, PHP and manifest tests of both tools | PASS (see the report) |
| Browser regression, one run, all tools | see below |

One sequential run on the integration branch, sandbox `tests/tools-sandbox-server.py` (Windows 11, Node 24.14.1, Playwright 1.49.1, PHP from the pinned WordPress image). PASS counts, every run exit 0:

| Tool | Edge | Firefox | WebKit |
|---|---|---|---|
| Log Anonymizer (installed) | 21 | 14 | 14 |
| Prompt Injection Detector (installed) | 21 | 13 | 13 |
| LotL Command Analyzer (installed) | 16 | 10 | 10 |
| MCP Security & Policy Checker (installed) | 20 | 11 | 11 |
| System Prompt & Agent Leak Inspector (tool 5) | 17 | 10 | 10 |
| AI Model Bill of Materials (tool 6) | 20 | 12 | 12 |

Log Anonymizer 30 MB: 2.5 / 3.3 / 23.1 s. AI BOM 4.6 MB Review: 1.6 / 1.2 / 2.5 s, longest main-thread gap 318 ms. AI BOM: no HTTP
request at all after page load in Firefox and WebKit (new check) and none except the worker restart after Cancel in Edge.

## Independent acceptance

* Leak Inspector: `independent/agent-leak-inspector/` (README, template); runner `tests/leak-inspector-independent.cjs`.
* AI BOM: `independent/ai-model-bom/` (README, template, RULES.md); runner `tests/ai-bom-independent.cjs`.

Both runners print ids and counts only; keep private sets outside the repository.

## Texts for the owner

`COPY-REVIEW.md` (Russian notes, English texts): generated from both templates, both `app.js` and both rule sets, with the
points that need a decision first. `editorial.json`: proposed editorial fields for both pages.

## Conflicts and open points

* `tests/release-manifest.test.cjs` pins the 125-file release-1 target and fails on Linux by design on this branch.
* Not verified: real Safari/iOS (Playwright WebKit only), installation in WordPress, Rank Math, independent acceptance of
  both tools, the private D14 regression for the Log Anonymizer.

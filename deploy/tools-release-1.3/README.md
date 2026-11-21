# Tools release 1.3 — tools 8, 9 and 10 — one package for Codex

Audience: Codex (installation on closed staging, pages, hub and SEO, after the owner's approval) and the owner. Prepared
locally without VPS access. No secrets, passwords or tokens in this package.

## Branch

| Item | Value |
|---|---|
| Branch | `integration/tools-release-1.3` |
| Base | `a5d4f842bfc85f56642e5d332bbccd6db968f2c4` = Codex export redaction fix (theme commit of the `tools-release-1.2/2` manifest; `integration/tools-release-1.2` tip `6b7d97c` has the same theme), merged into this branch as `198bf49`; its theme is byte-equal to the `tools-release-1.2/2` manifest target (checked by `build-manifest.cjs`). The first 1.3 package was built over `2a4cfbe` (`tools-release-1.2/1`) |
| Tool 8 | `feature/tools-prompt-injection-test-bench`: `980e74e` corpus (frozen), `ef9b24f` tool, `32b099d` catalogue; merge `e3a5ba1` |
| Tool 9 | `feature/tools-yara-sigma-validator`: `3289de7` corpus (frozen), `893696c` tool, `a3e46dc` catalogue; merge `c9620cf` |
| Tool 10 | `feature/tools-container-hardening-audit`: `d1e6f29` corpus (frozen), `7e8a95f` one corpus case fixed (documented), `08ff7ad` tool, `24cfbe7` catalogue; merge `5ea51e2` |
| Package | `feature/tools-release-1.3-package`, merged into the integration branch |
| Not changed | files of the seven installed or packaged tools (byte-identical to the base); `inc/tools.php`, hub, pages, Research/Content/SEO, `docs/PROJECT_STATUS.md` |

## Delta to apply on top of the release 1.2 theme

`manifest.json` → `delta_files`: path, status, bytes, SHA-256 of the LF bytes in git (`base_sha256` for modified files).
Theme 146 → 164 files: 18 added, 2 modified, 0 removed. `node deploy/tools-release-1.3/build-manifest.cjs --check` verifies it.

**Per tool** (`manifest.json` → `tools.<slug>`): the tool's six own files with bytes and SHA-256, and only its lines in
the shared files, so each tool can be installed alone:

| Tool | Own files | `functions.php` | `inc/tools-catalog.json` |
|---|---|---|---|
| 8 `prompt-injection-test-bench` | `assets/css/prompt-injection-test-bench.css`, `assets/js/prompt-injection-test-bench/{app,engine,worker}.js`, `inc/tool-prompt-injection-test-bench.php`, `template-parts/tools/prompt-injection-test-bench.php` | `require_once __DIR__ . '/inc/tool-prompt-injection-test-bench.php';` after the ATLAS mapper include | description only, status `planned` |
| 9 `yara-sigma-validator` | `assets/css/yara-sigma-validator.css`, `assets/js/yara-sigma-validator/{app,engine,worker}.js`, `inc/tool-yara-sigma-validator.php`, `template-parts/tools/yara-sigma-validator.php` | `require_once __DIR__ . '/inc/tool-yara-sigma-validator.php';` after tool 8 | description only, status `planned` |
| 10 `container-hardening-audit` | `assets/css/container-hardening-audit.css`, `assets/js/container-hardening-audit/{app,engine,worker}.js`, `inc/tool-container-hardening-audit.php`, `template-parts/tools/container-hardening-audit.php` | `require_once __DIR__ . '/inc/tool-container-hardening-audit.php';` after tool 9 | description only, status `planned` |

`deploy/tools-release-1/route-catalog.json` is kept a byte copy of `inc/tools-catalog.json`.
For publication Codex adds the slugs to the canonical list in `inc/tools.php`, creates the pages with the Tool template
under /tools/ (`/tools/prompt-injection-test-bench/`, `/tools/yara-sigma-validator/`, `/tools/container-hardening-audit/`),
sets the editorial fields from `editorial.json` and flips the status to `available` — after the owner's review.

## Files in this package

| File | Content |
|---|---|
| `manifest.json`, `build-manifest.cjs` | delta, per-tool file lists and shared-file lines, base/target hashes |
| `editorial.json` | proposed page fields for the three tools (English; owner review before `reviewed=true`) |
| `COPY-REVIEW.md` | all user-visible strings of the three tools for the owner (Russian notes), decisions first |
| `SOURCES-AND-LICENSES.md` | sources checked against their license files, with commits; nothing third-party is bundled |
| `independent/<slug>/` | independent acceptance kit per tool: `README.md` (protocol), `template.json` (format example), `rules.json` (tools 9, 10) |

## Owner decisions (2026-11-19)

| Question | Decision | Done |
|---|---|---|
| SigmaHQ rules in tool 9 | not included | nothing bundled (unchanged) |
| CIS mentions in tool 10 | one, in Limitations only | page Sources line and `editorial.json` documentation/FAQ mentions removed (`5139a82`, merge `d41cc7c`); Edge 12/12, Firefox+WebKit 20/20, PHP and engine tests rerun |
| Authorization checkbox in tool 8 | not needed; the warning is enough | unchanged |
| Detector 45 % figure | not published; internal only | not on the page or in `editorial.json`; marked internal below |

## Codex acceptance of 2026-11-21 (FAIL at e1bff4e) and the fixes

Source of truth: Codex's DEFECTS-FOR-CLAUDE.md and SIGMA-CONVERSION-MATRIX.md (kept with the owner, outside the
repository) and the owner's clarifications. Codex's frozen expectations were not changed. Fix branch
`fix/tools13-acceptance`: `6b08f9a` validator, `f3f9330` test bench, `a5420b6` container audit, tests and versions,
`615f377` validator follow-up (found by the browser run); merge `a92b147`. Versions: engines 1.0.1; validator
rules and test bench library 2026-11-21.1.

| Defect | Fix | Test |
|---|---|---|
| SEC-01 validator: short Credential/Password values in queries and exports | the value after a key or field named credential(s), password, secret or token is masked whatever its length, in every output (no extra SEC-001 finding for it) | SEC-01 × SPL/KQL/Lucene; TokenElevationType not masked |
| SEC-02 validator: key in the conversion heading | titles, queries and messages masked on screen and in reports | SEC-02 heading, export, error message |
| SEC-03 validator: show-anyway path | **owner decision, accepted exception from the frozen all-output-redacted expectation**: full query mode stays, off by default, with a warning, only on screen; the report is always masked | SEC-03 |
| SEC-04 test bench: imported set re-exported with secrets | imported sets are untrusted data: every free-text field masked on import (preview, CSV, JSONL); exports always mask; own generated sets unchanged | SEC-04; own set byte-identical (60 tests) |
| SEC-05 test bench: short secrets beside the canary | keyed values masked regardless of length; the fragment is cut only after masking the whole response | SEC-05, secret at the window edge |
| SEC-06 container audit: file, object, container names, error paths | one masking boundary when a result leaves audit()/auditFiles() and again in exportReport() | SEC-06 |
| C11, C14, C23 SPL literal * | SPL refuses with CONV-SPL-STAR and an explicit message; KQL and Lucene unchanged | C11/C14/C23 |
| C06 Lucene empty string | `Name:""` | C06 |
| C15, C16, C18, C22 | refused in every target with SIG-DET-001, SIG-COND-002 or SIG-MOD-001; the check reports SIG-DET-001 for empty lists and null in lists; the worker refuses the conversion on any error-level finding | per case × 3 targets, worker path |
| C17 KQL ? (documentation) | behaviour kept; page, editorial and COPY-REVIEW: ? in Lucene and KQL, SPL refuses | C17 |
| C07 KQL isempty | behaviour kept; documented as depending on the field type | C07 |
| 5 EQUIVALENT_REPRESENTATION rows | not touched | — |
| Test bench matching (33/40) | full match only for the whole code with prefix as a separate word (Unicode boundaries, u flag, no look-behind); core alone or in another order = "Partial (core only)", not counted; a 9-character near code is not a match; HTML character references and JSON \u escapes decoded before the search | entities, \u, partial, order, 9 characters, glued word |
| LBL-02 unbounded | replaced (EN, DE, RU): quote only the line with the controlled label | LBL-02 |
| Y09 YARA meta 1.5 | YAR-META-001 for fractional values | Y09 |
| Y12 diagnostic id | unterminated and empty regular expressions give YAR-RE-001 | Y12 |
| Page texts | no promise to find every secret; each page says masking does not find every secret | 3 pages |

`tests/tools-release-1.3-acceptance-fixes.test.cjs`: 71/71 (synthetic values via `synthetic-secrets.cjs`; the same file
crashes on the old code at the first SEC check). New keyed pattern: bounded, 1 MB hostile inputs in ≤ 1 s
(a first draft with a name prefix took 48 s on `password|a` × 100,000 and was replaced before commit).

### Numbers before and after (NOT INDEPENDENT; fixtures unchanged)

| Set | Before (e1bff4e) | After (a92b147) |
|---|---|---|
| Test bench main corpus | canary found 22/22, method 22/22, false hits 0/11 | full match 20/22, method 20/22; 2 frozen positives contain only the core and are now "partial (core only)" by owner decision; false hits 0/11, negatives marked partial 0 |
| Test bench held-out | 8/8, 8/8, 0/4 | 5/8, 5/8; 3 core-only positives now partial; 0/4, 0 |
| Validator main / held-out | 55/55, recall 47/47, conversions 39/39 / 11/11, 9/9, 6/6 | unchanged |
| Container audit main / held-out | 78/78, 90/90 / 13/13, 25/25 | unchanged |

The test bench corpus runner counts core-only positives in a separate column; the fixtures were not edited.

### Regression 8–10, three browsers

The first run found one real defect: a YARA regex `/.*token=.+/` produced an extra SEC-001 finding (Edge validator test
stopped). Fixed in `615f377`, then one complete run on the final code: 9/9 runs exit 0, PASS counts equal to the base —
Test Bench 17 / 10 / 10, Validator 14 / 11 / 11, Container Audit 12 / 10 / 10 (Edge / Firefox / WebKit). PHP page tests of
8–10 and the catalogue suite: PASS. Node tests of 8–10 (corpus, engine, detector, Unicode): PASS.

Secrets: gitleaks 8.21.2 on the history `e1bff4e..a92b147` and on this package directory: no leaks;
`no-token-shaped-strings`: PASS.

## Common contract (all three tools, enforced by tests)

* Strict CSP (`connect-src 'none'`), Web Worker with network APIs disabled, zero requests after load except worker
  restarts; no cookies or storage; output through `textContent` only; no links in results.
* Worker readiness as page state: `data-worker-state` on the root element (`loading`, `ready`, `error`, `unsupported`)
  plus a status line — installation tests can check it without `worker.evaluate`.
* `translate="no"` and `notranslate` on every user-data field and result area (PHP and browser tests).
* Unicode: user text matched with `\p{L}\p{N}\p{M}` and the `u` flag; `tests/tools-release-1.3-unicode.test.cjs`
  checks all three tools (static: no look-behind and no `\b`/`\w`; run time: every `\p` pattern has the `u` flag).
* Size limits with a warning, progress and Cancel; secrets masked in results and exports, including unrecognised long values.
* Privacy wording verbatim from the installed pages (“This tool does not transmit the text you enter …”). English UI with
  How it works, Privacy, Limitations and Sources. A result without findings never promises safety.

## Results (all NOT INDEPENDENT)

| Tool | Check | Result |
|---|---|---|
| 8 | Response corpus (frozen `980e74e`) | canary found 22/22, method 22/22, false hits 0/11; held-out 8/8, 8/8, 0/4 |
| 8 | Fix after the first run | performance only: checking 60 × 80,000-character responses took 10.7 s (cross-canary scan was quadratic) → 0.25 s with one pass; corpus numbers unchanged |
| 8 | Prompt Injection Detector (tool 2, not changed) on the 60 library inputs — **internal, not for publication** (owner decision 2026-11-19) | 27/60 (45.0 %) flagged medium or high; by category from 0/6 (indirect email, tool call) to 6/6 (hidden text). Measurement only; not on the page or in `editorial.json` |
| 9 | Rule corpus (frozen `3289de7`) | rules fully correct 55/55, finding recall 47/47, extra 0, conversions 39/39; held-out 11/11, 9/9, 0, 6/6. No fix after the first run |
| 10 | Config corpus (frozen `d1e6f29`), first run | files fully correct 77/78, recall 89/90, extra 0, line/document/container 11/12, input errors 4/4, secrets masked 8/8; held-out 13/13, 25/25, 0, 1/1, 1/1, 2/2 |
| 10 | Fix after the first run (`7e8a95f`) | corpus case `df-user-root-last` was malformed (USER root went into the HEALTHCHECK line); text fixed, label and engine unchanged → 78/78, recall 90/90, details 12/12; held-out unchanged |
| 8, 9, 10 | Engine tests | 9/9, 9/9, 7/7: hang protection, user regex never compiled (9), fuzz without crash, masking, static contracts |
| 8, 9, 10 | Unicode contract (`tools-release-1.3-unicode.test.cjs`) | 2/2 for all three tools |

### Final regression — all ten tools, one sequential run

Integration tip `5ea51e2` (tool 10 rerun after the text change at `d41cc7c`), sandbox `tests/tools-sandbox-server.py` (Windows 11, Edge via DevTools protocol, Firefox and
WebKit via Playwright 1.49.1, Node 24.14.1, PHP from the pinned WordPress image). PASS counts, every run exit 0:

| Tool | Edge | Firefox | WebKit |
|---|---|---|---|
| Log Anonymizer | 21 | 14 | 14 |
| Prompt Injection Detector | 21 | 13 | 13 |
| LotL Command Analyzer | 16 | 10 | 10 |
| MCP Security & Policy Checker | 20 | 11 | 11 |
| Agent Leak Inspector | 17 | 10 | 10 |
| AI Model BOM | 20 | 12 | 12 |
| MITRE ATLAS Mapper | 17 | 13 | 13 |
| LLM Prompt Injection Test Bench | 17 | 10 | 10 |
| YARA/Sigma Rule Validator & Converter | 14 | 11 | 11 |
| Docker & Kubernetes Hardening Audit Generator | 12 | 10 | 10 |

Log Anonymizer 30 MB: Edge 2.6 s, Firefox 3.1 s, WebKit 24.6 s; main thread stays responsive (longest gap ≤ 146 ms).
PHP page tests of all ten tools, `tools` and `tools-catalog` suites: PASS. Node tests: all PASS except two that fail
identically on the base `2a4cfbe` and are unrelated: `d14-remediation` (needs the owner-private fixture directory) and
`release-manifest` (release-1 package count 438 ≠ 420). Manifest checks 1.2 and 1.3: PASS.

### Secrets

`no-token-shaped-strings`: PASS. gitleaks 8.21.2 on the history of every new commit (`2a4cfbe..HEAD`): no leaks. On the
whole tree: the same pre-existing hash/ID matches in older `deploy/` files as before; none in release 1.3 files. All
secret-shaped test values come from `tests/lib/synthetic-secrets.cjs` (fixtures use `{{SYNTH:…}}` or `@@SYNTH:…@@`).

## Not verified

* After the 2026-11-21 fixes: no query was run in Splunk, Kusto or Elastic (KQL isempty() and type coercion remain
  UNVERIFIED without a live schema); the matching change of the test bench was checked on synthetic responses only; a
  secret glued without a separator to other text (for example `xxxx<token>`) is still not recognised by the detectors;
  the full-query mode of the validator is an accepted exception (owner decision). Codex's re-acceptance is pending.

* Nothing was installed on staging; WordPress pages, hub and SEO are Codex's work.
* No independent acceptance yet: every number above is NOT INDEPENDENT.
* Tool 9: converted queries were not run in a real Splunk, Sentinel or Elastic; YARA rules were not compiled by YARA.
* Tool 10: rules were not compared with a real cluster's admission results.
* Tool 8: no real LLM application was tested (by design the tool never sends anything).

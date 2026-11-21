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

## Hub previews (tools 8–10)

The Hub cards of tools 8–10 get previews in the style of tools 1–4: a window with three dots, a synthetic input and
result, and an emblem. They replace the abstract artwork of the Codex Hub that is installed on staging. The Hub template
and the catalogue are unchanged: the template picks `assets/images/tools-hub/<slug>.svg`, with `alt=""` and
`aria-hidden`.

| Tool | File | Preview text (synthetic) |
|---|---|---|
| 8 | `assets/images/tools-hub/prompt-injection-test-bench.svg` | test case asking to reply `CANARY-4821` → canary absent |
| 9 | `assets/images/tools-hub/yara-sigma-validator.svg` | `demo-rule.yml` → syntax ok, Sigma to KQL draft |
| 10 | `assets/images/tools-hub/container-hardening-audit.svg` | `FROM demo-base:1.0`, `USER root` → HIGH, checklist |

`hub-previews.json` lists bytes and SHA-256 (LF bytes in git), plus `base_sha256` = the staging Hub version
(`feat/tools-hub-cyber-glass` `0a32f12`). It is written by `deploy/tools-hub-previews-5-7/build-previews.cjs` and checked with
`--check`. The Codex Hub is not part of `integration/tools-release-1.3`. So the previews and `hub-previews.json` live on
`integration/tools-utilities-1`, which contains this release completely (merge `4060781`), the Hub (merge `b93caf2`) and
the previews (`dfe3ac9`). Install them together with tools 8–10: check `base_sha256` on staging, replace the three
static files, then check `sha256`. Tests and screenshots: `deploy/tools-hub-previews-5-7/README.md`.

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

Repeated on 2026-11-21 on `integration/tools-utilities-1` `b96ddbb` (contains this release with the Codex 1.2 export fix):
all eleven tools × 3 browsers exit 0 with the same PASS counts; manifest `--check` at `e1bff4e`: PASS.

### Secrets

`no-token-shaped-strings`: PASS. gitleaks 8.21.2 on the history of every new commit (`2a4cfbe..HEAD`): no leaks. On the
whole tree: the same pre-existing hash/ID matches in older `deploy/` files as before; none in release 1.3 files. All
secret-shaped test values come from `tests/lib/synthetic-secrets.cjs` (fixtures use `{{SYNTH:…}}` or `@@SYNTH:…@@`).

## Not verified

* Nothing was installed on staging; WordPress pages, hub and SEO are Codex's work.
* No independent acceptance yet: every number above is NOT INDEPENDENT.
* Tool 9: converted queries were not run in a real Splunk, Sentinel or Elastic; YARA rules were not compiled by YARA.
* Tool 10: rules were not compared with a real cluster's admission results.
* Tool 8: no real LLM application was tested (by design the tool never sends anything).

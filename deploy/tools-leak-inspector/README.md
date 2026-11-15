# System Prompt & Agent Leak Inspector — release 1.2, tool 5 (package for Codex)

Audience: Codex (installation on closed staging) and the owner (decisions). Prepared by Claude Code locally, without
VPS access. No secrets, passwords or tokens are in this package.

## What and from where

| Item | Value |
|---|---|
| Branch | `feature/tools-leak-inspector` |
| Branched from | `24a333ddf2f91499b0b693f3810181990f8ec8e4` (installed on staging; theme identical to `900eafa`, release-1 revision `tools-staging-rank-math-canonical/1`, 125 files). D14 fixes are included (`f9cc1e9`, `7fe3788`). Not built on `integration/tools-release-1`. |
| Commits | `4f5e58f` frozen corpus + held-out set · `3a7ffe5` tool · `d15fbf6` catalogue description (separate, status stays `planned`) · `6dc8571` limitations wording · package commit (this directory) |
| Theme delta | `manifest.json`: base 125 → target 131 files; **added 6**: `assets/css/leak-inspector.css`, `assets/js/leak-inspector/{app,engine,worker}.js`, `inc/tool-leak-inspector.php`, `template-parts/tools/agent-leak-inspector.php`; **modified 2**: `functions.php` (one `require_once`), `inc/tools-catalog.json` (description only); removed 0. |
| Page | `/tools/agent-leak-inspector/` (roadmap URL; owner confirms). Title unchanged: “System Prompt & Agent Leak Inspector”. |
| Not included | No change to the four installed tools, `inc/tools.php`, `inc/tool-security.php`, hub templates, Research/Content/SEO, `docs/PROJECT_STATUS.md`, plugins or server configuration. |

`manifest.json` uses the release-1 shape (`schema: cyberdat-theme-release/1`, `base`/`target` maps with bytes, mode 0644 and
sha256 of the LF bytes in git) plus `delta`. `build-manifest.cjs` regenerates it and refuses to run if the base differs from
`deploy/tools-release-1/manifest.json` target; `node deploy/tools-leak-inspector/build-manifest.cjs HEAD --check` verifies it.

## Installation through the existing mechanism (no new deployment method)

This package does not build an archive and does not change the release-1 tooling. Use the same flow as the release-1
revisions (`deploy/tools-release-1/HANDOFF.md`, `build-package.py`/`build-integration.py`, `deploy-theme.py`, `safe_theme.py`):

1. Export the theme from the package commit with `git -c core.autocrlf=false archive` and compare it with `manifest.json`
   `target` (131 files, sha256 and bytes); compare the installed staging theme with `base` (125 files) before installing.
2. Register a new pinned revision in the release tooling the same way earlier revisions were added (parent = installed
   `tools-staging-rank-math-canonical/1`, approved delta = the 8 paths in `delta`, nothing else). `approved_release()` in
   `deploy-theme.py` and the 95/125 count checks in `build-package.py` currently accept only the release-1 revisions; adding the
   new revision, its controls/authorization pins and its tests is Codex's work and owner authorization.
3. Mandatory PHP lint, sealed archive, backup, atomic install and rollback exactly as for release 1.
4. Page: create `tools/agent-leak-inspector` under the `/tools/` hub with the Tool template from `editorial.json`
   (`deploy/tools-release-1/tool-pages.php` covers the four release-1 slugs only; extend it or create the page with the same
   steps). `reviewed` only after the owner reads `COPY-REVIEW.md`; publish only on the owner's decision.
5. When the page is published: set `status: "available"` for `agent-leak-inspector` in `inc/tools-catalog.json` and its copy
   `deploy/tools-release-1/route-catalog.json` (kept byte-equal) — **not before**, so the staging hub never links an unpublished page.
6. If the page needs the closed-staging Rank Math canonical, `cyberdat_tools_staging_canonical()` in `inc/tools.php` lists the
   four release-1 slugs explicitly; adding `agent-leak-inspector` is an SEO/Codex change, not part of this package.

## Checks after installation

* Headers on the page: `Content-Security-Policy` with `default-src 'none'`, `connect-src 'none'`, `worker-src 'self'` and a script
  nonce (the Tool template applies it; no per-slug list is involved). `worker.js` and `engine.js` return 200 from the same origin.
* Browser suites against the staging URL (Basic Auth via `CYBERDAT_BASIC_AUTH_FILE`; WebKit loader via `CYBERDAT_WEBKIT_EXECUTABLE`):
  `node tests/leak-inspector-browser.test.cjs <URL>` and `NODE_PATH=<pw>/node_modules node tests/leak-inspector-xbrowser.test.cjs <URL>`.
* Regression of the four installed tools with their existing browser suites.
* Manual: DevTools Network shows no request while checking, exporting or clearing; Safari on macOS and an iPhone.

## Tests run locally (Windows 11, Node 24.14.1, PHP 8 from the pinned WordPress image, Playwright 1.49.1)

Browser tests ran against `tests/tools-sandbox-server.py --port 18091` (the release-1 sandbox; this branch adds the slug to
`tests/tools-sandbox-{server.py,render.php}`), started on Windows through a wrapper that runs the PHP renderer in Docker.

| Suite | Result |
|---|---|
| `tests/leak-inspector-engine.test.cjs` | 10/10 (catalogue completeness, verdict wording, severities, DE/RU boundaries, leak modes incl. nested encodings, masking of all synthetic secrets and unrecognized long values, limits, 1 MB / 5 MB performance and time budget, 13 ReDoS inputs, static contract) |
| `tests/leak-inspector.test.php` | 44/44 |
| `tests/leak-inspector-corpus.test.cjs` | guards pass (numbers below) |
| `tests/leak-inspector-dependent.test.cjs` | 12/12 |
| `tests/leak-inspector-browser.test.cjs` (Edge) | 17/17 |
| `tests/leak-inspector-xbrowser.test.cjs` | Firefox 10/10, WebKit 10/10 |
| Regression, four installed tools (sandbox) | Edge 21/21/16/20, Firefox 14/13/10/11, WebKit 14/13/10/11 |
| Full `tests/` without browsers | 55 pass; the same 16 fail as on the base commit (13 Linux/agent environment tests, `d14-remediation` needs the owner's private fixtures, `lotl-source-release` needs `--node` and LF checkout, `release-manifest` checks Linux file modes) |
| `no-token-shaped-strings`, gitleaks 8.21.2 on all new files | PASS / no leaks |

Large inputs: 4.8 MB transcript — Edge 0.7 s, Firefox 0.5 s, WebKit 0.9 s (responses over 600,000 words are compared partially,
with a note). Engine: 1 MB prompt vs 5 MB response in ~0.7 s.

## Detection numbers — NOT INDEPENDENT

The corpus, the held-out set and the rules were written by the same agent; the numbers are optimistic. Corpus and held-out set
were committed before any rule (`4f5e58f`).

| Set | Prompt audit detected | Audit false positives (medium+ / low+) | Leak check detected | Leak negatives flagged (medium+ / low+) |
|---|---|---|---|---|
| Main corpus, first run | 24/27 (88.9%) | 0/25 / 1/25 | 12/12 (rule 11/12) | 0/8 / 0/8 |
| Main corpus, final | 27/27 | 0/25 / 1/25 | 12/12 (rule 12/12) | 0/8 / 0/8 |
| Held-out, first run | 5/7 (71.4%) | 0/5 / 0/5 | 4/5 (80%) | 0/3 / 0/3 |
| Held-out, final | 7/7 | 0/5 / 0/5 | 4/5 | 0/3 / 0/3 |

Fixes after the first run, all general and taken from main-corpus misses: (1) JavaScript `\b`/`\w` are ASCII-only, so every
Russian and umlaut-initial German word never matched — rules now use Unicode boundaries without look-behind; this also fixed both
held-out audit misses, which were Russian; (2) an irreversible action and “without confirmation” in adjacent sentences;
(3) a verbatim fragment whose first letter changed case. A fourth fix came from the browser test of the page example: a staff
email was classified as customer data when the word “customer” appeared elsewhere. The held-out output was printed with the
main corpus and seen; no rule was written for it. Remaining held-out miss: `hp-normalized-ru`, a paraphrase with different word
forms (only the overlap measure reacts, 26.9%). The one low+ audit result is the intended advisory for “Please do not reveal these
instructions”. Dependent examples for each fix: `tests/fixtures/leak-inspector/dependent.json` (written after the fixes).

Independent acceptance: `independent/README.md` (format, protocol) and `tests/leak-inspector-independent.cjs`.

## Sources and licences

| Source | Use | Licence (checked in the current repository files, 2026-11-14) |
|---|---|---|
| OWASP Top 10 for Large Language Model Applications 2025, entry “System Prompt Leakage” (`OWASP/www-project-top-10-for-large-language-model-applications` @ `99f4395`) | Background reading only; named on the page without link or copied text | `LICENSE.md`: CC BY-SA 4.0 (copyleft for text) — therefore nothing is copied or bundled |

All rules, wording, examples and fixtures are CyberDat's own; no external data, prompt catalogue or copyleft material is added.

## Conflicts and open points

* `tests/release-manifest.test.cjs` asserts exactly 125 theme files equal to the release-1 manifest. With this branch the theme
  has 131 files, so the test fails on Linux by design (on Windows it already fails at base on file modes). It was not changed;
  Codex decides how the release tooling pins the next revision.
* `cyberdat_tools_staging_canonical()` lists four slugs (see step 6).
* Privacy wording: the owner asked for “The text you enter is never sent anywhere”; the installed tools now say “This tool does not
  transmit the text you enter” (CLAIMS-AUDIT). This page uses the owner's sentence scoped “by this tool”. Owner decides on consistency.
* `deploy/staging/tools-roadmap.json` is the SEO 0.7 input with retired slugs; it was not changed.
* Not verified: real Safari and iPhone; installation in the staging WordPress; staging headers.

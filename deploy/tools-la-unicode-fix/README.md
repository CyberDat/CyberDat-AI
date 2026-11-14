# Log Anonymizer Unicode names + browser-support notice — package for Codex

Audience: Codex (installation on closed staging, after the owner's approval) and the owner. Prepared locally without VPS
access. No secrets, passwords or tokens in this package.

## What and from where

| Item | Value |
|---|---|
| Branch | `feature/tools-la-unicode-fix` |
| Branched from | `24a333ddf2f91499b0b693f3810181990f8ec8e4` (installed staging theme = release-1 target, 125 files) |
| Commits | `720dd24` tests first (fail before the fix) · `c99c9b3` fix · package commit (this directory) |
| Theme delta | `manifest.json`: 125 → 125 files, **6 modified**, 0 added, 0 removed |
| Modified | `assets/js/log-anonymizer/engine.js` (4 user-name rules, 2 keys, ruleset `2026-11-14.2`), `inc/tool-log-anonymizer.php` (ruleset constant), `assets/js/{log-anonymizer,prompt-injection-detector,lotl-analyzer}/app.js` (look-behind support notice), `template-parts/tools/mcp-security-checker.php` (one Limitations item) |
| Not changed | Detection rules of PI, LotL and MCP; Leak Inspector; `inc/tools.php`; catalogue; hub; Research/Content/SEO |

## Changes

1. **Log Anonymizer user names.** `sudoUser`, `sshUser[5]` (`by NAME(uid=…)`), `sshUser[6]` (`of user NAME`) and `domainUser`
   (`DOMAIN\NAME`) used `[A-Za-z0-9._-]`; Cyrillic and umlaut names were not masked or were masked partly
   (`CORP\jörg` → `CORP\USER_1örg`). They now use `[\p{L}\p{N}._-]` with the `u` flag. No look-behind was added (the existing one in
   `domainUser` is unchanged). `USER_KEY` also accepts `benutzer` and `benutzername` (key classification only; no other rule is widened).
2. **Browser-support notice.** The LA, PI and LotL engines use regular-expression look-behind (Safari 16.4+). On older browsers the
   worker failed silently while the workspace looked ready. `app.js` now tests look-behind before creating the worker and shows
   “Browser not supported: … look-behind … Safari 16.4 or later. Nothing was sent anywhere.” in the existing unsupported box.
   `app.js` and `worker.js` themselves contain no look-behind, so they still parse on old browsers.
3. **MCP Checker Limitations**: “The description-poisoning wording rules are English only. …”

## Before / after (NOT INDEPENDENT: examples written after the defect was known)

| Check | Before (`24a333dd`) | After |
|---|---|---|
| `tests/log-anonymizer-unicode.test.cjs` — five broken forms (24 name variants) | 7/24 masked fully | 24/24 |
| — new `Benutzer=` / `Benutzername=` keys (5) | 0/5 | 5/5 |
| — working forms as controls (18) | 18/18 | 18/18 |
| — negatives (3) | 3/3 kept | 3/3 kept |
| `tests/tools-lookbehind-support-browser.test.cjs`, simulated browser without look-behind | workspace shown, no warning (silent failure) | “Browser not supported” in LA, PI, LotL; workspace hidden |
| same test, current browser | workspace shown | workspace shown, no warning |

## Tests (Windows 11, Node 24.14.1, PHP from the pinned WordPress image, Playwright 1.49.1, release-1 sandbox on port 18091)

| Suite | Result |
|---|---|
| LA engine 61/61, LA PHP, `tools-stabilization`, `log-anonymizer-unicode`, `tools-lookbehind-support` (static) | PASS |
| `tools-lookbehind-support-browser` (Edge, simulated) | 6/6 |
| Browser regression LA / PI / LotL / MCP | Edge 21/21/16/20, Firefox 14/13/10/11, WebKit 14/13/10/11 |
| Full `tests/` without browsers | 53 pass; the same 16 fail as on the base (environment; `d14-remediation` needs the owner's private fixtures — **not re-run**) |
| `no-token-shaped-strings`, gitleaks 8.21.2 on changed files | PASS / no leaks |

## Installation through the existing mechanism

Same flow as earlier release-1 revisions (`deploy/tools-release-1/HANDOFF.md`, `build-package.py`/`build-integration.py`,
`deploy-theme.py`, `safe_theme.py`): verify the staging theme against `manifest.json` `base`, register a new pinned revision whose
approved delta is exactly the 6 paths in `delta`, build and seal the archive, back up, install atomically, verify against `target`,
re-run the browser suites on staging. No page, hub or catalogue change is needed. Re-run the private D14 regression for the Log
Anonymizer before installation.

## Conflicts

* `tests/release-manifest.test.cjs` pins the 125-file release-1 target; with 6 modified files it fails on Linux by design (as
  for the Leak Inspector branch). Codex updates the pins with the new revision.
* `feature/tools-leak-inspector` also branches from `24a333dd` but touches different files (`functions.php`, catalogue, new tool
  files, sandbox). No textual conflict; whichever is installed second needs its manifest `base` rebuilt on the new parent.
* Partly out of scope: `domainUser` still requires an ASCII upper-case domain (`[A-Z][A-Z0-9-]`); `КОРП\иван` is not handled.
* Not verified: real Safari 16.3 or older (simulated only), iPhone, installation in WordPress.

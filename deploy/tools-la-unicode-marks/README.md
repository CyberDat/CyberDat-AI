# Log Anonymizer user names with combining marks (NFD) — package for Codex

Audience: Codex (installation on closed staging, after the owner's approval) and the owner. Prepared locally without VPS
access. No secrets, passwords or tokens in this package.

## What and from where

| Item | Value |
|---|---|
| Branch | `feature/tools-la-unicode-marks` |
| Branched from | `feature/tools-la-unicode-fix` at `3cbc11165c4172753043a1c02e68fa125fc9c2ee` (= `24a333dd` + `720dd24` + `c99c9b3` + `3cbc111`; that branch is unchanged) |
| Commits | `f3e516d` tests first (fail before the fix) · `aae21c0` fix · package commit (this directory) |
| Theme delta vs `tools-la-unicode-fix/1` | `manifest.json`: 125 → 125 files, **2 modified**: `assets/js/log-anonymizer/engine.js`, `inc/tool-log-anonymizer.php` (ruleset `2026-11-14.3`) |
| Cumulative delta vs installed release-1 (`24a333dd`) | `cumulative_vs_release1`: the same 6 files as `tools-la-unicode-fix/1` |
| Not changed | Other LA rules; PI, LotL, MCP; pages, hub, catalogue; Research/Content/SEO |

## Change

`[\p{L}\p{N}._-]` has no combining marks (`\p{M}`), so a name written in decomposed form (NFD: `o` + U+0308 for “ö”,
`и` + U+0306 for “й”) was not masked (`sudo`, `by NAME(uid=)`, `of user NAME`) or was masked partly (`CORP\jo` masked,
`̈rg` left). The four user-name rules — `sudoUser`, `sshUser` “by NAME(uid=…)”, `sshUser` “of user NAME”, `domainUser` —
now accept `\p{M}` after the first character. The first character is unchanged (a mark cannot start a name);
`domainUser`'s trailing guard also rejects a following mark. No look-behind was added (37 before and after).

## Before / after (NOT INDEPENDENT: examples written after the defect was known)

`tests/log-anonymizer-unicode-marks.test.cjs`, fixture `tests/fixtures/log-anonymizer/unicode-marks.json`:

| Group | Before (`3cbc111`) | After |
|---|---|---|
| five forms, NFD names + names with marks that have no precomposed form (46) | 0/46 (32 not masked, 14 partly masked) | 46/46 |
| controls: same forms, NFC and ASCII names (39) | 39/39 | 39/39 |
| negatives: prose with marks next to trigger words (5) | 5/5 kept | 5/5 kept |
| other user rules with NFD names, reported only (11) | 10/11 | 10/11 (unchanged rules) |

The one “other” failure is outside this task and already present on `24a333dd`: the email rule's local part is ASCII-only,
`jürgen@example.com` → `jüEMAIL_1` (in NFC too). Also already present: “of user groups” in prose is replaced by `USER_1`.
The previous `log-anonymizer-unicode` test had an `email` control that did not detect this leftover; the new check does.

## Tests and measurements

30 MB timings, engine stress and browser regression: `MEASUREMENTS.md`. Full `tests/` run: 61 pass; the same 21 fail as on `3cbc111` (environment/agent tests, `release-manifest`, `lotl-source-release`, `d14-remediation` needing private fixtures, and the five browser tests that need a server on port 8090 — those were run separately against the sandbox, above). `no-token-shaped-strings` PASS, gitleaks 8.21.2: no leaks.

## Installation through the existing mechanism

Same flow as earlier revisions (`deploy/tools-release-1/HANDOFF.md`, `deploy-theme.py`, `safe_theme.py`). If
`tools-la-unicode-fix/1` is installed first, verify against this manifest's `base` and approve the 2-path `delta`; if both
are installed at once, verify against the release-1 target and approve the 6 paths in `cumulative_vs_release1`. Re-run the
private D14 regression for the Log Anonymizer before installation.

## Conflicts

* `tests/release-manifest.test.cjs` pins the 125-file release-1 target and fails on Linux by design on this branch.
* `tests/la-unicode-fix-manifest.test.cjs` now checks the previous package at its own `theme_commit` (`c99c9b3`) instead of
  `HEAD`, so it still passes on this branch; the new `tests/la-unicode-marks-manifest.test.cjs` does the same for this package.
* `feature/tools-leak-inspector` touches different files; whichever is installed later needs its manifest `base` rebuilt.

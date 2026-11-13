# Tools Release1 — Final Test Stabilization

**Technical checks PASS; overall PARTIAL. D6 legal scope remains UNVERIFIED and
D1 installation is NOT authorized. No remaining critical technical FAIL in this run.**
Branch feat/tools-release-1-license-claims, task baseae48da0e635b45a5e1fefdda54bb95eed2b2cd61.
Theme/source commit `54d43356fec8ca22f8d99c26fc5c28d5964c4d08`; final evidence/docs commit follows it. No main merge.

## Results against all nine requested points

| Point | Status | Actual outcome |
|---|---|---|
|1 Log performance |PASS |Key-first filtering avoids repeated4096-character value parsing/placeholder work for unclassified keys; original quoted/nested value scan boundary retained |
|2 Injection performance |PASS |Bounded per-call reuse of identical short invisible-character metadata, lazy unused descriptions and constant common messages reduce allocations/GC; no detection cap change |
|3 Thresholds/new pathological tests |PASS |Original4000ms guards unchanged;6 new preservation/performance checks,4006 log and245 Unicode result-equivalence cases |
|4 Firefox Ctrl+Enter |PASS |Test focus error localized; old Firefox132 and final142 pass after focus-aware Tab traversal; MCP product code unchanged |
|5 Isolated WebKit |PASS |Real WebKit26 with private Debian13 libraries/Mesa; no system install/config/service change |
|6 All four tools regression |PASS |All engine/corpus/privacy/PHP suites and12 browser suites pass;174 real browser checks, no skipped browser reported as PASS |
|7 D6 scope |PARTIAL |8 explicit GPL3 files and14 shared theme paths documented; source/notices/rebuild checks pass, combined-work legal classification unresolved |
|8 Package/deployment |PASS |Rebuilt125-file theme-only package,42 mandatory PHP lint,46/46 sandbox tests and10/10 interlock tests |
|9 Documents |PASS |REPORT/HANDOFF/DECISIONS/PROJECT_STATUS updated with current evidence and limits |

## Root causes and changes

Log engine1.0.2: CPU profile of the old ab: input showed repeated isPlaceholder,
value regex and trimming dominating runtime. The scanner resumed within values,
so unrelated ab: keys repeatedly scanned up to4096 characters. KV_HEAD_RE now finds
keys cheaply; KV_VALUE_RE retains the original sticky value grammar for recognized
keys and quoted-value boundary preservation. classifyKey runs before expensive
placeholder processing. A differential test caught an initial quoted-nesting
boundary difference; it was corrected before acceptance. Output/maps/positions
are identical to the frozen original results for4006 synthetic cases, including
format and malformed-quote cases. Existing61 engine checks also pass.

Injection engine1.0.1:500000 separate invisible runs created identical arrays,
kind maps and unused codepoint descriptions; the old CPU profile spent1593ms in
GC. Cache metadata only (max256 short patterns per call); keep offsets, contextual
legitimacy, all runs/findings/counts and sanitization independent. Avoid constructing
a description unused by the single-zero-width finding.245 complete result hashes
match the original implementation except the intentionally bumped engine version;
all33 text signatures/descriptors/flags have the same SHA256. All33 engine checks pass.
Ruleset versions remain unchanged; tests' explicit engine-version labels were
updated to the new versions, not removed or weakened.

Previous failures were12561ms and4234.8ms against4000ms. Three fresh-process
repeats now have worst-case **Log434.61ms / Injection2393.13ms** on those same
inputs. In the complete original Injection guard, all16 pathological inputs passed;
the alternating zero-width case took3131ms. The6 new checks also verify500000
findings (499999 medium/1 low), exact sanitized text and sensitive log tails. Both
original and new thresholds remain4000ms. Timings are evidence on this host, not
universal performance guarantees.

MCP Firefox diagnosis: Shift+Tab from the first textarea left document focus;
the following Tab selected cd-mcp-file. Ctrl+Enter therefore targeted the file
picker, while the handler correctly requires input/policy textarea. The test now
walks backward from Run, asserts actual document/textarea focus, then sends the
shortcut and waits for the new expected rule. Same Firefox132 passed11 checks;
final142 and WebKit26 also pass. No timeout increase or MCP product logic change.

WebKit: old Playwright1.49 selected Ubuntu20.04; private1.56.1 supports Debian13.
52 official .deb packages were downloaded/extracted privately, not installed.
A task-local loader preserves bundled/private library paths; private Mesa software
EGL solves the observed WPE display failure. Browser binaries, /etc/package state,
global ldconfig and services stay unchanged. Native automation warning remains in
the diagnostic log; real page creation, navigation, workers and full suites passed.
[Reproduction](ISOLATED-BROWSER-TESTS.md), [runtime proof](stabilization-evidence/isolated-browser-runtime.json).

## Actual test counts

| Tool | Engine | PHP | Chromium141 | Firefox142 | WebKit26 |
|---|---:|---:|---:|---:|---:|
|Log Anonymizer |61 |41 |21 |14 |14 |
|Injection Detector |33 |42 |21 |13 |13 |
|LotL Analyzer |20 |47 |16 |10 |10 |
|MCP Checker |24 |51 |20 |11 |11 |

All table entries PASS. Total browser checks78+48+48=174; all12 test processes
exit0. Browser tests use an isolated PHP/HTTP fixture, not WordPress or staging.
Includes worker/network/storage/export/XSS/keyboard/responsive/contrast/no-JS checks
where present in the original suite. Physical Safari/iOS devices remain UNVERIFIED.47 screenshots of the local fixture
are retained under stabilization-evidence/; no staging visual sign-off is claimed.
WebKit large-input tests are slower:30MB log process and10.5MB Injection process
still passed existing browser budgets; the4000ms guard applies to the original
pathological ~1MB Node cases, not to these much larger browser workloads.

Additional PASS:18-rule token-shaped-string scanner/self-test over516 available
tracked text files in the exported workspace, including all changed code/evidence;
9 MCP privacy checks;6 new stabilization checks;7 GPL/source checks;
4 Injection corpus checks; MCP52/52 main and15/15 holdout,7/7 dependent; LotL9/9
dependent;36 catalog/27 hub PHP checks; JS filters; full125-file manifest check.
LotL unchanged main corpus:34/35 suspicious medium+ and0/45 benign medium+; holdout
13/15 suspicious and2/15 benign medium+. These are observed limitations, not perfect
accuracy or independent acceptance. No corpus threshold or holdout was retuned.

[All engine/PHP suite exits](stabilization-evidence/tools-tests-final.json),
[browser runs](stabilization-evidence/browser-summary.json),
[browser counts](stabilization-evidence/browser-counts.json),
[performance repeats](stabilization-evidence/performance-repeats.json),
[old CPU profiles summarized](stabilization-evidence/profiling-before.json),
[keyboard diagnosis](stabilization-evidence/keyboard-diagnosis.json).
Earlier initial version-label assertion failures and EGL diagnostic remain retained;
final runs were actually executed after correction. No failed run relabeled PASS.

## D6 and source delivery

[GPL-BOUNDARY.md](GPL-BOUNDARY.md) lists all8 explicitly GPL3-only LotL source files
and14 concrete shared GPLv2-or-later theme dependencies, with hashes in
[gpl-boundary.json](gpl-boundary.json). Original248 YAML and complete LICENSE/NOTICE/
README (251 files) remain available;7 offline checks reproduce data byte-for-byte
and reject altered input. Source archive remains
fa823d580bcbac5eb8ccd3eaa191ca34943a745985d5812f01f669a68794c8a6.
All8 public source/license URLs also passed anonymous HTTP200 and exact archive/
notice checks: [source-availability.json](source-availability.json).
No automatic GPL3 relicensing of other tools/agents. Shared-theme combined-work/
aggregate classification and ongoing source-offer obligations remain legal review
items. This is not a declaration of full legal compliance. See [LICENSES.md](LICENSES.md).

## Frozen package and preservation

- Source `54d43356fec8ca22f8d99c26fc5c28d5964c4d08`, theme Git tree `09bdf8b38031bb7b8059678d8c8d759b0d445de8`; all125 Git blobs verified.
- Archive `/home/cyberdat/cyberdat-deploy/tools-release-1-stabilized-package/theme.tar.gz`.
- SHA256 `9fae3b45f8edbb49e5ea31314183f0dc7909457e1b7b63cb745a9678531ad46b`.
- package.json SHA256 `590ffd091e8225776a661bd1a3a7e526dae8430f1445467e803dae8f4f2463b5`; full manifest.json and artifact-SHA256SUMS updated.
- Only125 theme files; no plugins/SQL/config/timers/helpers. Base95,4 modified/
  30 added, no deletions. Modes0644/0755, no links/extras,42 PHP files linted.
- [46/46 deployment sandbox tests](evidence-stabilization-deployment/tests.json),
  [10/10 isolated interlock tests](evidence-stabilization-interlocks/tests.json),
  no actual legacy deployment or rollback. Existing atomic exchange/selective
  pages-before-theme rollback mechanisms retained; no full SQL restoration.
- Live theme95 and43 Research/Content/unit/launcher fingerprints match;11+11
  interlock prefixes intact: [preservation proof](stabilization-evidence/preserved-staging.json).
- No WordPress bootstrap/SQL access, page changes, sync, checkpoint/backoff/timer/
  protected config/production changes, real rollback, new service or main merge.
- No new staging backup because no live change. Existing D15 scripts backup is
  /var/backups/cyberdat-staging/tools-d15-20261113T164151Z; not a new Tools install backup.

## Remaining D1 gates

No remaining critical technical FAIL in this stage. Overall PARTIAL because D6
legal scope remains UNVERIFIED, D1 is not approved and independent D14 product
acceptance is pending. D2/D4/D8/D9/D11 page/hub/SEO decisions remain separate;
all4 discoverable on the hub is still not claimed. Live FPM/OPcache/WordPress
selective restoration and installed HTTP/browser regression require a future
separately authorized deployment.22 historical out-of-scope scripts remain unsafe
to execute/restore; userspace interlocks cannot prevent arbitrary sudo bypass.

No automatic installation/publication or next phase. Stop after this report.

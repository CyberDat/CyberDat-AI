# Tools Release 1 — D5/D6/D7 Final Release Preparation

**Final verdict: PARTIAL. Installation under D1 is NOT authorized or performed.**
Branch `feat/tools-release-1-license-claims`, starting803da063. Final source/theme
revision `a5611f225ad1ff9858f84103036b73cc7c38568c`; evidence/control/documentation commit follows it on this branch.
No main merge or repository settings change.

## Decisions

| Decision | Result | Evidence/limit |
|---|---|---|
| D5 | PASS within the stated technical scope | False universal secret-concealment claims removed;9 new privacy checks +24 MCP engine checks pass; unknown free-form secret remains deliberately demonstrated/disclosed |
| D6 | PARTIAL | OptionA implemented: GPL notices/complete source delivery/rebuild/anonymous access pass; legal combined-work/theme scope remains UNVERIFIED |
| D7 | PASS | Repository remains public;8 source/license/archive URLs HTTP200 without auth/cookies, archive/notices SHA verified; no settings changed |

## Changes

File groups and purposes: [CHANGES-D567.md](CHANGES-D567.md).

MCP engine1.0.1 suppresses known token formats and additional structural credential
values (env/header/option/query/fragment), avoids arbitrary input in parser/policy
errors, redacts policy report warnings and preserves rule/severity metadata. UI,
comments, proposed editorial content and tests disclose best effort; policy downloads
are explicitly verbatim/unredacted. No public server/API or remote code execution.

All four Tools/hub/privacy copies distinguish tool behavior from browser extensions,
session restore/clipboard/downloads and secure erasure. Existing safety limitations
remain: no universal anonymization, no injection-safety guarantee, LotL matches are
not proof of malice, MCP does not audit remote server implementation. Details and
file-level scope: [CLAIMS-AUDIT.md](CLAIMS-AUDIT.md), [COPY-REVIEW.md](COPY-REVIEW.md).

LotL's four JS files, specific CSS/PHP and generator have GPLv3/date/copyright/
no-warranty notices. Complete original upstream LICENSE and MITRE NOTICE preserved
byte-for-byte.251 preferred-source files include248 original YAML with author/
acknowledgement fields, NOTICE, LICENSE, README. All source hashes match the pinned
upstream2056cb7; generator reproduces shipped data byte-for-byte and rejects altered
input. Source archive SHA256 fa823d580bcbac5eb8ccd3eaa191ca34943a745985d5812f01f669a68794c8a6.
UI links to license/notices/full theme source/preferred YAML archive; anonymous
HTTP proof is [source-availability.json](source-availability.json). Theme shared
GPLv2-or-later retained; independent agents/tools not blanket-relicensed. Legal
scope uncertainty is explicit: [LICENSES.md](LICENSES.md). GPL provisions consulted
are [GPLv3](https://www.gnu.org/licenses/gpl-3.0.html) and the
[GNU FAQ](https://www.gnu.org/licenses/gpl-faq.en.html).

## Actually executed tests

| Check | Actual result |
|---|---|
| Safe deployment/rollback sandbox, final new archive |46/46 PASS,0 errors/failures/skips; real atomic exchange/lock/lint/fault injection, fake JSON pages |
| D15 isolated guard AST |10/10 PASS; exact11+11 prefixes rechecked before executable bodies; no legacy body run |
| LotL GPL/source |7/7 PASS:251 source hashes,248 original YAML, verbatim notices, exact offline rebuild, tamper refusal, license scope disclosure |
| MCP |24 engine PASS,9 new privacy PASS;52/52 main corpus,15/15 holdout,7/7 dependent;51 PHP PASS |
| LotL |20 engine PASS, corpus guards PASS,9/9 dependent,47 PHP PASS |
| Injection |4 corpus PASS,42 PHP PASS; engine stops at pre-existing performance guard FAIL |
| Log Anonymizer |41 PHP PASS; engine stops at pre-existing performance guard FAIL |
| Chromium local browser |78 checks PASS: Log21/Injection21/LotL16/MCP20; storage/network/export/XSS/keyboard/responsive/contrast/no-JS |
| Firefox |Log14/LotL10/Injection13 completed; MCP10 then Ctrl+Enter wait timed out, FAIL/UNRESOLVED |
| WebKit |UNVERIFIED: launch blocked by missing host libraries; no system package/service installed |
| Manifest/catalog/hub |125-file SHA256/lengths/modes/no links exact;36 catalog/27 tools PHP checks and JS filters PASS |
| Token-shaped strings |18-rule scanner/self-test PASS over496 existing tracked text files; synthetic values constructed at test time, not literal real tokens |

Engine timing failures occurred before current changes and again on final code:
Log pathological ab: input12561ms vs4000ms (baseline11650ms); Injection zero-width
input4234.8ms vs4000ms (baseline4058.9ms). Unchanged engine bytes/thresholds; not
relabeled PASS. These require investigation/reliable passing verification before
READY. Full engine suites stop at the failed guard, so later engine checks are not
claimed. Browser large-file worker tests did complete independently.

All browser work used a standalone PHP renderer/loopback fixture, no WordPress or
SQL.33 local screenshots in claims-evidence/*-browser-verified/. Initial fixture
failures (missing theme tokens CSS, relative-link test resolution), old diagnostic
text assertion and public NOTICE newline normalization were corrected and rerun;
earlier failed logs are retained. MCP Firefox timeout and WebKit failures remain.

Evidence: [final46-test report](evidence-d567-final/tests.json),
[interlock tests](evidence-d567-interlocks/tests.json),
[engine/PHP results](claims-evidence/tools-tests-final.json),
[privacy tests](claims-evidence/mcp-release-privacy.sealed.txt),
[browser results](claims-evidence/browser-summary-final.json),
[Cross-browser attempts](claims-evidence/xbrowser-summary-final.json).

## Final package and preservation

- Source commit `a5611f225ad1ff9858f84103036b73cc7c38568c`, theme tree `e7f385e56de29a6eeb1fbcfe3b3107dfd96dbaf8`.
- Only125 theme files; base95 retained,4 modifications/30 additions, no deletions.
- All42 theme PHP files +3 controls lint PASS; all file/directory modes/links/file
  sets/hashes checked. Existing atomic deployment/selective rollback retained.
- Archive: `/home/cyberdat/cyberdat-deploy/tools-release-1-d567-package/theme.tar.gz`.
- SHA256 `783eec70b43bb7149c0fa0c122aadb23699cbf11534bd2070404849a6c1507ed`.
- package.json SHA256 `d49674a6abaa41821d402469a21fcd0fb31a99eba485980ea228d0cee4643cbf`.
- Full manifest updated. Previous7fc33b... and intermediate33975f... artifacts
  superseded; old hashes/authorizations must not be reused.
- Read-only live hashing: installed95-file theme exact +43 Research/Content/unit/
  launcher fingerprints match: [preserved proof](preserved-staging-d567.json).
  No WordPress bootstrap, SQL access/write, sync, page/status/timer/config change,
  production operation, real rollback or new service.
- No live change means no new staging backup. Existing D15 backup retained:
  `/var/backups/cyberdat-staging/tools-d15-20261113T164151Z`.

## Remaining D1 gates

D1 owner installation approval remains absent. D6 legal scope is unresolved;
two engine timing guards/MCP Firefox failure/WebKit coverage and independent D14
acceptance prevent READY. D2/D4/D8/D9/D11 page/hub/SEO decisions remain explicit;
no publication implied. Actual WordPress selective restore/FPM/OPcache/HTTP/CSP/
Research-Dashboard-Pulse acceptance follows a future separately authorized install.
D15 still covers only11+11 known paths;22 historical out-of-scope copies remain
unsafe to invoke/restore. Arbitrary sudo bypass is not prevented.

Next owner step: review D6 scope and the retained test failures; authorize only
that follow-up if desired. This report does not request or assume D1. Work stops.

# Tools Release1 — decisions after D14 Independent Product Acceptance

Preparation branch: feat/tools-release-1-license-claims, D14 task base0b73a9f.
Owner instructions supersede earlier alternatives; no installation authorization.

| ID | Current status | Consequence |
|---|---|---|
| D1 | NOT AUTHORIZED: package preparation/tests only | No staging install, page changes, publication or real rollback |
| D3 | DECIDED: retain Research0ef03e9; theme-only payload | Repository-root/plugin deployment forbidden |
| D5 | PASS for claim correction and bounded technical tests | Best-effort masking, export limits and browser-control limits disclosed; independent product acceptance still D14 |
| D6 | Owner selected A; PARTIAL technical delivery complete, legal combined-work/theme boundary UNVERIFIED | Resolve scope review before treating D6 as closed for installation |
| D7 | PASS: retain public repository, anonymous source URLs verified | No repository visibility/settings change; source access must remain available |
| D15 | PASS, previously APPLIED_APPROVED_SCOPE:11 repository +11 prepared entry points | Current static checks and10 isolated interlock tests pass; no reapplication today |
| D2 | Corrected catalog/manifests/200-renderer vs404 policy prepared; adoption by old SEO publication checks pending | Page publication/checks |
| D4 | Four canonical slugs still require explicit page-action confirmation; old lolbas-analyzer alias stays404 | Creating/changing pages |
| D8 | Hub release1.1 still lists3 tools; MCP1.2 direct URL implementation present | Claim that all4 are discoverable on hub is not accepted |
| D9 | Reuse of ID51/stale Rank Math description, old ID53 and removed backlog drafts not decided | Page/meta/SEO work |
| D11 | SEO publication/sitemap policy pending; protected legacy entry points do not approve SEO actions | SEO acceptance/publication |
| D14 | PARTIAL:40 new frozen examples,32 PASS / 8 FAIL; no fixes. Log7/10, Injection5/10, LotL10/10, MCP10/10 | Public release NOT READY; further closed manual evaluation requires D1/D6 and explicit limits |
| D10/D12/D13 | Naming unchanged; main merge not requested; historical scanner alerts not waived | No unrelated changes |

Technical stabilization PASS:61 Log/33 Injection/20 LotL/24 MCP engine checks,
9 privacy +6 new regressions,4006/245 frozen-result equivalence cases,174 browser
checks on Chromium/Firefox/WebKit,46 deployment tests and10 interlock tests.
Original4000ms limits/signatures unchanged;3-repeat worst times434.61/2393.13ms.
Firefox timeout was a test focus target error, not a product keyboard regression.
WebKit runs with private Debian13 libraries/Mesa; no OS installation/config change.

D6 remains PARTIAL.8 declared GPL3 files and14 shared dependencies now have exact
paths/hashes in GPL-BOUNDARY.md/gpl-boundary.json. Full source/notices delivery and
rebuild pass, but the shared-theme combined-work/aggregate legal question is not
settled by those technical checks. Do not declare full compliance or automatic
relicensing of Research/Content/SEO/other tools. D7 remains public, no settings change.
The earlier stabilization had no critical technical FAIL. New D14 product acceptance
has 8 functional/coverage/format failures and remains PARTIAL. No critical automatic
network leak or active input execution observed; HIGH sharing/trust risks remain.
[D14 evidence](d14-public/README.md). D1 still NOT authorized.

The22 historical source copies in d15-residual-paths.json remain outside approved
scope and unguarded. Never execute with sudo or restore them over guarded entry
points. Arbitrary root execution cannot be prevented by these userspace interlocks.
Do not expand maintenance scope automatically. Research timers/collectors do not
invoke these Python deployment entry points.

No decision authorizes automatic publication. Any later D1 must bind exact new
archive/package hashes, fresh staging identity/base/protected checks, controls and
expiry. authorization.example.json remains fail-closed. Existing Research rollback
hash guards remain unchanged and will refuse Tools theme drift.

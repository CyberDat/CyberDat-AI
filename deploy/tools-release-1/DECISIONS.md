# Tools Release 1 — reviewed controls consistency repair

Preparation branch: feat/tools-release-1-license-claims, D14 remediation base afa0b56.
The latest owner instruction authorizes only the pinned closed-staging D1 installation; mandatory safeguards still apply. It supersedes earlier no-install wording in historical reports/handoffs.

| ID | Current status | Consequence |
|---|---|---|
| D1 | Owner authorization retained; controls registry rebuilt from reviewed sources | Runtime deployment evidence held privately; no public operational inventory or page-publication authorization |
| D3 | DECIDED: retain Research0ef03e9; theme-only payload | Repository-root/plugin deployment forbidden |
| D5 | PASS for claim correction and bounded technical tests | Best-effort masking, export limits and browser-control limits disclosed; independent product acceptance still D14 |
| D6 | OWNER DECIDED option A for closed staging: LotL remains GPLv3, corresponding sources public, LICENSE/NOTICE retained | Owner authorizes D1 with this decision; legal shared-theme/combined-work boundary remains UNVERIFIED, no blanket compliance declaration |
| D7 | PASS: retain public repository, anonymous source URLs verified | No repository visibility/settings change; source access must remain available |
| D15 | PASS, previously APPLIED_APPROVED_SCOPE:11 repository +11 prepared entry points | Current static checks and10 isolated interlock tests pass; no reapplication today |
| D2 | Corrected catalog/manifests/200-renderer vs404 policy prepared; adoption by old SEO publication checks pending | Page publication/checks |
| D4 | Four canonical slugs still require explicit page-action confirmation; old lolbas-analyzer alias stays404 | Creating/changing pages |
| D8 | Hub release1.1 still lists3 tools; MCP1.2 direct URL implementation present | Claim that all4 are discoverable on hub is not accepted |
| D9 | Reuse of ID51/stale Rank Math description, old ID53 and removed backlog drafts not decided | Page/meta/SEO work |
| D11 | SEO publication/sitemap policy pending; protected legacy entry points do not approve SEO actions | SEO acceptance/publication |
| D14 | PASS: 40 original cases per browser and 32 new controls; 174 existing +24 new browser checks | Bounded acceptance closed; D1/D6 and page/SEO decisions remain separate |
| D10/D12/D13 | Naming unchanged; main merge not requested; historical scanner alerts not waived | No unrelated changes |

Historical technical stabilization PASS:61 Log/33 Injection/20 LotL/24 MCP engine checks,
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
D14 remediation fixes all eight original product failures; the original expected outcomes are unchanged. The 33 original signatures are intact; seven bounded families are additive. No universal detection or sanitation guarantee. All required tests PASS, while D6 legal scope remains UNVERIFIED; the latest owner D1 authorization is recorded below and controls consistency has been repaired; runtime execution evidence is retained privately. [Current evidence](d14-remediation/README.md); [historical acceptance](d14-public/README.md).

The22 historical source copies in d15-residual-paths.json remain outside approved
scope and unguarded. Never execute with sudo or restore them over guarded entry
points. Arbitrary root execution cannot be prevented by these userspace interlocks.
Do not expand maintenance scope automatically. Research timers/collectors do not
invoke these Python deployment entry points.

No decision authorizes automatic publication. D1 authorization must still bind the exact approved
archive/package hashes, fresh staging identity/base/protected checks, controls and
expiry. authorization.example.json remains fail-closed. Existing Research rollback
hash guards remain unchanged and will refuse Tools theme drift.

2026-11-14 artifact update: source f9cc1e9cca55a3f3587b12fe4228f86b2c55e9c3, archive SHA256 5ce6c412c8444d36e9ac2f6960c4ee71c3cea7fec3dc0468afd0a4ee9317bc8b. Exact new hashes supersede previous packages. No staging changes or publication.

Current remediation measurements and acceptance supersede historical timings: see d14-remediation/ACCEPTANCE.json. Original detection/sanitization limits, unknown-secret limitations and possible misses on long/compound/paraphrased inputs remain; D14 PASS is bounded to the tested criteria.

## Owner D6 + D1 execute decision — 2026-11-14 (historical checksum refusal)

Owner explicitly approved D6 option A: LotL remains GPLv3; corresponding sources stay public and LICENSE/NOTICE are retained. The legal boundary of the shared theme remains UNVERIFIED. This uncertainty is recorded, not treated as a missing owner decision or as full legal compliance.

D1 authorizes only the prepared closed-staging 125-file theme archive SHA256 `5ce6c412c8444d36e9ac2f6960c4ee71c3cea7fec3dc0468afd0a4ee9317bc8b` (package.json SHA256 `3ec45c9198efad34c5a107a58144032bf31a0d32832e2c6dfefba7600516a65e`). No new pages/publication, Research/Content/SEO, SQL/checkpoint/backoff, timers, production, unsafe legacy execution or full SQL restore authorized.

**D1 result: BLOCKED before any deployed change.** The mandatory helper-integrity comparison checked nine controls: eight match; `deploy-theme.py` does not. controls-sha256.json pins `fdc7fa951640b950267b7540e9b08850ec2f778091dfa8b17ca99f873fac8bbf`; actual SHA256 is `8879fd4a8a21a1511357e499fc27747d23cea2f75fd734a418ea7e95908e4046`. The actual helper matches its committed Git blob `27848287d42104a2c3a9b5b59830516e62946b12` at base7fe3788, so the inconsistency is present in the prepared controls. No manifest/helper rewrite, control sealing, staging backup/theme switch, WordPress/SQL operation, forced sync or rollback was performed. The separate sudo preflight invocation did not execute because it lacked a matching cached sudo context. Staging remains unchanged; current WordPress health was not verified in this blocked attempt. Stop as required; reconciling the pin is a separate owner task, not silently included here.

## Reviewed controls source repair

Approved installer provenance: ae48da0 changed target123 to125 for added notices; the registry stayed old. build-controls.py regenerates the full registry from reviewed Git blobs and exact reviewed deltas, with package binding and unchanged identity/authorization gates. Canonical-slug lookup fixes the tested WP-CLI local-include snapshot warning (6ec9ff0); warnings are not suppressed. Controls build checks8/8 and deployment sandbox checks46/46 pass; full D14 not rerun. Runtime paths, backup inventory, route state and health are owner-private and omitted here. D6 optionA and UNVERIFIED legal boundary remain; no publication authorization.

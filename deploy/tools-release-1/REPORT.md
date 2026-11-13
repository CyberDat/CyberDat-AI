# Tools Release1 — D14 Independent Product Acceptance

**D14 PARTIAL: 32 PASS / 8 FAIL across40 new frozen product examples.**
Base0b73a9f98d1da980051865cfa4896827074ab49e; branch
feat/tools-release-1-license-claims. No product code, rules, thresholds or old
expectations changed. Full method,40 per-case expected/actual/risks and evidence:
[d14-public/README.md](d14-public/README.md), [machine acceptance](d14-public/ACCEPTANCE.json).

| Tool | PASS | FAIL | Findings |
|---|---:|---:|---|
|Log Anonymizer |7 |3 |Full name/phone and indirect CEF credential remain; small-file upload changes CRLF→LF |
|Prompt Injection Detector |5 |5 |Paraphrase/Spanish misses; Russian attack only low; incomplete indirect-attack sanitation; benign report medium FP |
|LotL Analyzer |10 |0 |New suspicious/benign/encoded examples pass; bounded set, prior limitations remain |
|MCP Checker |10 |0 |Known/opaque/userinfo secrets, invalid JSON, policy/report export and inert poisoned HTML pass their specific expectations |

Per-case matrices: [Log](d14-public/LOG.md), [Injection](d14-public/INJECTION.md),
[LotL](d14-public/LOTL.md), [MCP](d14-public/MCP.md). The full inputs remain private; public 40-case matrices contain minimized semantic
expected/actual/risks and original evidence hashes. Inputs/expectations frozen before first run,
SHA25690af74dd5a38336d05b93366bc719be15a04b1c97fcde41b6ac236a38635399d.
The set is newly authored separately from old fixtures; the author has worked on
the implementation, so this is not an externally independent human audit.

## Failure interpretation

- LA05: person_name and contact_phone untouched; desired PII coverage gap.
- LA06: IP/user/host masked, cs1 credential identified via cs1Label left intact;
  indirect-field coverage gap. These are HIGH sharing risks if real inputs are shared
  without review, not observed network exfiltration or a universal-detection promise.
- LA07: synthetic key body masked. File.text has6 CR/6 LF, textarea has0 CR/6 LF,
  direct engine preserves6/6. The unchanged app.js loadFile lines182–185 copies small
  files through textarea. [Unscored localization](d14-public/LA07-localization.json).
- PI02: high PI-OVR-005 concealment finding, but the read-credentials + HTTP POST
  instruction remains in sanitized text. High detection is not successful sanitation.
- PI04/PI06: zero findings on English paraphrase/Spanish attack, full FN cases.
- PI07: two low PI-EXT-020 findings and partial removal, not a complete miss;
  fails the predeclared minimum medium, important for threshold-based triage.
- PI08: medium PI-OVR-006 on the benign negated phrase not an instruction to the
  assistant. The quoted attack itself is low.1 FP case in this new set.

All 8 failures reproduced with identical failed predicates in Firefox142 and WebKit26;
16 repetitions are confirmation, not additional scored examples. No fixes applied.

## Security/privacy observation

Actual UI/worker/export tests in Chromium141, fresh contexts and an isolated PHP
fixture, not staging/WordPress.370 expected static GETs;0 requests after input,
0 bodies/unexpected network attempts,0 JS/console/CSP errors,0 observed web-storage
writes or active HTML/script execution.50 real exports were local blobs. No known
synthetic credential was found in MCP report/error/console outside the input field.
No critical automatic exfiltration/execution was observed. HIGH product sharing/
trust risks above remain. See the bounded-scope/export warnings in d14-public/README.md.

## Readiness and remaining decisions

Closed staging: **PARTIAL**, further restricted manual testing only after separate
D1 authorization and D6 decision; no deployment is authorized now. Public release:
**NOT READY**, D14 not closed with 8 FAIL. D6 legal combined-work/aggregate scope
remains UNVERIFIED; D2/D4/D8/D9/D11 page/hub/SEO decisions remain separate. There is
no new GPL compliance declaration or automatic relicensing.

Tool theme125 and existing archive remain unchanged. Archive SHA256:
9fae3b45f8edbb49e5ea31314183f0dc7909457e1b7b63cb745a9678531ad46b.
No package rebuild, staging/theme/pages/Research/Content/SEO/SQL/systemd/production
access/change, real rollback or main merge. No new staging backup because no live
change. Existing stabilization46/10/174 PASS are previous-stage evidence; these new
product failures are not waived by them. Prior report is retained at base commit0b73.

Potential repairs require a separate owner instruction. Work stops after this report.

Detailed-evidence publication was rejected by automatic approval review because
of personal-looking/credential-like/sensitive-path strings. Only minimized public
summaries are committed; full synthetic definitions, raw private downloads and
harness remain local. Test expectations and32/8 results unchanged.

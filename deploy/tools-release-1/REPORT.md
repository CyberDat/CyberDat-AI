# Tools Release 1 — D14 Remediation, 2026-11-14

**D14 PASS: all 40 original criteria and additional checks passed. Release readiness remains PARTIAL: D6 unresolved; D1 installation is NOT authorized.**

Base `afa0b56fd0db2fe277e4e006231353cf27b89d35`, branch `feat/tools-release-1-license-claims`. [Detailed minimized acceptance](d14-remediation/README.md), [machine results](d14-remediation/ACCEPTANCE.json). Original independent acceptance remains historical at base commit; its eight failures were retained and repaired, not redefined.

| Defect | Result | Repair and observed behavior |
|---|---|---|
| LA05 | PASS | Explicit person/contact name and telephone fields, Unicode name validation and bounded phone formats; dedicated independently toggleable categories. Original required values now masked. |
| LA06 | PASS | CEF custom-string cs1–cs6 labels resolved to their matching value within one event, including reverse order and escaped content; other fields preserved. |
| LA07 | PASS | Small-file textarea is a preview; the worker retains the original File until a real edit. CRLF preserved; stale async preview reads cannot replace newer input. Large-file path unchanged. |
| PI02 | PASS | New bounded read-sensitive-file/transfer-contents family removes the dangerous instruction in the original sanitized output. Output remains explicitly Still untrusted. |
| PI04 | PASS | Bounded authority-replacement and confidential-startup-instruction extraction families detect the original paraphrase. No general semantic-understanding claim. |
| PI06 | PASS | Spanish disregard-prior-instructions and internal-instruction extraction families detect the original attack and new variants. |
| PI07 | PASS | Russian prior-instruction invalidation and explicitly hidden/internal instruction extraction families raise the original scenario to High. Existing low findings are retained. |
| PI08 | PASS | Narrow PI-OVR-006 negated meta-address handling removes the benign Medium FP; later independent attacks are still detected. Quoted evidence remains context-sensitive. |

Original matrices: [Log 10/10](d14-remediation/LOG.md), [Injection 10/10](d14-remediation/INJECTION.md), [LotL 10/10](d14-remediation/LOTL.md), [MCP 10/10](d14-remediation/MCP.md). Each 40-case set passed unchanged in Chromium, Firefox and WebKit (120 repeated UI executions, not 120 independent examples). Frozen original SHA256 `90af74dd5a38336d05b93366bc719be15a04b1c97fcde41b6ac236a38635399d` unchanged. 32 new controls frozen before code changes also PASS; raw fixtures stay private, [minimized holdouts](d14-remediation/HOLDOUTS.json).

## Regression evidence

- All 19 Node/PHP/privacy/corpus/source/controller suites exit 0. Engine checks: Log 61, Injection 33, LotL 20, MCP 24; 9 privacy and 6 stabilization checks PASS.
- All 33 original Injection text patterns, flags, descriptors and check-function source unchanged. Seven additive bounded lexical families plus narrow negated-address/Spanish direct-negation context changes: [exact rule inventory](d14-remediation/RULES.json). No signatures removed or thresholds lowered. Positive behavior verified for all 33: 32 from the existing attack corpus plus one after-implementation EXF-009 positive, not counted as a holdout. [Coverage](d14-remediation/RULE-COVERAGE.json).
- Frozen 4006 Log / 245 Injection behavior hashes still match. Projection only asserts and omits new zero-valued schema categories and normalizes the version label to its historical value for hash comparison. Output, map, warnings, findings, offsets, counts, preview and sanitization expectations remain unchanged; frozen hashes were not rewritten. Metadata/rendered-category/privacy-text assertions were updated for the actual new release, not to loosen detection outcomes.
- 174 existing UI checks + 24 new file-input checks PASS across Chromium/Firefox/WebKit. File tests cover CRLF/LF/mixed/lone-CR, 1 MiB boundary, large input, editing and delayed read races. An initial new WebKit file-test FAIL was localized to classifying a bodyless same-origin blob GET as network XHR; bytes were already exact. The classification was corrected and all 24 criteria rerun unchanged; no product/package edit. Physical Safari/iOS and installed WordPress/FPM remain UNVERIFIED.
- Original 4000 ms guards unchanged and PASS. Three fresh-process worst measurements: Log 530.67 ms, Injection 2756.89 ms. New near-match stress inputs also PASS; repeated contact keys 2939.05 ms. Existing large multi-MB limits remain separate.
- No unexpected network attempts, request bodies, runtime/console/CSP errors or active input execution in the 120 repeated original-case runs; local blob exports only. Specific known/opaque MCP masking criteria pass. This does not guarantee universal masking, sanitation or whole-browser privacy; export limitations remain explicit.

## Changed implementation

Only six theme files: Log engine/app/PHP metadata/limitation markup and Injection engine/PHP metadata. Log 1.0.3, Injection 1.0.2, rulesets 2026-11-14.1. Existing test changes are limited to actual metadata/category counts/scoped limitation text and the explicit compatibility projection above; two new runners require private fixtures or use non-sensitive line-ending text. LotL/MCP implementation, all eight declared GPL files and notices/source archive are unchanged. No new dependencies or services.

## Package and boundaries

Theme source commit `f9cc1e9cca55a3f3587b12fe4228f86b2c55e9c3`, tree `0324800d705f74da563d371c0f60acde56873dee`. Reproducible theme-only package at `/home/cyberdat/cyberdat-deploy/tools-release-1-d14-remediation-package/`.

- Archive SHA256: `5ce6c412c8444d36e9ac2f6960c4ee71c3cea7fec3dc0468afd0a4ee9317bc8b`.
- package.json SHA256: `3ec45c9198efad34c5a107a58144032bf31a0d32832e2c6dfefba7600516a65e`.
- 125 target / 95 base files, 34 deltas (4 modified / 30 added over Research acceptance); no deletions. All file hashes/set/modes verified, no links/nonregular members; files 0644, directories 0755.
- Mandatory 42 theme PHP lint + 46/46 deployment and 10/10 interlock tests PASS. Real Linux atomic exchange tested only in sandbox; no real legacy body, deployment or rollback executed.
- Atomic switch, staged identity checks, selective page/meta-before-theme rollback and D15 mechanisms unchanged. Earlier package hashes are superseded and cannot authorize this artifact.

D6 remains PARTIAL: eight declared GPL source files unchanged, notices and corresponding sources retained; shared-theme combined-work/aggregate legal scope UNVERIFIED. No automatic relicensing. D1 remains NOT authorized; page/hub/SEO decisions D2/D4/D8/D9/D11 are separate. No staging/theme/page, Research/Content/SEO, SQL/checkpoint/backoff, systemd, production, repository-settings or main change.

Private definitions/results/screenshots were not published. Automatic review initially rejected full-source egress because of pre-existing public examples. A SHA-verified public-base comparison established no new credential/person/private-target literals in the changed lines; reviewed retry approved. Only minimized acceptance evidence is committed. Local pre-edit backup retained; no staging backup because no deployed change. Scope limits are in the detailed report. Stop after report; installation requires a separate owner instruction.

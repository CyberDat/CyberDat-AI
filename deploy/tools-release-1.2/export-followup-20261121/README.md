# BOM / ATLAS export follow-up — 2026-11-21

Scope: integration/tools-release-1.2; exact parent 838fecc8a817f6fbab776131787ea6f8d6138a46. No installation, WordPress write, main update, Research/Content/SEO change or private-fixture publication.

## Changes

- BOM 1.0.3: weights.file uses the general export mask, including conservative long/hex values. Findings mask location/evidence before constructing VER-003, WGT-001, WGT-004, DAT-001, DAT-002, LIC-002 and DEP-001. Review inventory display uses the same redacted inventory as exports. Canonical editable input stays in memory; typed validated digests/revisions keep their prior treatment.
- ATLAS 1.0.3: every URL query value is considered independently of its parameter name; percent encoding is decoded before inspecting long token-shaped values. Replacement uses original source spans and preserves other parameters, scheme, host and fragment. Unicode classes use u; no look-behind.
- Manifest revision tools-release-1.2/3 identifies an actual theme subtree, not the unavailable 581c3f0 commit. theme_reference_type=tree and theme_tree are authoritative; legacy theme_commit is an explicit alias for the same tree so old readers can pass it to the updated builder. source_base_commit is the existing GitHub parent. The final root commit includes this subtree; publication verifies identical local/API root trees before updating the ref.

## Executed regression

- New synthetic helper-based checks: baseline 7/34 PASS, 27 FAIL; final 34/34 PASS. The extra Review inventory assertion exposed an intermediate leak and is retained. No raw probe value, private fixture or export is published.
- Existing tools12-masking-review-regression: 32/32 PASS; tools12-export-redaction-regression: 20/20 PASS.
- BOM engine 11 checks PASS; corpus 86/86 and previous held-out 19/20 unchanged (Russian unknown-marker coverage). ATLAS engine 9 checks PASS, main profiles 13/13, findings 55/55, benign 7/7; held-out profiles 3/3, findings 14/14, benign 3/3. Unicode contract 4/4 PASS; BOM/ATLAS PHP checks PASS.
- One completed focused browser matrix: BOM and ATLAS once in Chromium, Firefox and WebKit, 6/6 PASS, JSON/Markdown local downloads, 0 post-input HTTP requests, 0 runtime/console errors, XSS not executed, translate=no. Firefox uses no interception; completeness of Firefox worker-network observation remains UNVERIFIED. An earlier launch could not connect to the terminated sandbox; it loaded no application and is retained privately as infrastructure evidence.
- Required expectation change: ai-bom-engine clean round-trip used to exempt untyped filenames from conservative masking. It now checks an explicit masked filename, absence of the original in both exports, and exact equality of every remaining field. No rule catalogue, corpus expectation or performance threshold changed.

Masking remains best effort. Conservative false positives for long benign filenames are expected; arbitrary/short unlabelled secrets are not guaranteed to be detected. No mapping rules or ATLAS data/license files changed. This regression is dependent and does not replace independent owner review.

## Package

23 declared delta files; 125-file reference base and 146-file reference target. It is NOT a live-theme installer. Future installation requires an approved rebase over the verified current staging theme, preserving LA Stage1 and Hub. No installation is authorized by this task.

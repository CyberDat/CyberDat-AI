# Task0 — secret-safe exports: remediation report

2026-11-20. Branch `fix/tools12-secret-export`, based on `integration/tools-release-1.2` at `2a4cfbe8a7ff94508944eb4fd67a4755ffa8ae2f`.

## Tests before implementation

Public test-first commit: `63af024b38ee1d929c5c8efe10a31e3de166b9a3` (local equivalent `5e78dbe`, identical tree8a1c6449d6f2d1c40045cb0a2509995db48a5b49). The engines were unchanged in that commit.
Actual baseline: **5/20 PASS,15/20 FAIL**, saved in `security-export-fix/before.json`.
No private independent-acceptance fixture, raw export, personal-looking input or credential value is published. Regression inputs reference existing synthetic factories.

One test was corrected for scope after the first fix run: BOM-06 originally searched the entire JSON for a value also deliberately used as a validated public weights digest. It now inspects the free-text purpose field, while BOM-07 separately requires the digest to survive. The corrected test still fails the unchanged base; its baseline remains5/20,15FAIL (`before-scoped.json`). The requirement to mask the secret was not removed. The first implementation's19/20 result is retained privately.

## Implementation

Fixed source commit: `a5d4f842bfc85f56642e5d332bbccd6db968f2c4` (local `4213995`, identical tree1a331ca09430372974d280bbefcf5cba7fb0c7c4).

**AI Model BOM:** every export helper redacts a copy of the canonical inventory before generating CycloneDX JSON/Markdown. This avoids trying to redact already-escaped serialization. Actual exports and previews share safe data; the raw-export checkbox/override and obsolete instructions are removed. A warning tells the operator to remove secrets from the original source. Unknown long token-shaped values are handled conservatively, including free-text hex and long URL-query values. Dedicated validated weights hashes, exact revision ids and ordinary typed filenames retain their public-identifier semantics; URL syntax is preserved unless sensitive components need masking. Input data is not mutated and remains in memory for editing; no raw export route exists.

**ATLAS Mapper:** explicit secret assignments, including quoted JSON values, use the same maskSecrets path as findings and notes. Notes are masked before truncation. Every user-controlled selection source and supplied timestamp also passes masking. Long unknown token-shaped values are conservative. JSON and Markdown use the same redacted item list, before Markdown escaping. ATLAS mapping rules, ids, snapshot and licenses are unchanged. Engine versions1.0.1; PHP constants aligned.

Masking remains heuristic, not a guarantee for every possible secret. Conservative masking can hide benign long identifiers; review the result. No new dependency, network service or LLM was added.

## Actual checks

- Focused regression: **20/20 PASS**.
- One post-fix three-browser run: **6/6 PASS** — BOM and ATLAS once in Chromium, Firefox and WebKit; JSON/Markdown exports parsed/inspected after Markdown decoding, known/assigned/unknown values absent. No open-export acknowledgement remains.
- All6 scenarios:0 post-input HTTP requests,0 runtime/console errors, XSS probe not executed; local blob downloads and translate=no result containers verified. Firefox had no interception.
-48 theme PHP files lint PASS. BOM engine11 checks PASS, including80 Build structure/round-trip cases,10 secret-format cases, Unicode, parser and4.9MB input (6047ms under existing10000ms guard). Clean records retain exact round trips; secret-containing exports deliberately do not restore secret values. Non-secret findings survive re-import.
- Existing BOM corpus86/86; previous held-out19/20 remains19/20 (not relabelled). ATLAS engine9 checks and corpus guards PASS; Unicode contract4/4 PASS. Publisher corpora remain dependent. No private LA D14 was rerun and no new independent acceptance score is claimed.
- Existing browser tests were updated from the now-forbidden raw-export acknowledgement contract to masked exports. Only the focused6-case browser matrix was executed in this task; no claim that every legacy browser suite ran.

## Seven-tool export inventory

Source inspection plus synthetic engine probes, not a new full browser acceptance of every legacy mode. The LA probe uses the accepted Stage1 source, whose engine hash was verified against its accepted package manifest; the integration branch's older LA code was not substituted for installed Stage1.

| Tool | Export channel | Observed handling | Status |
|---|---|---|---|
| Log Anonymizer Stage1 | anonymized log | assigned password/known provider token masked; an unlabelled unknown opaque value remains |PARTIAL, existing coverage limit|
| Log Anonymizer Stage1 | replacement map | intentionally contains original sensitive values behind its separate warning/acknowledgement |RAW BY DESIGN|
| Prompt Injection Detector | sanitized copy; finding excerpts | injection removal is not secret masking; synthetic secret remains in sanitized text; report excerpts copy source text |RAW/PARTIAL|
| LotL Analyzer | analysis JSON | original command lines, including the synthetic password, are retained |RAW BY DESIGN|
| MCP Checker | findings report | known token masked in probe; best-effort scope only |PASS for probe|
| MCP Checker | policy JSON download | explicitly verbatim, without redaction |RAW BY DESIGN|
| Leak Inspector | findings JSON | tested assigned/known/opaque values masked |PASS for probe|
| AI Model BOM | CycloneDX JSON/Markdown | redaction before formatting, no override |FIXED; browser PASS|
| ATLAS Mapper | selection JSON/Markdown | notes/source/user strings redacted before formatting |FIXED; browser PASS|

Therefore **“all exports of all seven tools are anonymized” is false**. Intentional map/policy/raw-command functionality and existing opaque-value limits were not silently rewritten or excused. This Task0 fixes the two named defects; extending one uniform export policy to legacy raw modes requires an explicit product decision and separate implementation. No absolute masking promise is made. Detailed minimized evidence: `security-export-fix/export-surfaces.json`; diagnostic script: `tests/tools-export-surface-audit.cjs`.

## Package

Revision `tools-release-1.2/2`. Source-delta archive `theme-delta.tar.gz`:

SHA256 **`44e698d3b80d9615e368f1b234c114ad007ef73ed6bb86747c6f329a7941a583`**.
Manifest SHA256 `8e49b58462fd56d97fd0ce3797d7bb319995295802fa6acd1b18d8557cb5a9ef`.

Exactly23 delta files:21 additions and2 integration changes over reference base125; reference snapshot146. Each archive member SHA256/size/mode0644 matches manifest; no unexpected files or symlinks. ATLAS data and both license files remain included and byte-identical. Archive is deterministic (sorted entries, fixed timestamps).

This is **a source delta, not a full-theme deployment package**. Current staging has accepted LA Stage1/Hub changes outside the old reference base. Any later owner-authorized installation must compose only this delta over a fresh verified current theme. No runtime installation controls, WordPress pages/catalogue status, staging, Research/Content, timers/checkpoints/backoff, production or main were changed. No deployment or rollback was run.

Merge into integration is separately recorded by its resulting commit; the test-first and fix commits remain in history. Original independent functional failures remain documented; this remediation is not an assertion that the whole release is ready for production.

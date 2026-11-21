# BOM/ATLAS masking review — 2026-11-21

Owner requested four bounded corrections on integration/tools-release-1.2, package revision tools-release-1.2/2 (base6b7d97ca). This is dependent remediation/regression, not independent acceptance. No staging access or installation, no WordPress/agents/systemd/SEO change, no main update.

## Changes

1. AIBOM-WGT-001 redacts the complete invalid hash before its24-character display limit. Build findings, Markdown and Review use the safe evidence. Valid typed weights digests stay public and unchanged.
2. Long-value scanning in both engines consumes Unicode letters/numbers/combining marks with the u flag, so Cyrillic, NFC accents and NFD combining marks do not hide an attached token. Ordinary long Unicode words remain readable: non-ASCII values without numbers are only treated as token-like when a known credential format matches. This remains heuristic; arbitrary all-letter secrets and other unknown formats are not guaranteed to be detected. Existing ASCII conservative export behavior is retained. No look-behind, new dependency or network API.
3. BOM masks long URL path components before URL-level credential findings or clipping can retain their original text. Query/userinfo combinations are covered too; hostname, safe paths and validated typed digest/revision handling stay intact.
4. ATLAS scans URL userinfo and tail values separately. Assignment matching accepts only the existing recognized sensitive keys with Unicode-aware boundaries; it cannot start at https:. Thus a later ?token= value is no longer consumed as part of a rejected scheme assignment. Userinfo, named query values, fragments and safe URLs are covered. URL component inspection preserves conservative long-value masking without masking an ordinary hostname/path as one opaque token.

Only four theme files change: two engine.js files and their two PHP asset-version constants. Engines1.0.2; rule catalogues, ATLAS data/licenses, apps/workers/templates and all other tools unchanged.

## Tests and scope correction

New review regression file:32 checks, using only existing synthetic-secrets.cjs factories. Local test-first commit bc30722 records tests before implementation. The initial baseline6/32 included a boundary control whose whole key=value text already exceeded the conservative opaque-value threshold. That control now uses a shorter existing synthetic factory to isolate key matching; the expected behavior (ordinary unrelated key/value text remains unchanged) was retained. Scoped original-engine baseline7/32 PASS,25 FAIL is preserved in before.json. An initial URL assertion also needed to read the existing CycloneDX source-property fallback when redaction makes a URL non-URL-like; no secret-removal requirement was dropped. Initial diagnostics remain private.

Targeted development checks exposed a combined URL/finding leak and an ordinary long German-word false positive. Both were fixed; the original corpus expectations were not changed. The one completed final regression sweep passes all8 suites in regression.json; earlier aborted development runs are retained privately, not represented as successful acceptance.

- New targeted32/32 PASS; previous export regression20/20 PASS.
- BOM engine11 checks PASS, including full corpus/round-trip checks, existing main86/86 and held-out19/20 (the known unrelated miss remains19/20, not relabelled),4.9MB Review6121ms under unchanged10000ms bound.
- ATLAS engine9 checks PASS; profiles13/13+3/3; mapped findings55/55+14/14; benign7/7+3/3. Mapping rules/data/expectations unchanged.
- Existing Unicode contract4/4 and both PHP suites PASS. No full D14 or unrelated browser acceptance rerun.
- One focused Chromium/Firefox/WebKit matrix6/6 PASS. It exercises Build+Review truncated-hash evidence, Unicode attachment, URL-path exports, ATLAS query/userinfo and JSON/Markdown exports through the actual browser UI.0 post-input HTTP,0 runtime/console errors, no XSS execution in the synthetic probe. Firefox has no interception; network completeness remains UNVERIFIED.

Only minimized case IDs, boolean outcomes and counts are in this folder. Synthetic token/password values are assembled at runtime by the pre-existing factory; no real credential, private fixture, raw export, screenshot or private path is published.

## Package and limits

The existing1.2/2 source-delta builder is used to refresh manifest and archive after the source fix; the final artifact hash is in artifact-sha256.json. Installed staging is deliberately not changed. Any future installation needs separate owner approval and rebasing over the current accepted theme; no controls profile or authorization changed.

Masking remains best effort, not a promise that every secret is detected. Conservative long URL components may also be public identifiers. Existing raw-export gaps in tools1–4 remain a public-launch blocker. Claude Code will perform the requested read-only review after publication.

Current locally rebuilt source delta: `252815d1c7464e3643c68d073d8e18537b04b804fbc2dd92ec699e61ca022f92` (23 files); manifest `6c3ae3a96e3ce49a06e4fa00679b35479073a0a1f391c2c05c2ce88f8027ffd5`; local tested source `581c3f0fc22fa8385052994cc4611fadd662e81b`. No remote publication or staging installation was performed in this task; publication awaits explicit owner clarification.

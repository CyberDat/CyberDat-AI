# Tools Hub — Cyber Command + Cyber Glass

Status: implemented and tested in an isolated Git worktree; ready for owner visual review. **No staging deployment, merge or WordPress mutation.** Base: `24a333ddf2f91499b0b693f3810181990f8ec8e4`; branch: `feat/tools-hub-cyber-glass`.

## Presentation

The Hub now has a shield/orbit/grid hero, four-column operational deck on wide screens, two-column intermediate layout and single-column mobile cards. Large, distinct vector previews replace the repeated small-icon composition. Operational cards have an availability badge, category, illustration, unchanged catalogue title/description and an obvious action. Planned entries form a subordinate grid with their original names, categories, descriptions and release labels; none receives a fake link. Artwork is explicitly illustrative, not analysis output. All text that explains the tool remains normal HTML.

Every one of the ten current catalogue entries has dedicated SVG artwork. Preview fragments are synthetic, with no real credentials, personal information or executable payloads. The hero is hidden on narrow screens. Hover lighting/elevation is modest, with no continuous animation and a reduced-motion override.

Availability still requires both catalogue availability and a ready WordPress permalink. Neither the catalogue nor `cyberdat_ready_tools()` was modified. The template groups actual ready entries rather than hardcoding four cards. A future-readiness fixture promotes the next planned entry **in memory only** and verifies five featured cards without losing any entries. This is not a claim that Claude's fifth tool is implemented, approved or deployed.

The existing filter remains the only implementation. Two small additions hide group headings when every card in that group is filtered out. Native buttons retain keyboard/touch operation, aria-pressed and the polite live count. All cards render without JavaScript. New CSS is enqueued only by the Hub template; shared styles, branding/navigation, individual tools, engines, workers, routes and SEO code are unchanged.

## Verification actually executed

- Original PHP catalogue/readiness/navigation predicates pass; only four WordPress asset-function doubles were added for the new enqueue/image calls.
- Existing filter unit test passes; Hub PHP lint and all SVG XML/safe-resource checks pass.
- Chromium 141 and Firefox 142: 320,375,768,1024,1440,1920 px — 12 combinations,72 category checks. No horizontal overflow, lost cards or browser console/runtime errors; four correct operational links and six non-clickable planned cards.
- Keyboard focus/reset, touch emulation,44 px filter targets, empty-group hiding, no-ready and future-ready scenarios, and reduced motion pass. Important copy is not clipped or line-clamped. Text palette contrast is at least7.35:1 for the tested conservative foreground/background pairs.
- Actual captured WordPress shell/Rank Math head is reused for both isolated variants. SEO title, description, canonical, Open Graph, robots and JSON-LD compare identically across all twelve cases; one Hub H1 and unchanged navigation remain. This is an isolated presentation test, not a new deployed WordPress check.
- All preview requests are restricted to the loopback origin. Unchanged baseline WordPress emoji JS is mirrored locally, not requested from staging. Illustrations are lazily loaded static files; the filter test finishes decoding them before measuring filter-only requests. Filter interactions then produce zero requests. No remote image, font, analytics or new network API was introduced.
- Visual inspection compared desktop1440 and mobile320/375 screenshots against the previous layout. Clean before/after desktop/mobile captures and a comparison sheet are delivered owner-locally. Owner approval remains pending. Physical-device testing is UNVERIFIED; mobile evidence uses viewport/touch emulation.
- WebKit: **UNVERIFIED for HTTPS**, as the isolated browser environment cannot navigate staging HTTPS correctly. TLS verification and system dependencies were not changed to bypass this limitation.

## Measured performance

Three cold Chromium contexts,375 px mobile viewport,4x CPU throttle,150 ms RTT,1.6 Mbps downstream and0.75 Mbps upstream, cache disabled. Local static preview uses the captured WordPress shell and real PHP template with explicit readiness doubles; it excludes live WordPress/database TTFB.

| Run | LCP | CLS | Maximum Event Timing interaction |
|---|---:|---:|---:|
| 1 |1008 ms|0|112 ms|
| 2 |1016 ms|0|136 ms|
| 3 |968 ms|0|136 ms|

Measured lab LCP/CLS meet the2.5 s/0.1 targets. The interaction values meet200 ms **as a lab proxy**; they are not field INP or a field p75 guarantee. Actual deployed Core Web Vitals and real-user INP remain UNVERIFIED until separately approved integration and measurement. Event Timing was unsupported or had no slow entries in some unthrottled cases; zero recorded entries does not mean zero interaction latency.

11 SVGs total20,484 bytes (8,149 bytes gzip); largest2,942 bytes. Hub CSS10,032 bytes (2,663 bytes gzip). Compression figures are reproducible gzip estimates, not a claim about configured server transfer encoding. No framework or remote dependency was added.

## Concurrency and deployment boundary

The existing source export and installed125-file theme were read only. Before/after installed theme SHA256 maps match the last confirmed `a9ec1e5f556e69344f6828b15c2e65ebea3ba1d05aa37e4714fb19cc69ea485f` revision. No active Claude checkout or process was exposed in this sandbox; uncommitted work outside it cannot be audited. Isolation and the explicit path allowlist prevent this task from writing to that work.

No catalogue, Research/Content/SEO agents, Threat Intelligence, tool renderer, worker, SQL, metadata, timer, checkpoint, deployment/security control or production file was edited. No deployment package was rebuilt and no deployment command ran. The installed package manifest deliberately remains a historical staging artifact; this source branch is not an installable approved package.

After Claude finishes, compare the then-current Hub template/catalogue/readiness with this branch, reconcile any shared-template edits, repeat focused browser checks for the actual operational set, and request owner approval for a freshly protected theme package. Do not deploy this worktree over a newer theme or run old deployment scripts. No automatic merge or installation is authorized.

## Files and reproducibility

Production changes are confined to `page-templates/tools.php`, `assets/css/tools-hub.css`, two supporting lines in `assets/js/tools-filter.js`, and the new `assets/images/tools-hub/` assets/readme. Tests: existing catalogue doubles plus new `tools-hub-render.php`, `tools-hub-preview.py`, `tools-hub-browser.test.cjs`. Documentation: this report, minimized acceptance/scope JSON and `docs/PROJECT_STATUS.md`. Exact allowlist: `scope.json`.

Use a private read-only HTML export of the current Hub as the baseline. Do not commit credentials, captures, raw reports or screenshots. The static preview starts no WordPress or database process:

```sh
python3 tests/tools-hub-preview.py --baseline-html "$BASELINE_HTML" \
  --baseline-filter "$BASELINE_FILTER" --output "$PREVIEW_OUTPUT" \
  --wordpress-public "$WP_PUBLIC" --port 18115
node tests/tools-hub-browser.test.cjs http://127.0.0.1:18115 "$FRESH_EVIDENCE_DIR"
php -n tests/tools-catalog.test.php
node tests/tools-filter.test.cjs
```

`BASELINE_FILTER` is the original filter script exported from the base commit; `WP_PUBLIC` supplies optional first-party core static files read only. Browser test prerequisites: Node22, Playwright1.56.1 and privately available Chromium/Firefox runtimes. The browser harness refuses non-loopback origins and requires a new evidence directory. Stop the preview after testing. No system-service or system-package installation is required.

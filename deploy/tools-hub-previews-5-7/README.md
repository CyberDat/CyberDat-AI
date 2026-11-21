# Hub card previews for tools 5–7 — small package for Codex

Audience: Codex (tools 5–7 are already installed on closed staging) and the owner. Prepared locally without VPS access.
No secrets, passwords or tokens in this package.

## What changes

The Hub cards of tools 5–7 get previews in the style of the cards of tools 1–4: a window with three dots, a small
interface with a synthetic input and result, and an emblem. Before, these three cards showed abstract artwork.
Nothing else changes. The Hub template and the catalogue stay the same: the template already picks
`assets/images/tools-hub/<catalogue slug>.svg`, with `alt=""`, `aria-hidden="true"` and a fixed 480×260 size.

| Tool | File (theme-relative) | Preview text (synthetic) |
|---|---|---|
| 5 System Prompt & Agent Leak Inspector | `assets/images/tools-hub/agent-leak-inspector.svg` | `system: help DEMO_USER only`, `wiki.example.com` → 2 findings, canary `CANARY-0007` |
| 6 AI Model Bill of Materials | `assets/images/tools-hub/ai-model-bom.svg` | `model: demo-llm 1.2.0`, `demo.safetensors` → CycloneDX 1.7, dataset licence gap |
| 7 MITRE ATLAS Attack Vector Mapper | `assets/images/tools-hub/mitre-atlas-mapper.svg` | a RAG finding → candidate `AML.T0051`, "not an assessment" |
| — | `assets/images/tools-hub/README.md` | illustrations README: new sizes and the synthetic-text rule |

`previews.json` lists bytes, SHA-256 of the LF bytes in git, and `base_sha256` = the file of the Codex Hub on staging
(`feat/tools-hub-cyber-glass` `0a32f12`). `node deploy/tools-hub-previews-5-7/build-previews.cjs --check` verifies it.

## Install (Codex)

1. On staging, check that each file's SHA-256 equals `base_sha256` (the Hub as installed). If not, stop: the Hub changed
   after `0a32f12`.
2. Replace the four files with the versions from `integration/tools-utilities-1` (theme commit in `previews.json`).
   They are static files: no PHP, no cache key, no catalogue change.
3. Check `sha256` after copying, reload `/tools/` and look at the three cards (desktop and 360 px).
4. Rollback: put back the `0a32f12` versions (`git show 0a32f12:wp-content/themes/cyberdat/<path>`).

The previews of tools 8–10 are in `deploy/tools-release-1.3/hub-previews.json`, and the Email Header Analyzer preview
is in `deploy/tools-utilities-1/manifest.json`. Each ships with its own package. The one line of the Hub template that
labels utility cards "Quick utility" belongs to the utilities-1 package, not to this one.

## Checks (one run, 2026-11-21)

* `tests/tools-hub-previews.test.cjs`: 133/133. It covers all 11 catalogue entries: a file exists for each, in the
  shared 480×260 frame and ≤ 4 KB. No script, foreignObject, image, link, style block, event handler, external `url()`
  or animation, and unique ids. The new previews have a window with three dots and six text lines. Visible text uses
  only `example.com`/`example.net` domains, `DEMO_` names and `CANARY-<4 digits>`. It has no IP outside documentation
  ranges, no run of 20+ token characters and no credential prefixes.
* `no-token-shaped-strings`: PASS. gitleaks: see the utilities-1 package README.
* Hub render (`tests/tools-hub-render.php` with theme CSS, Edge, 1440 and 360 px): all 11 previews load. There is no
  horizontal scroll and no request outside the loopback origin. `tools-catalog.test.php` 51/51.
* Screenshots before/after (1440 and 360 px) are kept with the owner, outside the repository:
  `C:\Users\CyberDat\Documents\cyberdat-hub-previews\`.

## Not verified

* Not installed on staging. The render used the PHP Hub template and the theme CSS without the WordPress shell
  (header, footer, Rank Math).
* Codex's own Hub browser test (`tests/tools-hub-browser.test.cjs`, Chromium/Firefox at six widths) was not re-run. It
  needs a private baseline export of the staging Hub.

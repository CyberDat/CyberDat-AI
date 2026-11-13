# Privacy Shield Log Anonymizer — Tools release 1.1, tool 1

> **2026-11-13:** this tool is deployed as part of `integration/tools-release-1`. Its own `manifest.json` was replaced by the combined `deploy/tools-release-1/manifest.json`; follow `deploy/tools-release-1/HANDOFF.md`, not the staging steps below.


Status: **conditionally accepted (PARTIAL); iteration 2 (quality, checks, wording) done locally; staging
acceptance pending owner action.** Not deployed, not merged.
Branch: `feature/tools-log-anonymizer`, based on `feat/cyberdat-research-agent-0.8.3` @ `c3f9a5e`
(the newest linear tip; an older base would roll back theme changes that are already on staging).

## What changed

Theme-only change. No plugin, database schema, menu, SEO setting, Research/Content/SEO agent code, server
configuration or `docs/PROJECT_STATUS.md` is touched.

| File | Purpose |
| --- | --- |
| `wp-content/themes/cyberdat/functions.php` | +2 `require_once` lines |
| `inc/tool-security.php` | Strict CSP (+ nonce for WordPress scripts), `Referrer-Policy`, `nosniff`, `Permissions-Policy`, COOP and removal of the third-party emoji loader — **only on pages using the Tool template** |
| `inc/tool-log-anonymizer.php` | Registers the reviewed renderer via the existing `cyberdat/tool/renderer` filter for `/tools/log-anonymizer/` only; enqueues its assets on that page only |
| `template-parts/tools/log-anonymizer.php` | Server-rendered UI, "How it works", "Privacy", "Limitations" blocks |
| `assets/js/log-anonymizer/engine.js` | Detection/replacement engine (pure, no DOM/network/storage) |
| `assets/js/log-anonymizer/worker.js` | Web Worker: file decoding, engine run, network APIs disabled |
| `assets/js/log-anonymizer/app.js` | UI; user text only via `textContent`/text nodes |
| `assets/css/log-anonymizer.css` | Scoped `.cd-la` styles using existing CyberDat tokens |
| `inc/tools-catalog.json`, `page-templates/tools.php`, `assets/css/tools.css` (iteration 2) | `/tools/` catalogue: the ten tools of spec v1.0 as data; only release 1.1 is shown (3 cards + "More tools planned.") |
| `deploy/staging/tools-roadmap.json`, `tools-roadmap.md` (iteration 2) | Approved roadmap updated to spec v1.0 |

Publication still follows the 0.7 fail-closed contract in `inc/tools.php`: the page is only live when the
renderer exists **and** all editorial fields are filled **and** "reviewed" is ticked. Proposed English copy for
those fields is in [`editorial.json`](editorial.json) (needs owner review).

### `/tools/` catalogue

Three release 1.1 cards: Log Anonymizer, Indirect Prompt Injection Sanitizer & Detector, LotL / LOLBAS Command
Analyzer, followed by one line "More tools planned." The IoT, Modbus and Webhook cards are gone; backlog tools are
no longer in the catalogue data. A card says **Available** and links to the tool only when the catalogue marks it
available **and** its page passes the readiness check; otherwise it says **Coming soon** and is not a link.
Category filters are no longer rendered (`tools-filter.js` stays and is inert without them). The URL slugs
`/tools/prompt-sanitizer/`, `/tools/mcp-security-checker/`, `/tools/agent-leak-inspector/` follow the Stage 0.9
roadmap in `docs/PROJECT_STATUS.md` and should be confirmed by the owner before pages are created.

## Privacy and security design

- **The text you enter is never sent anywhere.** All processing happens in the browser; the page has no endpoint
  that accepts input. `connect-src 'none'` blocks `fetch`/XHR/WebSocket/beacons from page scripts; the worker
  additionally replaces `fetch`, `XMLHttpRequest`, `WebSocket`, `EventSource`, `importScripts` after loading.
- **Requests you can see in DevTools:** loading the page downloads its own files, including the worker and
  engine scripts (before you enter anything). Processing, changing options, copying, downloading and clearing
  make no request. **If you select Cancel, or a job reaches the 180 s timeout, the worker is terminated and
  restarted, and the browser requests its two static JS files (`worker.js`, `engine.js`) again** (or serves them
  from cache). These requests carry only the version query string, never input. Verified in Edge, Firefox, WebKit.
- No input in `localStorage`, `sessionStorage`, IndexedDB, cookies or the URL; settings are not persisted either.
- Inputs opt out of browser cloud spell-check, Grammarly/LanguageTool and autofill.
- Inputs ≤ 50 MB; 1 MB chunks in the worker; preview limited to 200 000 characters, copy/download contain all.
- Fail-closed structure check: the worker refuses to return output if the number of LF/CR characters changed.
- CSP keeps `style-src 'unsafe-inline'` because WordPress core prints inline CSS; script sources are
  `'self'` + per-response nonce only (no `unsafe-eval` — strict enough that Playwright's own `waitForFunction`
  is refused). A nonce per response is compatible with full-page caches only if header and body are cached together.

## Detection rules (ruleset `2026-11-11.2`, engine 1.0.1)

IPv4 (validated; version-keyword and `Product/1.2.3.4` contexts, 0.0.0.0, broadcast and netmasks are skipped;
optional keep RFC 1918/loopback/link-local), IPv6 (parser-validated, zone IDs, IPv4-mapped), email (also
URL-encoded `name%40domain`), MAC (`:`/`-`/Cisco dotted), JWT, Bearer/Basic (Basic must decode to `user:pass`) and
other `Authorization` schemes, 16 API-key formats (AWS keys and 21-character IAM unique IDs, GitHub ×2, GitLab,
Slack token/webhook, Stripe, Google API/OAuth, OpenAI, Anthropic, SendGrid, npm, Hugging Face, DigitalOcean, Azure
storage), secrets in key=value/JSON/YAML/XML, cookies (also JSON-quoted), URL passwords, PEM/OpenSSH/PGP private
keys (incl. JSON-escaped and truncated blocks), usernames (sshd, PAM incl. `by user(uid=)`, systemd-logind, sudo,
useradd/passwd, Apache `user X not found`, access-log `remote_user`, nested JSON `"user":{"name":…}`, AWS IAM/STS
ARNs, key names, Windows events, `/home/x`, `C:\Users\x`, `DOMAIN\user`), hosts (URLs, key names, syslog/RFC 5424
headers, FQDNs with known TLDs; shared AWS service endpoints such as `iam.amazonaws.com` are kept), CSV/TSV columns
classified by a header row (same key names as key=value), cards (IIN + Luhn, consistent separators), US SSN
(`123-45-6789` with SSA invalid ranges excluded) and user-defined regex rules (validated, max 20, no empty matches,
no multi-line matches). Priority: custom → private key → JWT → Authorization → API keys → URL parts → cookies →
key/value → CSV → card → SSN → email → IPv6 → IPv4 → MAC → usernames → hosts.

Iteration 2 fixes found by the real-format corpus: access-log `remote_user`, Apache auth users, PAM `by X(uid=)`,
`New session … of user X`, `useradd`/`passwd` names, `Disconnected from authenticating user`, ARN user names,
URL-encoded emails (the local part leaked), JSON-quoted cookies, nested JSON user names, CSV columns, 21-character
IAM unique IDs; structure/false-positive fixes: `key= next=value` swallowed the next pair (structure changed),
sudo `PWD=/home/x` treated as a password, `pam_unix(passwd:chauthtok)` treated as a secret, trailing comma eaten by
`/home/x,`, `session_id` no longer masked (iteration 1 regression), AWS service endpoints masked.

## Tests

| Suite | Command | Result 2026-11-11 (iteration 2) |
| --- | --- | --- |
| Engine (Node, no deps) | `node tests/log-anonymizer-engine.test.cjs` | 61/61 PASS — 13 categories × positive/negative, false-positive corpus, **13 real-format fixtures** (nginx/Apache access+error, auth.log, Windows Event text+XML, Kubernetes, Docker json-file, CloudTrail, JSON lines, key=value, CSV) with mask/keep lists and structure checks (lines, CR, delimiters, JSON shape, CSV field counts), fuzz, chunk boundaries, labels, custom rules, 18 ReDoS inputs, 30 MB in ≈2.5 s |
| Server (PHP 8.4, offline container) | `docker run --rm --network none -v "<repo>:/app:ro" -w /app --entrypoint php wordpress@sha256:bb954f75…7676 tests/log-anonymizer.test.php` | 38/38 PASS |
| Catalogue (PHP) | same container, `tests/tools-catalog.test.php` | 29/29 PASS — 3 cards, no backlog cards, Coming soon until ready, Available + link when ready, roadmap 3/4/3 |
| Edge (headless, CDP, no deps) | `tests/local-wp/up.sh` then `node tests/log-anonymizer-browser.test.cjs` | 21/21 PASS |
| **Firefox 132 + WebKit 18.2** (Playwright 1.49.1, outside repo) | see header of `tests/log-anonymizer-xbrowser.test.cjs` | 13/13 + 13/13 PASS — strict CSP with nonce, Web Worker under `worker-src 'self'`, worker network lockdown, fetch blocked, no console errors, XSS, downloads, storage, 30 MB (Firefox 3.3 s, WebKit 23 s; main-thread gap < 100 ms), Cancel requests, 360 px, keyboard |
| Existing suite, base vs branch | Windows host and Linux container, see `evidence-2026-11-11-iter2/` | identical on base and branch; see "Pre-existing failures" |

Raw outputs: [`evidence-2026-11-11/`](evidence-2026-11-11/) (iteration 1), [`evidence-2026-11-11-iter2/`](evidence-2026-11-11-iter2/).
Screenshots (not committed): `C:\Users\CyberDat\CyberDat-tools-log-anonymizer-20261111T205558Z\` (Edge) and
`C:\Users\CyberDat\CyberDat-tools-log-anonymizer-xbrowser-20261111T205610Z\` (Firefox/WebKit 360 px).

### Pre-existing failures (not related to Tools)

On the owner's Windows checkout 13 tests fail on the base commit and on this branch alike. All are environment
artefacts; none involves Tools files, and none hides a Research problem:

| Test | Windows cause | Linux container (LF checkout, `python3`, `php8.4`) |
| --- | --- | --- |
| `editorial-sections.test.php` | `core.autocrlf=true` turns `front-page.php` into CRLF; the test searches an LF snippet | PASS |
| `content-admin-menu.test.php` | needs the WordPress core path argument (defaults to the VPS path) | PASS with `/usr/src/wordpress` |
| `analytics-permissions`, `preview-guard` (.py) | call `php8.4`/`php`, not installed on Windows | PASS |
| `content-worker.test.py` | Windows temp-path/rename semantics | PASS |
| `rankmath-free-finish`, `research-finish`, `research-resume`, `threat-seo-verifier` (.py) | import `fcntl` (POSIX only) | PASS |
| `research-admin-permissions`, `staging-config` (.py) | import `pwd` (POSIX only) | admin-permissions PASS; staging-config needs VPS binaries (nginx/php-fpm), refuses to install — same on base |
| `research-cli-registration`, `research-fixture-repair` (.py) | read the prepared bundle in `/home/cyberdat/cyberdat-deploy/…` | VPS-only — same on base |

`analytics-ring-hit.test.py` passes on Windows and needs Node in Linux (not installed in the container).

### Local WordPress

`tests/local-wp/` starts a disposable WordPress 7.1.4/PHP 8.4 + MariaDB 11.8.6 from the image digests already
pinned for DR (no pull), bound to `127.0.0.1:8090`, database on an internal network, `WP_HTTP_BLOCK_EXTERNAL`,
no cron/updates/mail, theme mounted read-only, random throwaway DB password in the environment only. It never
touches the `cyberdat-dr-*` containers or volumes. Stop and delete with `tests/local-wp/up.sh down`.

## Staging — owner-run procedure (not performed by the agent)

The agent has no VPS access. Use the fixed commit and per-file hashes in [`manifest.json`](manifest.json).

1. **Backup (verifiable)** as root on the VPS:
   ```sh
   set -euo pipefail; umask 077
   B=/var/backups/cyberdat-staging/log-anonymizer-$(date -u +%Y%m%dT%H%M%SZ); mkdir -m 0700 "$B"
   T=/var/www/cyberdat-staging/public/wp-content/themes
   (cd "$T" && find cyberdat -type f -print0 | sort -z | xargs -0 sha256sum) > "$B/theme-before.sha256"
   tar -C "$T" -czf "$B/theme-before.tar.gz" cyberdat
   sha256sum "$B/theme-before.tar.gz" > "$B/SHA256SUMS"
   mkdir "$B/verify" && tar -C "$B/verify" -xzf "$B/theme-before.tar.gz" && (cd "$B/verify" && sha256sum -c --quiet "$B/theme-before.sha256") && rm -rf "$B/verify"
   ```
   Record `$B` in the acceptance report. Also confirm the modified files on staging equal the base commit's
   versions (`base_sha256` per modified file in `manifest.json`); if not, stop — staging differs from Git.
2. **Fetch** the fixed-SHA archive from GitHub into a private directory, reject links/traversal, extract only the
   files listed in `manifest.json`, and check each against its `sha256` (and `git_blob_sha1`).
3. **Install** only those files into the staging theme: code owned by root/deploy, mode 0644 (dirs 0755),
   readable by PHP, not writable by the staging user. No reload of Nginx/PHP-FPM is required.
4. **Page**: in wp-admin edit the existing draft *Privacy Shield Log Anonymizer* (`/tools/log-anonymizer/`,
   template "Tool + SEO Content"), paste the reviewed fields from `editorial.json`, tick "reviewed", save, and use
   **Preview**. Publishing on staging is optional (staging is Basic-Auth + noindex). Do not touch production.
   Read **before** publishing: Research deploy scripts check that every catalogue URL returns 404 (see conflicts).
5. **Verify** (Basic Auth). Record browser versions and results.
   - **Headers:** `curl -sI -u <user> <tool URL>` → `Content-Security-Policy` contains `connect-src 'none'` and
     `script-src 'self' 'nonce-…'`; `/` and `/tools/` have no such header.
   - **Network tab (Edge/Chrome and Firefox):** DevTools → Network, enable *Preserve log*, filter *All*. Reload,
     then *Clear* the list. Load sample → Anonymize → switch label mode/categories → Anonymize → Copy → Download
     result → tick acknowledgement → Download map → Clear everything. Expected: **no new entries** except `blob:`
     downloads. Then load a large file, Anonymize, press Cancel: only `worker.js?ver=…` / `engine.js?ver=…` may
     appear (or none if cached). Console: no errors or CSP violations.
   - **Firefox (desktop):** repeat the sample run and the Network check; upload a 20–40 MB non-production log; page
     stays responsive and the progress bar moves.
   - **iPhone (Safari, current iOS):** open the tool, load the sample, Anonymize, scroll the preview horizontally,
     Copy result (paste into Notes to confirm), Download result (Files app). Check that nothing overflows the
     screen, buttons are easy to tap, the keyboard does not hide the Anonymize button. Optional: Safari Web
     Inspector from a Mac for the Network/Console check. Not covered by automated tests (see limitations).
   - **360 px width:** DevTools device mode 360 × 780 (or a small Android phone): no horizontal page scroll; the
     category table and preview scroll inside their own boxes; all buttons ≥ 44 px high.
   - **Keyboard only:** Tab through all controls (visible focus ring), Enter on "Load sample log", Ctrl+Enter in
     the text box, Esc cancels a running job.
   - **Proofreading (English):** read the tool page top to bottom — summary, the two callouts, step headings,
     category labels and examples, help texts, error messages (try an invalid custom regex and an empty input),
     result summary, replacement-map warning, "How it works", "Privacy", "Limitations", and the editorial sections
     from `editorial.json` (How It Works, Documentation, Examples, FAQ). Also the `/tools/` notice, card texts and
     "More tools planned." The copy uses US spelling (anonymization, recognize, analyze).
   - **Regression:** `/tools/` catalogue (3 cards; Log Anonymizer Available only once the page is ready),
     homepage, Threat Intelligence and wp-admin Research/Content screens unchanged.
6. **Rollback**: `tar -C /var/www/cyberdat-staging/public/wp-content/themes -xzf "$B/theme-before.tar.gz"` after
   moving the updated theme aside; then `sha256sum -c` against `theme-before.sha256`. The page meta can stay
   (without the renderer the guard falls back to draft/404).

## Known limitations

- Heuristic detection: bare random secrets, personal names (e.g. CSV `full_name`), postal addresses, phone
  numbers, non-US national IDs, IBANs, Windows SIDs, AWS account IDs and S3 bucket names in separate fields,
  secrets inside Base64 blobs or split across lines are not detected.
- Bare four-part numbers (`1.2.3.4`) are treated as IPv4 unless preceded by a version keyword; six decimal pairs
  (`10:20:30:40:50:60`) look like a MAC; Luhn-valid 13–19 digit IDs with a card IIN (e.g. IMEI) are masked.
- Single-label hostnames are only found in context (URLs, key names, syslog headers, Windows events); EC2-style
  names after unknown keys (e.g. `node=ip-10-0-1-23`) are missed. NetBIOS domain in `DOMAIN\user` is kept.
- Two-label names whose TLD collides with file extensions or code (`app.py`, `readme.md`, `x.ai`, `Safari.app`,
  `user.id`) are deliberately not masked; mixed-case labels (`System.out`) are treated as code.
- CSV columns are only classified when the first line is a header and the second line has the same field count;
  quoted fields must not contain line breaks.
- Custom regexes run with JavaScript semantics; catastrophic patterns are only stopped by the 180 s timeout.
- Stable labels are per run; label numbering reveals counts of distinct values.
- UTF-8 and UTF-16 (with BOM) only; output downloads are UTF-8; invalid bytes become U+FFFD (warned).
- `style-src 'unsafe-inline'` remains for WordPress core CSS. Browser extensions can still read page content.
- **Browsers:** automated in Edge (Chromium), Firefox 132 and WebKit 18.2 (Playwright build on Windows).
  **Real Safari on macOS and Safari/WebKit on iPhone were not available** and are only covered by the manual
  checklist above. WebKit on Windows processed 30 MB in ≈23 s (vs ≈3 s in Firefox/Edge); the page stayed
  responsive, but real devices may differ.

## Possible conflicts with parallel agent work

- **Research deploy scripts vs a published tool:** `deploy/research/update-research.py`, `resume-research.py`
  and `deploy/staging/update-tools-ui.py` assert that every URL in `inc/tools-catalog.json` returns **404** on
  staging ("unfinished tool"). `/tools/log-anonymizer/` is in the catalogue (old and new), so once the owner
  publishes the tool on staging those Research checks will fail. They are Research files and were not changed;
  the owner should decide whether Research scripts skip catalogue entries with `"status": "available"`.
- `functions.php` (+2 lines after `inc/tools.php`): trivial merge if another branch adds requires nearby.
- `inc/tools-catalog.json`, `page-templates/tools.php`, `assets/css/tools.css`, `deploy/staging/tools-roadmap.*`
  are Tools/SEO-0.7 files; no Research branch has changed them since 0.7.
- `docs/PROJECT_STATUS.md` was intentionally **not** edited (Research sessions edit it); owner to record status.
- **Integration path:** `main` contains only docs, no theme. Cherry-picking onto `main` fails (`functions.php`
  modify/delete) and would anyway lack the 0.7 Tools architecture the tool depends on. Merging **after Research
  0.8.3** is the simple path: the Research tip is an ancestor of this branch (fast-forward, no conflicts); if
  Research gains new commits, cherry-picking the Tools commits onto its tip applies cleanly unless `functions.php`
  or the catalogue files change there.

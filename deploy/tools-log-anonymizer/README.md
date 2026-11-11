# Privacy Shield Log Anonymizer — Tools release 1.1, tool 1

Status: **implemented and locally accepted; staging pending owner action.** Not deployed, not merged.
Branch: `feature/tools-log-anonymizer`, based on `feat/cyberdat-research-agent-0.8.3` @ `c3f9a5e`
(the newest linear tip; an older base would roll back theme changes that are already on staging).

## What changed

Additive theme change only. No plugin, database schema, menu, SEO setting, Research/Content/SEO agent code or
server configuration is touched.

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

Publication still follows the 0.7 fail-closed contract in `inc/tools.php`: the page is only live when the
renderer exists **and** all editorial fields are filled **and** "reviewed" is ticked. Proposed English copy for
those fields is in [`editorial.json`](editorial.json) (needs owner review).

## Privacy and security design

- All processing in the browser; the page has no endpoint that accepts input. `connect-src 'none'` blocks
  `fetch`/XHR/WebSocket/beacons from page scripts; the worker additionally replaces `fetch`, `XMLHttpRequest`,
  `WebSocket`, `EventSource`, `importScripts` after loading the engine.
- No input in `localStorage`, `sessionStorage`, IndexedDB, cookies or the URL; settings are not persisted either.
- Inputs opt out of browser cloud spell-check, Grammarly/LanguageTool and autofill.
- Worker and engine are loaded at page load, so processing itself performs zero requests (verified).
  **Exception:** *Cancel* or a 180 s timeout must terminate the worker; restarting it re-requests the two static
  theme scripts (no user data; verified by test).
- Inputs ≤ 50 MB; 1 MB chunks in the worker; preview limited to 200 000 characters, copy/download contain all.
- Fail-closed structure check: the worker refuses to return output if the number of LF/CR characters changed.
- CSP keeps `style-src 'unsafe-inline'` because WordPress core prints inline CSS; script sources are
  `'self'` + per-response nonce only. A nonce per response is compatible with full-page caches only if header and
  body are cached together.

## Detection rules (ruleset `2026-11-11.1`, engine 1.0.0)

IPv4 (validated; version-keyword and `Product/1.2.3.4` contexts, 0.0.0.0, broadcast and netmasks are skipped;
optional keep RFC 1918/loopback/link-local), IPv6 (parser-validated, zone IDs, IPv4-mapped), email, MAC
(`:`/`-`/Cisco dotted), JWT, Bearer/Basic (Basic must decode to `user:pass`) and other `Authorization` schemes,
16 API-key formats (AWS, GitHub ×2, GitLab, Slack token/webhook, Stripe, Google API/OAuth, OpenAI, Anthropic,
SendGrid, npm, Hugging Face, DigitalOcean, Azure storage), secrets in key=value/JSON/YAML/XML, cookies, URL
passwords, PEM/OpenSSH/PGP private keys (incl. JSON-escaped and truncated blocks), usernames (sshd, PAM, sudo,
key names, Windows events, `/home/x`, `C:\Users\x`, `DOMAIN\user`), hosts (URLs, key names, syslog/RFC 5424
headers, FQDNs with known TLDs), cards (IIN + Luhn, consistent separators), US SSN (`123-45-6789` with SSA
invalid ranges excluded) and user-defined regex rules (validated, max 20, no empty matches, no multi-line matches).
Priority: custom → private key → JWT → Authorization → API keys → URL parts → cookies → key/value → card → SSN →
email → IPv6 → IPv4 → MAC → usernames → hosts.

## Tests

| Suite | Command | Result 2026-11-11 |
| --- | --- | --- |
| Engine (Node, no deps) | `node tests/log-anonymizer-engine.test.cjs` | 47/47 PASS — 13 categories × positive/negative, false-positive corpus (67 lines), structure/CRLF/BOM/fuzz, chunk boundaries, stable/generic labels, custom rules, 18 ReDoS inputs (1 MB each), 30 MB in ≈2.5 s |
| Server (PHP 8.4, offline container) | `docker run --rm --network none -v "<repo>:/app:ro" -w /app --entrypoint php wordpress@sha256:bb954f75…7676 tests/log-anonymizer.test.php` | 38/38 PASS — renderer scoping, escaping, English-only, ids/labels, CSP directives, nonce scope, asset scope |
| Browser (headless Edge via CDP, no deps) | `tests/local-wp/up.sh` then `node tests/log-anonymizer-browser.test.cjs` | 21/21 PASS — zero requests, CSP enforcement, worker lockdown, storage, XSS, 30 MB file (longest main-thread gap ≈100 ms), keyboard, accessible names, contrast ≥ 7.59:1, 360/390/768 px, no-JS |
| Existing suite, base vs branch | see `evidence-2026-11-11/full-suite-*.txt` | identical; 13 pre-existing failures on both (Linux-only Python tests needing `pwd`/`php`, `content-admin-menu`, `editorial-sections`) |

Raw outputs are in [`evidence-2026-11-11/`](evidence-2026-11-11/). Screenshots (not committed, ~7 MB):
`C:\Users\CyberDat\CyberDat-tools-log-anonymizer-20261111T202205Z\`.

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
   Record `$B` in the acceptance report. Also confirm `functions.php` on staging equals the base commit's
   version (sha256 in `manifest.json` → `base_functions_php_sha256`); if not, stop — staging differs from Git.
2. **Fetch** the fixed-SHA archive from GitHub into a private directory, reject links/traversal, extract only the
   files listed in `manifest.json`, and check each against its `sha256` (and `git_blob_sha1`).
3. **Install** only those files into the staging theme: code owned by root/deploy, mode 0644 (dirs 0755),
   readable by PHP, not writable by the staging user. No reload of Nginx/PHP-FPM is required.
4. **Page**: in wp-admin edit the existing draft *Privacy Shield Log Anonymizer* (`/tools/log-anonymizer/`,
   template "Tool + SEO Content"), paste the reviewed fields from `editorial.json`, tick "reviewed", save, and use
   **Preview**. Publishing on staging is optional (staging is Basic-Auth + noindex). Do not touch production.
5. **Verify** (Basic Auth):
   - `curl -sI -u <user> https://staging.cyberdat.eu/tools/log-anonymizer/?preview=true…` (or the published URL):
     `Content-Security-Policy` contains `connect-src 'none'`; other pages (`/`, `/tools/`) have no such header.
   - Browser DevTools → Network, "Preserve log": load sample → Anonymize → change options → Copy/Download →
     Clear: no new requests. Console: no errors.
   - Upload a real (non-production-secret) log of 20–40 MB: page stays responsive, progress shows.
   - Phone or 360 px responsive mode, keyboard-only pass (Tab/Enter/Space, Ctrl+Enter in the text box).
   - `/tools/` catalogue, homepage, Threat Intelligence and wp-admin Research/Content screens unchanged.
6. **Rollback**: `tar -C /var/www/cyberdat-staging/public/wp-content/themes -xzf "$B/theme-before.tar.gz"` after
   moving the updated theme aside; then `sha256sum -c` against `theme-before.sha256`. The page meta can stay
   (without the renderer the guard falls back to draft/404).

## Known limitations

- Heuristic detection: bare random secrets, personal names, postal addresses, phone numbers, non-US national IDs,
  IBANs, secrets inside Base64/URL-encoded blobs or split across lines are not detected.
- Bare four-part numbers (`1.2.3.4`) are treated as IPv4 unless preceded by a version keyword; six decimal pairs
  (`10:20:30:40:50:60`) look like a MAC; Luhn-valid 13–19 digit IDs with a card IIN (e.g. IMEI) are masked.
- Single-label hostnames are only found in context (URLs, key names, syslog headers, Windows events); EC2-style
  names after unknown keys (e.g. `node=ip-10-0-1-23`) are missed. NetBIOS domain in `DOMAIN\user` is kept.
- Two-label names whose TLD collides with file extensions or code (`app.py`, `readme.md`, `x.ai`, `Safari.app`,
  `user.id`) are deliberately not masked; mixed-case labels (`System.out`) are treated as code.
- Custom regexes run with JavaScript semantics; catastrophic patterns are only stopped by the 180 s timeout.
- Stable labels are per run; label numbering reveals counts of distinct values.
- UTF-8 and UTF-16 (with BOM) only; output downloads are UTF-8; invalid bytes become U+FFFD (warned).
- `style-src 'unsafe-inline'` remains for WordPress core CSS. Browser extensions can still read page content.
- Pre-existing: the `/tools/` catalogue (`inc/tools-catalog.json`, `deploy/staging/tools-roadmap.json`) still
  lists the **old** 0.7 roadmap (IoT helper, Modbus, Webhook listener; no Prompt Sanitizer/MCP/Leak Inspector)
  and marks all ten "Coming Soon". Changing it was out of scope and needs an owner decision.

## Possible conflicts with parallel agent work

- `functions.php` (+2 lines after `inc/tools.php`): trivial merge if another branch adds requires nearby.
- Branch contains the Research 0.8.3 commits it is based on; merge order should be Research 0.8.3 first.
- `docs/PROJECT_STATUS.md` was intentionally **not** edited (Research sessions edit it); owner to record status.
- No shared files with `wp-content/plugins/*`, `worker/`, `deploy/research*`, `deploy/content*`.

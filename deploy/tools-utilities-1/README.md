# Quick utilities 1 — Email Header Analyzer — package for Codex

Audience: Codex (installation on closed staging, page, hub and SEO, after the owner's approval) and the owner. Prepared
locally without VPS access. No secrets, passwords or tokens in this package. The utility is outside the ten approved
tools (owner decision of 2026-11-19).

## Branch

| Item | Value |
|---|---|
| Branch | `integration/tools-utilities-1`, created from `58ed710` (tip of `integration/tools-release-1.3`) |
| Utility branch | `feature/tools-email-header-analyzer`: `12d01f7` Public Suffix List snapshot, `867bc1f` corpus and held-out set (frozen), `69b3a4a` utility, `d2cc2db` catalogue entry; merge `50e916b`; `386e37c` owner decisions of 2026-11-19 (PSL from publicsuffix.org, "Quick utility" card label, URL confirmed); merge `429e097` |
| Package | `feature/tools-utilities-1-package`, merged into the integration branch |
| Not changed | files of the ten tools (byte-identical to the base); `inc/tools.php`, pages, Research/Content/SEO. The hub template changes in one line only (owner decision 3) |

## Delta to apply on top of the release 1.3 theme

`manifest.json` → `delta_files` (SHA-256 of the LF bytes in git). Theme 164 → 173 files: 9 added, 3 modified, 0 removed.
`node deploy/tools-utilities-1/build-manifest.cjs --check` verifies it. `manifest.json` → `tools.email-header-analyzer`
lists the utility's own files and only its lines in the shared files:

| Status | Path |
|---|---|
| added | `assets/css/email-header-analyzer.css`, `assets/js/email-header-analyzer/{app,engine,worker}.js`, `inc/tool-email-header-analyzer.php`, `template-parts/tools/email-header-analyzer.php` |
| added | `assets/js/email-header-analyzer/public_suffix_list.dat` (Public Suffix List, unmodified, MPL-2.0), `psl-data.js` (the same bytes as a JS string for the worker), `LICENSE-MPL-2.0.txt` — publish the three together |
| modified | `functions.php` — one line `require_once __DIR__ . '/inc/tool-email-header-analyzer.php';` after the container audit include |
| modified | `inc/tools-catalog.json` — one entry appended after the ten tools (`kind: utility`, release `utilities-1`, category Quick Utilities, status `planned`); the ten entries are unchanged. `deploy/tools-release-1/route-catalog.json` stays a byte copy |
| modified | `page-templates/tools.php` — one line (46): cards with `kind: utility` read "Quick utility" instead of "Phase · Release"; all other cards render as before |

**Hub effect** (owner decision 3, 2026-11-19: keep the card): the hub shows an 11th "Coming soon" card labelled
"Quick utility" and a Quick Utilities filter button; the ten tool cards are unchanged. The hub tests
(`tests/tools-catalog.test.php`, `tests/tools-filter.test.cjs`) now check the ten tools as a subset plus the utility.
For publication Codex adds the slug to the canonical list in `inc/tools.php`, creates the page with the Tool template at
`/tools/email-header-analyzer/` (URL confirmed by the owner), sets the editorial fields from `editorial.json` and flips the status.

## Files in this package

| File | Content |
|---|---|
| `manifest.json`, `build-manifest.cjs` | delta, the utility's files and shared-file lines, base/target hashes |
| `update-psl.cjs`, `psl-snapshot.json` | Public Suffix List download from publicsuffix.org with pinned SHA-256 and list date, verification (`--check`), provenance |
| `editorial.json` | proposed page fields (English; owner review before `reviewed=true`) |
| `COPY-REVIEW.md` | all user-visible strings, the brand list and the rules (Russian notes), decisions first |
| `SOURCES-AND-LICENSES.md` | sources with dates and hashes, the PSL decision and the owner decisions |
| `independent/email-header-analyzer/` | independent acceptance kit: instructions for Gmail and Outlook and what to replace, `template.json`, `rules.json`; runner `tests/email-header-analyzer-independent.cjs` |

## What the analyzer reads

* Input: pasted headers or the whole source, or an .eml/.txt file, up to 5 MB. Only the part before the first empty
  line is used; the body is counted, never parsed, shown or exported. Folded headers, RFC 2047 encoded words (via
  TextDecoder: UTF-8, ISO-8859-x, windows-125x, KOI8-R …), CRLF/LF/CR (also CR CR LF), webmail indentation and
  non-breaking spaces, an mbox `From ` line.
* Received formats recognised (corpus): Postfix, Gmail (IPv6 `by`, `mx.google.com`), Microsoft 365 / Exchange Online
  (`prod.outlook.com`, `mail.protection.outlook.com`, IPs in parentheses, multi-line folding), on-premises Exchange
  (`with mapi`, link-local IPv6 with zone), Exim (`helo=`, `envelope-from`), Sendmail, Cisco-style gateways
  (`from unknown (HELO …) ([ip])`, no weekday), third-party relays; IPv4 and IPv6 (`[IPv6:…]`).
* Not parsed (shown as written, `EHA-PARSE-001`): lines without a `from`/`by` part such as qmail
  `(qmail … invoked by uid …)` and `via HTTP`; unusual custom formats.

## Results (NOT INDEPENDENT)

| Check | Result |
|---|---|
| Corpus (frozen `867bc1f`), first run | messages fully correct 49/50, finding recall 62/62, extra 1; path/auth/decoding details 51/51; body never shown 52/52 |
| Held-out set, first run | 13/14, recall 32/32, extra 2; details 7/8; body 13/13 |
| Fixes after the first run (in `69b3a4a`) | (1) the Date check used the lowest Received line, which the sender writes, as delivery reference → only trusted lines are used; (2) `CR CR LF` (a doubly converted line ending) was read as an empty line and cut the headers → a run of CRs before LF is one line break. The held-out set revealed (2), so it is no longer unseen |
| After the fixes | corpus 50/50, recall 62/62, extra 0, details 51/51; held-out 14/14, 32/32, 0, 8/8 |
| Engine test | 11/11: PSL lookups (co.uk, wildcard and exception rules, IDN), punycode equal to Node `url.domainToASCII`, encoded words in 5 charsets, 6 line-ending variants, body never in output, masking, 1,000 Received lines in 17 ms, 12 pathological inputs each under 30 ms, 600 fuzz inputs |
| Unicode contract (`tools-utilities-1-unicode.test.cjs`) | 3/3 |
| Browser | Edge 13/13; Firefox 10/10, WebKit 10/10: XSS through names and subjects stays text, .eml body never shown or exported, masking, 800 Received lines + 2 MB body in 1.2 s, 360 px, keyboard, contrast ≥ 7.59:1 |

### Final regression — all eleven tools, one sequential run

Integration tip `50e916b`; repeated once after the owner decisions at `429e097` with identical PASS counts (33/33 runs exit 0); sandbox `tests/tools-sandbox-server.py` (Windows 11, Edge via DevTools protocol, Firefox and
WebKit via Playwright 1.49.1, Node 24.14.1, PHP from the pinned WordPress image). PASS counts, every run exit 0:

| Tool | Edge | Firefox | WebKit |
|---|---|---|---|
| Log Anonymizer | 21 | 14 | 14 |
| Prompt Injection Detector | 21 | 13 | 13 |
| LotL Command Analyzer | 16 | 10 | 10 |
| MCP Security & Policy Checker | 20 | 11 | 11 |
| Agent Leak Inspector | 17 | 10 | 10 |
| AI Model BOM | 20 | 12 | 12 |
| MITRE ATLAS Mapper | 17 | 13 | 13 |
| LLM Prompt Injection Test Bench | 17 | 10 | 10 |
| YARA/Sigma Rule Validator & Converter | 14 | 11 | 11 |
| Docker & Kubernetes Hardening Audit Generator | 12 | 10 | 10 |
| Email Header Analyzer | 13 | 10 | 10 |

PHP page tests of all eleven, `tools` and `tools-catalog` suites: PASS. Node tests: all PASS except `d14-remediation`
(needs the owner-private fixtures) and `release-manifest` (release-1 package count), which fail identically on the base.
Manifest checks 1.3 and utilities-1 and the PSL `--check` (publicsuffix.org list of 2026-11-17): PASS. After the switch to that list the corpus (50/50) and held-out (14/14) results are unchanged; the hub test checks the Quick utility label (tools-catalog 51 checks).

### Secrets

`no-token-shaped-strings`: PASS. gitleaks 8.21.2 on the history of every new commit (`58ed710..HEAD`): no leaks; on the
new utility and test directories: no leaks. Secret-shaped test values come only from `tests/lib/synthetic-secrets.cjs`.

## Not verified

* No real mail: the corpus is synthetic (written from scratch); the owner's 10–15 real header sets are pending
  (kit in `independent/email-header-analyzer/`). Every number above is NOT INDEPENDENT.
* Received formats of other vendors (Proofpoint, Mimecast, Zimbra, Yandex, Mail.ru, Apple iCloud) were not tested.
* Nothing installed on staging; the hub with the 11th card was checked only by the PHP render test.

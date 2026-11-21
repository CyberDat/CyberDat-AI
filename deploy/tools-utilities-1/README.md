# Quick utilities 1 — Email Header Analyzer — package for Codex

Audience: Codex (installation on closed staging, page, hub and SEO, after the owner's approval) and the owner. Prepared
locally without VPS access. No secrets, passwords or tokens in this package. The utility is outside the ten approved
tools (owner decision of 2026-11-19).

## Branch

| Item | Value |
|---|---|
| Branch | `integration/tools-utilities-1`, created from `58ed710` (tip of `integration/tools-release-1.3`). On 2026-11-21: `integration/tools-release-1.2` (Codex export redaction fix `6b7d97c`) merged into 1.3 (`198bf49`), the 1.3 package rebuilt over `tools-release-1.2/2` (`e1bff4e`), 1.3 merged here (`df0f51a`, `4060781`); the Codex Hub `feat/tools-hub-cyber-glass` (`0a32f12`, installed on staging) merged here (`b93caf2`); Hub previews `feature/tools-hub-previews` `dfe3ac9`, merge `b96ddbb` |
| Utility branch | `feature/tools-email-header-analyzer`: `12d01f7` Public Suffix List snapshot, `867bc1f` corpus and held-out set (frozen), `69b3a4a` utility, `d2cc2db` catalogue entry; merge `50e916b`; `386e37c` owner decisions of 2026-11-19 (PSL from publicsuffix.org, "Quick utility" card label, URL confirmed); merge `429e097` |
| Package | `feature/tools-utilities-1-package`, merged into the integration branch |
| Not changed | files of the ten tools (byte-identical to the base, including the Codex fix of tools 6 and 7); `inc/tools.php`, pages, Research/Content/SEO, `docs/PROJECT_STATUS.md` (kept byte-identical in the Hub merge). The staging Hub template changes in one line only (owner decision 3) |

## Delta to apply on top of the release 1.3 theme and the staging Hub

Base = the theme of `integration/tools-release-1.3` (`e1bff4e`, equal to the 1.3 manifest target) with the Codex Hub on
staging overlaid (`hub_commit` `0a32f12`; `hub_overlay` lists its 15 theme files; the builder checks that 1.2/1.3 do not
touch them). `manifest.json` → `delta_files` (SHA-256 of the LF bytes in git). Theme 177 → 187 files: 10 added,
10 modified, 0 removed. Utility: 9 files, its Hub preview, `functions.php`, the catalogue and one Hub template line.
Previews of tools 5–10 (6 SVGs and the illustrations README) ship with their own packages (`hub_previews`):
`node deploy/tools-utilities-1/build-manifest.cjs --check` verifies it. `manifest.json` → `tools.email-header-analyzer`
lists the utility's own files and only its lines in the shared files:

| Status | Path |
|---|---|
| added | `assets/css/email-header-analyzer.css`, `assets/js/email-header-analyzer/{app,engine,worker}.js`, `inc/tool-email-header-analyzer.php`, `template-parts/tools/email-header-analyzer.php` |
| added | `assets/js/email-header-analyzer/public_suffix_list.dat` (Public Suffix List, unmodified, MPL-2.0), `psl-data.js` (the same bytes as a JS string for the worker), `LICENSE-MPL-2.0.txt` — publish the three together |
| modified | `functions.php` — one line `require_once __DIR__ . '/inc/tool-email-header-analyzer.php';` after the container audit include |
| modified | `inc/tools-catalog.json` — one entry appended after the ten tools (`kind: utility`, release `utilities-1`, category Quick Utilities, status `planned`); the ten entries are unchanged. `deploy/tools-release-1/route-catalog.json` stays a byte copy |
| added | `assets/images/tools-hub/email-header-analyzer.svg` — Hub card preview (headers only, `"Demo Bank" <a@example.net>` → dmarc=fail, brand in name) |
| modified | `page-templates/tools.php` (the staging Hub template from `0a32f12`) — one line (66): planned cards with `kind: utility` read "Quick utility" instead of "Phase · Release"; all other cards render as before |
| other packages | tools 5–7 previews + illustrations README → `deploy/tools-hub-previews-5-7/` (Codex, tools already on staging); tools 8–10 previews → `deploy/tools-release-1.3/hub-previews.json` |

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

## Independent acceptance (owner's set) and the fix after it

Owner's set: 11 Gmail messages, labelled by the owner, `set.json` sha256 `9a76e028fac3e54e…`, `labels.json` not changed
between the runs. Kept outside the repository (no real headers committed).

| Run | Engine / rules | Result line |
|---|---|---|
| First run (owner), `0218b84` | 1.0.0 / 2026-11-19.1 | messages as expected **0/11**, extra or unwanted **23**, DMARC/boundary checks **0/11**, benign messages with a high finding **1/11** |
| Second run after the fix, `82a0c48` — **not primary numbers** | 1.0.0 / 2026-11-21.1 | messages as expected **10/11**, extra or unwanted **1**, DMARC/boundary checks **11/11**, benign messages with a high finding **0/11** |

Remaining difference: m01 `EHA-AUTH-005` (result by dkim-verifier.icloud.com below the boundary). The owner classified it
as a labelling error: the rule is right, so the code is unchanged for it.

Fix `990a064` (merge `82a0c48`), owner decisions of 2026-11-21, ruleset `2026-11-21.1`:

1. Own domain at a mailbox provider. The owner entered example.com, so mail accepted by mx.google.com got EHA-AUTH-004 and
   EHA-AUTH-005 and DMARC none. This would hit every Google Workspace and Microsoft 365 user with an own domain. Now,
   with an own domain, the provider becomes the trust boundary when four conditions hold: the topmost external Received
   line was written by a known mailbox provider; the provider list in the engine (`MAILBOX_PROVIDERS`) is short (Google
   `mx.google.com`, Microsoft `*.outlook.com` incl. `*.protection.outlook.com`); nothing above that line recorded results;
   and the provider wrote Authentication-Results in a trusted position. Results lower down that only name the provider
   stay untrusted (EHA-AUTH-005 unchanged). The trust explanation and the exports show "Trust boundary: <host> (mailbox
   provider for your domain)". No new finding ids; frozen catalogue unchanged.
2. `appleid.com` added to Apple's domains (false EHA-LOOK-003 high on `privaterelay.appleid.com`). Nothing else in the
   brand list changed.

Tests: `tests/email-header-analyzer-provider-boundary.test.cjs` 19/19 (synthetic: Workspace, M365, a forged lower
mx.google.com result, a message with only a forged result, the Apple relay address). The same file against the old
engine fails 12 checks. Corpus before/after: 50/50 → 50/50 (recall 62/62, extra 0), held-out 14/14 → 14/14 (32/32, 0).
Engine 11/11, Unicode 3/3, PHP page test PASS, browser regression of the utility once: Edge 13, Firefox 10, WebKit 10,
all exit 0.

### Update 2026-11-21 (second round)

Merged again: `integration/tools-release-1.2` `838fecc` (Codex BOM/ATLAS masking review) into 1.3 (`47ef75d`), and 1.3 with the
Codex acceptance fixes of tools 8–10 and the Test Bench possible-leak status into this branch (`3489250`, `e821469`). Manifest base:
`integration/tools-release-1.3` `4ee0ada` plus the staging Hub overlay; the utility files are unchanged. One regression run of the
affected tools 6–10 (three browsers, 15/15 exit 0, PASS counts as before) — details in `deploy/tools-release-1.3/README.md`. The
Email Header Analyzer was not changed and not re-run.

### Final regression — all eleven tools, one sequential run

Last run 2026-11-21 at `b96ddbb` (after the merges of the Codex export fix, the Hub and the previews): 33/33 runs exit 0, PASS counts identical to the earlier runs at `50e916b` and `429e097`; Log Anonymizer 30 MB: Edge 2.8 s, Firefox 3.2 s, WebKit 27.1 s; sandbox `tests/tools-sandbox-server.py` (Windows 11, Edge via DevTools protocol, Firefox and
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

PHP page tests of all eleven, `tools` and `tools-catalog` suites: PASS (`content-admin-menu` and `editorial-sections`, Content area, stop on
missing staging paths / the production guard in this environment; not touched). Node tests: all PASS, including Codex's
`tools12-export-redaction-regression` (20/20), `tools-hub-previews` (133/133) and the 1.2/1.3/utilities/preview manifest
checks, except `d14-remediation` (needs the owner-private fixtures) and `release-manifest` (release-1 package count),
which fail identically on the base.
Manifest checks 1.3 and utilities-1 and the PSL `--check` (publicsuffix.org list of 2026-11-17): PASS. After the switch to that list the corpus (50/50) and held-out (14/14) results are unchanged; the hub test checks the Quick utility label (tools-catalog 51 checks).

### Secrets

`no-token-shaped-strings`: PASS (890 files). gitleaks 8.21.2 on the history of every new commit (`58ed710..HEAD`, and on
2026-11-21 `a7e66b1..HEAD` including the merged Codex commits, and `58ed710..integration/tools-release-1.3`): no leaks; on the
new utility and test directories: no leaks. Secret-shaped test values come only from `tests/lib/synthetic-secrets.cjs`.

## Not verified

* The corpus is synthetic (written from scratch); every number above is NOT INDEPENDENT. The owner's independent set is
  Gmail-only (owner decision 2026-11-19): 11 messages, labelled and run (see above); the second run is after a fix and
  its numbers are not primary. **Covered only by synthetic headers:** corporate Microsoft 365 / Exchange
  Online and on-premises Exchange, mail gateways, Postfix/Exim/Sendmail as receivers, and phishing variants other than the
  owner's spam message. The page Limitations state this (`bee7105`).
* Received formats of other vendors (Proofpoint, Mimecast, Zimbra, Yandex, Mail.ru, Apple iCloud) were not tested.
* Nothing installed on staging. The Hub with the 11th card and the new previews was checked by the PHP render tests and
  by an offline render with the theme CSS in Edge (1440 and 360 px), not in WordPress. The Codex Hub browser test was
  not re-run (it needs a private baseline export of the staging Hub).

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
| Not changed | files of the ten tools (byte-identical to the base, including the Codex fix of tools 6 and 7), except the secret masking fix of tools 2 and 3 (`fix/tools-mask-pi-lotl-exports` `8ed3a81`, merge `1749a5a`: two engines, their version constants and one help text each, below) and the masked sanitized copy of tool 2 (`fix/tools-pi-sanitized-mask` `544439d` and `2ef24aa`, merges `92fe70a` and `747b6ef`: also the detector's `app.js` and `worker.js`, below); pages, Research/Content/SEO, `docs/PROJECT_STATUS.md` (kept byte-identical in the Hub merge). The staging Hub template changes in one line only (owner decision 3) |

## Install rule (owner decision 2026-11-21)

**The installer changes no theme file.** It copies the delta files of `manifest.json` as they are: no prepare step edits
`inc/tools.php`, `inc/tools-catalog.json` or any other file. Before the installation every theme file on staging equals the
`base` map; after it every theme file equals the `target` map (= the branch at `theme_commit`) byte for byte; verify with the
manifest hashes. Catalogue statuses and the staging canonical scope come with the package.

## Base = the staging theme (revision `tools-utilities-1/2`, 2026-11-22)

Base = `snapshot/staging-theme-20261122` `cd06239` (Codex: exact snapshot of the staging theme, 159/159 files equal to staging
by SHA-256), merged into this branch (`c0963b4`). So `base_sha256` of every modified file is the staging version; the former
`staging_known_differences` and the Hub overlay are gone. Theme 159 → 188 files: **29 added, 22 modified, 0 removed**
(`manifest.json` → `delta_files`, SHA-256 of the LF bytes in git). `node deploy/tools-utilities-1/build-manifest.cjs --check`
verifies it; the builder also checks the owner decisions below and that base + delta = target.

Owner decisions per file group (`manifest.json` → `owner_decisions`; fix `2cfbea0`):

| Group | Files | In the delta |
|---|---|---|
| A — staging kept | `assets/js/intelligence-live.js`, `intelligence-charts.js`, `threat-analytics.js`, `threat-pulse.js`, `inc/threat-pulse.php`, `template-parts/home/threat-dashboard.php`, `threat-pulse.php`; Log Anonymizer Stage1: `assets/js/log-anonymizer/{app,engine,worker}.js`, `inc/tool-log-anonymizer.php`, `template-parts/tools/log-anonymizer.php` (engine 1.1.0, already contains our Unicode/NFD fixes) | no (checked: equal to staging) |
| B — our branch | `assets/js/ai-model-bom/engine.js`, `assets/js/atlas-mapper/engine.js`, `inc/tool-ai-model-bom.php`, `inc/tool-atlas-mapper.php` (b8ff2f3); `assets/js/prompt-injection-detector/{app,engine,worker}.js`, `inc/tool-prompt-injection-detector.php`; `assets/js/lotl-analyzer/engine.js`, `inc/tool-lotl-analyzer.php`; `inc/tools-catalog.json`, `inc/tools.php`; previews 5–10; `functions.php` (four includes: tools 8–10 and the utility); `page-templates/tools.php` (the one "Quick utility" line) | yes, 20 files |
| C — merged | `template-parts/tools/prompt-injection-detector.php`, `lotl-command-analyzer.php`: 3-way merge (base `0a32f12`, the parent of Stage1 `d0cba38`): Stage1 `notranslate`/privacy note + our masking texts and switch; `mcp-security-checker.php` and `inc/assets.php`: the merge equals staging | 2 files |
| absent on staging | tools 8–10 (release 1.3), the utility (9 files + preview), `assets/images/tools-hub/README.md` | yes, 29 added |

Catalogue: entries 1–7 equal to staging; tools 8–10 `planned` → `available` with their release descriptions; the utility appended.
`manifest.json` → `release_1_3` (files of tools 8–10), `tools.email-header-analyzer` (the utility's files and shared lines),
`export_masking_5_6`, `secret_masking`, `sanitized_copy_editorial` (FAQ of tool 2), `hub_previews` (5–7: Codex package, 8–10: 1.3).

| Status | Path |
|---|---|
| added | `assets/css/email-header-analyzer.css`, `assets/js/email-header-analyzer/{app,engine,worker}.js`, `inc/tool-email-header-analyzer.php`, `template-parts/tools/email-header-analyzer.php` |
| added | `assets/js/email-header-analyzer/public_suffix_list.dat` (Public Suffix List, unmodified, MPL-2.0), `psl-data.js` (the same bytes as a JS string for the worker), `LICENSE-MPL-2.0.txt` — publish the three together |
| added | tools 8–10: `assets/css/`, `assets/js/<tool>/{app,engine,worker}.js`, `inc/tool-<tool>.php`, `template-parts/tools/<tool>.php` for `prompt-injection-test-bench`, `yara-sigma-validator`, `container-hardening-audit` |
| modified | `inc/tools.php` — `cyberdat_tools_staging_canonical()` takes the pages with catalogue status `available` instead of a hand-written slug list; the staging, published-page, `cyberdat_tool_ready` and Rank Math checks are unchanged |
| modified | secret masking of tools 2 and 3 and the masked sanitized copy of tool 2 (`secret_masking`). Page fields of tool 2: `how_it_works` and `faq` from `deploy/tools-prompt-injection-detector/editorial.json` |

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

### Update 2026-11-22 (seventh round: package over the staging snapshot)

Base and owner decisions: see "Base = the staging theme" above. Check: the snapshot theme (`git archive cd06239`) with the
29 + 22 delta files applied equals the theme at `theme_commit` byte for byte (188 files); no group A file is in the delta.
One regression run (local sandbox): all eleven tools, 33/33 runs exit 0, PASS counts as before (detector 21 / 13 / 13,
LotL 16 / 10 / 10, MCP 20 / 11 / 11, Log Anonymizer Stage1 21 / 14 / 14, tools 5–10 and the utility as in the table below);
Hub 174/174 in Edge, Firefox and WebKit. PHP tests of the eleven pages, `tools`, `tools-catalog` and both canonical suites: PASS.
Failing after the merge, **not changed here** (owner decision needed): `log-anonymizer-unicode(-marks).test.cjs` (case
`of-user-eol`: Stage1 masks "of user X" only inside a session record), `tools-stabilization.test.cjs` (frozen pre-Stage1 Log
Anonymizer digest; fails on Stage1 `d0cba38` too), `analytics-dialog-lifecycle.test.cjs`, `threat-dashboard.test.php`,
`threat-pulse.test.php` (the staging intelligence/home files are newer than these tests; outside Security Tools).

### Update 2026-11-22 (sixth round: masked sanitized copy in the detector, owner decision)

The detector's sanitized copy is usually pasted into an LLM; until now it was the complete text. Fix
`fix/tools-pi-sanitized-mask` (`544439d`, merge `92fe70a`; test line endings `2ef24aa`, merge `747b6ef`):

* **Masked by default, after sanitization.** The same shared masking block as for excerpts and the report (known formats,
  JWT, private keys, values after secret keys whatever their length, Bearer/Basic, password options, credentials, secret
  query values with percent escapes decoded and token-like path segments in addresses, long opaque values) runs on the
  finished sanitized copy. Sanitization and detection are unchanged: the engine (1.0.4) builds the masked copy and its
  change view only when the worker asks for it (`hooks.maskSanitized`); without the hook `analyze()` returns exactly the
  former result, so the frozen stabilization digests (`tests/tools-stabilization.test.cjs`) still hold. In the masked change
  view a secret is shown once as an inserted mask, also when it crosses an edit (an invisible character removed inside a
  token); removed passages are masked before they are cut to 4,000 characters.
* **Switch** "Do not mask secrets in the sanitized copy" next to the copy: off on every page load (not stored; `autocomplete="off"`
  and reset by the script, because Firefox restores form fields on reload), `translate="no"` on the switch and on its warning
  "Secrets are not masked. …". Copy and Download take the version on screen. The JSON report never contained the copy and
  stays masked whatever the switch says. The highlighted original text is unchanged.
* **Texts:** help text next to the copy, the report help text, the last "How it works" item and the FAQ/`how_it_works` in
  `deploy/tools-prompt-injection-detector/editorial.json` (new question "Are secrets masked in the sanitized copy?") describe
  the behaviour and the switch; masking "can miss a secret", no promise of complete detection. New strings: COPY-REVIEW.

Test `tests/prompt-injection-detector-sanitized-mask.test.cjs` (values from `tests/lib/synthetic-secrets.cjs`): 35/35 engine,
page and FAQ checks (one per form of secret, the split token, masked removals, unchanged complete copy, analyze without the
hook unchanged, worker, switch markup, Copy/Download from the screen, report, texts; ReDoS: masking the sanitized copy of 1 MB
hostile input, 10 shapes, slowest 114 ms, limit 1 s) — 31 of 35 fail on `b879796` (the 4 that pass are guards); with a
sandbox URL another 24 browser checks in Edge, Firefox and WebKit (masked by default, Copy = Download = screen, switch on:
complete copy with the warning, report still masked, switch reset after a reload): 24/24. Corpora before → after: the
corpus test output is byte-identical (detector main 77/87, 88.5 %, medium+ 75/87; benign 65: any 10, medium+ 0; held-out
26/30, benign 25: medium+ 2; RAG 6/6), and the complete engine result of all 211 corpus, held-out and RAG texts under three
option sets (633 runs) is identical to `b879796` apart from the new masked copy (which differs from the complete copy in 24
runs). 10 MB analysis in the worker path: 5.2 s → 5.6 s. Engine 33/33, `tools-mask-pi-lotl` 62/62, stabilization PASS.
Export surface audit: its "sanitized text" row stays `secret_visible: true` because it inspects the whole `sanitized`
object, which still holds the complete copy for the switch; the masked copy shown by default exposes none of its three
probe values (checked with the same probe). One regression run (local sandbox): detector Edge 21 / Firefox 13 / WebKit 13,
exit 0, as before; Hub 174/174 in each browser. PHP tests: as before (see below).

### Update 2026-11-21 (fifth round: secret masking in tools 2 and 3, blocker of the public launch)

Tools 2 (Indirect Prompt Injection Sanitizer & Detector) and 3 (LotL / LOLBAS Command Analyzer) on staging showed and exported
secrets: the detector in finding excerpts, the LotL analyzer in the quoted commands. Fix `fix/tools-mask-pi-lotl-exports`
(`8ed3a81`, merge `1749a5a`):

* **One shared masking block in both engines** (the same text; `tests/tools-mask-pi-lotl.test.cjs` and the builder check it):
  known formats (AWS, GitHub, GitLab, Slack, Anthropic, OpenAI-style, Google, Hugging Face, Stripe, npm, Azure storage key),
  JWT, private key blocks from BEGIN to END, values after credential / password / secret / token / api key / x-api-key /
  access or private key / authorization / auth / csrf / session id / cookie keys whatever their length (`key=value`,
  `key: value`, JSON, `=>`), Bearer and Basic with or without a key, password options (`/pass:`, `/rp`, `-Password`,
  `--token=`, `-u user:password`, `ConvertTo-SecureString "…"`), credentials before `@`, secret query and fragment values in
  addresses (names and values percent-decoded before they are classified; the original span is replaced), token-like address
  path segments, long opaque values. Base64 that decodes to readable text with spaces (an encoded command, a payload) is
  content and stays visible; hex hashes, GUIDs, paths and names made of words stay visible.
* **Mask first, then cut.** The detector finds the secrets of the whole text once and builds every excerpt from it: a secret
  that crosses the 60-character window or the edge of the match is kept whole and replaced. Quoted text in details (normalized,
  decoded, hidden and comment text) and the decoded previews are masked before they are cut to 80–200 characters. LotL masks the
  command line, the normalized command, deobfuscation notes, binaries as written, heuristic details, decoded commands and their
  nested analysis; decoded commands (4,000 characters) and the address detail (120) are masked before the cut.
* **Not masked (stated on the page; the sanitized copy changed on 2026-11-22, see above):** the detector's highlighted text and sanitized copy are the complete text the user pasted
  (the sanitized copy is the tool's product: injection sanitization, not secret redaction). Error messages contain no input
  text (checked; unchanged). Both tools export JSON only (no Markdown export exists).
* Detection runs on the original text and is unchanged. Engines: detector 1.0.3, LotL 1.0.1 (PHP constants and the page
  version line follow). Page help texts: masking is best-effort and can miss a secret, check the report before sharing it.
  The page texts and the FAQ/documentation (`editorial.json` of both tools, not changed) promise no complete detection (checked).
* Unicode classes use the u flag (38 literals in the block, checked by a scanner), no look-behind. 1 MB hostile inputs
  (15 shapes: keyed runs, keys without values, Bearer runs, a 1 MB address, trailing brackets, many addresses and query pairs,
  broken percent escapes, private key headers, opaque runs, unclosed quotes, options, JWT-like, Base64): slowest 63 ms per
  engine (limit 1 s). The detector's 10 MB engine test: 5.1 s → 7.7 s (one masking pass over the whole text).

Test `tests/tools-mask-pi-lotl.test.cjs`: 62/62 (values from `tests/lib/synthetic-secrets.cjs`); the same file against the
engines and page texts of `8580ed4`: 51 of 62 fail (the 11 that pass are guards: ordinary text not masked, detection
unchanged, error messages, timing, and the four "no promise" checks — the old texts promised nothing either; the commit
message of `8ed3a81` says 49, counted before the page-text checks were added). Corpora before → after (outputs byte-identical): detector main 77/87 (88.5 %, medium+ 75/87),
benign 65: any 10, medium+ 0; held-out 26/30 (86.7 %), benign 25: medium+ 2; RAG 6/6 as expected. LotL main suspicious
medium+ 34/35 (97.1 %), function correct 31/35, benign medium+ 0/45; held-out 13/15 (86.7 %), function 12/15, benign medium+
2/15; dependent 9/9. Engine tests: detector 33/33, LotL 20/20. Export surface audit: LotL `secret_visible` true → false.

One regression run (local sandbox): detector Edge 21 / Firefox 13 / WebKit 13, LotL 16 / 10 / 10 — all exit 0, PASS counts as
before; Hub 174/174 in each of Edge, Firefox and WebKit. On the pages in the three browsers (real worker): synthetic secrets
pasted into each tool appear neither in the findings / commands list nor in the downloaded JSON report (6/6). PHP tests of all
eleven pages, the tools contract, catalogue and canonical suites: PASS.

### Update 2026-11-21 (fourth round: catalogue statuses and staging canonical)

Fix `fix/tools-utilities1-catalog-status` (`96024c1`, merge `c7a55d9`): final catalogue statuses (tools 1–10 and the utility
`available`), `cyberdat_tools_staging_canonical()` from the catalogue, the install rule above. Test
`tests/tools-staging-canonical-catalog.test.php`: 27/27 (canonical for every available page, none for planned, no slug in the
function; 14 fail on the old code). `tests/tools-staging-canonical.test.php` gets a catalogue stub, `tests/tools-catalog.test.php`
expects 11 available, `tests/tools-hub-browser.test.cjs` skips its "next planned tool" case when no entry is planned (that
Codex test needs a private staging HTML export and was not run here). Release 1.3 is not changed.

One regression run: Hub (PHP render of the template with the theme CSS and `tools-filter.js`; all ready / none ready; 360 and
1440 px; cards, links, previews, filters, overflow, console, external requests): 174/174 checks in each of Edge, Firefox and
WebKit. Pages whose status or canonical scope changed (tools 5–10 and the utility): 21/21 runs exit 0, PASS counts as before —
Leak Inspector 17 / 10 / 10, AI Model BOM 20 / 12 / 12, ATLAS Mapper 17 / 13 / 13, Test Bench 17 / 10 / 10, Validator 14 / 11 / 11,
Container Audit 12 / 10 / 10, Email Header Analyzer 13 / 10 / 10 (Edge / Firefox / WebKit). PHP tests of all eleven pages, the
tools contract suite, the catalogue suite and both canonical tests: PASS.

### Update 2026-11-21 (third round)

Merged again: `integration/tools-release-1.2` `b8ff2f3` (Codex second masking fix, files byte-identical) into 1.3 (`865f74d`), the
Test Bench re-acceptance fix (`173c946`, merge `40e2469`) and the rebuilt 1.3 package (`835bb53`), then 1.3 into this branch (`1798dfa`).
Manifest base: `integration/tools-release-1.3` `835bb53` plus the staging Hub overlay; the utility files are unchanged.
One regression run of the affected tools (AI Model BOM, ATLAS Mapper, Test Bench), three browsers: 9/9 runs exit 0, PASS counts as
before (20 / 12 / 12, 17 / 13 / 13, 17 / 10 / 10, Edge / Firefox / WebKit). Codex tests `tools12-followup-redaction-regression` 34/34,
`tools12-masking-review-regression` 32/32, `tools12-export-redaction-regression` 20/20. The Email Header Analyzer was not changed
and not re-run. `inc/tools.php` and `inc/tools-catalog.json` against staging: done in the fourth round (above).

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

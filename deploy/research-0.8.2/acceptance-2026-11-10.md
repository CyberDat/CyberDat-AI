# Research Agent 0.8.2 — staging acceptance evidence

Verified from the owner-run result on 2026-11-10; SQL evidence timestamp **2026-11-10T15:34:31+00:00**. Overall **PARTIAL**: controlled live ingestion and integration pass; new-source scheduled recurrence, browser admin interactions and long-term load are not yet verified.

## Deployment and architecture

- Existing Research Agent plugin, database, secure client, global lock, retry/backoff and dispatcher reused. No separate agent/database/scheduler.
- Additive discovery/category/identifier/audit tables; original publication rows retained in existing items. No Content/Social Agent, n8n, LLM, article generation or automatic publication.
- Original Dashboard source scope preserved, so newly discovered news/papers do not become advisory KPIs. Theme, Analytics UX 2.1, SEO, Basic Auth/noindex and protected configuration/timer fingerprints passed the controller checks.
- Existing administrator login and Research Queue HTTP 200 verified. No credentials reset. Production HTTPS health and protected fingerprints passed the controller checks.

## Verified counts

| Stream | Persisted publications |
|---|---:|
| Cybersecurity News | 50 |
| Threat Intelligence & Technical Research | 120 |
| Cybersecurity Research Papers | 42 |
| Total discovery publications | 212 |

- All-source queue: **5684** items at this evidence snapshot, including 1773 KEV and 3638 NVD records. These are timestamped counts, not constants.
- Stable source-ID duplicate groups: **0**. Re-upsert of representative real records retained counts.
- Live event/topic groups: **212**; groups containing multiple source records: **0** in this first batch. Do not claim real corroborated events from fixed fixtures.
- Fixture tests demonstrate related coverage grouping, independent-CVE separation, scientific DOI linking, manual split retention, classification overrides, assignment uniqueness and transactional rollback.
- Technical records may be older publications still present in a current feed. Crossref uses recent index updates, which can legitimately expose older publication dates; those dates are preserved rather than relabeled as new research.

## Source catalog — runtime evidence

12 new sources successfully fetched, parsed and persisted. Together with five existing working collectors this is **17 functioning channels**, not 45. The other 28 registry channels remain blocked/disabled; they are not counted as connected. Several channels share publishers.

| Channel | Stream | Records | Last successful sync UTC | Status |
|---|---|---:|---|---|
| talos | research | 15 | 2026-11-10 15:30:51 | Persisted / no reported error |
| unit42 | research | 15 | 2026-11-10 15:30:56 | Persisted / no reported error |
| sentinelone | research | 10 | 2026-11-10 15:31:01 | Persisted / no reported error |
| eset | research | 25 | 2026-11-10 15:31:06 | Persisted / no reported error |
| ncsc | research | 20 | 2026-11-10 15:31:11 | Persisted / no reported error |
| bleepingcomputer | news | 15 | 2026-11-10 15:31:16 | Persisted / no reported error |
| hackernews | news | 25 | 2026-11-10 15:31:21 | Persisted / no reported error |
| securityweek | news | 10 | 2026-11-10 15:31:26 | Persisted / no reported error |
| sans-isc | research | 10 | 2026-11-10 15:31:31 | Persisted / no reported error |
| portswigger | research | 25 | 2026-11-10 15:31:36 | Persisted / no reported error |
| arxiv | papers | 21 | 2026-11-10 15:31:42 | Persisted / no reported error |
| crossref | papers | 21 | 2026-11-10 15:31:50 | Persisted / no reported error |

| Other configured channel | State / reason |
|---|---|
| ms-security | BLOCKED: Endpoint verification: unapproved_source_link; no redirect/access-control bypass |
| ms-defender | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| ms-research | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| project-zero | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| mandiant | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| google-security | BLOCKED: Endpoint verification: http_302; no redirect/access-control bypass |
| cisco-advisories | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| crowdstrike | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| sophos | BLOCKED: Endpoint verification: http_301; no redirect/access-control bypass |
| fortinet | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| elastic | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| trailofbits | BLOCKED: Endpoint verification: http_301; no redirect/access-control bypass |
| enisa | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| bsi | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| darkreading | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| therecord | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| owasp-genai | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| mitre-atlas | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| deepmind | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| nvidia | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| github-security | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| openalex | BLOCKED: Verified API docs: cursor pagination requires API key; no key provisioned; disabled |
| semantic-scholar | BLOCKED: Official API access/rate-limit requirements not yet verified from VPS; no key provisioned |
| usenix | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| ieee-sp | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| acm-ccs | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| ndss | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |
| raid | BLOCKED: No verified permitted metadata endpoint; no HTML scraping or access bypass |

Existing KEV, NVD, CISA advisories, CERT-EU and MSRC had successful health timestamps and no reported error in the supplied proof. Registry state is runtime-derived; an enabled toggle alone is not ACTIVE evidence.

## Real examples and scientific metadata

- News: [Chrome Update Patches Exploited XML Zero-Day, Eighth This Year](https://www.securityweek.com/chrome-update-patches-exploited-xml-zero-day-eighth-this-year/), source publication 2026-11-10 06:12:24 UTC; categories News/Vulnerabilities; heuristic priority 33, not an exploitation probability.
- Technical research: [Bypassing character blocklists with unicode overflows](https://portswigger.net/research/bypassing-character-blocklists-with-unicode-overflows), source publication 2025-01-28; correctly receives no recency bonus.
- Scientific metadata: DOI [10.3390/proceedings2024101013](https://doi.org/10.3390/proceedings2024101013), venue ISCDISD 2023; source publication 2024-05-10. Review status **Unknown**, not inferred from DOI or venue.
- arXiv: 21 persisted records, normalized IDs/revisions, authors and bounded abstracts; Preprint status. Crossref: 21 persisted records, DOI/authors/venue/publisher and dates; no copied abstracts.
- OpenAlex and Semantic Scholar are not active. Conference channels remain blocked without verified permitted metadata endpoints; no invented RSS or access bypass.

## Classification and prioritization

Deterministic, multi-label metadata/keyword rules retain reasons and permit audited administrative correction. Scores are bounded editorial heuristics; examples include source weight, publication recency, category relevance and confirmed KEV relationships. Manual overrides retain audit history. Scientific validity, novelty and independent corroboration are not proven; syndicated copies receive no corroboration bonus. Some scientific records have no specific research subcategory and require editorial classification.

## Acceptance results

| Check | Result |
|---|---|
| Legacy fixed-fixture MariaDB integration | PASS |
| New discovery temporary-table integration — 11 checks | PASS |
| Three real content streams; arXiv plus independent metadata provider | PASS |
| Actual re-upsert / zero source-ID duplicate groups | PASS |
| Dashboard KPI scope versus independent SQL | PASS |
| Admin queue/registry render; authorized nonce; anonymous rejection | PASS |
| Existing administrator HTTPS login / queue | PASS |
| Protected public pages and Basic Auth/noindex | PASS |
| No post-count change / no automatic publication | PASS |
| Untouched theme/Analytics/protected configuration/timer hashes | PASS |
| New-source repeated scheduled cycle | UNVERIFIED |
| Real-browser registry/filter/edit/merge/split interactions | UNVERIFIED |
| Long-term resource impact | UNVERIFIED |

The existing dispatcher timer was additionally read as active, with a successful service exit at 2026-11-10 16:35:07 CET. This alone does NOT prove a new discovery source was polled; correlate a later per-source timestamp/cursor with scheduler evidence.

## Resource snapshot

Controlled controller duration: **79 seconds**. Available memory changed from 2207676 KiB to 2183468 KiB (about 23.6 MiB difference); one-minute load changed from about 0.009 to 0.204. This is a shared-host before/after sample, not isolated process RAM attribution or long-term capacity proof. Research tables total 32391168 bytes (about 30.9 MiB). Existing worker CPU/memory limits were not changed.

## Release, backup and continuation

- Runtime release: `ec8be39b8210580e201b4a4ac8956fc4be3f2bb8`.
- CLI orchestration fix: `dcd687db86cacfe4db775307d80e00d79fcab8f3`.
- Fixture correction/resume guards: `5e857ec974ed9f005dcdf38277bf17127aaa374d`. Runtime source-change protections were not weakened.
- Private backup: `/var/backups/cyberdat-staging/research-0.8.2-20261110T151206Z`. Controller wrote verification evidence and COMPLETE after acceptance.
- Explicit code rollback: owner-run `research-0.8.2-resume-prepared/resume-discovery.py --rollback-code BACKUP`; disables discovery and atomically restores previous plugin code while retaining records, additive schema and backups. No SQL restore or archive deletion.
- Next: read-only source/cursor and dispatcher observation using `observe-discovery.py --read-only`; no manual sync or reinstallation is necessary. Then verify the admin UI in a real browser and record recurring behavior.

Stop within Research Agent 0.8.2; no subsequent agent phase authorized.

## Later evidence and admin UI follow-up

- Automatic Crossref continuation observed by the owner at 2026-11-10T15:46:22Z: source count 44, pending offset 50, last success 15:45:10 UTC aligned with the scheduled dispatcher run. New totals: news 50, research 120, papers 65; zero duplicate source-ID groups. This proves one automatic continuation, not full-source or long-term recurrence.
- Real Edge login and read-only queue/registry functionality passed: news/research/papers filters, scientific metadata, DOI search, server pagination and 45 configured registry rows.
- The 10 recorded console entries were all external Gravatar requests intentionally blocked by the capture harness; runtime exceptions were zero. The updated helper separately counts only confirmed harness-origin Gravatar blocks and retains all diagnostics. Unknown errors still fail.
- At 768 px the Source Registry produced horizontal overflow; at 320 px it did not. A scoped admin stylesheet is prepared. Do not report this layout fixed before the owner-run staging patch and browser recheck pass.
- `fix-admin-layout.py` backs up staging SQL/plugin/admin PHP, changes only `includes/discovery-admin.php` plus `assets/discovery-admin.css`, and verifies other Research/theme/config/timer hashes. It does not import or change source state. Roll back this UI patch before using an older Research release rollback that expects the previous admin PHP hash.

### Admin stylesheet delivery

The first UI patch installed its files and backed up staging at `/var/backups/cyberdat-staging/research-admin-ui-20261110T160728Z`, then CSS HTTP/hash verification failed. The new assets directory was confirmed mode 0700 due to umask 077. A tested permission continuation validates that it contains only the exact public stylesheet before setting this directory to 0755. Existing private directory modes, configuration, source state and timers are not changed. Run `finish-admin-layout.py --verify BACKUP`; do not repeat `--apply`. CSS delivery and responsive acceptance are still pending actual verification.

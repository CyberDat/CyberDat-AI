# Research Agent 0.8.2 stabilization — 2026-11-10

Status: PARTIAL — staging deployment and consolidated smoke test PASS; remaining source/recurrence limitations below. Branch: feat/cyberdat-research-agent-0.8.1. Runtime commit: `411341bf67d3717ad4de8c054ec0d141109767b4`.

## Verified baseline

Owner read-only snapshot 16:32:02 UTC: KEV 1773; NVD 3638; queue 5779; 307 discovery topics; zero duplicate source IDs and zero correlated live topics. NVD transport at 15:40:16 recovered automatically by 15:50:40; latest success 16:29:39, HTTP 200, no current error. Checkpoint 1794305945 is preserved. Historical curl errno was not recorded: precise DNS/TLS/timeout cause cannot be reconstructed. No collector change is justified.

Crossref automatic cursor continuation is evidenced by the 15:45 dispatcher cycle: records 21→44, offset 25→50; later snapshot 116/offset150. This proves Crossref recurrence, not every source cadence.

## Confirmed changes

* Healthy overdue legacy jobs were skipped: fixed timers fired seconds before health.next_due, and dispatcher retried errors/pending NVD only. Select oldest eligible due source fairly using existing intervals/backoff and global lock. No timer/unit edits.
* Correct token boundaries (enrollment is not LLM), exploit-parallelism false positives, model-backdoor/malware distinction, crypto/OT and contextual AI-security categories. Event invitation penalty is an explicit heuristic, not a paid-content assertion. Existing manual decisions are preserved.
* Scoped endpoint/host corrections below; fetch security implementation, redirect prohibition, DNS/public-IP pinning and response caps are unchanged.
* Real SAP ICM2SHELL/ProxyGate pair 5559/5600 is eligible for audited merge/split/merge via existing APIs, only if exact evidence and New/manual-unassigned conditions still match. Independent publications remain intact. This is manual editorial correlation, not proof of independent reporting or automatic grouping.

## Recheck of all 28 previously disconnected channels

| Channel | Public probe result / limitation |
|---|---|
| Microsoft Security Blog | CONNECTED: 10 real records persisted; https://www.microsoft.com/en-us/security/blog/feed/ |
| Microsoft Defender Threat Intelligence | UNSUPPORTED: Overlapping Microsoft publisher topic feed; intentionally consolidated into Microsoft Security Blog rather than duplicate polling/records |
| Microsoft Research Security | UNSUPPORTED: Official general Research RSS includes non-security content and is not a scientific-paper metadata feed; security-specific relevance requires confirmation |
| Project Zero | CONNECTED: 9 real records persisted; https://projectzero.google/feed.xml |
| Google Threat Intelligence / Mandiant | CONNECTED: 20 real records persisted; https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/ |
| Google Security Blog | CONNECTED: 20 real records persisted; https://blog.google/security/rss/ |
| Cisco Security Advisories | CONNECTED: 25 real records persisted; https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml |
| CrowdStrike Research | CONNECTED: 10 real records persisted; https://www.crowdstrike.com/en-us/blog/feed |
| Sophos X-Ops | BLOCKED: public feed/parser passed, but staging live fetch returned transport; 0 records, enabled for normal bounded retry at 17:23:50 UTC |
| FortiGuard Labs | BLOCKED: Official tested RSS landing/threat feed URLs returned 404; no functioning documented machine-readable endpoint verified |
| Elastic Security Labs | CONNECTED: 25 real records persisted; https://www.elastic.co/security-labs/rss/feed.xml |
| Trail of Bits | CONNECTED: 20 real records persisted; https://blog.trailofbits.com/index.xml |
| ENISA | BLOCKED: Official site accessible; tested RSS endpoints returned HTTP 404 |
| BSI / CERT-Bund Security Advisories | CONNECTED: 25 real records persisted; https://wid.cert-bund.de/content/public/securityAdvisory/rss |
| Dark Reading | CONNECTED: 25 real records persisted; https://www.darkreading.com/rss.xml |
| The Record | CONNECTED: 5 real records persisted; https://therecord.media/feed |
| OWASP GenAI Security Project | CONNECTED: 10 real records persisted; https://genai.owasp.org/feed/ |
| MITRE ATLAS | UNSUPPORTED: Official ATLAS site is a technique/knowledge-base application, not a verified dated publication feed |
| DeepMind Security Research | UNSUPPORTED: Official general blog RSS works but contains product announcements; security-specific filtering required before enabling this channel |
| NVIDIA Security | BLOCKED: Official advertised/tag feed returned HTTP 200 with zero records; tested category RSS URLs returned HTTP 404 |
| GitHub Security Lab | BLOCKED: Official advertised Atom feed returned HTTP 200 with zero publication records; cannot prove ingestion |
| OpenAlex | BLOCKED: Official keyless metadata GET succeeds (HTTP 200), but reliable cursor pagination requires an owner-provisioned API key; no key created |
| Semantic Scholar API | BLOCKED: Official metadata API returned HTTP 429; shared anonymous quota unavailable, API key/rate-limit provisioning required; no bypass |
| USENIX Security Symposium | UNSUPPORTED: Official Security 2026 proceedings HTML accessible (HTTP 200); no verified supported incremental metadata feed/API for this channel |
| IEEE Symposium on Security and Privacy | UNSUPPORTED: Official 2026 accepted-papers HTML accessible (HTTP 200); no verified supported incremental metadata feed/API for this channel |
| ACM CCS | BLOCKED: Official ACM proceedings endpoint returned HTTP 403; no access-control bypass |
| NDSS Symposium | UNSUPPORTED: Official 2026 accepted-papers HTML accessible (HTTP 200); oEmbed is not a paper-discovery feed |
| RAID Symposium | UNSUPPORTED: Original catalog hostname did not resolve; official 2026 site is accessible but has no verified supported incremental metadata feed/API |

OpenAlex basic keyless queries succeeded; full cursor access requires an owner-provisioned key (official documentation: https://help.openalex.org/api/authentication/). Semantic Scholar returned 429; access/quota provisioning remains blocked. UNSUPPORTED means no verified connector under the current metadata-only policy, not that a publisher has no possible integration.

## Acceptance and operational limits

Existing 11-suite offline batch passed; latest 14 classification and 8 fairness regressions pass. Fixed-fixture database tests run after backup before new source enablement. Public endpoint probes do not count as CONNECTED: persistence and last_success are required.

36 latest real records were reviewed across three streams; regression excerpts include TUTTI, BioBind, LoRA and OT papers. This is a diagnostic sample, not a measured global precision rate. Staging applied the v2 derivation to all 327 existing discovery records (not 327 proven incorrect labels). Source timestamps and manual categories/priority were preserved. Live SAP merge/split/merge PASS with both publications retained. There are now two multi-record topics; only the named SAP pair has a documented human evidence review. Automatic correlation recall/precision across the entire corpus remains UNVERIFIED.

Read-only resources: load 0.09/0.06/0.07, available RAM ~2.05 GiB of ~3.83 GiB; Research tables 33,603,584 bytes. No load test. Existing capacity limits remain; long-duration growth/load is UNVERIFIED.

Owner-run stabilize-research.py creates a private staging SQL/plugin backup before three-file patching, executes integration fixtures, bounded derived corrections, controlled new feeds and one protection/SQL smoke test. Controlled due recovery is never counted as automatic recurrence. --observe BACKUP is read-only. --resume BACKUP retains partial progress. Code rollback disables new jobs and restores classifier/dispatcher while retaining registry definitions and all actual records/audit; it is not a destructive SQL restore.

Public theme, Analytics 2.1, SEO, mail, TLS, DNS, existing HTTP client and NVD ingestion code are not deployment targets. No automatic posts, new service, Content/Social/Ollama or production writes.

## Owner-confirmed deployment — 17:19:50 UTC

Backup: `/var/backups/cyberdat-staging/research-stabilization-20261110T171824Z` (private staging SQL + plugin archive + pinned prior files). Owner supplied completed script output, including integration tests, existing admin login and final PASS. [Structured evidence](stabilization-evidence-2026-11-10.json) contains only bounded verification metadata, no credentials/cookies/abstracts.

* **29/45 CONNECTED** (12 newly persisted), **8 BLOCKED**, **8 UNSUPPORTED**. A channel is counted only after real validated fetch and persistence; channels are not necessarily independent publishers.
* New persisted sources: Microsoft Security Blog, Google Security Blog, Trail of Bits, Project Zero, Mandiant/Google Threat Intelligence, Cisco Advisories, CrowdStrike, Elastic Security Labs, Dark Reading, The Record, OWASP GenAI, BSI/CERT-Bund. Sophos returned transport and remains BLOCKED with normal backoff/retry; no HTTP-client workaround added.
* Discovery streams: News 87, Technical Research 294, Scientific Papers 150: **531 publications**. These exclude the separate CVE/legacy-advisory records; not a claim that the entire Research Queue has only 531 rows. Duplicate source IDs: **0**.
* KEV **1773**, verified 17:18:32 UTC (HTTP 304 retains received/source timestamps). NVD **3688**, HTTP 200 success 17:15:37 UTC; checkpoint **2026-11-10T10:19:05Z**, pending cursor **600**. Fresh success is not a Complete window or complete historical coverage. NVD collector unchanged; prior transport/pagination errors recovered on subsequent scheduled runs.
* Known overdue KEV/CISA/CERT jobs were recovered once in controlled scheduled-mode requests after the dispatcher fix. These three calls are explicitly NOT evidence of automatic recurrence. Existing dedicated and dispatcher unit frequencies and hashes are unchanged. Crossref and existing news automatic progress is already evidenced; first post-deployment cycle of each newly added feed remains UNVERIFIED until its unchanged interval is due.
* SQL Dashboard comparisons, three-stream nonempty check, checkpoint monotonicity, temporary-table integration and existing Research Queue login **PASS**. Homepage/Threat Intelligence/Tools authenticated 200, anonymous 401, noindex preserved. Public theme, Analytics, protected configuration, unrelated plugin files and timer fingerprints unchanged; production read-only HTTPS 200. No post-count increase or automatic publication; no new checked PHP/Nginx error indicators.
* Duration **101.5 seconds**; load before 0.09/0.06/0.07, after 0.26/0.14/0.10; available RAM after **2.04 GiB**. Research tables **33,980,416 bytes (32.41 MiB)** versus 33,603,584-byte baseline; this small increase accompanies new records/audit and is not a long-term growth forecast. No stress test.

Current final limitation: normal recurrence/recovery of Sophos and first long-interval cycles of the 12 new successful feeds await observation; no need to rerun --apply. Use immutable release `--observe BACKUP` for read-only status. Long-term load, whole-corpus classification accuracy and all real grouping precision are UNVERIFIED. Existing safe bounds and partial scientific/NVD coverage remain explicit. Overall **PARTIAL**, not 45/45 or a claim that every acceptance point is proven.

## Later read-only observation — 17:28:11 UTC (supersedes health, not prior deployment PASS)

Owner executed immutable `--observe BACKUP`; no sync, source toggle, cache or checkpoint writes. [Selected observation fields](stabilization-observation-2026-11-10.json).

* Crossref automatic success **17:20:09 UTC**, records **129→134**, cursor **175→200**. Papers **150→155**, discovery publications now **536** (87 News + 294 Research +155 Papers). This confirms post-deployment dispatch progress; no manual request was run.
* NVD last success remains **17:15:37 UTC**, records **3688**, but current error is **nvd_pagination_changed** at **17:25:08 UTC**. Inspection of the unchanged installed implementation confirms that this code is raised when validated HTTP200 page total differs from the stored total for the same window. Page ledger/index are restarted conservatively to avoid advancing offsets over a moving result set. Durable completed checkpoint **10:19:05 UTC** is unchanged. Old/new totals were not persisted in this error log and cannot be reported exactly. This is neither a 429 indication nor evidence of database loss. Do not relax this guard or call the window Complete. Next normal retry is **17:30:08 UTC**; no collector change or manual import is justified by this observation.
* Sophos remains **0 records / transport**, unchanged last attempt and due time **17:23:50 UTC**. It was not retried at17:25 because NVD had an older due time (17:20:37). The fair selector processes one bounded job per existing dispatcher cycle; no parallel collectors or polling-frequency increase was added. Recovery remains UNVERIFIED, not failed a second time.
* 29 CONNECTED denotes historical fetch/parse/persistence proof, **not 29 currently healthy collectors**. NVD is currently in error/backoff; Sophos is not connected. All six timers active; duplicate source IDs0; SQL Dashboard matchtrue; data/projections retained.

Overall remains **PARTIAL**. A single later read-only observation after17:41 UTC is requested to inspect normal retries; do not rerun deployment or manually bypass backoff. First4h/24h new-source recurrences and long-term load remain UNVERIFIED. No further code or production changes in response to this observation.

## Final acceptance observation — 17:44:28 UTC

This supersedes earlier current-health statements, while retaining their diagnostic history. [Selected final observation](stabilization-final-observation-2026-11-10.json). No further deployment, manual ingestion, timer operation, HTTP-client change or production access was performed for these observations.

* **NVD automatic recovery PASS**: successful HTTP200 request **17:40:40 UTC**, error cleared;3688 persisted CVEs, cursor100, completed checkpoint **2026-11-10T10:19:05Z** unchanged. Partial bounded window remains unfinished; a log named sync_complete describes a successful bounded operation, not proof the entire window/historical corpus is Complete. Normal retry/backoff worked after pagination-change guard; no reset of durable checkpoint or weakening of consistency checks.
* **Crossref automatic continuation PASS**: records **129→134→150**, cursor **175→200→225**, last success **17:35:09 UTC**. Window checkpoint remains null until bounded coverage completes. Real discovery publications **552**: News87, Research294, Papers171 (arXiv21+Crossref150). No duplicate source-ID groups; Dashboard SQL match remains true; all6timersactive.
* **Sophos remains BLOCKED**: zero persisted records; transport error retained. Retry/backoff state advanced next_due **17:23:50→17:40:07 UTC**. It is enabled for normal bounded retry, not counted connected. Existing client does not persist curl errno/TLS/timeout diagnostics; precise low-level cause is therefore UNVERIFIED, not invented from a generic transport code. Response/timeout/SSRF protection was not relaxed.

### Final disposition against the specification

1. **Sources:** 28 disconnected channels rechecked; 12 newly persisted; 29/45 total CONNECTED. The full table above covers all 28 rechecks. Eight BLOCKED channels: Sophos (transport), FortiGuard/ENISA (tested feed URLs failed; working machine endpoint unverified), NVIDIA/GitHub Security Lab (empty official feeds), OpenAlex (owner key required for reliable cursor access), Semantic Scholar (429/quota), ACM CCS (403). Eight UNSUPPORTED channels under current connector scope: Microsoft Defender (overlapping channel consolidated), Microsoft Research/DeepMind (general feeds lack confirmed security-only selection), MITRE ATLAS (knowledge base, not dated publication feed), USENIX/IEEE S&P/NDSS/RAID (official pages accessible, supported incremental metadata connector unverified). These classifications do not rule out a future lawful integration.
2. **NVD:** automatic recovery observed after transport and changing-pagination failures. Collector and completed checkpoint untouched; no full historical import. Current window completion remains pending.
3. **Scheduler:** all six existing timers active; actual dispatch continuation and NVD recovery proven; healthy overdue source selection fixed. Controlled KEV/CISA/CERT recovery is not called automatic recurrence. Individual first 4h/24h cycles of every newly connected channel remain UNVERIFIED; polling frequencies unchanged.
4. **Classification:** representative diagnostic sample reviewed; 14 regression cases and eight dispatcher cases pass. All 327 existing records received v2 derived metadata with source dates and manual decisions preserved. Real examples confirm crypto/AI/OT corrections. This is not a measurement of global classification accuracy; broad scientific relevance still needs editorial review. No LLM.
5. **Correlation:** real SAP pair 5559/5600 merge/split/merge PASS; both publications retained, CVE coincidence alone unused. Two live correlated topics exist; only the named SAP pair has a documented evidence review. Whole-corpus grouping precision/recall remains UNVERIFIED; no automatic corroboration bonus.
6. **Operations/regressions:** database integration, capabilities/nonces/stale-evidence/review statuses, queue login, SQL projection, Basic Auth/noindex, unchanged public theme/Analytics/config/timers, no automatic publication and checked PHP/Nginx indicators PASS. Prior browser acceptance applies to unchanged UI. No stress test; observed load/RAM/DB size modest. Long-duration load/growth UNVERIFIED.
7. **Repository/rollback:** runtime commit `411341bf67d3717ad4de8c054ec0d141109767b4`; private backup `/var/backups/cyberdat-staging/research-stabilization-20261110T171824Z`; `docs/PROJECT_STATUS.md` updated. Immutable bundle retained with `--resume`/`--rollback-code` for owner-controlled continuation or code rollback; no destructive database restore. No further action is required merely to produce the report.

**Final overall: PARTIAL.** Working ingestion across three streams, validated storage, safe retries and the editorial queue are demonstrated. Sophos and documented unavailable channels remain limitations, along with unobserved long intervals and broad quality/load measurements. No artificial 45/45 target or blanket claim that all checks passed. No production, design, SEO, Analytics, DNS, TLS, mail, Content, Social or Ollama changes. Stabilization work stops here as requested; no next agent/phase was started.

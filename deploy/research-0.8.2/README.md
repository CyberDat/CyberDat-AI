# Research Agent 0.8.2 — implementation and acceptance

Status: **IN PROGRESS — not yet deployed**. Staging only. No Content Agent, n8n, LLM or publication.

## Architecture

The existing Research plugin, `CDRA_Service`, `CDRA_Client`, `CDRA_Store`, ingestion lock, health state, retry/backoff and five-minute dispatcher are reused. No second database, scheduler or fetching service is introduced. Existing CISA/NVD collectors and checkpoints remain intact.

Additive tables under the existing `stg_cdra_` prefix hold discovery metadata, categories, stable paper identifiers and editorial audit. Original publications remain in the existing items table. Topic correlation links records rather than deleting independent coverage.

The public Dashboard continues to aggregate only its original five sources; news and papers are not miscounted as security advisories. No public theme, Analytics UX 2.1, SEO, width, Tools or source timer configuration changes.

## Source catalog

The 40 discovery channels below supplement five existing channels: KEV, NVD, CISA advisories, CERT-EU and MSRC. Channel counts are not publisher counts. A successful public fetch/parser test is not ACTIVE status; ACTIVE additionally requires staging persistence. No missing endpoint or redirect is bypassed.

| ID | Publisher / channel | Stream | Endpoint check | Runtime status before deployment |
|---|---|---|---|---|
| ms-security | Microsoft / Microsoft Security Blog | research | unapproved_source_link | BLOCKED — Endpoint verification: unapproved_source_link; no redirect/access-control bypass |
| ms-defender | Microsoft / Microsoft Defender Threat Intelligence | research | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| ms-research | Microsoft / Microsoft Research Security | papers | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| project-zero | Google / Project Zero | research | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| mandiant | Google / Google Threat Intelligence / Mandiant | research | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| google-security | Google / Google Security Blog | research | http_302 | BLOCKED — Endpoint verification: http_302; no redirect/access-control bypass |
| talos | Cisco / Cisco Talos Intelligence | research | parser_verified | Disabled; persistence UNVERIFIED |
| cisco-advisories | Cisco / Cisco Security Advisories | research | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| unit42 | Palo Alto Networks / Unit 42 | research | parser_verified | Disabled; persistence UNVERIFIED |
| crowdstrike | CrowdStrike / CrowdStrike Research | research | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| sentinelone | SentinelOne / SentinelLabs | research | parser_verified | Disabled; persistence UNVERIFIED |
| eset | ESET / WeLiveSecurity | research | parser_verified | Disabled; persistence UNVERIFIED |
| sophos | Sophos / Sophos X-Ops | research | http_301 | BLOCKED — Endpoint verification: http_301; no redirect/access-control bypass |
| fortinet | Fortinet / FortiGuard Labs | research | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| elastic | Elastic / Elastic Security Labs | research | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| trailofbits | Trail of Bits / Trail of Bits | research | http_301 | BLOCKED — Endpoint verification: http_301; no redirect/access-control bypass |
| enisa | ENISA / ENISA | research | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| ncsc | UK NCSC / UK NCSC | research | parser_verified | Disabled; persistence UNVERIFIED |
| bsi | BSI / BSI Germany | research | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| bleepingcomputer | BleepingComputer / BleepingComputer News | news | parser_verified | Disabled; persistence UNVERIFIED |
| hackernews | The Hacker News / The Hacker News | news | parser_verified | Disabled; persistence UNVERIFIED |
| darkreading | Dark Reading / Dark Reading | news | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| securityweek | SecurityWeek / SecurityWeek | news | parser_verified | Disabled; persistence UNVERIFIED |
| therecord | Recorded Future / The Record | news | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| owasp-genai | OWASP / OWASP GenAI Security Project | research | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| mitre-atlas | MITRE / MITRE ATLAS | research | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| deepmind | Google / DeepMind Security Research | research | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| nvidia | NVIDIA / NVIDIA Security | research | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| sans-isc | SANS / Internet Storm Center | research | parser_verified | Disabled; persistence UNVERIFIED |
| portswigger | PortSwigger / PortSwigger Research | research | parser_verified | Disabled; persistence UNVERIFIED |
| github-security | GitHub / GitHub Security Lab | research | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| arxiv | arXiv / arXiv Computer Security | papers | parser_verified | Disabled; persistence UNVERIFIED |
| crossref | Crossref / Crossref Security Metadata | papers | parser_verified | Disabled; persistence UNVERIFIED |
| openalex | OpenAlex / OpenAlex | papers | Not verified | BLOCKED — Verified API docs: cursor pagination requires API key; no key provisioned; disabled |
| semantic-scholar | Semantic Scholar / Semantic Scholar API | papers | Not verified | BLOCKED — Official API access/rate-limit requirements not yet verified from VPS; no key provisioned |
| usenix | USENIX / USENIX Security Symposium | papers | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| ieee-sp | IEEE / IEEE Symposium on Security and Privacy | papers | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| acm-ccs | ACM / ACM CCS | papers | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| ndss | Internet Society / NDSS Symposium | papers | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |
| raid | RAID / RAID Symposium | papers | Not verified | BLOCKED — No verified permitted metadata endpoint; no HTML scraping or access bypass |

The machine-readable catalog stores official websites, endpoint candidates, acquisition method, priority, interval, verification timestamp and explicit blocked reasons. It is displayed in CyberDat → Source Registry; administrator toggles require capability and nonce checks. No endpoint may be edited through request parameters.

## Data semantics and safety

- News/research: bounded metadata and short feed excerpts, source publication/update/discovery distinct. Missing publication date is never replaced with ingestion time. No full article/PDF fetching.
- arXiv: Atom metadata, authors, abstract, stable ID, revision, DOI if supplied, original/open-access link. Always Preprint unless independent verified review evidence is added.
- Crossref: DOI, title, authors, venue, publisher and publication/deposit timestamps; abstracts are not copied. DOI/venue alone never implies peer review. Exact unknown dates are skipped and counted, not fabricated.
- OpenAlex and Semantic Scholar: registry entries remain blocked pending appropriate access/endpoint verification; no account or API key has been created. Conferences have no assumed RSS.
- Scientific paper records from different providers share a topic only through exact stable identifiers, never similar titles. All providers and revisions remain as separate attributable evidence.
- News event correlation is deliberately conservative: at least six significant title tokens, ≥0.90 token overlap, same stream and source publication within 72 hours. Shared CVE alone never groups events. Manual merge/split is audited and retained through ingestion.
- Syndicated copies receive no automatic independent-corroboration bonus. Scientific novelty and validity are not machine-verified. Scores 0–100 are editorial heuristics, with reasons and manual override.
- Existing selected statuses retain their stored keys. Display workflow: New → Reviewed → Selected → Ready for Content Agent, plus Rejected / Archived. A topic cannot receive multiple selected/ready assignments.
- Ready handoff is a private, read-only CLI contract. It does not run a Content Agent or create posts.

## Scheduling and limits

The existing dispatcher handles one due new source after legacy pending work. Default polling: news 1 hour, technical research 4 hours, papers 24 hours. Existing retry/backoff and global lock apply. RSS/Atom use validators; API cursors and watermarks persist transactionally with the committed page.

Academic discovery starts with approximately 25 hours, not historical mass import. Each request/page is at most 25 records; each window is capped at 500 results. arXiv offset shifts trigger a bounded window retry without resetting the committed checkpoint. Crossref next-cursor advances by API results, including metadata skipped for unknown exact dates. No checkpoint advances merely because a request succeeded.

RSS coverage is the bounded current feed/prefix, not full publisher history. arXiv offers no immutable snapshot token; complete global academic coverage is not claimed. Provider errors retain previous valid records. Unknown API credentials remain outside Git and are not requested in chat.

## Owner-run deployment and acceptance

Prepared bundle: `/home/cyberdat/cyberdat-deploy/research-0.8.2-prepared`. Interactive sudo belongs to the owner; never paste passwords into chat.

1. Verify exact existing file hashes, staging identity, Basic Auth, free disk and protected configuration/timer/theme/Analytics fingerprints.
2. Create private staging SQL/plugin/theme backups; atomic whole-plugin exchange while holding the existing ingestion lock. No partial live PHP overwrite.
3. Install additive tables. Run legacy and discovery integration tests exclusively in uniquely named temporary tables. Stop on failure before enabling new sources.
4. Enable only parser-verified source endpoints; one controlled bounded request per source. No KEV/NVD reimport.
5. Require actual persisted news, technical research, arXiv and Crossref records. Verify repeated upsert, classification, topic identity, papers, capabilities, nonce, admin queue and protected public routes.
6. Confirm zero source/CVE duplicates, unchanged theme/Analytics/config/timer hashes, no post creation, no new checked PHP errors and production HTTPS health.
7. Observe a subsequent scheduled discovery cycle; until observed, recurrence remains UNVERIFIED. Record CPU/RAM/database evidence separately from estimated limits.

If blocked, retain the private backup and use `--resume BACKUP`; never blindly repeat `--apply`. Explicit `--rollback-code BACKUP` disables discovery sources and atomically restores the previous plugin directory. It retains discovered records/additive schema and does not restore SQL or delete archives.

## Verified tests and outstanding work

Offline parser/classifier/security fixtures and existing Research/Pulse/Dashboard/Analytics regression checks pass. Public HTTPS metadata parser tests pass for 12 new channels including arXiv and Crossref. Temporary-table tests are prepared but not executed; they are not reported PASS. No source is reported ACTIVE on this evidence alone.

Still required: real staging persistence and counts, duplicate/event statistics, admin actions and browser verification, scheduled recurrence, bounded load observation, and final backup/commit/deployment report. The 0.8.2 definition of done is not yet satisfied.

Official reference documentation: [arXiv API](https://info.arxiv.org/help/api/user-manual.html), [Crossref REST](https://www.crossref.org/documentation/retrieve-metadata/rest-api/), [OpenAlex authentication](https://help.openalex.org/api/authentication/).

## Deployment continuation — 2026-11-10

Owner-created backup: `/var/backups/cyberdat-staging/research-0.8.2-20261110T151206Z`.
The plugin directory was exchanged, but the first migration command was not registered: the methods are `discovery_install` and `discovery_test`, not hyphenated names. Reproduced using the actual installed WP-CLI factory without WordPress/DB bootstrap.

Use the separate `resume-discovery.py --resume BACKUP` launcher. It checks the original script SHA-256 and changes exactly two command-name literals in memory; the original prepared bundle, release COMMIT, backup and installed plugin files remain untouched by this helper. The existing resume path verifies release/protected hashes and continues migrations/tests before enabling new sources. Do not run `--apply` again.

### Discovery fixture correction

The schema migration and legacy tests succeeded. The discovery fixture then used a cached content hash after re-importing a different source-ID alias; the runtime correctly returned `source_changed_reload`. The corrected fixture now asserts that stale evidence is rejected, reloads current evidence and proceeds with the positive approval case.

The enhanced resume launcher accepts only the exact old/corrected fixture checksums. After validating the existing release, backup and Basic Auth, it saves `discovery-test-before-hash-fix.php` privately in that backup, atomically replaces only `tests/discovery-database.php`, and continues the temporary-table tests. No runtime hash guard is weakened and no collector is changed. The original prepared bundle and its release manifest remain immutable. The launcher also supports explicit `--rollback-code BACKUP` with the corrected fixture present.

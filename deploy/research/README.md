# CyberDat 0.8.1 — Research Agent + Live Threat Intelligence

Staging-only MVP. No LLM, automatic article generation/publication, Content/Social/SEO Agent, new inbound port, DNS, mail or TLS changes. Source code is prepared from the deployed 0.7 Tools commit `f773b31640219ddd5c6dc2e84a19c34fe5c196d9`; the older scaffold branch is not a safe deployment base. Do not rerun the original staging installer or the 0.7 installer.

## Components and ownership

`wp-content/plugins/cyberdat-research/` owns source registry, a constrained HTTPS client, normalization, storage, deduplication, explainable priority, health, scheduling entry points, protected WordPress Admin review and approved-only export. Theme changes are small data-provider adapters and truthful status captions. Existing theme validators/loaders remain solely for offline/Playground compatibility; when the unified provider is enabled, their live flags return false and refresh functions refuse execution. No parallel live ingestion is active.

Pipeline: official sources → secure fetch → validate/normalize → idempotent transactional MariaDB upsert → explainable priority → cached Dashboard and human Editorial Queue. Dashboard/page requests never fetch sources. WordPress's global outbound HTTP blocker remains intact. The only narrow exception is this plugin's CLI-only cURL client: an explicit owner-controlled grant and exact staging path/environment/database/home URL are required. No global WordPress HTTP exemption is added.

## Explicit endpoint registry

| ID | Exact HTTPS GET endpoint | Schedule |
|---|---|---|
| kev | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | 00/06/12/18:13 UTC, six-hour checks |
| nvd | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Every two hours, :29 UTC |
| cisa-advisories | `https://www.cisa.gov/cybersecurity-advisories/all.xml` | Every six hours, :41 UTC |
| cert-eu | `https://cert.europa.eu/publications/security-advisories-rss` | Every six hours, staggered |
| msrc | `https://api.msrc.microsoft.com/update-guide/rss` | Every six hours, staggered |

Source IDs/URLs and source-link hosts are code-reviewed allowlists, not editable URL fields. Adding a feed needs code review, offline fixtures and explicit operator approval. Official source pages: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [CERT-EU advisories](https://cert.europa.eu/publications/security-advisories/), [Microsoft Security Update Guide FAQ](https://www.microsoft.com/en-us/msrc/faqs-security-update-guide), [NVD API](https://nvd.nist.gov/developers/vulnerabilities), [NVD developer guidance](https://nvd.nist.gov/developers/start-here). No article scraping, linked-page downloads, unofficial mirrors or arbitrary hosts are allowed.

A documented endpoint may be unavailable, blocked or return a changed feed format. The controlled live batch records this honestly. Only sources with a successful initial load get timers. An initially unavailable advisory feed remains Sync Error without an automatic retry schedule. It may be retried manually after backoff. Core KEV/NVD failures, or no successful advisory source, block completion and schedule activation. Do not call the entire stage PASS if a required component remains unverified.

## Validation and data integrity

CISA validation reuses the reviewed structural/CVE/date parser, plus all required description/action/due-date fields and optional notes/CWE types. Original row values are retained unchanged under `cisa_original`; the presentation may explicitly label a missing ransomware field as Not provided. Empty, duplicate-ID, invalid-date, oversized or rolled-back catalogs cannot replace the validated catalog. Catalog, records and success metadata commit together. ETag/Last-Modified are used when returned; 304 is accepted only with a previous valid dataset.

Source catalog release, last 200-response received time, last successful validation/check, first seen and last seen are distinct fields. A 304 advances successful-check time, not source release or received time. For a first-seen KEV item, dateAdded is the only known per-item date; its UTC day boundary is not an invented per-item update timestamp. An observed changed item can use the containing catalog release with an explicit basis annotation. An unchanged item does not become a new editorial update merely because the catalog release changes.

NVD records preserve publication/modification times, English description, all supported source assessments, CVSS version/score/severity/source/vector/type, CWE and HTTPS references. A deterministic display assessment prefers higher supported version, NIST source, Primary, then lexical tie-breaks; it never selects the highest score. CVSS v2 legacy severity is retained separately and not reclassified as v3/v4. Missing metrics stay unrated. Rejected NVD records become explicit unrated tombstones, replacing old scores. Source-reference URLs are not fetched and all displayed texts are escaped.

DNS results must be public; private, loopback, shared-address, link-local and metadata addresses are rejected. A checked address is pinned for the TLS connection while hostname/certificate verification remains active. Proxy environment variables are ignored. Redirects are never followed. Connect timeout 5s, transfer timeout 12s, headers ≤64KiB, JSON ≤4MiB and feed XML ≤2MiB. DTD/entity declarations are refused and XML parsing uses LIBXML_NONET without entity expansion. This is application-level egress control, not proof that arbitrary compromised PHP code cannot access the network.

## NVD coverage, pagination and backfill

Initial modified-date window: the latest 24 hours ending ten minutes before the request. Completed windows have a two-hour overlap. In-progress fixed windows persist start/end/index/total; records and page cursor commit in the same transaction. A changed total resets pagination conservatively and reports an error instead of advancing a false checkpoint. The upstream API provides no immutable snapshot: concurrent upstream changes are a known best-effort pagination limitation, mitigated by overlap and reprocessing.

Each normal NVD run performs at most two requests: up to three missing/stale KEV-ID enrichments and/or up to two 50-CVE modified pages. A missing KEV result has a one-day lookup cooldown. The request spacing is at least 31 seconds even with an optional API key and persists before I/O, including across process restarts. Retry-After and exponential backoff are respected; no HTTP retry loop monopolizes a process. The full all-source CLI batch is capped at six requests and a request-admission wall-clock budget; systemd adds a hard 180s timeout.

`nvd_checkpoint` means **completed tracked modified window**, not a complete historical NVD database. `nvd_window` means a partial page run. Backfill has separate state, window, checkpoint and last success; completing a requested backfill interval never means completing all historical NVD. Request at most seven days, processed as ≤24h windows and ≤100 records per dispatcher batch:

```text
wp cyberdat-research backfill --start=YYYY-MM-DD --end=YYYY-MM-DD
```

The command only requests a bounded job; the server dispatcher processes it under the shared lock/rate limit. No historical backfill is requested by deployment. The Dashboard shows Indexed CVEs, partial-data warning, tracked coverage origin, completed window, backfill status and metric-version counts. Its severity chart includes only actually synchronized KEV-linked records, not unloaded CVEs or old snapshots.

MVP safety caps: 5,000 NVD records, 12,000 total research items, 2,000 KEV-linked NVD records in the Dashboard projection, 12MiB projection. Capacity exhaustion stops the batch, preserves old data/checkpoint and reports an error. Increase limits only after measured database/resource review; these are finite staging limits, not an unlimited production retention strategy.

## Storage, deduplication and priority

Six dedicated staging-prefixed InnoDB tables: `cdra_items`, `cdra_aliases`, `cdra_cves`, `cdra_state`, `cdra_logs`, `cdra_events`. There are indexes for source identities, canonical identities, CVE relationships, source-update dates, editorial status, priority, active KEV membership and technical-log dates. Canonical URL normalization removes fragments/tracking parameters. Source-ID aliases survive GUID/URL changes. A unique canonical URL within a source can resolve an existing item; ambiguous identities stop rather than merge arbitrarily. Different advisories with a common CVE remain distinct, linked evidence records. Content hashes ignore irrelevant JSON-object key order and catalog-only release metadata.

Priority is a documented internal heuristic: current KEV membership, labeled supported CVSS, source freshness, official provenance, available context, explicit audience keyword matches and significant source change. It is not EPSS, a probability or proof of active exploitation. A manual 0–100 override is stored separately and retained across updates. KEV relationship and computed priority can be refreshed without pretending the NVD source was retrieved again.

The persistent Dashboard projection is one database row, with an atomic private JSON last-good copy as DB-failure fallback. A fallback or source/job failure is visibly Sync Error; stale data is not silently Fresh. Technical logs contain only fixed source/error codes, with 30-day/5,000-row retention and indexed batched cleanup. Editorial audit events are separate from technical logs; do not delete research evidence automatically. System service journaling inherits the VPS's existing policy; this update does not alter global journald settings.

## Editorial Queue and manual jobs

Admin: **CyberDat → Research Queue**. `manage_options` is required (administrators by default). Filters: source, updated-since date, CVE, severity, status; sort is effective manual/automatic priority descending. Evidence links, source text, confirmed relationships and score explanations are visible. Page size 25. Statuses: New, Under Review, Approved for Draft, Rejected.

POST changes require capability, per-item nonce, valid server-side status/priority, matching current evidence hash and an audit event. Source updates preserve manual priority and review state, except changed evidence automatically invalidates an old Approved for Draft status and returns it to Under Review. Approved export also requires the approved content hash to match current content. No WordPress post or draft is generated.

Manual sync requests use an authenticated, nonce-protected admin POST. At most one pending flag per allowlisted source is stored; no unbounded Action Scheduler/WP-Cron queue is created. The dispatcher runs every five minutes and handles one manual job, eligible retry or bounded backfill batch. Manual requests cannot bypass API backoff or the minimum cooldown. Concurrent ingestion uses one database advisory lock; page transactions protect persisted state. Retry exhaustion does not enqueue infinite jobs; normal source timers remain bounded.

## Future home-PC Ollama adapter (not connected)

The versioned CLI-only `wp cyberdat-research export --limit=20` contract emits approved source evidence with content hash, first/last seen, current confirmed KEV relation and editorial priority. All external text is explicitly untrusted, and publication authorization is false. No administrative REST API is added.

Future safe pattern: the home PC initiates an authenticated private SSH pull using a separately approved restricted/forced-command identity; it retrieves only approved evidence. Ollama remains loopback-only on the home PC; do not publish port 11434, add VPS-to-home routes or send credentials in source text. Treat retrieved text as data, not prompt instructions. Content generation, networking, model selection and any publication workflow require a separate phase and approval. Nothing connects to the RTX 5090 PC in 0.8.1.

## Owner-controlled deployment and rollback

The prepared private bundle pins its exact Git commit and all theme/plugin file SHA-256/Git blob IDs, plus the previous deployed Tools theme manifest. `update-research.py --apply` requires owner interactive sudo and hidden **existing** Basic Auth/WordPress passwords. It checks exact staging identity, previous files, free space, protected config fingerprints and absence of a conflicting research installation. Existing targets stop the script; do not rerun blindly after a partial failure.

Before changes it creates a root-only staging theme archive and a compressed consistent staging-database dump under `/var/backups/cyberdat-staging/research-0.8.1-<UTC>/`, with checksums. This private SQL rollback snapshot contains staging credentials/hashes: never add it to Git, logs or external services, and encrypt it before any offsite transfer. It is not a replacement for the encrypted production backup.

Deployment installs only this plugin, the theme data-provider adapters and dedicated worker units. A root-owned `/etc/cyberdat-staging/research.json` grants the narrow client permission. An optional NVD key belongs in `/etc/cyberdat-staging/nvd-api.key`, root-owned 0640, staging group, entered outside shell history; no key is required at the default conservative rate. No production vhost/FPM pool, existing staging safety MU-plugin, DNS, TLS, credentials, email, Basic Auth or global outbound blocker changes.

The updater runs fixed-fixture tests in MariaDB TEMPORARY tables before live I/O. Then one controlled batch executes each source once under its real systemd resource policy. KEV/NVD must succeed, and at least one advisory source must succeed before live Dashboard activation. The smoke test covers Dashboard/queue/admin login, Tools/archives/REST, guest 401, noindex, tool draft 404, nonce rejection, deduplication, blocked legacy loaders, mail/global HTTP restrictions and production HTTPS/fingerprints. Only then are successfully verified source timers and the dispatcher enabled. Timers are staggered, PHP is limited to 192MiB, the job cgroup to 256MiB/25% CPU, and only dedicated runtime/log/temp directories are writable.

The printed `--rollback <exact-backup-path>` command stops/disables only research timers/jobs, deactivates the plugin, closes its grant, and restores the previous theme. It **retains** research tables/evidence, plugin files, source cache and the SQL snapshot for review. It does not overwrite the whole staging database or delete evidence automatically. A full DB restore is a separate, destructive recovery decision. Production is never a rollback target.

## Validation status before owner execution

PASS: offline validation/security tests; existing KEV/NVD/Tools/editorial/preview/mobile-menu regressions; PHP/shell/Python syntax. PASS: real wpdb/dbDelta against a separate private temporary MariaDB, including indexes, aliases, deduplication, status/approval invalidation, rollback, 304 time semantics, Retry-After and pagination interruption/resume. That lab used auth doubles; the same suite runs with real WordPress capabilities/nonces during owner deployment. No real queue tables, network sources or WordPress posts were used by the lab.

BLOCKED until owner sudo execution: module activation, real WordPress self-tests, actual official-source counts, live HTTP/TLS ingestion, Dashboard/queue runtime, backup creation and schedule enablement. UNVERIFIED: future scheduled recurrence after real time passes, browser/mobile rendering and complete historical NVD. Do not label the whole stage PASS from source tests. Keep the updater's final runtime report as evidence; document unavailable feeds explicitly.

## 2026-11-08 initial deployment interruption and resume

The owner's initial run created and verified `/var/backups/cyberdat-staging/research-0.8.1-20261108T155527Z`, installed the plugin/theme/units and passed the real WordPress temporary-table tests. The first source worker failed with systemd `203/EXEC`: `umask 077` reduced the requested `/opt/cyberdat-research` directory mode to root-only 0700. The wrapper had not executed; no first KEV download was started. A second updater error called `.get()` on a PHP empty-array health value decoded as a Python list, hiding the worker failure.

The correction explicitly applies 0755 to the directory containing public worker code, keeps runtime/backup/key protections unchanged, emits empty health as a JSON object and accepts legacy empty-list health safely. `resume-research.py --resume` verifies the existing backup, pinned files, staging identity and protected configuration fingerprints, checks that no research job/timer is running, backs up the one CLI code file and applies only that patch and the code-directory permission repair. It never calls activation/install/database migration or resets credentials. It skips successful sources and respects pending backoff before finishing the same controlled batch and smoke test. The existing staging database snapshot is reused, not overwritten.

Use only the owner-supplied resume command for this partial state; do not rerun `update-research.py --apply`. The original rollback command remains available. The offline `tests/research-resume.test.py` verifies the actual helper functions under umask 077 and old/new empty health formats, without service/database access. Runtime completion remains pending until the owner executes resume successfully.

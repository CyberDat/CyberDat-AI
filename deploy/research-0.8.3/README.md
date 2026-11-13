# Research Agent 0.8.3 — staging stability acceptance

Status: **PARTIAL**, final acceptance snapshot 2026-11-13 15:13:44 UTC. The original NVD window completed and automatic progress is proven; the Nov13 dense-slice/Crossref-capacity corrections await their existing scheduled backoff. See [final report](REPORT.md) and [machine-readable evidence](acceptance-2026-11-13.json).

## Scope and protected components

Staging only. Base branch is `feat/cyberdat-content-agent-0.9.0` at `d0df9ca3698336ea0ee770c00821f04adeaf61af`, which includes the Research branch ancestor and Content Stage 1.1. New branch: `feat/cyberdat-research-agent-0.8.3`. No merge to main.

Backup: `/var/backups/cyberdat-staging/research-0.8.3-20261111T170009Z`. Full staging SQL and affected files/configuration are archived privately. Gzip and restored-file hashes passed; all 16 Research/Content tables were restored into isolated connection-local TEMPORARY tables and row counts matched the archive. No live SQL restoration occurred.

Content Stage 1.1, public design/styles/JS, SEO, navigation, DNS/TLS, mail, production, editor selections and WordPress posts are outside the changes. No model, GPU, historical import, Content job processing or publication is run.

## NVD algorithm and limitations

The previous collector retained offset pages only while `totalResults` remained equal. A changed total erased its page ledger and restarted at zero. Even equal totals do not guarantee stable membership; the API has no snapshot token.

`includes/nvd-progress.php` adds an independent interval proof to the saved active window. The original bounds, offset, total and committed page ledger remain in `legacy_prefix`; neither the completed checkpoint nor CVE rows are reset or deleted. An oversized range is split. A range is certified only when one validated API response returns every result for it. All requests use `startIndex=0`, with 200 results for ordinary ranges and up to 2,000 only for an indivisible <=1-second range. Adjacent inclusive ranges overlap at their shared boundary; SQL upserts remain idempotent by CVE identity.

Each certified segment retains its bounds, actual IDs, ID hash and verification time. Segments must cover the full root range contiguously, with no pending range, before the atomic transaction advances the checkpoint. Public projections contain only compact progress, not ID ledgers. A later modified CVE is refreshed in subsequent overlapping windows; existing records are never removed when membership shrinks.

Future windows advance by at most one hour, with the existing two-hour overlap and ten-minute safety delay. Outstanding bounded catch-up continues through the existing five-minute continuation policy; the normal source interval resumes when caught up. At most two NVD requests per run, fixed 31-second pacing, 12-second HTTP timeout, 4 MiB response bound and service CPU/RAM limits remain. A dense response above200 rows ends the run after its one response, bounding SQL work. Oversized bodies cause further splitting. A confirmed >200-record second stopped the Nov11 implementation. The Nov13 correction requests up to2,000 records for this leaf only. More than2,000 results produces `nvd_dense_slice` before any upsert; a body above4 MiB produces `nvd_dense_response_size`. Neither limit creates false completion. HTTP503/timeout in the read-only verification prevents claiming real post-fix recovery.

This proves coverage of the API ranges as actually observed, **not** a transactional NVD snapshot or immunity to delayed/backdated indexing beyond the overlap. Historical NVD coverage remains partial. The former 5,000-row NVD ceiling left only 781 slots after the pre-deploy count of 4,219, insufficient to guarantee storage of a bounded window with roughly 3,920 results of unknown overlap. The NVD ceiling is now 10,000, enough for the existing rows plus the maximum 5,000-ID window proof, while the existing 12,000-row total and 12,000-row read-model bound remain unchanged. A lightweight offline 10,000-row aggregation checked exact counts, bounded feed/cache and a 16 MiB peak; the same size inside loaded WordPress peaked at75.3 MiB, with only20 feed entries and a12951-byte read-model. The service cgroup256 MiB/CPU25% limits are unchanged. Capacity failures remain visible: no deletion or false completion. This remains a bounded staging index, not unlimited retention or a historical import.

## Crossref dates

A real response at saved cursor 275 contained DOI `10.64701/jdpa/345/9096`, publication `2026-12-31`, deposit `2026-11-10T09:43:18Z`, index `2026-11-10T10:26:59Z`. The generic future timestamp restriction rejected the publication date as `discovery_date` although HTTP was 200.

Only Crossref publication metadata accepts valid bounded future calendar dates; the source deposit/update timestamp retains the normal non-future validation. Future publication metadata receives no recency bonus. Missing year/month/day or invalid dates are not filled with an import date. Original bounded metadata is withheld in private `discovery_withheld:crossref:<hash>` state. Nov13 adds page offset to new archive keys (max25 withheld records/page); prior window archives remain unchanged. Valid sibling records, withheld metadata and the actual API cursor commit atomically. Cursor progress counts raw API results, not just accepted records. Archives are retained. Real continuation also exposed the old whole-window raw offset limit500; Nov13 raises only the Crossref bound to10,000 raw results, with an additional2 MiB cursor-state limit, preserving opaque cursor/bounds/checkpoint and one25-result page/run. Future Crossref windows advance at most6h plus the existing1h overlap, using the existing5-minute continuation while behind; the normal registry interval resumes when caught up. arXiv retains its500 offset limit. Existing in-flight bounds are not truncated.

## Sophos

The unchanged official endpoint is `https://www.sophos.com/en-us/category/threat-research/feed`. On the VPS the existing public-address validation and TLS handshake succeed; the installed client reports `curl_errno=92`, kind `http2_stream`, HTTP status null, TCP 4 ms, TLS 22 ms, total 46 ms in the post-deployment read-only probe. At 18:07:06 UTC the isolated HTTP/1.1 diagnostic also failed (curl 28 timeout, HTTP null, TCP4 ms, TLS26 ms, total12002 ms); no protocol fallback was installed on speculation. The stream is closed without a usable HTTP response; provider anti-bot intent cannot be inferred from this alone. Sophos ingestion remains BLOCKED, not recovered.

No TLS, SSRF, redirect, User-Agent or proxy restrictions are weakened. No CAPTCHA/access-control bypass. The probe does not upsert records or rewrite retry state; natural backoff remains in force.

## Telemetry, Dashboard and WP-CLI

`CDRA_CLI::sync/dispatch` propagate scheduled context from the root-owned launcher. Actual attempts/successes write scheduled timestamps, without inventing historic values. Inserted/updated/unchanged/stale counters roll back with failed transactions; successful checks with no new rows remain distinct from new-item receipt. Transport failures include safe errno/type/HTTP/timing diagnostics; stale HTTP 200 is cleared before each attempt. Retry-After and exponential backoff remain in force. A bounded `last_failure` object retains the last observed error, safe transport diagnostic and original backoff after successful recovery; it does not invent historical errno values. Scheduled output uses compact completion progress instead of repeating private identifier ledgers. Dispatcher propagates collector failure as a nonzero process exit.

The single changed Dashboard template preserves publication sorting and all six charts, adding first receipt, source sync, exact latest-12/latest-6 scope captions, scheduled/new-item/retry fields and current checkpoint age. Historical fields render `Not recorded`. Home Threat Pulse 2.1, filter logic, CSS/JS and SEO are unchanged.

WP-CLI searches upward for a local config from the service working directory. Previously it reached `/var/lib`, outside the existing open_basedir. A root-owned empty local `wp-cli.yml` stops project-config discovery inside the allowed directory. No vendor patch or expansion/disabling of open_basedir. The exact service cwd/config/basedir check passed without warnings.

## Primary references

- [NVD vulnerability API](https://nvd.nist.gov/developers/vulnerabilities) — last-modified bounds/pagination; no snapshot token is exposed by the current integration.
- [NIST NVD operational notices](https://www.nist.gov/itl/nvd) — changed records and larger payloads; not evidence that a local window is globally complete.
- [Crossref API documentation](https://github.com/CrossRef/rest-api-doc) — incomplete bibliographic dates, indexed-date filtering and cursor pagination.
- [Crossref retrieval guidance](https://www.crossref.org/documentation/retrieve-metadata/rest-api/tips-for-using-the-crossref-rest-api/) — source publication, deposit and indexing dates are distinct.

## Rollback boundaries

The verified backup contains the original Research, Content and theme files, launcher, unit/timer/config files and SQL. New committed data/checkpoints must be retained: do not restore the old SQL over newer records.

Immediate limited rollback of informational UI/launcher: `sudo /usr/bin/python3 -I /home/cyberdat/cyberdat-deploy/research-0.8.3-prepared/manage.py rollback-ui`. It verifies expected installed hashes, acquires the ingestion lock, restores the one original template and launcher and removes the new local WP-CLI config. It deliberately retains the new NVD interpreter and all SQL/state; it is not a full return to 0.8.2. The older collector's mutable-offset limitations would return with a full code rollback. Full collector rollback requires a maintenance review of the saved legacy prefix/new interval proof and the current checkpoint, without checkpoint reset. No automatic destructive rollback was executed or claimed as tested.

Operator scripts are pinned to this staging installation and its existing private support/backup paths; they are not a general installer. `manage.py deploy` rejects an already-installed release, and `observe` performs read-only SQL/unit checks only.

## Final continuation rollback

Fresh backup: `/var/backups/cyberdat-staging/research-0.8.3-continuation-20261113T145510Z`. Gzip, isolated file restoration/hash comparison and all16 SQL tables restored into TEMPORARY tables PASS; restored JSON validates. Original NVD4139 IDs still exist.

`sudo /usr/bin/python3 -I /home/cyberdat/cyberdat-deploy/research-0.8.3-prepared/rollback-continuation.py` validates hashes and performs no live write (tested). Adding `--apply` restores the pre-Nov13 Research code under the ingestion lock, retaining all SQL/checkpoints/cursors/backoff. Earlier dense/capacity limitations will return. It does not restore old SQL, touch Content/theme/production, restart a service or request sync. The live rollback was not executed; isolated restore and preflight are the tested evidence.

Read-only follow-up: `sudo /usr/bin/python3 -I /home/cyberdat/cyberdat-deploy/research-0.8.3-prepared/manage.py observe`. Existing next_due: NVD2026-11-13 19:09:18 UTC (actual request waits for an eligible normal job); Crossref2026-11-14 01:05:18 UTC; Sophos2026-11-14 08:25:05 UTC. No manual retry/backoff clearing was performed.

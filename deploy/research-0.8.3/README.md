# Research Agent 0.8.3 — staging stability acceptance

Status: observation in progress. This file is updated with final measurements before acceptance.

## Scope and protected components

Staging only. Base branch is `feat/cyberdat-content-agent-0.9.0` at `d0df9ca3698336ea0ee770c00821f04adeaf61af`, which includes the Research branch ancestor and Content Stage 1.1. New branch: `feat/cyberdat-research-agent-0.8.3`. No merge to main.

Backup: `/var/backups/cyberdat-staging/research-0.8.3-20261111T170009Z`. Full staging SQL and affected files/configuration are archived privately. Gzip and restored-file hashes passed; all 16 Research/Content tables were restored into isolated connection-local TEMPORARY tables and row counts matched the archive. No live SQL restoration occurred.

Content Stage 1.1, public design/styles/JS, SEO, navigation, DNS/TLS, mail, production, editor selections and WordPress posts are outside the changes. No model, GPU, historical import, Content job processing or publication is run.

## NVD algorithm and limitations

The previous collector retained offset pages only while `totalResults` remained equal. A changed total erased its page ledger and restarted at zero. Even equal totals do not guarantee stable membership; the API has no snapshot token.

`includes/nvd-progress.php` adds an independent interval proof to the saved active window. The original bounds, offset, total and committed page ledger remain in `legacy_prefix`; neither the completed checkpoint nor CVE rows are reset or deleted. An oversized range is split. A range is certified only when one validated API response returns every result for it. All requests use `startIndex=0`, with a local maximum of 200 results. Adjacent inclusive ranges overlap at their shared boundary; SQL upserts remain idempotent by CVE identity.

Each certified segment retains its bounds, actual IDs, ID hash and verification time. Segments must cover the full root range contiguously, with no pending range, before the atomic transaction advances the checkpoint. Public projections contain only compact progress, not ID ledgers. A later modified CVE is refreshed in subsequent overlapping windows; existing records are never removed when membership shrinks.

Future windows advance by at most one hour, with the existing two-hour overlap and ten-minute safety delay. Outstanding bounded catch-up continues through the existing five-minute continuation policy; the normal source interval resumes when caught up. Two NVD requests per run, fixed 31-second pacing, 12-second HTTP timeout, 4 MiB response bound and service CPU/RAM limits remain. Oversized bodies cause further splitting. More than 200 records within an indivisible one-second bucket produces `nvd_dense_slice`, not a false Complete.

This proves coverage of the API ranges as actually observed, **not** a transactional NVD snapshot or immunity to delayed/backdated indexing beyond the overlap. Historical NVD coverage remains partial. Existing hard limits (5,000 stored NVD rows, 12,000 total rows, 5,000 IDs per window proof) remain visible failure boundaries, not an excuse to delete data or mark a partial window complete.

## Crossref dates

A real response at saved cursor 275 contained DOI `10.64701/jdpa/345/9096`, publication `2026-12-31`, deposit `2026-11-10T09:43:18Z`, index `2026-11-10T10:26:59Z`. The generic future timestamp restriction rejected the publication date as `discovery_date` although HTTP was 200.

Only Crossref publication metadata accepts valid bounded future calendar dates; the source deposit/update timestamp retains the normal non-future validation. Future publication metadata receives no recency bonus. Missing year/month/day or invalid dates are not filled with an import date. Original bounded metadata is withheld in private, window-specific `discovery_withheld:crossref:<hash>` state. Valid sibling records, withheld metadata and the actual API cursor commit atomically. Cursor progress counts raw API results, not just accepted records. Completed window archives are retained; a global accumulating 500-record archive cannot block every future window.

## Sophos

The unchanged official endpoint is `https://www.sophos.com/en-us/category/threat-research/feed`. On the VPS the existing public-address validation and TLS handshake succeed; the installed client reports `curl_errno=92`, kind `http2_stream`, HTTP status null, TCP 4 ms, TLS 22 ms, total 46 ms in the post-deployment read-only probe. A separate HTTP/1.1 diagnostic also failed; no protocol fallback was installed on speculation. The stream is closed without a usable HTTP response; provider anti-bot intent cannot be inferred from this alone. Sophos ingestion remains BLOCKED, not recovered.

No TLS, SSRF, redirect, User-Agent or proxy restrictions are weakened. No CAPTCHA/access-control bypass. The probe does not upsert records or rewrite retry state; natural backoff remains in force.

## Telemetry, Dashboard and WP-CLI

`CDRA_CLI::sync/dispatch` propagate scheduled context from the root-owned launcher. Actual attempts/successes write scheduled timestamps, without inventing historic values. Inserted/updated/unchanged/stale counters roll back with failed transactions; successful checks with no new rows remain distinct from new-item receipt. Transport failures include safe errno/type/HTTP/timing diagnostics; stale HTTP 200 is cleared before each attempt. Retry-After and exponential backoff remain in force. Dispatcher propagates collector failure as a nonzero process exit.

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

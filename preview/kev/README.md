# CISA KEV 0.5.0 — data architecture and provenance

## Official input

Primary: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

Alternative: https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json

CISA describes `cisagov/kev-data` as its official mirror, updated shortly after the
canonical catalog (normally within minutes). A fallback can therefore lag the
canonical release. Both are official publications, not aggregators. See
https://github.com/cisagov/kev-data#update-schedule and its CC0 license.

Development retrieval: **2026-11-08 05:49:03 UTC**, canonical HTTP **200**,
`application/json`, **1,832,349 bytes**. Catalog `2026.11.06`, released
`2026-11-06T19:44:45.1797Z`, **1769** entries. The browsing tool separately returned
403; that was not the result of the direct development HTTPS check. No production
host or site was queried.

SHA-256 of the original JSON bytes:
`47e0406b2be5a40420eff66f3d90e83eb8883dae6ff4d08e1b2a942c366f6cc2`.

An independent download of the official GitHub mirror at immutable commit
`e5b3a9b25050a8da26c96266c5bfe438ee0bdebc` returned HTTP 200 and the **same checksum**.
Exact URL, timestamps, checksums and schema source are in `provenance.json`.
`official-schema.json` is the official CISA schema from that commit; the full
snapshot passes it. Unknown future schema fields are not interpreted by our UI.

`official-snapshot.json.gz.b64` is **the full original JSON**, gzip-compressed with
mtime=0 and base64-encoded (262,884 encoded bytes). Decode base64, then gunzip; the
result must match the SHA-256 above. No entries are invented or omitted. This keeps
Blueprint small; it embeds this file without downloading CISA data on opening.
The uncompressed local working copy is deliberately not a tracked theme asset.

## Service boundary

`inc/kev-data.php` contains validation, cache, HTTP and Cron. The independent
`template-parts/home/intelligence.php` only reads the cache and renders escaped
HTML. No network call occurs on a homepage request. No REST/admin/AJAX refresh
endpoint, new plugin, schema/taxonomy registration or secret is added.

The service is **development-only**: WordPress environment `local`, `development`,
`staging`, or explicit Playground. Live scheduling additionally requires
`CYBERDAT_KEV_LIVE === true` and is **always disabled in Playground**. The constant
is not defined by the theme or Blueprint. A direct internal refresh is only used
by tests with WP HTTP intercepted; it has no public trigger.

- WP HTTP API: `wp_safe_remote_get`, the two exact HTTPS URLs above, no configurable
  URL, no redirects (including otherwise trusted redirects), TLS verification,
  8-second timeout per source, 4 MiB limit + one byte to detect truncation.
- Require HTTP 200, JSON or text/plain MIME (GitHub), valid UTF-8 JSON, depth <=32,
  <=10,000 rows, matching integer count, valid release/version/dateAdded, unique
  uppercase CVE IDs, bounded text, and recognized optional ransomware values.
- Normalize only consumed fields. Ignore external links in notes; table links go
  to the fixed official CISA catalog. CVEs with equal dateAdded sort by CVE ID DESC.
- Persistent non-autoloaded `cyberdat_kev_last_good` contains normalized catalog,
  source URL, successful-check time and snapshot flag. It does not expire or get
  erased on network/validation failure. Reject older releases and unexpected empty
  replacements of a nonempty catalog. A valid initially empty catalog is supported.
- `cyberdat_kev_attempt` records attempt time and a bounded internal error code,
  never response bodies. One-hour minimum between attempts, success or failure.
- `cyberdat_kev_lock` uses atomic `add_option` (unique option key), a 120-second
  lease and owner token. Expired recovery/release uses SQL compare-and-delete on
  the serialized original value, then clears option caches. Old workers cannot
  delete newer locks; ownership is checked again before committing new data.
- WP-Cron event `cyberdat_kev_update`: twice daily, first run after 60 seconds,
  scheduled once using `wp_next_scheduled`. No HTTP in `init` or templates. Disabling
  the flag clears the event on init; switching themes clears it as well.

Fresh means a successful source verification <=24 hours old and no subsequent
failed attempt. It does not mean CISA released a new version in the last 24 hours.
Stale means older verification, a subsequent failed/in-progress attempt, or **any
fixed snapshot**. Unavailable means no usable cache. Both source release time and
successful check/snapshot time are shown. A snapshot is explicitly NOT LIVE even
on its acquisition date; it never becomes a Fresh live cache automatically.

## What metrics mean

At the snapshot reference date **2026-11-08 UTC**:

| Metric | Value |
| --- | ---: |
| KEV catalog entries | 1769 |
| Added in 7 UTC calendar days | 3 |
| Added in 30 UTC calendar days | 30 |
| Entries with ransomware use = Known | 361 |

Windows include the reference date and previous 6 / 29 UTC dates; they are not
rolling 168 / 720-hour windows. Chart points are the seven actual dateAdded buckets,
including real zero days. For snapshots, windows stay anchored to acquisition day,
which is explicitly shown. Live cached views use today's UTC date. These are
catalog additions, **not attacks, detections or incidents**. Ransomware Known is a
catalog field, not a count of ransomware incidents; Unknown is not No. Missing
ransomware values display Not provided. No CVSS is inferred; the neutral panel says
“CVSS data pending NVD integration” and its ring has no severity proportions.

## Isolation and verification

The fail-closed `front-page.php` guard preserves production fallback to index
before the dashboard can render. Version 0.6.0 additionally permits explicit isolated
staging; see `deploy/staging/README.md`. Approved header, menu, 3B assets, CSS and 0.4.0
editorial components are unchanged. Only dashboard text/data and the preview notice
are updated, preserving metric/panel/table layout and responsive containers.

Local `php tests/kev.test.php` runs the shared real-module suite with in-memory
WordPress primitives, intercepted HTTP, and no network or actual DB. It tests JSON,
size/count/date/duplicate errors, independent metric counts/window boundaries,
empty/unavailable/stale states, fallback/HTTP/redirect errors, retention/rollback,
throttling, lock overlap/ownership/recovery, escaping and cache-only rendering.
Existing Featured/section/navigation checks remain in use.

Playground runs **the same KEV suite against real WordPress options and WP HTTP
filters**, alongside both 0.4.0 suites. `finally` restores original cache, attempt
and lock. Test-only strings never remain in the displayed official snapshot.
Reports are shown in the browser inspector. The 320/768/1440px DOM checks now expect
real CVEs, a NOT LIVE/Stale snapshot, dateAdded chart and neutral severity panel.
No authoring browser engine is available: those runtime results must be checked
by opening Playground; local tests do not certify browser layout or WP-WASM SQL.

## Future live enabling — staging only, not performed

After approval and staging deployment of this branch:

1. Verify a separate staging DB, restricted/nonindexed access, WP environment type
   `staging` (or local/development), no production credentials, functioning outbound
   HTTPS and WP-Cron. No public refresh endpoint is needed.
2. In that environment's configuration only, define `CYBERDAT_KEV_LIVE` as `true`.
   Do not set it in Git or Playground. On the next init the event is scheduled;
   the first background run is due after 60 seconds. WP-Cron depends on traffic or
   a separately approved cron runner; it is not a guaranteed wall-clock scheduler.
3. Inspect `wp cron event list` for `cyberdat_kev_update`. An authorized staging
   operator can run `wp cron event run cyberdat_kev_update` to verify the worker;
   its one-hour throttle still applies. Check source, success timestamp and Fresh
   status, then confirm a failed source retains data as Stale.
4. To disable, remove/set the flag false; next init removes the recurring event.
   The last-good cache remains. Never delete cache to simulate refresh in production.

Production live enable/display is **not supported by this step**: the service's
development gate and unchanged homepage guard prevent it. A later separately
approved production release must review lifecycle ownership, scheduling and the
production UI before allowing it there. No DNS, Nginx, DB service, HTTPS, Coming
Soon, Rank Math or sitemap changes are part of this work. NVD remains unconnected.

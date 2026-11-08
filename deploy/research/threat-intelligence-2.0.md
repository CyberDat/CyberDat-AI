# Threat Intelligence 2.0 — separate dashboard and verified geo foundation

## Staging scope

Native WordPress Page `/threat-intelligence/`, template `page-templates/threat-intelligence.php`. Uses the existing Research Agent dashboard_v1 read-model; **no Research Agent files, ingestion jobs, stored records, cache regeneration or timers are changed by this release**. No duplicate CISA/NVD datastore, upstream calls, backfill, agents or publication of news is introduced.

The deployed baseline was checked against all eight Dashboard 1.1 file hashes. The full six KPI/charts, feed/filters, advisories, source links and source health move to the dedicated page. The order is Global Map → Overview → Analytics/Charts → Feed → Advisories → Status. The homepage retains three source-labelled Pulse metrics (Critical, seven-day source-published local CVEs, full last-validated KEV) plus one genuine latest collected advisory and the Explore link. Partial NVD scope and aggregate generation time remain explicit.

Eight primary navigation links preserve the seven existing sections. A virtual item avoids menu-setting writes, with fallback coverage and duplicate-link prevention. The existing mobile toggle is unchanged; primary link spacing is slightly compacted globally. Filters submit to the dedicated page; map filters are isolated state and cannot overwrite ti_source/ti_kind/ti_severity.

## Map choice and geography

A locally compiled Natural Earth 1:110m land SVG (public domain, input SHA recorded in assets/maps/NOTICE.md) replaces the need for MapLibre, remote tiles, WebGL and third-party code. Equirectangular projection matches event coordinates. Pan/zoom, keyboard controls, touch drag opt-in, markers, grid clustering, bounded cluster pagination, source/type/time filters and evidence cards use small first-party JS/SVG. No network call to a map provider occurs.

Atlas data is not telemetry. No observed geo source is connected. Server and client explicitly show **No verified geolocated threat events available.** No random attacks, IPs, country-to-country paths, attribution, historical-as-live labeling or sample events appear. Live Telemetry is a disabled mode until a separately approved operational source, freshness contract and validation exist. An event's location/confidence describes the observation, not attacker origin.

## Separate Geo Events module

Plugin `cyberdat-geo-events`, staging host/path/database guard, own `{prefix}cyberdat_geo_events` table, unique source/event identity and public-observed indexes. No Research schema is modified. Source registry is empty by default and can only be extended by reviewed PHP connector code; no connector or paid API is enabled. Future sources may include authorized sensors, reviewed aggregate feeds or public observations. Honeypots, new ports and persistent services are not installed.

Normalized contract: event ID, approved source, event type, observed UTC timestamp, country/region, approximate latitude/longitude (rounded to 0.1°), geolocation type/confidence, optional explicitly known coarse target location, approved HTTPS evidence URL, verification status and explicit display authorization. No source/target IP field is stored or publicly returned; any such field is rejected. URL credentials, queries/fragments, non-approved hosts, future dates, invalid coordinates and unsupported statuses are rejected. Do not register feeds containing private infrastructure or personal data. Only a reviewed administrator CLI integration can upsert. No writer, importer, writable REST route or automatic verification is exposed.

GET `/wp-json/cyberdat-geo/v1/events` is staging-only and requires the web-server Basic Auth identity. Only verified **and** explicitly display-authorized events from registered sources can be output. Parameters: event_type, source, days (7/30/90), zoom (1–6), format (clusters/events), page (1–10), per_page (1–100). Invalid limits return 400. A transient caches at most 1,000 latest authorized observations from 90 days for 60 seconds; connector upsert invalidates it. Larger coverage is explicitly marked truncated. Cluster samples hold at most five events, output at most 100 items/page. No upstream fetch is performed. Empty registry uses no event query and returns zero verified events.

## SEO

One native permalink and singular page, page-specific Rank Math title/description; no theme canonical, Open Graph, Schema or meta-description injection. Staging remains Basic Auth + noindex/nofollow. **Installed Rank Math intentionally suppresses canonical tags on noindex pages** (frontend class-head robots method). Verification therefore permits zero on staging and at most one correct canonical, while verifying the native permalink. Do not weaken noindex or duplicate canonical to force a tag. Existing Tools, Topics, News, Analysis, Guides and Learning routes remain unchanged.

## Deploy, backup and rollback

`deploy-threat-2.py --apply` is an owner-sudo, staging-only prepared bundle. It checks exact installed baselines, absence of reserved path/plugin/table conflicts, source artifact checksums and staging identity. Before copying any file or creating the page/table it saves private root-only staging SQL and a theme archive. It installs only theme changes and the new Geo plugin, creates one genuine native page, sets that page's template and Rank Math metadata. It never calls the original installer or changes/restarts/stops timers. Normal scheduled Research activity may continue; a bounded read-only wait avoids checking an in-flight projection.

Independent read-only SQL proof from Dashboard 1.1 verifies every retained KPI, chart series, advisory/source count and NVD∩KEV relationship. HTTP smoke checks compact home/Pulse, dedicated page/order/charts, eight-link navigation, dashboard and map filters, native permalink/SEO, map/JS assets, zero actual geo records and proper empty response, rejected POST/bad limits, existing routes, admin login/Research Queue, protected production/staging fingerprints and unchanged Research code/timer files. Logs are counted without raw messages; absent logs remain UNVERIFIED. Existing staging credentials are hidden; no resets.

On a failed post-deploy check use `--verify <printed-backup>`; do not reapply. `--rollback <backup>` restores previous theme files, deactivates Geo Events and makes only the newly created page draft. New inert files and Geo table/data remain; no SQL restore, deletion or timer action. The backup is an application snapshot, not an atomic full-VPS restore point.

## Tests / screenshots

Offline: `php8.4 tests/geo-events.test.php`, `php8.4 tests/threat-page.test.php`, existing `tests/threat-dashboard.test.php`, and Node `tests/threat-geo.test.cjs` / `tests/intelligence-charts.test.cjs`. Fixtures stay in memory, never in the staging Geo table. Tests cover IP/privacy/URL/date validation, source allowlist, query bounds, clustering, empty state, projection and camera bounds, preserved navigation, compact Pulse and six charts.

No real browser is available in the VPS workspace. Desktop 1440 / Tablet 768 / Mobile 320, screenshots and JS console are UNVERIFIED until actual browser execution. `capture-threat-2.py` uses existing Windows Edge with Python stdlib, disposable profile, loopback DevTools and hidden Basic Auth; no browser/package installation. It captures the real dedicated page including map and all charts, checks period switching, map empty/zoom/reset, menu, filters and overflow. Do not present fixture pictures as staging screenshots. No next-stage agents, n8n or production deploy.

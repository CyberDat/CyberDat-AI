# Threat Analytics UX 2.1 — staging only

This is a read adapter and UI release. The Research Agent plugin, source connectors, locks,
sync/checkpoints/backoff, scheduler/timers, DNS, TLS, mail, Basic Auth, SEO and existing site
container widths are unchanged. Production is never a deployment target.

## Architecture / interpretation

`cyberdat-threat-analytics` reads existing `cdra_items`, `cdra_cves`, `cdra_state`.
No CVE copy, new table, ingestion or background job. One grouped SQL aggregation returns
at most 180 source/date buckets; 12 period metrics are computed from those buckets.
One bounded transient contains this aggregate (600 seconds, one fixed key). Its signature
includes the existing projection generation, counts, chart series and metric-version totals;
new Research projections invalidate the cache. Health-only updates do not invent new counts.
No network request is made by the homepage. Source publication dates and CISA dateAdded
are authoritative. UTC windows include today plus the preceding 6/29/89 calendar days,
clipped to projection generation for NVD. NVD history remains partial for every period.

Homepage defaults to 7D. All four large KPIs, their scope text, window dates and both actual
NVD/KEV-addition sparklines follow 7D/30D/90D. Full KEV and total ransomware counts remain
separately labeled. CVSS severity breakdown explicitly retains its **all-indexed-date** scope.
Critical counts use the current selected assessment for CVEs published in the period,
not a reconstruction of their historical score. Ransomware counts use current CISA Known
classification for records added during the period, not the date of ransomware activity.
No Critical/ransomware trend is fabricated. Existing missing-series safeguards remain.

## Drill-down API and consistency

GET `/wp-json/cyberdat-analytics/v1/records`, only on the exact staging environment,
DB/root/home identity, behind existing Basic Auth (`REMOTE_USER`). No writer or administrative
REST route. Only source ID/title/description, official URL/source, publication/dateAdded and
selected CVSS score/version/severity are returned. No internal IDs/paths, editorial status,
raw payload, IPs, credentials, salts, API keys or queue data.

Exact allowlists for group/value/days/sort, bounded CVE prefix, real calendar dates,
page <= 600 and page size <= 50 (UI 20). Prepared values; fixed identifier/order expressions.
- severity: Critical/High/Medium/Low/None/Unrated, one selected assessment per NVD row.
- overlap: shared, KEV-only (not in **local** NVD), NVD-only (not in CISA KEV).
- ransomware: Known vs not marked Known/unreported; the latter is never called safe.
- advisory: CISA, CERT-EU, MSRC; actual stored records, not full publisher archives.
- day: NVD publication vs CISA dateAdded, within the retained 7/30/90-day chart period.
- period: the four homepage selections, for independent SQL acceptance.

Membership joins use EXISTS so multiple CVE relations/metric versions do not multiply rows.
Stable source-date/ID ordering, or selected score/date/ID ordering. No entire catalog goes to
browser. Source URLs are HTTPS and checked against existing Research source host allowlists.

Each operation uses a read-only consistent DB snapshot. The existing ingestion lock is only
observed with IS_FREE_LOCK, never acquired, released or modified by this module. Concurrent
Research activity returns 503 instead of blocking ingestion. The projection SHA-256 is pinned
for initial graph selection and subsequent pages/search/sort; stale revisions return 409.
Refresh explicitly selects current data and warns if it differs from the earlier chart.
No attempt is made to change checkpoints or repair Research data through a UI request.

## UX

Native dialog: right sidebar on desktop, full screen on mobile, modal focus, Escape, close,
focus return. Source links and all external text use safe DOM text insertion. SVG marks are
real actions; zero/tiny ring/bar groups also have text buttons under Browse source records.
Day points remain actionable after period redraw. Search, four sorts and pagination run on
server. Underlying charts and current periods are preserved. No framework/CDN/telemetry.
Existing menus, map, KPIs, feed and security status remain; no site-width CSS is changed.

## Owner-run deployment

Private prepared bundle: `/home/cyberdat/cyberdat-deploy/analytics-2.1-prepared`.
It packs exact Git blobs and before/after hashes. `support.py` is the pinned existing
`deploy/research/deploy-threat-2.py`, imported without calling its main. Independent existing
chart SQL proof is packed alongside new proof.php.

```bash
sudo -v && sudo -n /usr/bin/python3 -I \
  /home/cyberdat/cyberdat-deploy/analytics-2.1-prepared/deploy-analytics.py --apply
```

Hidden existing staging Basic Auth password only. Before any module/theme installation:
root-only SQL + full theme + old changed files under
`/var/backups/cyberdat-staging/analytics-2.1-<UTC>/`, checksums in state.json. SQL/files are
not an atomic whole-site snapshot. Only the new adapter is activated; no plugin updates,
reinstallation, timer operation, source fetch, queue change, reset or cache purge.
Normal WordPress bootstrap/HTTP writes and this module's bounded aggregate transient remain possible.

One consolidated acceptance set: independent SQL confirms all 12 KPI values, six severity
counts, three overlap sets, two ransomware sets, three advisory sources, all 180 date points,
search, stable nonoverlapping pages and sort limits. HTTP GET/method/bounds/revision checks,
homepage JSON, dashboard/map/charts/routes/SEO, Basic Auth/noindex, two logs, protected hashes
and production HTTPS health are checked. Outputs exact period table, commit and backup.
A concurrent scheduled ingestion can make validation return busy/revision mismatch: retain
installed state and run the printed `--verify BACKUP`; never blindly reapply.

Explicit `--rollback BACKUP` deactivates only the new adapter and restores saved theme files.
New inactive files/transient/backups remain; no SQL restore/deletion or Research/scheduler changes.
Full before/after hashes prevent overwriting unrelated changes.

## Browser acceptance / honest status

`capture-analytics.py` runs on Windows with existing Edge; hidden Basic Auth, disposable profile,
loopback DevTools, staging-only intercepted requests. Captures Pulse/dashboard/record panel at
320/768/1440/1920; checks period counts vs embedded model, all chart groups, server search/sort/
pagination, native Escape, touch at 320, overflow and console. No package/browser is installed
on VPS. Screenshots require human review. Until executed, browser/mobile interaction is UNVERIFIED;
static tests are not a visual PASS. Busy source ingestion may require a later browser run.

No Content/Social/SEO Agent or other project stage is included.

## Finish already installed 2.1 (no reapply)

The follow-up label fix makes all 14 filter headings human-readable, including direct gray
KEV-only/NVD-only SVG clicks. `finish-analytics.py --finish` verifies the installed original
8-file release and locates/checks its original private backup. It never reinstalls/activates
plugins, reruns the installer, edits Research code or changes scheduler/checkpoints.
Before replacing only `assets/js/threat-analytics.js`, it creates a new private SQL/theme/
previous-JS backup under `analytics-2.1-finish-<UTC>`. Already-patched runs resume verification
using that backup without rewriting JS or issuing another backup. Both original and finish
backups remain intact. An explicit `--rollback FINISH_BACKUP` restores only that previous JS.

```bash
sudo -v && sudo -n /usr/bin/python3 -I \
  /home/cyberdat/cyberdat-deploy/analytics-2.1-finish-prepared/finish-analytics.py --finish
```

After the one consolidated SQL/HTTP verification, output contains the actual 7D/30D/90D
KPI table, both backup paths, revision, counts and remaining browser UNVERIFIED items.
The updated Edge helper also checks human headings, close button, focus return, keyboard
opening and preservation of 7/30/90 chart periods after closing day drill-down.

The browser helper now uses one strict wait/diagnostic path for every group, sort, search,
pagination and day/period operation. A 409 permits one explicit click on the existing Refresh
control; a 503 permits at most four UI retries, 15 seconds apart, within 100 seconds. Neither
path bypasses server validation, rewrites cache/checkpoints or pauses Research jobs. Controlled
409/503 network events are counted separately in the report; uncaught JS and unexpected
console/HTTP errors still fail acceptance. Offline state-machine tests cover all terminal paths.

## Dialog lifecycle correction

An offline test executing the actual theme JavaScript reproduces a real race:
close Critical, open High, then receive Critical's queued native `close` event. The old handler
increments the new request serial and aborts the current controller, leaving High in Loading
because its abort callback is now stale. The minimal fix ignores a queued close while the dialog
has already reopened. Genuine closes still abort the pending request and restore focus.
`analytics-dialog-lifecycle.test.cjs` proves both the old failure and the fixed behavior.

`fix-dialog.py --finish` is an owner-run one-file staging deployment: verifies exact before/after
JS hashes, creates a fresh private SQL/theme/previous-JS backup under `analytics-2.1-dialog-<UTC>`,
then atomically replaces that JS only. Repeated finish resumes checks using its matching backup.
No new installation, plugin activation, API ingestion, checkpoint/cache reset or timer operation.
Explicit rollback restores only the prior JS. Browser verification is still required after deploy.

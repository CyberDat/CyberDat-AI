# Homepage UX 2.0 — Interactive Threat Pulse

Theme-only staging release. Uses the existing `cyberdat_research_dashboard()` persistent
projection and current source health. No Research plugin, scheduler, API, SQL schema,
source connector, WordPress settings, navigation, full Dashboard, map or SEO changes.
The homepage preview/production guard is unchanged.

## Presentation contract

- Four fixed-scope KPIs: Critical in the partial NVD index; source-published NVD CVEs
  in seven UTC calendar days; the full last validated KEV catalog; ransomware `Known` KEVs.
- Two real daily sparklines: source publication of **indexed** NVD CVEs and CISA `dateAdded`.
  KEV's line is additions, not historical total catalog size. NVD is a partial index in all periods.
- 7D/30D/90D changes only the trend subsets and daily tables, not the fixed seven-day KPI
  or all-index CVSS distribution. At least two nonzero dated observations and a complete,
  contiguous period of valid daily counts are required to draw a line. Otherwise display
  an insufficient-data message. Zero means zero local indexed observations, not zero global CVEs.
- No sparkline for Critical totals or ransomware totals: historical snapshots of those totals
  are not recorded. No inferred history or new ingestion mechanism is introduced.
- Six severity shares include explicit score-zero `None` and missing-score `Unrated`.
  Selected CVSS versions are listed separately; one selected score is counted per CVE.
- Threat Signal: bounded existing feed (up to 20 records/source), last 30 publication days;
  confirmed KEV first, then selected severity, then newest publication, stable source/ID ties.
  Source import order is ignored. This does not claim exhaustive global ranking or EPSS.
- Source last-success times and Fresh/Stale/Sync Error use the existing source thresholds.
  A health update newer than the cached projection is marked Projection pending. Projection
  timestamp is separately labeled. No remote request or cache write occurs on homepage load.

## UX and limits

Homepage main container alone grows to at most 1280 CSS px. Header, articles and other pages
retain existing widths. Four/two/one columns; no new service, library or dependency. Native SVG,
keyboard left/right/Home/End point inspection, focus/tap severity labels, daily HTML tables and
server-rendered KPI/legend/signal work without remote scripts. Period buttons are hidden until
JS enhancement succeeds. Reduced-motion disables transitions. Desktop compactness is a target,
not a fixed height that clips zoomed text, translated strings or opened data tables.

## Owner-run deployment

The prepared bundle contains exact candidate hashes, pre-update hashes, `COMMIT`, the
pinned existing `deploy/research/deploy-threat-2.py` as `support.py`, and its independent
SQL chart proof. Importing support does not execute its deployment main function.

```bash
sudo -v && sudo -n /usr/bin/python3 -I \
  /home/cyberdat/cyberdat-deploy/home-pulse-2.0-prepared/deploy-pulse.py --apply
```

Only the existing Basic Auth password is requested, using hidden terminal input. Before
any theme write, create a root-only staging SQL backup, full theme archive and old changed
files under `/var/backups/cyberdat-staging/home-pulse-2.0-<UTC>/`. Check SHA-256 before
verify/rollback. No automatic SQL restore, credential reset, deletion, cache flush, service
reload, timer operation or ingestion. Normal WP bootstrap/HTTP request writes remain possible.
A full DB + file backup is not an atomic whole-site snapshot.

If interrupted after changes, do not rerun apply. Use the printed `--verify BACKUP` command.
Explicit `--rollback BACKUP` restores prior bootstrap/template files, leaving inert new
assets/helper files and all SQL/backups intact. No production data is restored or changed.

## Acceptance

Offline: PHP syntax, presentation fixtures, 7/30/90 JS subsets, absent/gapped/zero history,
source-date ranking, escaping, existing guards, six Dashboard charts and navigation.
Owner deployment: independent SQL checks all 180 daily values, period totals, KPI/histogram,
rendered HTML series, selected source link, Basic Auth/noindex, exact unchanged non-target
files/Research/timer/config hashes, full Dashboard six charts/SEO, two staging logs, prod HTTPS.
An active Research job is only waited for (bounded), never stopped; a concurrent projection
change fails verification safely instead of rewriting data.

Browser acceptance remains UNVERIFIED until `capture-pulse.py` is run on Windows with existing
Edge. It uses hidden Basic Auth, a disposable profile, staging-only intercepted requests and
loopback DevTools. Produces homepage and Pulse screenshots at 320/768/1440/1920, period and
severity interactions, keyboard points, menu/overflow/console checks. No browser is installed
on the VPS. Actual screenshots must be reviewed; static tests are not visual proof.

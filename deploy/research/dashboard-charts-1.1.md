# Dashboard 1.1 — restore and extend visual analytics (staging only)

Adds six server-rendered native SVG charts while retaining Dashboard 1.0 KPI cards, filtered Research Feed, Security Advisories, Research Agent Status, the CVSS version table and all editorial sections.

## Data and definitions

- CISA KEV Additions: full validated catalog's dateAdded by UTC day, 30/90-day selector.
- NVD CVE Trends: source published dates of the **locally indexed subset**, 7/30/90-day selector. No historical backfill or import is performed. Local zeros are not global zeros. The existing origin, checkpoint and window-completeness text remains visible.
- Severity ring: every indexed local NVD CVE, one selected assessment per CVE. None (explicit score zero) and Unrated (no score) are distinct; selected CVSS versions remain disaggregated in a table. Score bands across versions are not interchangeable.
- KEV vs NVD: two independently normalized bars with exact shared/unmatched counts and explicit denominators, not a Venn diagram suggesting complete NVD coverage. Unmatched KEV means not in **local NVD**, not absent from the global database.
- Ransomware ring: CISA Known versus other/unreported field values among all validated KEV entries. Unknown does not prove absence of ransomware use.
- Advisory bars: actual stored records per CISA advisories/CERT-EU/MSRC source, not full publisher archives.

The Research Agent's existing background projection now includes two 90-day series in dashboard_v1. Existing six KPIs, feed bounds, upserts, source connectors, schedule and cursor semantics do not change. No remote calls occur during rendering or interaction; the browser only switches cached data. Cache regeneration uses the existing named ingestion lock. Old cache without chart aggregates displays Not Available, never a snapshot substitution.

## Accessibility and performance

All initial graphs, descriptions, legends, values and full accessible data tables are server HTML. Native SVG titles and keyboard-focusable marks remain usable without JavaScript; complete 90-day tables are available in details. An independent first-party script adds period switching, focus/pointer/touch tooltips and nearest-date inspection on line charts. It uses textContent/createElementNS, validates bounded numeric series and never inserts untrusted HTML or requests URLs. No libraries, fonts, animations beyond a small reduced-motion-aware focus highlight, or third-party assets are introduced.

Mobile-first chart grid: one column below 640 px, two above. Rings stack their legend on narrow screens; scrollable CVSS/data tables remain inside their own region. Actual device layout and console behavior must be observed in a browser, not inferred from CSS.

## Verification and deploy

Offline commands:

```
php8.4 tests/threat-dashboard.test.php
php8.4 tests/research.test.php
node tests/intelligence-charts.test.cjs
```

PHP tests verify 90-day source-date aggregations, zero/missing distinctions, existing six KPI/source/filter contracts, all six chart outputs and escaped external data. Node tests verify 7/30/90 selectors, sum conservation, finite SVG geometry, all-zero series and invalid input rejection.

The owner-run `deploy-charts.py` requires existing sudo, staging Basic Auth and staging WordPress credentials entered hidden. It verifies exact installed before hashes, pauses existing Research timers, waits for bounded workers, and backs up staging SQL/theme/plugin privately **before installed-file changes**. Only eight pinned plugin/theme code files are changed. The existing agent installer is never rerun. No API ingestion, schema migration, DNS/TLS/mail/production changes or cache flush occurs.

The read-only independent `dashboard-charts-proof.php` checks all 180 daily data points against SQL GROUP BY source dates; six KPI values, severity counts, source bars and the confirmed CVE intersection must agree with database records. HTTP verifies six rendered charts, period controls, tooltip/arc HTML, CSS/JS availability, existing filters/Tools/archives/login/REST/noindex, Research Queue and protected fingerprints. Existing timer active states are restored. Logs are checked at the actual staging PHP path `/var/log/cyberdat-staging/php-errors.log` and dedicated Nginx error path `/var/log/nginx/cyberdat-staging.error.log`; raw messages are suppressed. Zero readable files is UNVERIFIED, never proof of no errors.

An explicit `--verify <backup>` checks the installed release without reinstall; `--rollback <backup>` restores preexisting files, retains new inert files and accumulated Research data, and rebuilds the old projection. No automatic SQL restore/deletion. Backup path is printed only once it is actually created. Backups can contain staging secrets and remain root-only.

## Screenshots and browser acceptance

No browser is available in this VPS workspace. Browser/mobile/console and screenshots are **UNVERIFIED until a real run**. `capture-charts.py` runs with Python standard library and existing Microsoft Edge on Windows, installs nothing and uses an isolated disposable profile/loopback DevTools. It captures real staging at 1440/768/320 px, checks overflow, KPI columns, mobile menu, all six charts, each period selector, point focus tooltip, filter submission and console/runtime errors. Credentials are hidden and never placed in argv or output. It saves screenshots/report in a new `CyberDat-charts-1.1-screenshots-<UTC>` Windows-home directory. Do not represent fixture output as real staging screenshots.

No next-stage agents, publication, n8n or production deploy.

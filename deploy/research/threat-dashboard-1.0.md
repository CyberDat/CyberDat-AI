# Threat Intelligence Dashboard 1.0 — staging

## Scope and state

This release presents the existing Research Agent database, without changing ingestion connectors, CVE upserts, NVD checkpoint semantics, editorial statuses or publishing. The last owner-confirmed NVD result before this release was 920 indexed records and a verified 917-result modified-date window ending 2026-11-08T15:54:49Z; it is not a claim about the current count. The deploy proof reports current SQL values.

New `includes/analytics.php` builds `stg_cdra_state.dashboard_v1` during the existing locked background projection. It reads only active Research records, with the existing hard limits (12,000 total / 5,000 NVD), restricted SQL-extracted fields, bounded summaries and a 2 MiB result cap. There is no external API call, schema migration or new job. Each successful or failed ingestion projection rebuilds the read-model; page requests read one aggregate plus five small health records, never source payload scans. A missing read-model returns Not Available, never a static snapshot. Cached last-good values remain labelled with their generation time; source statuses age independently. UTC calendar charts use the explicit reference date in the projection.

## UI and data definitions

- Six source-labelled KPI cards: full current KEV, local NVD, selected-score Critical (9–10), High (7–8.9), CISA ransomware Known, collected official advisories. Every card gives sync time and scope. The advisory KPI shows the oldest source sync; individual source times are listed below.
- Threat Feed: up to 20 latest published records per source, combined publication-date DESC with deterministic source/ID ties. Twelve matching events are rendered. The form filters by allowlisted source, selected score severity and event type using server HTML GET; no JavaScript is required. It explicitly filters the bounded feed, not all historical records. CVSS version/source, confirmed KEV and CISA ransomware flags are shown only when present. Imports never masquerade as source publication.
- Analytics: distribution over **all local NVD** (including Unrated and explicit score None), cross-table by selected CVSS version, 7/30-day publication counts and 30-day UTC trend. Score ranges across CVSS versions are not represented as interchangeable; versions remain visible. The trend describes the local modified-date sample, not worldwide CVE incidence. KEV total/additions and NVD∩KEV are separate.
- Advisories: genuine CISA/CERT-EU/Microsoft records, publication dates, source organizations, CVE links/IDs and original URLs; no synthetic news.
- Status: live source health/last received/last successful sync, CISA catalog version/release, NVD origin/checkpoint/current or completed bounded window and Research Queue count. A successful API request is distinct from a complete bounded window, and neither means complete historical NVD.
- Last scheduled success is **Not Available** when the existing health schema lacks evidence of whether a successful run was scheduled or manual. No timestamp is inferred.

External data is escaped; GET input is exact-allowlisted and arrays rejected. No new REST endpoint, inline scripts, frameworks, fonts, third-party assets or SEO metadata are added. Existing WordPress/Rank Math, Tools URLs, guards, Research Queue, header/menu and editorial sections remain intact. Production's preview guard is unchanged. The old isolated Playground snapshot presentation remains available only where the Research provider is inactive; dynamic staging KPIs never read it.

Future cybersecurity news, AI research, malware analysis, vendor blogs and incident reports need separately approved source connectors feeding the existing normalized model. They are not connected by this release.

## Acceptance / deploy

Offline:

```
php8.4 tests/threat-dashboard.test.php
php8.4 tests/research.test.php
php8.4 tests/nvd-resume.test.php
```

PHP lint all changed PHP; Python AST the two owner tools. Offline fixtures test aggregate source separation, all-local-NVD denominator, CVSS versions, publication dates, real missing data, confirmed overlap, bounded feed fairness, filters and HTML escaping/rendering.

`deploy-dashboard.py --apply` is owner-run via sudo in the prepared bundle, not the original installer. It checks exact before/after file hashes, pauses existing Research timers, waits for bounded workers to finish, then creates private root-only staging SQL, theme and plugin backups. It changes only seven pinned plugin/theme files. No import is run. It runs the existing temporary-table DB fixtures, refreshes projection under the existing named lock, and checks independent SQL KPI/histogram/feed evidence. It compares six rendered KPI values, authenticates existing admin/Research Queue, checks filters/routes/assets/noindex/Basic Auth and production HTTPS/protected fingerprints. Existing timer active states are restored in finally. Secrets are entered hidden or passed in a stdin pipe and never logged.

A failed post-deploy check retains the backup and prints `--verify <backup>` (verify only, not a blind reinstall) and `--rollback <backup>`. Code-only rollback restores the four preexisting files, retains the three new inert files and accumulated Research data, and rebuilds the previous projection. No SQL restore or deletion is automatic. Backups contain staging database/configuration secrets: keep their root-only permissions. The application backup is not a full VPS snapshot.

## Real browser screenshots

This VPS workspace has no browser or browser automation tools. **Do not mark browser/mobile acceptance PASS from PHP/CSS inspection.** `capture-dashboard.py` uses an existing Microsoft Edge on Windows 11 and Python standard library only; it installs nothing. After deployment copy that one script from the prepared bundle to Windows and run `py -3 .\capture-dashboard.py` in Windows PowerShell. Enter only the existing staging Basic Auth password, hidden.

It uses a disposable browser profile and loopback-only DevTools, allows page requests only to the staging origin, keeps credentials out of argv and files, and saves actual Dashboard screenshots at 1440, 768 and 320 pixels. It measures horizontal overflow, KPI columns, source advisories, mobile menu interaction, a submitted server filter and console/runtime errors. Output is a new `CyberDat-dashboard-screenshots-<UTC>` directory in the Windows home, with PNGs and a sanitized report. Screenshots are real staging data, not mockups. This optional program is statically checked here but its Edge/CDP behavior remains UNVERIFIED until run on Windows.

No Content Agent, n8n, LLM calls, new sources or production deployment.

# CyberDat

Source repository for CyberDat.eu and future CyberDat SEO Intelligence integrations.

## WordPress theme prototype

The lightweight PHP/Gutenberg theme lives in `wp-content/themes/cyberdat/`.
See its README for scope, progressive navigation, integration ownership and preview requirements.

This repository does not include WordPress core, credentials, uploads or the production database.
Existing production MU plugins retain taxonomy, sitemap and Coming Soon responsibilities.

## Checks

With PHP 8.0+ and Node.js 18+ available:

```sh
find wp-content/themes/cyberdat -name '*.php' -exec php -l {} \;
node --check wp-content/themes/cyberdat/assets/js/navigation.js
node --test tests/navigation.test.cjs
```

Validate `theme.json` against its declared official WordPress schema. Navigation unit tests exercise disclosure state and focus behavior with lightweight DOM doubles; a real-browser accessibility and responsive review is still required.

## Release policy

Work is developed on feature branches. No automatic deployment is configured.
Production deployment, theme activation and removal of Coming Soon require separate approval.
The theme foundation has not been activated on production.

## Project milestones and recovery status

- **0.3 — Premium Editorial Design:** the editorial design foundation, originally
  reviewed in WordPress Playground.
- **0.5 — CISA KEV / NIST NVD:** threat-data integration and fixed official
  snapshots for isolated preview; live API access requires separate approval.
- **0.6 — Backup / Disaster Recovery / staging preparation:** encrypted offsite
  backup and a successful local WordPress application recovery on 2026-11-08.
  See the [DR report](deploy/staging/dr-2026-11-08.md),
  [backup procedure](deploy/staging/backup.md) and
  [staging readiness gates](deploy/staging/verification.md).

The DR test restored WordPress 7.1.4 with Twenty Twenty-Five and Rank Math, not the
CyberDat prototype theme or the complete production VPS. Media recovery (empty
uploads), editor/content creation, full host/network isolation and production
Nginx/PHP-FPM recovery remain unverified. Backup is not a single atomic snapshot;
RTO/RPO were not measured. The three working DR containers were stopped on
2026-11-08 with their containers and volumes retained; the source test MariaDB
remains separate. This is a dated record, not a live Docker status check.

Staging remains **preparation only**: DNS/HTTPS, full Nginx/FPM validation, outbound
connection controls and verification of the pinned theme deployment artifact are
deployment gates. See [staging preparation](deploy/staging/README.md) and
[Playground scope](preview/README.md). Production activation, merge and deployment
remain unapproved.

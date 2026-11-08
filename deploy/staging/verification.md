# Verification — preparation checks vs future deployment checks

## Recorded application DR acceptance

The [2026-11-08 report](dr-2026-11-08.md) records operator-run Windows Docker
checks: encrypted offsite backup/decryption/integrity, MariaDB 11.8.6 (18 checked
tables), WordPress 7.1.4, local administrator login, Twenty Twenty-Five, Rank Math,
Coming Soon, noindex/CSP and an authenticated real 404. The working WordPress,
proxy and MariaDB containers were stopped with their containers and volumes
retained. The source test MariaDB remains separate; production was not changed.

This is application recovery, not full production VPS or CyberDat theme recovery.
Editor/content creation, media restoration (empty uploads), production Nginx/FPM
restoration and complete Windows-host/network isolation remain unverified. SQL and
file backups were not one atomic snapshot; RTO/RPO were not measured. Repeat
future recovery using the actual six-file set described in [backup.md](backup.md).

## Staging deployment gates

The local DR PASS does not close these gates or authorize deployment:

- Approve and verify staging DNS, dedicated HTTPS certificate, Basic Auth and
  automated renewal without changing mail/production DNS or introducing an auth
  bypass. None is established by the local HTTP test.
- Run full Nginx and PHP-FPM configuration checks in the real server context
  before separately approved activation/reloads; workspace syntax tests are not
  substitutes. Do not replace the production pool or vhost.
- Verify outbound HTTP, SMTP and host/production connectivity controls as both the
  staging FPM UID and CLI UID. Mail hooks and false KEV/NVD flags do not guarantee
  general egress isolation. Keep live flags false until separately authorized.
- Verify `theme-source.json` against the approved immutable Git commit/tree and
  the actual staged artifact: file inventory, hashes, modes and unexpected extras.
  The reviewed source pin is `6f09f8c12f01ca25eec90df2f42f7a780e78be94`; theme files
  are unchanged in approved preparation commit
  `7e0476ea465101f677741ae66e56e783b4d2a875`. Recheck at deployment time. The local
  working folder contained nine extra 1280px WebP files outside the 71-entry
  manifest; do not deploy the whole folder or silently extend the manifest.
- Verify fresh staging DB grants, independent credentials/salts, runtime/file
  permissions, reviewed taxonomy registration and offline snapshot import. Do not
  execute Playground bootstrap scripts on the VPS or copy production users/options.
- Complete CyberDat theme/editor/responsive and cron/resource acceptance below.
  Record the untested production-service/media recovery scope and RTO/RPO rather
  than relabeling the local application test as a complete recovery certificate.

## Run safely in the development workspace (no real server config loaded)

```sh
python3 tests/preview-guard.test.py
python3 tests/staging-config.test.py
php tests/editorial-save.test.php
php tests/editorial-sections.test.php
php tests/kev.test.php
php tests/nvd.test.php
node --test tests/navigation.test.cjs
python3 preview/build-blueprint.py
```

Guard matrix executes actual front-page branch, asset condition, live-enable
predicates and staging MU safety callbacks in child PHP processes: production,
production-root mislabel, explicit staging, missing/wrong flags, unauthenticated
staging, malformed URLs/paths and Playground. No HTTP/API or WP bootstrap runs.
A positive live-permission predicate is checked without invoking any worker.

Configuration tests are contracts and syntax checks, not a live server/security
certification. They generate a temporary self-signed **test-only** certificate,
unusable auth entry and isolated configs in an auto-removed project temp directory.
Nothing is copied to /etc or served. No service/reload/sudo is used. FPM test uses
`-n -t` and one test pool; Nginx test uses a private prefix, log paths and high test
ports. In this sandbox Nginx reports syntax OK but cannot complete socket validation
(Operation not permitted). That full `nginx -t` remains UNVERIFIED, not a PASS claim.
Do not escalate or bypass the sandbox just to obtain a green test.

The source scanner checks new staging text for private-key blocks and recognizable
access-key patterns. It is heuristic, not proof that arbitrary secrets cannot exist.
Review all changed files before commit, especially generated configs, logs, dumps,
archives, htpasswd, API environment files and keys. None belongs in Git. Public
NVD/KEV fixtures are source data, not API secrets. Unresolved private config template
values intentionally cannot bootstrap WordPress.

PHP-lint theme/tests/preview and `*.php.template`; validate Blueprint schema, pinned
theme ref and offline flags. Browser Playground still uses local environment and
no live flags; run its existing reports and 320/768/1440px panel. The new staging
layout has no design/CSS/logo changes. No authoring browser is available; browser
results must be obtained there, not inferred from unit tests.

## Only after separate deployment approval

Before activation, fill private placeholders and confirm staging user, paths,
certificate chain, auth file and permissions actually exist. As an authorized
operator, syntax-test the new pool with the existing complete FPM configuration
and new vhost with complete Nginx configuration:

```sh
sudo /usr/sbin/php-fpm8.4 -t
sudo /usr/sbin/nginx -t
```

Those full-system checks are **not run by the workspace tests**. No reload until
both pass and controlled activation is approved. Verify root/database grants,
Basic Auth and certificate renewal rather than assuming templates prove them.

Acceptance checklist:

- Production still serves existing Coming Soon, its active theme/settings/cert and
  WordPress DB are unchanged; no stage secret/cron points to production.
- HTTP staging redirects to fixed HTTPS without asking for plaintext credentials.
  HTTPS root, wp-admin, wp-login, wp-json, static assets and sitemap require Basic
  Auth (401 without credentials). Denied paths may return 403/404 instead.
- `/.env`, `/.git/config`, `/wp-config.php`, config backups, SQL/log paths, uploads
  PHP variants and PATH_INFO never disclose content or execute PHP. Test only with
  harmless staging fixtures, never public copies of real production config.
- Authenticated staging requests render full theme and load homepage CSS. A forged
  HTTP_REMOTE_USER/request parameter cannot activate it; Nginx passes REMOTE_USER.
- All relevant responses, including errors/401, have X-Robots-Tag noindex,nofollow;
  WordPress blog_public=0 and robots filter remain effective. Indexing prevention
  supplements auth, it does not replace auth.
- Dedicated PHP/CLI UID is not in www-data/sudo and cannot read production wp-config
  or write production files. Use exit-status tests only, never print secret content.
  Check PHP open_basedir as that UID, staging own writable dirs and Nginx symlink
  restrictions. Public Unix-readable code is not a full OS sandbox boundary.
- DB account can read/write staging only; production database access is denied.
  Inspect grants privately without exposing password hashes.
- MU mail filter returns false and direct mail is disabled; do not verify using a
  real email delivery. No SMTP plugin/production mail credentials.
- Debug log is outside webroot with private permissions; no log URL/alias. Raw
  authorization/query contents and API keys are not logged.
- Cron uses exact staging path/UID, flock, timeout and private temp; no duplicate
  HTTP wp-cron runner. Deliberate overlap is skipped; raw errors are not published.
- Both live API predicates false and no `cyberdat_kev_update`/`cyberdat_nvd_update`
  events appear before permission. Cached official snapshots remain NOT LIVE and
  source/checksum verified. Independent DB caches cannot change production options.
- Test Featured/Briefing/editorial queries, real CVSS coverage, empty/missing-image
  cases, basic Gutenberg, 320/768/1440px overflow/menu. Official positive CVSS 4.0/3.0
  fixture checks from 0.5.0 remain pending until real source examples are available.
- Observe available RAM/RSS, load and free disk; no heavy batch/API work, second DB
  instance or additional pool children enabled implicitly.
- Review the dated application DR acceptance above, backup freshness and remaining
  recovery scope in [backup.md](backup.md); close the staging deployment gates
  before considering activation. No full-VPS recovery claim follows from local DR.

Rollback plan: disable only the staging job/site/pool in a separately approved
operation and restore their previous staging revisions. Do not restore a whole
production SQL/config archive as a casual rollback for a staging mistake. If
production itself is affected, stop and use the separately reviewed recovery plan.

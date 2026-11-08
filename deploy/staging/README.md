# CyberDat 0.6.0 — staging preparation, NOT deployment

Nothing here is an apply script. All `.template` files require human review and a
separate approval before copying into system paths. Never run these instructions
against production automatically. This branch does not install users, software,
WordPress, DNS, databases, jobs, certificates or configuration.

## Approved layout

| Component | Staging only |
| --- | --- |
| Origin | `https://staging.cyberdat.eu` |
| WordPress | `/var/www/cyberdat-staging/public` — real directory, no symlinks |
| Runtime user/group | `cyberdat-staging:cyberdat-staging`, nologin, no sudo/www-data membership |
| Database/account | `cyberdat_staging`, localhost-only, privileges only on that database |
| FPM pool/socket | `cyberdat-staging`, `/run/php/php8.4-fpm-cyberdat-staging.sock` |
| Private runtime | `/var/lib/cyberdat-staging/{tmp,sessions}` |
| Private logs | `/var/log/cyberdat-staging`, no Nginx location/alias |
| HTTP auth file | `/etc/nginx/auth/cyberdat-staging.htpasswd`, outside webroot |
| Verified CLI PHAR | `/opt/cyberdat-tools/wp-cli.phar`, root-owned/read-only |
| Cron | Separate staging user/job with exact `--path`, flock, timeout |

Shared existing Nginx, FPM master and MariaDB service, not new instances. Initial
FPM child cap 1, PHP memory 256M, execution 45s/terminate 60s. CLI and WordPress CLI
memory stay 128M; one job max, 55s deadline, low CPU priority. Disable OPcache for
this pool without changing production/global cache settings. PHP memory_limit is
not an OS RSS cap. Budget roughly 400–800 MiB during use and 1–2 GiB disk reserve;
measure real traffic and RSS after approved deployment. Keep existing 2 GiB swap.

## Guard: fail closed

`cyberdat_home_preview_allowed()` controls both front-page rendering and homepage
CSS. Production always falls back to `index.php`; the known production root prefix
`/var/www/cyberdat/` is refused even if mislabeled local. No query/header from the
client can enable the preview. Runtime constants are explicit booleans.

Playground still requires `CYBERDAT_PLAYGROUND=true` and local/development context.
The existing Blueprint already supplies this context. That constant must never be
set on staging/VPS. It continues to disable automatic live KEV/NVD independently.

Staging requires **all**:

1. `WP_ENVIRONMENT_TYPE=staging`.
2. `CYBERDAT_STAGING_PREVIEW === true`.
3. Exact ABSPATH `/var/www/cyberdat-staging/public/`.
4. Both home/site URLs equal HTTPS staging origin (no userinfo/query/subdirectory).
5. Nonempty server `REMOTE_USER` set by Nginx Basic Auth, not an HTTP header.
6. No truthy Playground flag.

The guard grants display only; it does not set any live API flag or schedule a job.
The KEV/NVD modules remain unchanged. Their existing explicit live flags default
false in the proposed configuration. CLI Cron does not need the display guard or
Basic Auth identity. Dedicated staging DB means independent options/locks/caches.

## Isolation and web templates

Use `nginx/staging.cyberdat.eu.conf.template` as a separately reviewed server-block
file. All HTTPS resources, including login, REST and static assets, inherit Basic
Auth. Port 80 only redirects to fixed HTTPS; no credentials should be sent over HTTP.
Denied files can return 403/404 before auth; their contents are never served.
No auth exception for ACME, robots, sitemap, PHP or HTTP Cron. `REMOTE_USER` is
explicitly supplied by Nginx and Authorization is not forwarded to WordPress.

No aliases, symlink following, dotfiles, config/SQL/log downloads, PHP in uploads or
cache, alternative PHP suffixes, PATH_INFO, XMLRPC or HTTP wp-cron. PHP files must
exist before FPM. The root and socket are staging-only. `X-Robots-Tag: noindex,
nofollow` uses `always`; WordPress blog_public=0 and MU robots are additional layers.
Do not rely on robots.txt for access control.

Existing production certificate does **not** cover staging. Prefer a separate
DNS-01 certificate so the entire HTTPS site stays authenticated. Verify provider
support, scoped DNS credentials and automated renewal first. Manual DNS-01 alone
is not automatic renewal. No DNS/provider plugin is installed by this preparation.
An HTTP-01 exception would be a separately reviewed design change; it is not hidden
in this template. Do not run Certbot's Nginx installer against production.

Use `php-fpm/cyberdat-staging.conf.template` only as a new pool. Do not replace
`www.conf` or its existing 32M setting. New worker UID, restricted basedir, disabled
process execution/FFI/mail and private temp/session/log paths prevent application
reads of production config. CLI uses the same PHP basedir restriction plus its
verified PHAR path. Socket owned www-data is for Nginx to connect, not for adding the
staging user to that group. Production wp-config must remain unreadable to staging.

This is defense in depth for trusted code on a shared server, not a hostile-code
sandbox: open_basedir is not an OS security boundary; world-readable public code
may be readable to an OS account. Shared kernel/Nginx/FPM master remain common
failure domains. Stronger isolation requires a separately approved service namespace
or VPS; do not change production permissions to simulate it here.

## Future deployment sequence — requires approval

1. Complete and restore-test the encrypted offsite backup in [backup.md](backup.md).
   Confirm UFW, existing root schedules and TLS renewal plan. Do not alter MX/SPF/
   DKIM/DMARC or existing production A/AAAA records.
2. Approve this exact theme guard revision and source manifest. `theme-source.json`
   pins an immutable theme source commit; the final preparation commit has identical
   theme files. No deployment from a moving branch or `main`.
3. Verify the manifest against GitHub commit/tree metadata through trusted HTTPS.
   Download a fixed-SHA GitHub archive into a private review directory, reject archive
   traversal/symlinks, and extract only `wp-content/themes/cyberdat`. Check per-file
   Git blob hashes against the pinned tree (or an independently verified SHA-256
   manifest). A checksum produced from the same untrusted download is not provenance.
   Do not execute repository scripts as root. Git is not required; it is currently
   absent on the VPS. Install no tooling without separate permission.
4. Create the nologin staging account and staging-only directories. Code owned by
   deploy/root, readable but not writable by PHP; uploads/runtime/logs writable only
   by staging UID. Public static files readable to Nginx, private config 0640 with
   staging runtime group; logs/runtime directories 0700 and files 0600. No world-write,
   symlinks, cross-site shared uploads or cache directories. Auth file root:www-data
   0640, inaccessible to staging PHP. Never make staging a member of www-data/sudo.
5. Create a fresh database/account, using interactive/local protected credential
   handling; grant privileges only to `cyberdat_staging`.* at localhost. No global
   grants or production credentials. Do not import a production SQL dump on this
   shared MariaDB instance. Fresh DB is preferred; reproduce only approved taxonomy
   objects and demo content. No real users, addresses, passwords or sessions copied.
6. Use WordPress 7.1.4 from its official verified distribution. Prepare config from
   `wordpress/wp-config.php.template` in a **private non-Git location**. Generate eight
   independent salts and a unique DB password privately. Use hidden getpass/secure
   file descriptors, never password command arguments, shell history, xtrace or logs.
   Render PHP string literals safely (for example with PHP var_export), not unescaped
   string concatenation. Replace all `__STAGING_*__` values; unresolved placeholders intentionally stop
   bootstrap. Install config at staging public/wp-config.php with restrictive rights.
7. Copy `wordpress/cyberdat-staging-safety.php.template` to a staging-only MU file.
   It short-circuits wp_mail, sets robots and only acts at exact staging root/context.
   Disable PHP mail/sendmail too; do not install SMTP plugins or copy SMTP credentials.
   The MU mail filter does not claim to block arbitrary socket-based SMTP from
   untrusted code. Debug logs stay private outside webroot and must not log secrets.
8. Initialize WordPress with a separate admin and hidden password entry. No login,
   email or password is invented by this preparation. Set blog_public=0 and existing
   permalink/category bases. Reuse reviewed taxonomy registration from existing MU
   architecture; do not move it into the theme or blindly copy Coming Soon/Rank Math
   production options. Install only the approved theme from the manifest. Do not
   activate it in production.
9. If fixtures are desired, create a separately approved staging importer with exact
   staging path/environment guards. Playground seed/bootstrap files hardcode their
   own `/wordpress` sandbox; do not execute them on VPS or set Playground=true to
   bypass them. Import only checksum-verified official KEV/NVD snapshots and marked
   demo posts. No live fetch or production DB connection during initialization.
10. Only after DNS approval, add the staging A record pointing to the verified VPS
    IPv4; add no AAAA until IPv6 reachability is confirmed. DNS-01 may additionally
    require only its scoped `_acme-challenge.staging` TXT record. No mail or existing
    production DNS records change. After dedicated certificate and Basic Auth credentials exist (operator-selected username and a unique password
    entered hidden into the password-file tool, never `htpasswd -b`/command arguments),
    review both new
    system templates, run full Nginx/FPM config tests as an authorized operator, then
    separately approve controlled reloads. Never replace or rewrite production vhost.
    Test production before/after; failures require rollback of staging additions only.
11. After CLI/safety checks, install `cron.template` only for staging. Its PHAR must
    be root-owned, independently verified and readable by staging; do not use a PHAR
    under /home/cyberdat that the new account cannot access. Job hides raw output,
    so manually monitor bounded exit statuses/lock timings through an approved
    secret-free monitoring method. No HTTP Cron/auth bypass or scheduled API job is
    enabled by installing the prepared files themselves.
12. Perform [verification.md](verification.md) and report before any live API opt-in.
    Enabling KEV and NVD is a separate permission/configuration change; do not enable
    the flags for a visual test. Keep the API key outside Git/HTML/logs.

## Sources

- Nginx Basic Auth: https://nginx.org/en/docs/http/ngx_http_auth_basic_module.html
- Nginx symlink policy: https://nginx.org/en/docs/http/ngx_http_core_module.html#disable_symlinks
- PHP pool options: https://www.php.net/manual/en/install.fpm.configuration.php
- WordPress configuration: https://developer.wordpress.org/advanced-administration/wordpress/wp-config/

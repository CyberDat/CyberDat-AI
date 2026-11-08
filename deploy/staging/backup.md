# Production backup format and recovery procedure

This document records the format used on 2026-11-08 and requirements for future
separately approved operations; it is not an apply script. See the
[DR report](dr-2026-11-08.md) for the completed local application test. It does not
certify recovery of the complete production VPS.

## Actual six-file backup set

Set `20261108T082620Z-g8muao` was retained beneath `/var/backups/cyberdat/` and
copied encrypted to the owner's Windows 11 machine. Its identifier includes a
UTC timestamp, not a measured recovery duration.

| File | Purpose | Recorded bytes |
| --- | --- | ---: |
| `database.sql.gz.gpg` | SQL dump of `cyberdat_wp` | 168843 |
| `wordpress.tar.gz.gpg` | WordPress files, including production config and MU files, encrypted | 38691260 |
| `server-config.tar.gz.gpg` | Selected CyberDat server configurations and TLS material, encrypted | 55301 |
| `manifest.json` | Non-secret scope, versions, sizes, hashes, exclusions and warnings | 2626 |
| `SHA256SUMS` | Entries for the three encrypted archives and `manifest.json` | 344 |
| `COMPLETE` | Exactly `COMPLETE` followed by LF | 9 |

The former two-archive example is superseded. Do not rename or combine real
artifacts to match it. The completion marker alone proves neither authenticity
nor recoverability; verify the complete set.

## Preconditions and consistency

- Obtain approval; verify tools, space, destination permissions, conflicting backup
  processes and active updates/migrations. Do not install tools or stop services
  implicitly. Confirm the exact database identity without exposing wp-config.
- Verify root's MariaDB Unix-socket authentication; do not change users/passwords.
  Use explicit client/socket options, not password arguments or printed credentials.
- Verify table engines. The tested DB had 18 InnoDB tables. A different engine mix
  or concurrent DDL requires review of the consistency procedure.
- Use `set +x`, `set -euo pipefail` and ERR handling (the reviewed script uses
  `set -Eeuo pipefail`), `umask 077`, an exclusive lock and a unique 0700 destination.
  Artifacts must be 0600. Do not alter existing production-directory permissions.
- Use separate GPG homedir `/home/cyberdat/.gnupg-cyberdat-backup`. Verify the full
  public recipient fingerprint out of band and select it via `recipient_fpr`.
  Establish trust separately; do not add trust-bypass flags to conceal failures.
  The private decryption key stays off-VPS. No key material belongs in Git.
- Keep GPG operations under the operator identity and reviewed privilege separation;
  root reads must not create root-owned working files in the operator keyring.

The SQL snapshot and WordPress/config archives are **not one atomic snapshot**.
An InnoDB transaction does not protect filesystem changes or concurrent DDL. Agree
an approved quiet window or snapshot/quiescence method if needed; do not stop jobs
or services automatically or claim whole-server consistency from exit codes alone.

## Streaming and archive scope

The reviewed dump uses `--single-transaction --quick --skip-lock-tables`,
`--routines --events --triggers --hex-blob`, `--default-character-set=utf8mb4`
and `--databases cyberdat_wp`. After socket authentication is verified, select
explicit `--no-defaults`, local Unix socket, root and `--skip-password` options.

Data flow: `mariadb-dump ... | gzip -c | gpg --batch --encrypt ...`, with explicit
GPG `--homedir` and full recipient selection. WordPress and configuration archives
are separate tar/gzip/GPG streams. No persistent plaintext SQL/intermediate archive,
`tee`, xtrace or secret-bearing raw log is allowed. Write `.gpg.partial` output and
rename atomically only when every pipeline command succeeds. Stop on any error;
do not delete previous backups or silently accept partial artifacts.

WordPress archive members are relative to `/var/www/cyberdat/public`. Recorded
exclusions include `.git`, WordPress cache and debug.log. Production `wp-config.php`
is present only inside the encrypted backup and is excluded from local recovery.

The configuration archive uses an allowlist, not a blanket copy of `/etc`: CyberDat
Nginx vhost/dependencies, PHP 8.4 FPM/mods, MariaDB configuration and CyberDat
certificate/renewal files with the associated ACME account. The real manifest is
authoritative for exact paths. Exclude unrelated projects, SSH/OpenPGP private
keys and raw logs. TLS/ACME secrets may exist only within the encrypted archive.
Preserve required links without blind dereferencing; validate paths and link targets
before future system restoration. Never unpack this archive to the test host's `/`.

## Finalization and offsite verification

1. Check all three encrypted archives are nonempty and have restricted ownership
   and permissions. Do not decrypt on the VPS.
2. Create `manifest.json`: UTC start/end, encrypted filenames/sizes/SHA-256, scope,
   versions, table count/engines, public recipient fingerprint, exclusions and
   warnings. No SQL, config contents, credentials or private keys.
3. Generate `SHA256SUMS` for the three `.gpg` files and `manifest.json`; run
   `sha256sum -c SHA256SUMS`. Write `COMPLETE` only after successful final checks.
4. Transfer all six files using SFTP/SCP with verified SSH host identity. For
   root-owned originals, use separately approved user-owned 0700 transfer directory
   and 0600 copies; do not expose originals or enable root SSH.
5. On Windows, verify a separately trusted hash of `SHA256SUMS`, each listed file,
   manifest consistency and the exact completion marker. Keep the trusted checksum
   record separately. Checksums obtained with an archive do not authenticate it;
   public-key encryption alone does not authenticate the creator. A separately
   approved offline signature can strengthen provenance.
6. Verify GPG decryption and gzip/tar integrity with binary-safe streams. Do not use
   PowerShell text pipes for binary SQL/archives or print decrypted contents.
7. Retain source/offsite copies and record access/retention arrangements. Transfer
   cleanup, backup rotation and volume deletion require separate approval.

## Future independent application recovery

1. Restore only into an independent MariaDB instance, never shared production.
   The dump contains original database/use statements from `--databases`; restoring
   it on the VPS could overwrite production. Do not blindly rewrite database names.
2. Stream decrypt/decompress/SQL input into isolated MariaDB with events disabled;
   check count and integrity. Keep this source test instance separate from the
   mutable WordPress copy. Never attach its volume to a second database instance.
3. Stream a logical copy into a new working instance/volume. Validate WordPress
   archive paths/types and hashes; reject traversal, unsafe links and collisions.
   Extract into a new private destination, excluding production `wp-config.php`
   and unreviewed runtime configs. Do not install archived TLS/system configuration.
4. Generate new local DB credentials, salts and an administrator password. Use
   hidden input/stdin for the admin password, never history, argv or plaintext files.
   Block mail, HTTP integrations, Cron and updates before WordPress bootstrap.
5. Use verified WP-CLI for serialized-aware URL dry-run and separately approved
   replacement in the working DB only, excluding GUIDs. Set noindex and verify raw
   `home`, `siteurl`, `blog_public` using read-only SQL: `pre_option_*` filters can
   mask stored values from `wp option update`.
6. Publish on loopback only. The tested Docker Desktop setup required a separate
   pinned Nginx proxy for `127.0.0.1:8088`; WordPress/MariaDB stayed internal-only.
   Proxy egress and complete Windows-host isolation were not certified.
7. Check guest/admin HTTP, local redirects, theme/plugins, real 404 and private
   error logs. Record editor/media/system-service gaps; a web PASS is not proof
   that server configurations or the entire VPS have been recovered.
8. After approval, stop only identified recovery containers and retain volumes.
   Do not use `down -v`, `volume rm` or `system prune`. Record scope/results, backup
   date and test date; measure future RTO/RPO rather than inventing values.

The completed [DR test](dr-2026-11-08.md) covers application recovery only. See
[verification.md](verification.md) for remaining staging gates. Further backup,
full-VPS restoration and deployment each need separate approval.

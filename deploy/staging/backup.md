# Production backup plan — NOT executed, not an apply script

Before staging deployment obtain separate approval to read/backup production and
confirm the exact production database name locally without exposing wp-config.
The reviewed target is `cyberdat_wp`. No password, key or private config may be
printed, passed in process arguments, posted in chat or committed. Disable shell
tracing. Never run the following review blocks by copying the entire document.

## Prerequisites and consistency

- Verify a complete restore location on a separate disposable VM, not this VPS's
  MariaDB. Verify backup storage, access/retention and recipient identity off-VPS.
- This procedure uses GnuPG public-key encryption. Availability is not assumed;
  if absent, stop and seek separate approval for tooling. No software is installed
  by this branch. Verify the full recipient fingerprint out-of-band, import only
  the public encryption key into a private operator keyring, and establish trust
  explicitly. The private decryption key stays off-VPS. Test a harmless roundtrip
  before real backup; encryption without a usable recovery key is not a backup.
- Verify root's MariaDB Unix-socket authentication. If unavailable, use an approved
  private 0600 client option file, never --password/-p arguments or an environment
  password printed by diagnostics. Do not change authentication for this procedure.
- Check table engines and no active migrations/core/theme/plugin updates. The dump
  below is transaction-consistent for InnoDB, not arbitrary nontransactional tables.
  DB and filesystem are not one atomic snapshot: use an approved quiet window or
  separately agreed snapshot/quiescence method if writes are possible. Do not stop
  services or jobs automatically under the label of a read-only backup.

## Reviewed command blocks — future authorized root session only

Check identifiers/paths first. The fingerprint placeholder must be replaced with
the recipient's verified **public** fingerprint. No secret passphrase is an argument.
GPG must fail if recipient trust/availability has not been established; do not add
trust-bypass flags to make it work.

```bash
set +x
set -euo pipefail
umask 077
recipient_fpr='__VERIFIED_RECIPIENT_FINGERPRINT__'
[[ "$recipient_fpr" != __* && "$recipient_fpr" =~ ^[A-Fa-f0-9]{40,64}$ ]] || exit 1
backup_dir="/var/backups/cyberdat/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p -m 700 "$backup_dir"

# No plaintext SQL file is persisted; do not add tee or verbose query logging.
mariadb-dump --single-transaction --quick --skip-lock-tables \
  --routines --events --triggers --hex-blob --databases cyberdat_wp 2>/dev/null \
  | gzip -c \
  | gpg --batch --encrypt --recipient "$recipient_fpr" \
      --output "$backup_dir/database.sql.gz.gpg.partial"
mv "$backup_dir/database.sql.gz.gpg.partial" "$backup_dir/database.sql.gz.gpg"

# Contains wp-config, MU files, protected configs and TLS private keys ONLY encrypted.
# No -h/--dereference: preserve links; never follow an unexpected link outside scope.
tar --acls --xattrs --numeric-owner -C / -czf - \
  var/www/cyberdat/public etc/nginx etc/php/8.4/fpm etc/mysql etc/letsencrypt 2>/dev/null \
  | gpg --batch --encrypt --recipient "$recipient_fpr" \
      --output "$backup_dir/files.tar.gz.gpg.partial"
mv "$backup_dir/files.tar.gz.gpg.partial" "$backup_dir/files.tar.gz.gpg"

(cd "$backup_dir" && sha256sum database.sql.gz.gpg files.tar.gz.gpg > SHA256SUMS)
(cd "$backup_dir" && sha256sum -c SHA256SUMS)
```

Any failed pipeline stops (`pipefail`); partial outputs are not valid backups. Keep
failed files explicitly labeled partial pending private review; do not prune earlier
valid backups or production files. Suppressed raw errors avoid accidental disclosure;
record only step/exit status for the public report. Keep troubleshooting private and
redacted. This is a consistency-sensitive backup procedure, not a guarantee based
on exit codes alone.

The root-only archive directory and private keyring must be 0700, artifacts 0600.
The archive does not need to include raw application logs. It does contain protected
configuration and TLS key material intentionally, for recovery; encryption is mandatory.

## Off-VPS copy

Use a separately configured encrypted transport, verified host fingerprint and
restricted backup destination. Do not disable host-key checking. Only encrypted
artifacts and their checksum manifest leave the VPS. No private SSH key is requested
or embedded in this document. Example identifiers are placeholders, not configured
accounts/services:

```bash
scp -p "$backup_dir/database.sql.gz.gpg" "$backup_dir/files.tar.gz.gpg" \
  "$backup_dir/SHA256SUMS" backup@__OFFSITE_HOST__:__OFFSITE_PRIVATE_PATH__/
```

Verify checksums at the destination using `sha256sum -c SHA256SUMS`. Keep the
manifest in an independently trusted record as well; for tamper-resistant provenance,
sign it with an offline signing key outside the VPS. Encryption to a public key
alone does not authenticate who created the backup. Document
retention and access controls; keep at least one recoverable offsite copy and do
not delete the original backup until verification and retention approval.

## Restoration test — independent disposable VM, never shared production MariaDB

1. Restore-test network is isolated; outbound SMTP/API/production DB access blocked.
   Do not boot copied Nginx/PHP/Cron before reviewing configuration. Hold decryption
   keys privately; no dump content on terminal or logs.
2. Check encrypted checksums. Decrypt through a pipe to `gzip -t`; check file archive
   structure with `tar -tzf - >/dev/null`, no raw content output. Do not write a
   plaintext dump to a public/shared path.
3. SQL was made with `--databases cyberdat_wp` and contains original database/use
   statements. **Restoring it on this VPS could overwrite production.** Restore only
   into the disposable, independent MariaDB instance with event scheduler disabled.
   Decrypt → decompress → database client through a pipe; do not run statements
   through a production account or attempt a simple blind database-name replacement.
4. Extract the file archive under a private restore root, not `/`. Check for path
   traversal and dangerous links before any activation. Preserve original ownership
   metadata for reference; do not apply system configs directly to the test host.
5. Verify table counts, key WP options, files/MU/theme checksums and WordPress version.
   For an actual browser test, configure a separate local test installation with new
   credentials/salts, mail blocking/noindex, no Cron/live API and no production URLs.
   Replace copied secrets in the test copy before starting WordPress; do not log in
   using production admin passwords. Never send test emails.
6. Record encrypted checksums, backup date, test date, scope and PASS/FAIL. A tiny SQL
   file or successful encryption alone does not prove recoverability. Protect and
   retire the disposable copy under an approved data-retention process.

No backup, copy, encryption key import, remote transfer or restore was executed
while preparing this branch.

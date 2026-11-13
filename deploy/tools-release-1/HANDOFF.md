# Tools Release 1 — safe deployment preparation

**Preparation only: no live installation, page mutation or rollback authorized.**
Owner D3: retain installed Research `0ef03e9cb0d8821546983c84fc6998e85cf03f2e`.
D1 allows preparation/testing only. Read DECISIONS.md, SAFETY-AUDIT.md and the
current Research section of docs/PROJECT_STATUS.md before any future step.

## Pins and delivery boundary

- Branch feat/tools-release-1-safe-deployment starts at Research0ef03e9.
- Tools input eb9de8d2c51a515663d48205394cf7300bc0deae; exact theme from
  cd7df0c2a2fa5b5634977d765884b599a3495340. Theme behavior unchanged here.
- theme.tar.gz contains only cyberdat/:123 regular theme files. No plugins,
  SQL, configs, systemd, launcher, Content/Research code or helper scripts.
  Deploying the repository root is forbidden.
- manifest.json pins complete base95/target123 SHA256/length/mode sets.
  Directories0755/files0644; extra files/directories and symlinks rejected.
- Payload SHA256:7fc33bba8128e0a78aadeb83b772b02d4bcadcb8be0d42dbc6f0075d5daeec90
- Package JSON SHA256:8c57f78592d332ead7acd34aad8166fdf5284e251b1f77a1d9268aac8d9f5013
- Controls and editorial JSON are a separate private delivery, outside payload.

## Reproduce offline

BASE_THEME must be an isolated exact95-file export at Research0ef03e9. Outputs
must be new private workspace directories, never deployed WordPress paths.

```bash
python3 -I -B deploy/tools-release-1/build-package.py --base-theme "$BASE_THEME" --output "$PRIVATE_OUTPUT/package"
python3 -I -B deploy/tools-release-1/run-tests.py --base-theme "$BASE_THEME" --package "$PRIVATE_OUTPUT/package" --output "$PRIVATE_OUTPUT/evidence"
```

Builder checks every Git blob,95/123 counts,32-file delta/no deletions, and
mandatory PHP lint. Deterministic tar/gzip uses fixed modes/mtime0/no owner names.
Tests use temporary files/fake JSON pages, real Linux RENAME_EXCHANGE and PHP8.4.
No WordPress/bootstrap, MariaDB, network or systemd execution in sandbox tests.
First43-test evidence is retained: private Git-export root permissions were
correctly rejected; the fixture now explicitly emulates live0755/0644 modes.
Latest46-test run adds release-lock concurrency/symlink protection and passed with0 errors/failures/skips.

## Future authorized deployment order

1. Resolve DECISIONS. D15 is now adopted in the exact11 repository entry points
   AND11 prepared copies in legacy-entrypoints.json. Do not reapply the patch or
   overwrite these scripts with older copies. Backup and proofs: d15-acceptance.json.
   Do not change Research plugin/collectors/timers or rewrite original acceptance.
2. Recheck exact staging identity, base95, protected43 code/unit hashes and no
   concurrent deployment. Continuing Research SQL changes are expected.
3. Deliver payload/package/checksums privately. Seal controls beneath
   /opt/cyberdat-tools/tools-release-1/release-<artifact-id>/, directories
   root:cyberdat-staging0750/files0640, no links/subdirectories. Required files:
   deploy-theme.py,safe_theme.py,legacy_guard.py,route_policy.py,
   staging-contract.php,wp-state.php,tool-pages.php,protected-files.json,
   legacy-entrypoints.json,authorization.json. Editorial files, if approved
   later, use a separate private sibling hierarchy. Never expose /root.
4. Only a later installation approval can create expiring root-owned
   authorization.json: exact origin/Research/archive AND package hashes,
   install_approved=true, legacy adoption and required decisions. Example denies
   everything. LotL static JS/data is served with the theme: D6/D7 precede install.
5. Run deploy-theme.py preflight with --package pointing to package.json. It uses
   READ ONLY SQL identity queries, InnoDB checks, full hashes and interlocks;
   no WordPress bootstrap. After D15 this read-only preflight actually passed.
   Any later entry-point drift must still refuse; do not bypass the guard.
6. Separately authorized install creates private backup
   /var/backups/cyberdat-staging/tools-release-1-<UTC>/ before switching: theme
   archive/SHA256 and exact private page/meta/revision snapshots. No full SQL
   restore. Candidate sits below a new root-private0700 directory on the theme
   filesystem; all123 files and PHP lint must pass. Existing owner is preserved.
7. RENAME_EXCHANGE switches directories with no absent active path. There is
   no two-mv fallback, rsync --delete, timer stop or service restart. A durable
   intent journal supports process-interruption recovery. Adopted legacy entry
   points share the same release lock, preventing overlap even before Tools is
   switched in. Old theme is retained
   privately. Unknown hashes or editor changes cause refusal, not destructive repair.
8. Verify theme before page changes. Each tool-pages.php action separately checks
   staging identity/capability, action/slug approvals and owner decisions. Rank Math
   remains a separate authorized SEO edit. Published/unexpected-status pages are
   not overwritten by draft mode. After EACH approved page action, explicitly
   record-pages with the installer to acknowledge the exact state for rollback.
9. check-routes uses installed catalogue plus actual page state: published tools
   require200 + exact renderer + HTML marker; unpublished available tools, all6
   planned catalogue URLs and4 old alias/backlog URLs require404. No redirects
   silently followed. lolbas-analyzer stays404 until separately approved policy.
10. Later acceptance must check anonymous401, Basic Auth/noindex, PHP/FPM/OPcache,
    headers/assets/workers, real browsers and Dashboard/Pulse/Research regression.
    Observe a natural scheduler cycle; never force sync/reset errors/backoff.

For future install/rollback/recover/record-pages/check-routes, the entry point
requires --authorization and a safe --backup Tools directory. No arbitrary live
destination or sandbox bypass flag exists. Commands default to no mutation without
fresh authorization. Do not treat preparation approval as that authorization.

WP-CLI uses existing runtime user/HOME/WP_CLI_CONFIG_PATH/cwd/PHP sandbox and
unchanged open_basedir. Private helpers are inside the already allowed local-tools
prefix, with root-owned non-writable ancestors. Research/Content plugins are skipped for this helper bootstrap, not
deactivated. PHP independently checks CLI, exact ABSPATH/DB/prefix/origin/theme,
staging environment and administrator capability. No new service/public endpoint.

## Future rollback/recovery order

Compare active/retained full hashes, original backup SHA and exact expected
page/meta state. Restore only the four recorded page trees and their metadata/
revisions in a selective transaction; unknown human edits or ID conflicts refuse.
Existing pages recover originals. New deployment-owned pages/revisions are removed
only from that exact recorded scope. Other WordPress posts/Research tables excluded.

**Verify page/meta restore first, then atomic theme exchange, then verify base95.**
No SQL dump restore. Missing private slots require reviewed recovery, not blind
extraction over active files. Retain backups/failed slots. Current Research0.8.3
rollback tools will refuse changed theme hashes; any future Research rollback needs
a separate compatibility review. Do not weaken old guards or rewind live SQL.

Preparation tests PASS; next live deployment remains PARTIAL/blocked pending
authorization and decisions. No staging backup/install created today. Real WordPress
selective SQL restore, FPM/OPcache/renderer HTTP and browser acceptance are UNVERIFIED.
Historical Tools engine/browser evidence is not new staging acceptance. Stop here.

## D15 adoption (supersedes preparation-only interlock status)

Owner-approved maintenance completed2026-11-13T16:41:51Z. Original22 scripts were
backed up before changes to /var/backups/cyberdat-staging/tools-d15-20261113T164151Z;
backup checksums verified. Only the exact pre-execution prefix was added; original
bodies, owners and modes are preserved. A root0600 release lock coordinates future
deployment procedures and is not a Research ingestion/scheduler lock.

No legacy deployment/rollback was executed. Tests execute only extracted guard AST
with sandbox theme/lock paths and an inert body sentinel. Static checker/new package
preflight are the supported read-only paths. Old --verify commands may mutate
scheduler/cache/fixture state, so were not run or exempted. Active Research uses
run.sh to PHP WP-CLI and does not load the changed Python scripts; its support.py
copy is outside this scope and unchanged. Historical snapshots outside the11+11
manifest remain unguarded (d15-residual-paths.json); do not execute or restore them.

The statement above about no staging backup applies to the earlier theme preparation;
D15 now has its own scripts-only backup. Theme installation backup still does not
exist. D1 remains forbidden; D5 and D6/D7 remain unresolved. See D15-REPORT.md.

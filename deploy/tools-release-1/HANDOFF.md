# Tools Release 1 — D5/D6/D7 prepared package

**PARTIAL. D1 installation is NOT authorized. Stop after preparation.**
Branch feat/tools-release-1-license-claims starts at803da063. Installed Research
must remain0ef03e9cb0d8821546983c84fc6998e85cf03f2e. D15 is already applied in its
approved11+11 scope; do not reinstall it or restore old unguarded copies.

## Exact delivery

- Final source revision: `a5611f225ad1ff9858f84103036b73cc7c38568c`.
- Theme Git tree: `e7f385e56de29a6eeb1fbcfe3b3107dfd96dbaf8`.
- Archive: `/home/cyberdat/cyberdat-deploy/tools-release-1-d567-package/theme.tar.gz`.
- Archive SHA256: `783eec70b43bb7149c0fa0c122aadb23699cbf11534bd2070404849a6c1507ed`.
- package.json SHA256: `d49674a6abaa41821d402469a21fcd0fb31a99eba485980ea228d0cee4643cbf`.
- Complete manifest.json: base95/target125 regular files, all SHA256/length/mode
  entries.125 = original123 plus complete upstream NOTICE and SOURCE.md.34-file
  delta over95:4 modifications/30 additions, no deletions.
- Archive contains onlycyberdat/ theme files. No plugins, SQL, deployment helpers,
  configs, Research/Content code, launchers or timers. Never deploy repository root.
- Files0644/directories0755, no symlinks, no unexpected file/directory allowed.
- Original7fc33b... artifact and intermediate33975f... builds are SUPERSEDED.
  Never reuse their hashes/authorization for this archive.

## Reproduce in isolated workspace

Use the final branch head (including the updated controls), an isolated exact95-file Research0ef03e9 base export,
and fresh private output paths. Do not point these commands at installed WordPress.

```bash
python3 -I -B deploy/tools-release-1/build-package.py --base-theme "$BASE_THEME" --output "$PRIVATE_OUTPUT/package" --source-commit a5611f225ad1ff9858f84103036b73cc7c38568c
python3 -I -B deploy/tools-release-1/run-tests.py --base-theme "$BASE_THEME" --package "$PRIVATE_OUTPUT/package" --output "$PRIVATE_OUTPUT/evidence"
```

Builder checks Git blobs/file sets,125/95 counts,34-file delta and mandatory42-file
PHP lint. Deterministic tar/gzip has fixed modes/mtime and no owner names.46/46
sandbox tests pass against this final artifact; fake JSON pages are not live SQL
restoration proof.10 D15 tests execute isolated guard AST and an inert sentinel,
never a real old deployment/rollback. Source rebuild instructions and original
YAML/notice/license are in assets/js/lotl-analyzer/SOURCE.md and LICENSES.md.

## Future separately authorized installation order

1. Resolve DECISIONS.md: D6 legal scope review, D1 install approval and remaining
   product failures/UNVERIFIED conditions; page/SEO decisions separately. Current
   D5 PASS does not waive independent D14 acceptance or permit page publication.
2. Recheck staging identity and exact base95/protected43 hashes, D15 prefixes and
   shared release lock. Natural Research SQL activity is expected; never reset it.
3. Seal controls using the existing safe delivery mechanism under
   /opt/cyberdat-tools/tools-release-1/release-<artifact-id>/, root:cyberdat-staging
   directories0750/files0640, safe ancestors/no links. Required controls remain
   deploy-theme.py,safe_theme.py,legacy_guard.py,route_policy.py,staging-contract.php,
   wp-state.php,tool-pages.php,protected-files.json,legacy-entrypoints.json,
   authorization.json. Root-owned authorization must expire and bind BOTH hashes
   above, fixed staging origin/Research commit, approved decisions and page actions.
   The example currently denies all installation/actions. No root controls installed today.
4. Run the read-only preflight. Only later approved installation creates fresh
   /var/backups/cyberdat-staging/tools-release-1-<UTC>/ containing verified theme
   archive plus private selective page/meta/revision snapshots before changes.
   No full SQL restore or plugin/collector/timer changes.
5. Candidate is private on the theme filesystem; all125 hashes/modes/owners and
   PHP lint must pass. Existing WP-CLI user/HOME/config/cwd/open_basedir stay intact.
   Private helpers use the existing allowed staging prefix; Research/Content are
   skipped for this helper bootstrap, not deactivated. PHP independently checks
   CLI/ABSPATH/DB/prefix/origin/environment/theme/admin capability.
6. Real Linux RENAME_EXCHANGE, retained old tree and durable intent journal give
   continuous active-theme presence. No two-mv fallback/service restart. Shared
   release lock blocks legacy overlap before/after switch; unknown drift refuses.
7. Verify theme first. Page actions require separate owner approval and identity/
   capability checks. After each approved action, record exact pages for rollback.
   check-routes uses installed catalog/page state: published200 plus exact renderer/
   HTML marker, planned/unpublished404; old alias/backlog404. No silent redirects.
8. Later live acceptance must check BasicAuth/noindex, FPM/OPcache/PHP, assets/CSP,
   real browsers, Dashboard/Pulse/Research and a natural scheduler cycle. Current
   local fixture screenshots are not staging acceptance. Never force sync or reset
   checkpoints/backoff to manufacture a green status.

## Future rollback/recovery

Only with separate authorization. Validate active/retained full hashes, backup
SHA and expected page/meta state. Selectively restore the recorded pages, metadata
and revisions FIRST and verify; unknown human edits/ID conflicts refuse. Then
atomically exchange the theme and verify original95. No full SQL rollback or
Research checkpoint rewind. Existing Research rollback scripts refuse Tools drift;
future use requires review. Keep backups/failed slots, never blindly reapply.

## Remaining limits

D6 legal characterization UNVERIFIED; D7 public source8/8 anonymous HTTP checks
pass. Chromium78 local checks pass; MCP Firefox keyboard failure and all WebKit
acceptance are unresolved. Two pre-existing engine performance guards fail.
Actual WordPress selective SQL recovery/FPM/header/renderer acceptance is UNVERIFIED
because installation is forbidden. D8 hub visibility and D2/D4/D9/D11/D14 remain
explicit. Historical22 out-of-scope unsafe copies must not be run/restored.

No staging backup required or created today: no deployed files changed. Previous
D15 scripts-only backup remains /var/backups/cyberdat-staging/tools-d15-20261113T164151Z.
No staging theme/pages/SQL/timers or production changes, no main merge/real rollback.

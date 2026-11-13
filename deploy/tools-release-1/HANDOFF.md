# Tools Release1 — D14 product acceptance and unchanged package

**D14 PARTIAL: 32/40 PASS,8 FAIL. Public release NOT READY. D1 installation is NOT authorized.**

Current product evidence: [d14-public/README.md](d14-public/README.md) and d14-public/ACCEPTANCE.json.
Log7/10, Injection5/10, LotL10/10, MCP10/10. Failures are preserved; no fixes applied.
Closed staging remains conditional on separate D1/D6 decisions and explicit manual
evaluation limits. Prior regression PASS does not close D14. The package below is unchanged.
Branch feat/tools-release-1-license-claims; this stabilization starts atae48da0.
Technical suites PASS; D6 remains PARTIAL. Installed Research
must remain0ef03e9cb0d8821546983c84fc6998e85cf03f2e. D15 is already applied in its
approved11+11 scope; do not reinstall it or restore old unguarded copies.

## Exact delivery

- Final source revision: `54d43356fec8ca22f8d99c26fc5c28d5964c4d08`.
- Theme Git tree: `09bdf8b38031bb7b8059678d8c8d759b0d445de8`.
- Archive: `/home/cyberdat/cyberdat-deploy/tools-release-1-stabilized-package/theme.tar.gz`.
- Archive SHA256: `9fae3b45f8edbb49e5ea31314183f0dc7909457e1b7b63cb745a9678531ad46b`.
- package.json SHA256: `590ffd091e8225776a661bd1a3a7e526dae8430f1445467e803dae8f4f2463b5`.
- Complete manifest.json: base95/target125 regular files, all SHA256/length/mode
  entries.125 = original123 plus complete upstream NOTICE and SOURCE.md.34-file
  delta over95:4 modifications/30 additions, no deletions.
- Archive contains onlycyberdat/ theme files. No plugins, SQL, deployment helpers,
  configs, Research/Content code, launchers or timers. Never deploy repository root.
- Files0644/directories0755, no symlinks, no unexpected file/directory allowed.
- Original7fc33b..., intermediate33975f... and prior D5/D6/D7 artifact783eec... are SUPERSEDED.
  Never reuse their hashes/authorization for this archive.

## Reproduce in isolated workspace

Use the final branch head (including the updated controls), an isolated exact95-file Research0ef03e9 base export,
and fresh private output paths. Do not point these commands at installed WordPress.

```bash
python3 -I -B deploy/tools-release-1/build-package.py --base-theme "$BASE_THEME" --output "$PRIVATE_OUTPUT/package" --source-commit 54d43356fec8ca22f8d99c26fc5c28d5964c4d08
python3 -I -B deploy/tools-release-1/run-tests.py --base-theme "$BASE_THEME" --package "$PRIVATE_OUTPUT/package" --output "$PRIVATE_OUTPUT/evidence"
```

Builder checks Git blobs/file sets,125/95 counts,34-file delta and mandatory42-file
PHP lint. Deterministic tar/gzip has fixed modes/mtime and no owner names.46/46
sandbox tests pass against this final artifact; fake JSON pages are not live SQL
restoration proof.10 D15 tests execute isolated guard AST and an inert sentinel,
never a real old deployment/rollback. Source rebuild instructions and original
YAML/notice/license are in assets/js/lotl-analyzer/SOURCE.md and LICENSES.md.

## Future separately authorized installation order

1. Resolve DECISIONS.md: D6 legal scope review, D1 install approval and independent
   D14 product acceptance failures/limits; page/SEO decisions separately. Current
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

Current detailed results: REPORT.md and stabilization-acceptance.json. The8-file
GPL scope and14 shared dependencies are documented in GPL-BOUNDARY.md. Isolated
browser setup is in ISOLATED-BROWSER-TESTS.md. Do not install test dependencies
globally or treat fixture checks as installed WordPress acceptance.

## Remaining limits

D6 legal characterization UNVERIFIED; D7 public source8/8 anonymous HTTP checks
pass in the new anonymous source-access verification. Current Chromium78/Firefox48/
WebKit48 fixture checks PASS; original4000ms guards and6 new regressions PASS.
Current D14 has 8 product failures despite these historical regression passes.
Physical Safari/iOS and legal combined-work classification remain UNVERIFIED.
Actual WordPress selective SQL recovery/FPM/header/renderer acceptance is UNVERIFIED
because installation is forbidden. D8 hub visibility and D2/D4/D9/D11/D14 remain
explicit. Historical22 out-of-scope unsafe copies must not be run/restored.

No staging backup required or created today: no deployed files changed. Previous
D15 scripts-only backup remains /var/backups/cyberdat-staging/tools-d15-20261113T164151Z.
No staging theme/pages/SQL/timers or production changes, no main merge/real rollback.

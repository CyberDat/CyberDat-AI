# Tools Release 1 — D14 Remediation handoff, 2026-11-14

**D14 PASS: 40/40 original cases in each of three browsers, 32/32 new controls, all additional regression checks PASS. Release remains PARTIAL: D6 legal scope UNVERIFIED, D1 installation NOT authorized.**

[Current report](REPORT.md), [acceptance](d14-remediation/ACCEPTANCE.json). Original expectations unchanged. Six theme files repaired; LotL/MCP and all agents unchanged. Preparation base afa0b56; branch feat/tools-release-1-license-claims. Installed Research must remain 0ef03e9cb0d8821546983c84fc6998e85cf03f2e. Existing D15 approved 11+11 protection is not reinstalled or expanded.

## Exact delivery

- Final source revision: `f9cc1e9cca55a3f3587b12fe4228f86b2c55e9c3`.
- Theme Git tree: `0324800d705f74da563d371c0f60acde56873dee`.
- Archive: `/home/cyberdat/cyberdat-deploy/tools-release-1-d14-remediation-package/theme.tar.gz`.
- Archive SHA256: `5ce6c412c8444d36e9ac2f6960c4ee71c3cea7fec3dc0468afd0a4ee9317bc8b`.
- package.json SHA256: `3ec45c9198efad34c5a107a58144032bf31a0d32832e2c6dfefba7600516a65e`.
- Complete manifest.json: base95/target125 regular files, all SHA256/length/mode
  entries.125 = original123 plus complete upstream NOTICE and SOURCE.md.34-file
  delta over95:4 modifications/30 additions, no deletions.
- Archive contains onlycyberdat/ theme files. No plugins, SQL, deployment helpers,
  configs, Research/Content code, launchers or timers. Never deploy repository root.
- Files0644/directories0755, no symlinks, no unexpected file/directory allowed.
- Prior stabilized archive9fae3b... and original7fc33b..., intermediate33975f... and prior D5/D6/D7 artifact783eec... are SUPERSEDED.
  Never reuse their hashes/authorization for this archive.

## Reproduce in isolated workspace

Use the final branch head (including the updated controls), an isolated exact95-file Research0ef03e9 base export,
and fresh private output paths. Do not point these commands at installed WordPress.

```bash
python3 -I -B deploy/tools-release-1/build-package.py --base-theme "$BASE_THEME" --output "$PRIVATE_OUTPUT/package" --source-commit f9cc1e9cca55a3f3587b12fe4228f86b2c55e9c3
python3 -I -B deploy/tools-release-1/run-tests.py --base-theme "$BASE_THEME" --package "$PRIVATE_OUTPUT/package" --output "$PRIVATE_OUTPUT/evidence"
```

Builder checks Git blobs/file sets,125/95 counts,34-file delta and mandatory42-file
PHP lint. Deterministic tar/gzip has fixed modes/mtime and no owner names.46/46
sandbox tests pass against this final artifact; fake JSON pages are not live SQL
restoration proof.10 D15 tests execute isolated guard AST and an inert sentinel,
never a real old deployment/rollback. Source rebuild instructions and original
YAML/notice/license are in assets/js/lotl-analyzer/SOURCE.md and LICENSES.md.

## Future separately authorized installation order

1. Resolve DECISIONS.md: D6 legal scope review, D1 install approval and D14 residual limitations; page/SEO decisions separately. Current
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

Current detailed results: REPORT.md and d14-remediation/ACCEPTANCE.json; stabilization-acceptance.json is historical. The8-file
GPL scope and14 shared dependencies are documented in GPL-BOUNDARY.md. Isolated
browser setup is in ISOLATED-BROWSER-TESTS.md. Do not install test dependencies
globally or treat fixture checks as installed WordPress acceptance.

## Remaining limits

D6 legal characterization UNVERIFIED; D7 public source8/8 anonymous HTTP checks
pass in the new anonymous source-access verification. Current Chromium78/Firefox48/
WebKit48 fixture checks PASS; original4000ms guards and6 new regressions PASS.
D14 remediation now passes the 40 original cases and 32 new controls; 174 existing browser checks and 24 new file-input checks also pass. Residual heuristic limits remain explicit.
Physical Safari/iOS and legal combined-work classification remain UNVERIFIED.
Actual WordPress selective SQL recovery/FPM/header/renderer acceptance is UNVERIFIED
because installation is forbidden. D8 hub visibility and D2/D4/D9/D11 remain
explicit. Historical22 out-of-scope unsafe copies must not be run/restored.

No staging backup required or created today: no deployed files changed. Previous
D15 scripts-only backup remains /var/backups/cyberdat-staging/tools-d15-20261113T164151Z.
No staging theme/pages/SQL/timers or production changes, no main merge/real rollback.

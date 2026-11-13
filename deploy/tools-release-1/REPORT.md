# Tools Release 1 — Safe Deployment Preparation

**Current D15 result: PASS for the approved11+11 scope.** Applied2026-11-13T16:41:51Z
after verified private backup of22 deployment scripts. No Tools theme installation,
legacy execution, WordPress bootstrap, SQL write or timer change. Theme95 and
protected43 hashes preserved; counts/checkpoints/backoff identical across maintenance.
New read-only installer preflight passed after adoption. Details/tests/backup and
remaining out-of-scope paths: [D15-REPORT.md](D15-REPORT.md),
[machine proof](d15-acceptance.json). D1 remains NOT authorized; D5/D6/D7 remain open.

The preparation snapshot below describes commit731c9cd before D15. Its references
to interlocks not yet applied and no staging backup are historical, superseded by
this D15 result. Installed Research/Content plugin trees still match0ef03e9.

Verdict: **PARTIAL for the next staging deployment**. Authorized preparation is
complete; installation is neither authorized nor performed. No staging/production
write, WordPress bootstrap, live SQL operation, sync or publication was run.

## Source and artifact

Branch `feat/tools-release-1-safe-deployment` starts from Research acceptance
`0ef03e9cb0d8821546983c84fc6998e85cf03f2e`, not the older Research snapshot in Tools.
It imports the exact123-file theme tree from Tools cd7df0c/eb9de8d. Research and
Content plugin trees remain byte-identical to0ef03e9;11 original deployment
scripts are unchanged. Compatibility changes are prepared patch files only.

The deterministic payload contains only cyberdat/ theme files (123 regular,
no links, plugins, SQL or configs). Four modifications +28 additions over95 base.
Full manifest covers both95 and123 files, SHA256/size/mode, exact directory sets.

- theme.tar.gz SHA256:
  `7fc33bba8128e0a78aadeb83b772b02d4bcadcb8be0d42dbc6f0075d5daeec90`
- package.json SHA256:
  `8c57f78592d332ead7acd34aad8166fdf5284e251b1f77a1d9268aac8d9f5013`
- Prepared archive location:
  `/home/cyberdat/cyberdat-deploy/tools-release-1-safe-package/theme.tar.gz`
- No staging backup created. Future authorized backup path:
  `/var/backups/cyberdat-staging/tools-release-1-<UTC>/`.

## Implemented controls

- Real RENAME_EXCHANGE; no absent-theme interval/two-mv fallback. Private retained
  theme plus SHA-verified original archive and durable intent journal/recovery.
- Mandatory42-file theme PHP lint; every target file/length/SHA256, unexpected
  files/directories, symlinks,0644/0755 modes and live ownership checked.
- Staging-only fixed paths, read-only SQL identity and InnoDB preflight, independent
  PHP identity/capability gate, package-bound expiring owner authorization.
- Existing WP-CLI sandbox/HOME/config/cwd; private root-owned helpers under the
  allowed staging directory, with Research/Content bootstrap skipped. No public API.
- Selective page/meta/revision recovery before the theme switch. Unknown editor
  changes/ID conflicts stop rollback. No full SQL restore or queue/checkpoint change.
- Installed-catalogue route policy: published tool200 + exact renderer + HTML
  marker; planned and unpublished404. Includes old alias/backlog routes explicitly.
- Prepared11 legacy interlocks, checked before executable legacy code. They share
  the release lock to avoid overlap and refuse if Tools is present. NOT applied.
  New installer refuses until adoption. Arbitrary root bypass is not prevented.

## Actually executed checks

Latest evidence: [46-test report](evidence-2026-11-13-sealed/tests.json),
[complete output](evidence-2026-11-13-sealed/unittest.txt).

- **46/46 PASS,0 failures/errors/skips**; approximately1–3 seconds per suite.
- Full real123-file package installation and rollback to95 in a private temporary
  tree. Page storage is an explicit JSON fake; not a live SQL restoration claim.
- Seven install failure stages, both caught exceptions and simulated process death;
  three rollback crash points and recovery; edits/backup tampering/drift refusal.
-100 actual Linux atomic exchanges with concurrent path-existence observer:
  no missing active directory. Real lock contention, bad mode/symlink rejection.
- Real malformed-PHP test blocks before exchange; all42 actual theme PHP files
  and3 control PHP files linted with PHP8.4.
- Archive reproducibility, hostile tar members/counts/modes/paths, wrong permissions,
  wrong identity/authorization, correct CLI construction and route policy tested.
- All11 generated legacy-patch candidates compiled without applying them.
- Read-only end snapshot [preserved-staging.json](preserved-staging.json): all95
  deployed theme SHA256 values unchanged; all43 protected plugin/unit/launcher
  fingerprints match. No production access.

Earlier failed43-test evidence is retained honestly. It exposed private Git-export
root permissions in the test fixture; the fixture now emulates verified live modes.
Later45-test runs passed; final46-test evidence covers the added release lock.

## Remaining blockers and UNVERIFIED

- D1 installation approval still absent. D3 preservation of Research0ef03e9 decided.
- D15 legacy interlocks need separately authorized adoption in repository/prepared
  copies. Existing Research0.8.3 rollback hash guard remains unchanged and will
  refuse the Tools tree; no original acceptance/baseline was weakened.
- D6/D7 before installing served LotL JS/data; D2/D4/D5/D9/D11 for page/SEO work;
  D8 for four-tool hub visibility; D14 for independent product acceptance.
- Actual WordPress selective SQL restoration, FPM/OPcache behavior, staging HTTP
  renderer/CSP and real browser acceptance remain **UNVERIFIED**. No fixtures or
  temporary tables were created in staging. See DECISIONS.md for precise scope.

No next stage starts automatically. Commit identity is supplied by branch history
and the final owner report (not embedded self-referentially into this file).

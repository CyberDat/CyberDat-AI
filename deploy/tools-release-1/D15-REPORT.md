# D15 Legacy Deployment Protection — final report

**D15 PASS for the approved scope:11/11 entry points and11/11 prepared copies.**
Base731c9cd1557c828520abce059eeced36f65d3141, branch
feat/tools-release-1-safe-deployment. Prefix adopted2026-11-13T16:41:51 UTC;
Tools theme installation and page publication remain NOT authorized/performed.

## Backup and exact changes

Backup before any target modification:
`/var/backups/cyberdat-staging/tools-d15-20261113T164151Z`.
Private root0700 directory holds22 original scripts, before snapshot, pinned plan,
checksums and result/after evidence. Every original checksum was verified again.
No database dump or SQL restore. Original script bodies, owners and modes preserved;
the actual diff equals the previously prepared legacy-interlocks.patch.

The following table is the entire approved protection scope. Prepared paths are
relative to `/home/cyberdat/cyberdat-deploy/`; no other scripts were protected.

| Repository entry point | Prepared copy | Result |
|---|---|---|
| deploy/research/update-research.py | research-0.8.1-prepared/update-research.py | Protected |
| deploy/research/resume-research.py | research-0.8.1-prepared/resume-research.py | Protected |
| deploy/research/finish-research.py | research-0.8.1-prepared/finish-research.py | Protected |
| deploy/research/check-dashboard.py | dashboard-proof-prepared/check-dashboard.py | Protected |
| deploy/research/deploy-dashboard.py | dashboard-1.0-prepared/deploy-dashboard.py | Protected |
| deploy/research/deploy-charts.py | dashboard-1.1-prepared/deploy-charts.py | Protected |
| deploy/research/deploy-threat-2.py | threat-2.0-prepared/deploy-threat-2.py | Protected |
| deploy/home-pulse/deploy-pulse.py | home-pulse-2.0-prepared/deploy-pulse.py | Protected |
| deploy/analytics-2.1/deploy-analytics.py | analytics-2.1-prepared/deploy-analytics.py | Protected |
| deploy/staging/update-tools-ui.py | tools-ui-prepared/update-tools-ui.py | Protected |
| deploy/staging/update-seo-0.7.py | seo-0.7-prepared/update-seo-0.7.py | Protected |

All22 SHA256 and owner/mode checks passed. A root0600 Tools release lock now exists
at `/run/lock/cyberdat-staging-tools-release-1.lock`; it is unrelated to ingestion
locks and does not affect collectors. No systemd unit/configuration was changed.

## Blocking and read-only tests actually executed

- [Before adoption](d15-tests-before/tests.json):10/10 PASS.
- [After adoption](d15-tests-after/tests.json):10/10 PASS.
- Each suite checks all22 actual source/prepared candidates, before/after hashes,
  placement before executable legacy code and unchanged original bodies.
- Only guard AST is executed, with theme/lock paths redirected to private temporary
  fixtures and expected owner UID adapted to the sandbox uid. Presence of a Tools
  marker blocks all22 before body/import sentinel and before lock creation. Held
  release lock blocks all22. Wrong-mode and symlink locks are refused. No legacy
  deployment/rollback body was imported, executed or passed --help/--verify.
- With Tools absent/free lock, only an inert sandbox sentinel is allowed. This is
  not a real legacy deployment test. A read-only static checker succeeds without
  running the guard/body or creating a lock; a late guard is rejected.
- Real new installer `preflight --package .../package.json` passed under owner sudo
  after adoption. It checks staging identity using READ ONLY SQL, theme95, protected
  runtime43 and installed interlocks, without WordPress bootstrap or mutation.
- [Package regression](d15-package-acceptance/tests.json):46/46 PASS,0 errors/failures/
  skips; full sandbox install/rollback and PHP lint remain passing. Payload unchanged:
  SHA2567fc33bba8128e0a78aadeb83b772b02d4bcadcb8be0d42dbc6f0075d5daeec90.

Legacy --verify modes were not treated as read-only exemptions: several touch
cache/temporary fixtures/scheduler state. Use the new static checker/preflight.
Old bundle checksum files were not rewritten to legitimize running obsolete flows.

## Research/data/scheduler compatibility evidence

[Adoption proof](d15-acceptance.json), [runtime check](d15-runtime-check.json).

- All95 actual deployed theme SHA256 unchanged; all43 protected Research/Content/
  unit/launcher fingerprints match. No collectors, plugins, source rules, SQL schema,
  checkpoints, backoff or theme file was changed by D15.
- Before/after READ ONLY snapshots equal: queue10682, NVD7567, posts61, Content jobs1,
  Content versions1. Recorded NVD/Crossref health/checkpoints/next_due equal, including
  pre-existing nvd_dense_slice/academic_window_capacity errors. No error clearing.
- All6 timers active before and after. Actual service entry points are run.sh/PHP
  WP-CLI, not these Python scripts; active Research0.8.3 uses a separate unchanged
  support.py copy. No production access or main merge.
- A natural dispatcher cycle AFTER adoption ran2026-11-13 16:45:04→16:45:07 UTC,
  Result=success/ExecMainStatus=0. No manual run, timer restart or forced sync.
  This proves scheduled dispatcher continuity, not NVD/Crossref source recovery.

## Remaining overwrite paths and readiness

The11+11 operational scope is protected, but not every historical copy on disk.
Read-only inspection found22 unguarded source snapshots under
`research-0.8.3-work/deploy/` and `seo-0.7-work/deploy/`; exact paths are in
[residual inventory](d15-residual-paths.json). They were NOT edited because the
owner explicitly forbade scope expansion. In particular, manually invoking their
old update-research.py/update-seo-0.7.py with sudo, or restoring an old unguarded
copy over a protected script, remains a possible overwrite route. Do not use them.
Backup originals are retained privately. Arbitrary root shell operations cannot
be prevented by an entry-point guard. No timer/collector points to these copies.

**Next deployment verdict: PARTIAL. D15 is complete; D1 is not granted.** The package
is ready for a separate technical D1 review through the guarded installer; this
does not authorize installation. D6/D7 still block installing this payload because
LotL JS/data would be served. D5 remains open, especially the MCP complete-secret-
concealment promise, and must be resolved before publication/release. Other page,
hub, SEO and independent-evaluation decisions remain as in DECISIONS.md. Actual
WordPress selective SQL rollback, FPM/HTTP/browser acceptance remain UNVERIFIED.

No further stage is started. Commit identity is in branch history/final report.

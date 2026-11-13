# Read-only safety audit — 2026-11-13, approximately15:55 UTC

Prior audit, not a deployment or new acceptance:

- Staging theme95 files exactly matches Research0ef03e9 and earlier c3f9a5e
  theme. Four base SHA256 values match Tools;28 added files absent. No symlinks;
  directories0755/files0644; owner cyberdat-staging:cyberdat-staging.
- WordPress7.1.4; active cyberdat. Hub ID50 published. Log Anonymizer ID51
  draft has stale Rank Math planned/not-released description; old LotL ID53
  draft uses lolbas-analyzer. Three removed backlog drafts remain.
- All22 Research files match0ef03e9 acceptance; all6 timers active. Normal
  collectors do not replace themes. Tools eb9de8d lacks the latest acceptance;
  its Research plugin differs in10 files and must not replace installed code.
- Tools theme equals cd7df0c:123 files,4 modified +28 added, no deletions.
- Legacy update-research apply replaces the whole theme. Its rollback also
  disables6 timers/deactivates Research. Old Tools/SEO scripts replace themes;
  SEO rollback also restores SQL. Current Research0.8.3 rollback is narrower,
  but its protected-theme hash guard will reject the new Tools tree.
- Old 404 patch reads stale bundled catalogues (all planned) and skipping
  available alone proves neither published readiness nor HTTP200/renderer.
- Original handoff: two-mv absent-theme interval; lint echoes failure;
  manifest checks32 paths only; runuser cannot read /root helpers;
  rollback returns theme before reverting published pages.

Verdict UNSAFE to execute old handoff unchanged. Audit changed no files, Git,
SQL or configuration. Owner subsequently approved preparation only and D3
preservation of Research0ef03e9. No staging installation is authorized.

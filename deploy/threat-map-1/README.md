# Package threat-map-1 — Global Cyber Threat Map v1

Delta package for the theme on staging. Base: `integration/tools-utilities-1` at `5c12bef`, which is revision
`tools-utilities-1/5`, 188 theme files. Branch: `feature/threat-map-1`. `manifest.json` lists the `base` and `target`
sha256 of every theme file, and `delta_files` holds the exact files to copy:

- 10 added: collector, page block, script, styles, geometry, ISO table;
- 4 modified: `functions.php`, `inc/assets.php`, `template-parts/threat-map.php`, `assets/maps/NOTICE.md`.

The installer changes no other file. The Research plugin, its tables and its six timers stay untouched. The Tools,
the Tools hub, the shared masking block and SEO also stay untouched.

The sources, their terms and the frequencies are in `docs/THREAT-MAP-SOURCES.md`.

## What the server runs

- **Commands:** `wp cyberdat threatmap migrate | sync [--layer=feodo|ransomware] [--force] | status | uninstall --yes`.
- **Schedule:** a systemd timer starts `sync` at :07, :27 and :47. Each layer is collected once an hour in its own
  slot: Feodo at :07, Ransomware.live at :27. The :47 run only catches up a missed slot.
- **Request limits:** `MIN_INTERVAL` is 300 s for Feodo and 1800 s for Ransomware.live. It also applies to `--force`.
- **Storage:** counters only, in `{prefix}cdtm_counts` and `{prefix}cdtm_meta`. History is 48 hourly and 60 daily
  buckets.
- **Ransomware.live key:** read from the `wp-config.php` constant `CYBERDAT_RANSOMWARE_LIVE_API_KEY`, a free personal
  token from https://my.ransomware.live. Without the key the layer is shown as "not configured" and makes no
  requests.
- **Commercial use:** Ransomware.live forbids it without written approval. The owner decides whether CyberDat counts
  as commercial use before setting the key (see the sources document).

## Installation (Codex)

1. **Backup.** Archive the theme directory and dump the database, for example
   `tar czf theme-before-threat-map.tgz wp-content/themes/cyberdat` and `wp db export before-threat-map.sql`. Record
   the sha256 of the theme files and compare them with `manifest.json` → `base`; every file must match.
2. **Install the package.** Copy the 14 files from `delta_files` (from `theme_commit` of the manifest) to
   `wp-content/themes/cyberdat/`. Owner and mode must match the other theme files. Then check that every theme file
   equals `manifest.json` → `target`: 198 files.
3. **Storage migration.** Run as the site user:
   `wp cyberdat threatmap migrate` → `Success: Tables ready: <prefix>cdtm_counts, <prefix>cdtm_meta`.
   Optionally add `define('CYBERDAT_RANSOMWARE_LIVE_API_KEY', '…');` to `wp-config.php`; never put the key in the
   repository or in logs.
4. **Timer.** Copy `docs/threat-map/cyberdat-threatmap.service` and `.timer` to `/etc/systemd/system/` (check the
   sha256 in `server_files`). Adjust the WP-CLI path, the site path and the user if they differ on the server; the
   unit runs as `cyberdat-staging`, not root. Then run `systemctl daemon-reload` and
   `systemctl enable --now cyberdat-threatmap.timer`.
5. **First manual sync.** Run `wp cyberdat threatmap sync --force` as the site user. Expected: `feodo: ok — updated`,
   and `ransomware: ok — updated` with the key or `not_configured` without it.
6. **After 2 hours.** Run `wp cyberdat threatmap status`. Each enabled layer must show `freshness ok` and
   `successful_runs ≥ 2`. `journalctl -u cyberdat-threatmap.service --since -3h` shows the runs.
7. **Research timers.** `systemctl list-timers 'cyberdat-research-*'` must show the six timers active, with
   unchanged unit files (sha256 before = after):
   - cert-eu
   - cisa-advisories
   - dispatch
   - kev
   - msrc
   - nvd
8. **Browser check.** Open `/threat-intelligence/` in Chromium, Firefox and WebKit/Safari, desktop and mobile.
   - Layer tabs, 24 h / 7 days / 30 days, map, tooltip, country panel, top 10.
   - Under 640 px: a list with search instead of the map.
   - "Updated N min ago" per layer, a source and terms line under each layer, and the attacker-origin notice.
   - No requests to other hosts (DevTools → Network).

## Rollback

1. `systemctl disable --now cyberdat-threatmap.timer`, then remove both unit files from `/etc/systemd/system/` and
   run `systemctl daemon-reload`.
2. `wp cyberdat threatmap uninstall --yes` drops `{prefix}cdtm_counts` and `{prefix}cdtm_meta`, which hold only map
   data. Run it before restoring the theme, because the command is part of the theme.
3. Restore the theme from the backup of step 1. Every file must equal `manifest.json` → `base`.
4. Remove the constant `CYBERDAT_RANSOMWARE_LIVE_API_KEY` from `wp-config.php` if it was added.

No database restore is needed: the map writes only to its own two tables.

## Tests

| Test | Command | Runs in CI |
|---|---|---|
| Offline PHP (70 checks) | `php tests/threat-map.test.php`, wrapper `tests/threat-map-php.test.cjs` | yes |
| Script, geometry and assets | `node tests/threat-map.test.cjs` | yes |
| Manifest | `node tests/threat-map-manifest.test.cjs` | yes |
| Real WordPress + MariaDB + WP-CLI on an internal network | `bash tests/threat-map-wp-integration.sh <wp-cli.phar>` | no |
| Browsers on the local stand (synthetic data) | `tests/threat-map-sandbox.php`, `tests/threat-map-sandbox-server.cjs`, `NODE_PATH=<pw>/node_modules node tests/threat-map-xbrowser.test.cjs` | no |

The WordPress integration test checks migrate / status / sync / uninstall.

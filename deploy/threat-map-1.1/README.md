# Package threat-map-1.1 — Global Cyber Threat Map v1.1

Delta package over **threat-map-1/1**. Base: theme of `feature/threat-map-1` at `c964927`, 198 files. Branch:
`feature/threat-map-1.1`. `manifest.json` lists the base and target sha256 of every theme file and the exact delta:

- **253 added:** 250 flag SVGs, `flags.json`, `NOTICE.md`, the flag-icons license;
- **5 modified:** `inc/threat-map/core.php`, `view.php`, `render.php`, `assets/js/threat-map.js`,
  `assets/css/threat-map.css`.

The installer changes no other file. Install this package only after threat-map-1. If staging still runs v1, install
v1 first. If v1 is not installed yet, install both one after the other.

What is new:
- **Flags:** flag-icons 7.6.0 (MIT). Every SVG is checked and comes from the theme only.
- **Tab order and default tab:** chosen from the data. Ransomware.live wins ties and opens first when no layer is ok.
- **"Low activity" note:** shown for a layer with fewer than 5 countries with data.
- **New layer "DDoS targets":** data from Cloudflare Radar. Details are in `docs/THREAT-MAP-SOURCES.md`.

## Installation (Codex)

1. **Backup.** Archive the theme and export the database, as for v1. Check every theme file against
   `manifest.json` → `base`: 198 files from threat-map-1.
2. **Install.** Copy the 258 files from `delta_files` (from `theme_commit`). Then check every theme file against
   `target`: 451 files.
3. **Database.** No migration. The tables of v1 stay as they are; the Radar layer keeps its state in
   `{prefix}cdtm_meta`.
4. **Token.** Optionally add `define('CYBERDAT_CLOUDFLARE_RADAR_TOKEN', '…');` to `wp-config.php`. It is a Cloudflare
   Custom API Token with the permission Account › Radar › Read. Never put it in the repository or in logs. The owner
   must first decide about non-commercial use (CC BY-NC 4.0), the same decision as for Ransomware.live. Without the
   token the layer shows "not configured" and makes no requests.
5. **Timer.** The schedule is unchanged (:07, :27, :47). Radar now uses the :47 slot.
   - Replace `cyberdat-threatmap.service` from `docs/threat-map/`: the comments changed and `TimeoutStartSec` is
     now 600.
   - Replace `cyberdat-threatmap.timer` too: only its comment changed. Check both against `server_files`.
   - Then run `systemctl daemon-reload`.
6. **First sync of the new layer.** Run `wp cyberdat threatmap sync --layer=radar --force` as the site user. Expected
   result: `radar: ok — updated`, or `not_configured` without the token.
7. **After 2 hours.** `wp cyberdat threatmap status` must show every configured layer as `ok` with
   `successful_runs ≥ 2`. The radar history line says "no own history (periods from the API): 3 of 3 periods stored".
8. **Research.** The six `cyberdat-research-*` timers must be active and unchanged, as for v1.
9. **Browsers.** Open `/threat-intelligence/` and check:
   - the first tab is the layer with the most countries;
   - flags appear in the top 10, the country panel, the tooltip and the mobile list;
   - the Radar layer shows percentages, a change in "pp" against the comparison window, and the attribution with the
     CC BY-NC 4.0 link;
   - Feodo shows "Low activity…";
   - the browser makes no requests to other hosts.

## Rollback to v1

1. Restore the theme from the backup of step 1. Every file must equal `manifest.json` → `base`.
2. Remove `CYBERDAT_CLOUDFLARE_RADAR_TOKEN` from `wp-config.php`.
3. `state:radar` in `{prefix}cdtm_meta` can stay; v1 ignores it. To remove it:
   `wp eval 'global $wpdb; $wpdb->delete($wpdb->prefix."cdtm_meta", ["k" => "state:radar"]);'`
4. Restore the v1 unit file if it was replaced (`TimeoutStartSec=300`), then run `systemctl daemon-reload`.

A full rollback of the map is described in `deploy/threat-map-1/README.md`.

## Tests

| Test | Covers |
|---|---|
| `tests/threat-map.test.php` (70 checks) | v1 checks, still valid |
| `tests/threat-map-layers.test.php` (40 checks) | Radar, default tab in 10 combinations, low activity, flags in the server HTML |
| `tests/threat-map-flags.test.cjs` | 250 flags and the safety check |
| `tests/threat-map.test.cjs` | browser logic, including shares |
| `tests/threat-map-manifest.test.cjs` and `tests/threat-map-1.1-manifest.test.cjs` | both packages |
| `tests/threat-map-wp-integration.sh` | WordPress + MariaDB + WP-CLI |
| `tests/threat-map-xbrowser.test.cjs` | three browsers on the local stand, synthetic data |

The CI wrapper `tests/threat-map-php.test.cjs` runs both PHP tests.

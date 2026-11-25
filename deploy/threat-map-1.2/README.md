# Package threat-map-1.2 — borders (Crimea)

Delta package over **threat-map-1.1/1**. Base: theme of `feature/threat-map-1.1` at `9082de0`, 451 files. Branch:
`feature/threat-map-1.2`.

`manifest.json` lists the `base` and `target` sha256 of every theme file. The delta is 3 modified files, nothing added
or removed:

| File | Change |
|---|---|
| `assets/maps/threat-map-countries.json` | Rebuilt geometry; sha256 `73ccd9ea…`, deterministic |
| `assets/maps/NOTICE.md` | Borders statement |
| `inc/threat-map/render.php` | New note under the map |

**Borders follow UN-recognised boundaries: Crimea is shown as part of Ukraine. Derived from Natural Earth 1:110m.**
Natural Earth draws de facto control. The build script `tools/threat-map/build-geometry.cjs` applies these changes:
- It moves the Crimea polygon from Russia to Ukraine. The polygon is found by its bounding box, and the build stops
  unless exactly one polygon matches.
- It merges that polygon into Ukraine along the shared border, so no internal line is drawn.
- It joins N. Cyprus to Cyprus and Somaliland to Somalia.
- It keeps Kosovo separate (XK).

Data are not re-attributed. If a source reports RU for something in Crimea, it is counted for RU. The note under the
map says: "Country attribution is taken from each source as published."

## Installation (Codex), over threat-map-1.1

1. **Backup.** Archive the theme. Check every theme file against `manifest.json` → `base`: 451 files.
2. **Install.** Copy the 3 files from `delta_files`, taken from `theme_commit`. Then check every theme file against
   `target`: 451 files.
3. **No other changes.** The database, the timer, the unit files and `wp-config.php` stay as they are. Running
   `wp cyberdat threatmap sync` is not needed.
4. **Browser check.** Open `/threat-intelligence/` on a desktop and check:
   - Crimea is drawn as part of Ukraine, in Ukraine's colour, with no line between them;
   - the tooltip over Crimea says "Ukraine";
   - Cyprus and Somalia are one shape each;
   - the line "Country attribution is taken from each source as published." appears under the map.
5. **Research timers.** The six Research timers must be unchanged and active.

## Rollback to 9082de0 (v1.1)

Restore the theme from the backup of step 1. Every file must equal `manifest.json` → `base`. Nothing else needs to be
undone.

## Tests

- **`tests/threat-map.test.cjs`** (runs in CI), point-in-polygon checks on the geometry:
  - Simferopol, Sevastopol and Kyiv are in UA;
  - no RU polygon lies in the Crimea box;
  - Ukraine is one outline;
  - Kyrenia is in CY and Hargeisa in SO;
  - Pristina is in XK;
  - no area is without an ISO code;
  - the page contains no "Crimea" text.
- **`tests/threat-map-geometry-build.test.cjs`** builds the geometry twice and compares both with the committed file;
  the results must be byte-identical. It needs the npm tarball in `THREAT_MAP_WORLD_ATLAS_TGZ`, so CI shows SKIP.
- **`tests/threat-map-xbrowser.test.cjs`** checks the same points with the browser's own `isPointInFill`.
- **`tests/threat-map-1.2-manifest.test.cjs`** checks this manifest.

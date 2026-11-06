# CyberDat theme foundation

Stage 2: classic PHP templates, Gutenberg and theme.json. No framework, package manager or build step.

## Scope

- `index.php` provides a minimal listing/singular fallback; dedicated homepage, article and archive layouts are future stages.
- Shared header/footer, one-level navigation, responsive cards and editor styles.
- The fallback navigation uses existing editorial-format terms and only links Topics when that page is published. Assign menus to Primary and Footer for editorial control.
- Navigation works without JavaScript. On mobile, the disclosure supports keyboard navigation, Escape, focus return and viewport changes. There is no modal focus trap because the menu is not a dialog.
- No taxonomy registration, REST endpoints, database writes, SEO tags, JSON-LD, analytics, remote fonts or remote assets.
- Rank Math retains SEO ownership. Existing MU plugins retain taxonomy, sitemap and Coming Soon behavior.

## Files

`style.css` is the WordPress theme manifest; frontend styles are enqueued from `assets/css/`. `theme.json` contains the editor palette, typography and layout. `tokens.css` aliases those WordPress presets and supplies standalone fallbacks.

## Development and verification

Run PHP lint for every PHP file and validate theme.json against the WordPress 6.7 schema. Check menu behavior on mobile/desktop with and without JS, keyboard focus, 320px layouts, long titles and core Gutenberg blocks before release.

The theme has not been activated on production. Do not copy it into the live theme directory or switch the live theme as part of this stage. Preview in an isolated WordPress environment with the existing MU code and Rank Math before activation; do not use production administrator credentials in a preview.

Activation, menu assignment and publishing the drafted Home/Topics pages require a later approved release. Coming Soon must remain independently controlled.

Future stages: homepage sections, article metadata/TOC/related content, topic and format templates, then performance and accessibility review. Comments presentation is not implemented in this foundation.

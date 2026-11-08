# CyberDat theme — editorial homepage prototype

Version 0.3.0: classic PHP templates, Gutenberg and theme.json, with a Playground-only editorial homepage prototype. No framework, package manager or build step.

## Scope

- `front-page.php` presents the editorial homepage only when `CYBERDAT_PLAYGROUND` is true. Outside that sandbox it uses the ordinary `index.php` fallback, so sample stories and metrics are never rendered by this template in production. Dedicated article/archive layouts remain future stages.
- Shared header/footer, one-level navigation, responsive cards and editor styles.
- The fallback navigation uses existing editorial-format terms and only links Topics when that page is published. Assign menus to Primary and Footer for editorial control.
- Navigation works without JavaScript. On mobile, the disclosure supports keyboard navigation, Escape, focus return and viewport changes. There is no modal focus trap because the menu is not a dialog.
- No taxonomy registration, REST endpoints, database writes, SEO tags, JSON-LD, analytics, remote fonts or remote assets. The threat dashboard uses explicitly fictional CVE-DEMO identifiers and an offline sample dataset; it makes no live-data or threat-assessment claims.
- Rank Math retains SEO ownership. Existing MU plugins retain taxonomy, sitemap and Coming Soon behavior.

## Files

`style.css` is the WordPress theme manifest; frontend styles are enqueued from `assets/css/`. `theme.json` contains the editor palette, typography and layout. `tokens.css` aliases those WordPress presets and supplies standalone fallbacks.

## Development and verification

Run PHP lint for every PHP file and validate theme.json against the WordPress 6.7 schema. Check menu behavior on mobile/desktop with and without JS, keyboard focus, 320px layouts, long titles and core Gutenberg blocks before release.

The theme has not been activated on production. Do not copy it into the live theme directory or switch the live theme as part of this stage. Preview in an isolated WordPress environment with the existing MU code and Rank Math before activation; do not use production administrator credentials in a preview.

Activation, menu assignment and publishing the drafted Home/Topics pages require a later approved release. Coming Soon must remain independently controlled.

Future stages: visual approval, article metadata/TOC/related content, topic and format templates, then performance and accessibility review. Only after approval should real editorial selection and a real data source replace the sample-only homepage. Comments presentation is not implemented in this foundation.

## Homepage prototype

Featured Story uses an original responsive WebP illustration and a four-story briefing rail. The offline threat observatory has four metrics, a static accessible SVG activity chart, a severity chart and an explicitly scrollable demo-CVE table. Analysis, AI Security and Guides & Learning read the sandbox fixture posts using existing taxonomies. The nine curated section cards have distinct artwork and do not repeat articles. Cards include publication dates and categories. Search is a standard WordPress form. No new homepage JavaScript is required.

## Premium editorial refinement (0.3.0)

Compact masthead, dominant image-led featured story, four thumbnail briefings and tighter section spacing. Original generated artwork and its full prompt set are documented in `preview/art-direction.md` at the repository root. Images have explicit dimensions, responsive sources and lazy loading outside the hero. The original offline dashboard is unchanged. No new frontend JavaScript or external services were added.

## 0.7 Tools architecture

Reusable native Page templates for a Tools directory and Tool + SEO Content, typed REST metadata, secure editorial controls and implementation/content release gates. Rank Math owns SEO tags/schema; the theme does not emit a second graph. See `deploy/staging/seo-0.7.md` and `deploy/staging/tools-roadmap.md` in the repository. No utility implementation is included.

# CyberDat 0.3.0 — browser-only preview

This fixture is for the official WordPress Playground only. It does not connect to CyberDat.eu, production databases, passwords or private APIs. Do not deploy these fixture files or the generated demo MU code to production.

## Open

Load `preview/blueprint.json` using the official Playground `blueprint-url` parameter:

```text
https://playground.wordpress.net/?blueprint-url=https://raw.githubusercontent.com/CyberDat/CyberDat-AI/refs/heads/feat/cyberdat-theme-scaffold/preview/blueprint.json
```

For reproducibility, replace `refs/heads/feat/cyberdat-theme-scaffold` with the preview commit SHA. The Blueprint itself pins theme source to commit `62147ffe3540e6cfa21897f2759d52a76529c8f3`, WordPress 7.1.4 and PHP 8.4.

If the link is unavailable, open https://playground.wordpress.net/, choose New → Blueprint URL, and paste the raw JSON URL. The first load downloads WordPress and PHP WebAssembly into the browser.

## What opens

The landing page is a preview-only inspection panel with a route selector and 320, 768 and 1440 CSS-pixel iframe widths. Click **Run layout checks at all three widths**. Results are generated in your browser; they are not pre-recorded pass claims.

The panel checks listing, article, Gutenberg showcase, topic archive, format archive and missing-page template. Assertions cover page overflow, dark background, one H1, mobile disclosure/ARIA, Escape focus return, grid columns and core block presence. It is not a screenshot comparison or accessibility certification.

Use **Open site** for a normal full-window view. Use **Open Gutenberg editor**, open **Gutenberg Block Showcase**, and inspect headings, lists, code, tables, quotes, columns, buttons and theme colors. Verify keyboard focus and mobile layout manually. The preview automatically logs into the default disposable Playground account (`admin` / `password`); these are demonstration credentials, never production credentials.

## Isolation

- WordPress and its separate SQLite database run inside browser WebAssembly.
- `blog_public=0`, noindex headers and robots directives apply only to this preview.
- PHP outbound networking is disabled. Browser downloads from official Playground/WordPress and the public GitHub source are still required to initialize it.
- Outgoing WordPress email is short-circuited; cron is disabled.
- A guarded fixture-only MU file registers demonstration `editorial_format` and its routes. Production MU files and Coming Soon are not imported.
- Fifteen fictional articles, Topics, Block Showcase and About this preview are created only in the sandbox. The stock Hello world/Sample Page fixtures are removed only there.
- The homepage is a visual prototype with an offline SAMPLE DATA threat dashboard. No Rank Math account, analytics integration or production deployment is included.

## Rebuild and checks

```sh
python3 preview/build-blueprint.py
php -l preview/demo-support.php
php -l preview/seed.php
node --test tests/navigation.test.cjs
```

Validate the generated JSON against https://playground.wordpress.net/blueprint-schema.json. The official schema has string-valued deprecated annotations; Python Draft7Validator can validate the constraints without treating those annotations as newer-draft schema errors.

### Verified during preparation

- Official Blueprint schema constraints and PHP/JS syntax.
- Theme file hashes match the pinned source commit.
- Existing navigation unit tests pass.
- Blueprint is guarded and has no production paths, configuration or secrets.

### Not yet verified by the authoring agent

No browser engine is available in the authoring VPS. The complete Playground bootstrap, rendered screenshots, responsive results and Gutenberg editing session require running this link in a browser. The panel explicitly computes results at runtime. SQLite/WASM is also not a MariaDB/PHP-FPM production-equivalence test.

## Visual direction

The final design remains an editorial portal informed by Unit 42 with an analytical threat-dashboard character informed by vuln.eye. This release adds an editorial homepage with a Featured Story/Briefing lead, offline threat dashboard, Latest Analysis, AI Security and Guides & Learning. It is pending visual approval. Dedicated article/archive layouts and related-material components remain later stages.

## Prototype-specific checks (0.3.0)

The browser inspector now checks the homepage section structure, the SAMPLE DATA notice, fictional CVE-DEMO identifiers, the hero illustration and the responsive editorial card grid. The homepage is gated by CYBERDAT_PLAYGROUND, so it falls back to the normal listing outside the sandbox. The theme makes no external requests and does not render sample threat data outside Playground. The 0.2.0 browser suite must be rerun; 0.1.0 PASS results do not certify this new layout.

## 0.3.0 review

The compact masthead, four-story briefing, nine unique editorial illustrations and publication dates are now included in the browser checks. Open **Open site** for a full-window editorial review, then run **Run layout checks at all three widths**. The authoring environment has no browser engine, so runtime visual results are not claimed in advance. Artwork provenance and prompts are in `art-direction.md`. The source is a design prototype awaiting approval, not a production release.

## Premium Editorial Design review

Version 0.3.0 replaces the repeated abstract card artwork with nine distinct original local illustrations, adds a fourth thumbnail briefing and publication dates, and compresses the slogan into a compact editorial line. The dashboard data and markup are unchanged. See `art-direction.md` for full image prompts and provenance. The nine section cards are curated without repeating articles. Preview fixtures remain separate from production. The updated browser inspector checks image decoding, unique card artwork, dates, four briefings, compact masthead and responsive overflow. No rendered-width PASS claim is made until this new browser suite is run.

## Approved 3B branding integration

The header uses the original supplied horizontal dark-background SVG. Local favicon SVG, ICO and 16/32/48 PNGs are included unchanged. The inspector checks the wordmark load, original proportions and PNG decoding at every viewport. Site Icon is cleared only in the disposable Playground fixture so theme fallback icons can be inspected; production options are never read or changed. See `wp-content/themes/cyberdat/assets/branding/3b/README.md` for asset audit details. No unrelated design changes are part of this iteration.

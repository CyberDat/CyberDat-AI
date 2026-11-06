# CyberDat 0.1.0 — browser-only preview

This fixture is for the official WordPress Playground only. It does not connect to CyberDat.eu, production databases, passwords or private APIs. Do not deploy these fixture files or the generated demo MU code to production.

## Open

Load `preview/blueprint.json` using the official Playground `blueprint-url` parameter:

```text
https://playground.wordpress.net/?blueprint-url=https://raw.githubusercontent.com/CyberDat/CyberDat-AI/refs/heads/feat/cyberdat-theme-scaffold/preview/blueprint.json
```

For reproducibility, replace `refs/heads/feat/cyberdat-theme-scaffold` with the preview commit SHA. The Blueprint itself pins theme source to commit `86cf8b6207527acf1238b49672554301ea7b1d37`, WordPress 7.1.4 and PHP 8.4.

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
- Eight fictional articles, Topics, Block Showcase and About this preview are created only in the sandbox. The stock Hello world/Sample Page fixtures are removed only there.
- No homepage design, Rank Math account, analytics integration or production deployment is included.

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

The final design remains an editorial portal informed by Unit 42 with an analytical threat-dashboard character informed by vuln.eye. This release is the shared shell and reading/grid foundation; the generic fallback listing is not an approved final homepage. Dedicated homepage/article/archive layouts, header search and related-material components remain later stages.

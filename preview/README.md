# CyberDat 0.4.0 — isolated WordPress Playground

Official browser-only WordPress preview. No connection to production, real accounts,
mail, databases, analytics or external threat APIs. Never deploy these fixtures.

## Open

https://playground.wordpress.net/?blueprint-url=https://raw.githubusercontent.com/CyberDat/CyberDat-AI/refs/heads/feat/cyberdat-theme-scaffold/preview/blueprint.json

For an immutable preview replace `refs/heads/feat/cyberdat-theme-scaffold` with this
preview commit's full SHA. The Blueprint pins theme source separately to
`8536481ac9516e55a3910ef3f9b77dad96a98ab7`, WordPress 7.1.4 and PHP 8.4.
Initial loading downloads official WordPress/PHP WebAssembly and the public theme.
If needed, paste the raw Blueprint URL into the official Playground Blueprint UI.

## Inspect

The opening panel displays real WordPress integration reports from both editorial
steps. Click **Run layout checks at all three widths** for 320/768/1440px browser
checks: overflow, navigation/ARIA/Escape focus, dark surface, 3B logo and favicon
sizes, card columns/images/dates, Featured exclusion, Gutenberg blocks, archives
and the missing-page template. These results are calculated in your browser.

Use **Open site** for the homepage and admin toolbar. The default disposable
Playground account is logged in; it has no relationship to production credentials.
Use **Open Gutenberg editor** for the Block Showcase page. Manually inspect visual
composition, keyboard navigation, image crops and the actual editing canvas.
Automated DOM checks do not certify screenshots, screen readers or Core Web Vitals.

## Editorial workflows

- [Featured Story and The Briefing](dynamic-editorial.md): existing step-1 rules.
- [Dynamic Editorial Sections](dynamic-sections.md): Analysis, AI Security and
  Guides & Learning, three posts each, including instructions to publish a SAMPLE
  story in this sandbox. Overlap between sections is intentional. Featured is
  excluded from all three. Real posts and WordPress media replace curated arrays.

The approved dark 0.3.0 layout and 3B branding remain unchanged. Only the editorial
selection is dynamic. The offline Threat Intelligence Dashboard remains explicitly
fictional SAMPLE DATA, without external feeds. The production guard in
`front-page.php` still falls back to `index.php` outside Playground.

## Isolation and fixtures

WordPress and SQLite run in browser WebAssembly. `blog_public=0`, noindex headers,
networking disabled in PHP, email short-circuited, cron and file editor disabled.
A guarded preview-only MU file supplies the existing taxonomy architecture solely
inside this sandbox. Production MU files, Coming Soon, Rank Math and secrets are
not imported. Fifteen demo posts, three pages, categories/formats and media are
created only here. Test suites dispose of their own posts/users and restore seed
fixtures before inspection, recording explicit restoration results.

## Rebuild and local verification

```sh
python3 preview/build-blueprint.py
php -l preview/section-tests.php
php tests/editorial-save.test.php
php tests/editorial-sections.test.php
node --test tests/navigation.test.cjs
```

Validate `blueprint.json` against the official
https://playground.wordpress.net/blueprint-schema.json (Draft7Validator tolerates
its string-valued deprecated annotations). Lint all theme/preview/test PHP files
and syntax-check the embedded inspection JS. Blueprint uses only the official
installTheme, mkdir, writeFile and runPHP steps; no shell or production filesystem.

Local PHP syntax, 16 section/query/guard checks, 12 Featured save-handler cases,
existing navigation tests, JS syntax and Blueprint schema were checked during
preparation. There is no browser engine in the authoring environment: actual
WordPress/WASM suites, rendered widths and Gutenberg must run via this preview.
Their PASS status is not claimed before execution. Browser SQLite/PHP-WASM tests
also do not establish MariaDB/PHP-FPM production equivalence.

Original artwork provenance: [art-direction.md](art-direction.md).
Logo audit: [3B assets](../wp-content/themes/cyberdat/assets/branding/3b/README.md).

# CyberDat 0.4.0 — Dynamic Featured Story and The Briefing

## Editorial control

In the disposable Playground: Open site → WordPress Admin → Posts → edit a post → **CyberDat — Featured Story** → **Use as Featured Story** → Save/Update. The legacy-compatible meta box works in Gutenberg and the classic editor. Uncheck and save to remove the mark. Users must be able to edit that post. Standard Featured Image, Excerpt, Categories and Editorial Formats supply the lead content.

If several public published posts have `_cyberdat_featured_story=1`, order by publication date DESC, then post ID DESC. Modified date and sticky status do not affect selection. If none is marked, the latest public published post is the fallback using the same order. Drafts, scheduled/private posts and password-protected posts are excluded. A post of any editorial format may be Featured.

The Briefing queries up to four public published `editorial_format=news` posts by publication date DESC, ID DESC, excluding the selected Featured ID. Fewer News posts produce fewer rows; the theme never invents stories or fills gaps from other formats. Both small queries use fresh results so changing the meta flag is reflected without an extra theme cache purge.

## Security and architecture

- A typed protected post-meta key; no new Featured category, taxonomy or plugin.
- No public writable REST field is added in this stage.
- Standard meta-box nonce, capability check, scalar-value validation, and autosave/revision guards.
- Missing/invalid nonce preserves the value (including Quick Edit and other save contexts).
- Only a submitted valid unchecked box clears the value.
- No URL or Rank Math metadata changes. Registration and UI are theme-owned for this stage; stored meta remains in WordPress when the theme is inactive.
- New image sizes: `cyberdat-featured` 1280×800 and `cyberdat-briefing` 192×120. WordPress image metadata supplies srcset, sizes, dimensions and attachment alt. Existing uploads need suitable metadata/thumbnails; this stage does not regenerate production media.
- The neutral local SVG fallback is decorative. No fabricated article is used as a fallback.
- Explicit no-content messages are limited to local/development/staging or Playground environments.
- The existing homepage Playground guard remains. The dashboard and other editorial sections remain demonstration content. No production activation or deployment is performed.

## Tests and results

Local: PHP lint, existing menu tests, and `php tests/editorial-save.test.php` (12 actual save-callback unit cases using isolated WP primitive doubles).

The Blueprint then runs `preview/editorial-tests.php` against the actual isolated WordPress database. It temporarily hides only the sandbox fixtures, creates disposable cases, checks queries/meta permissions/images/empty states, cleans up its own posts and test user, and restores the original 15 demo articles. The report is `wp-content/cyberdat-preview/editorial-test-results.json` and is shown automatically in the browser inspection panel. No real credentials are used or logged.

The responsive browser checks additionally check lead IDs for duplicates and WordPress responsive image markup at 320/768/1440px. Browser/WordPress-runtime PASS results are computed when the Playground opens; they are not pre-claimed by an authoring environment without a browser engine. Inspect the updated report, then manually change the flag in the editor and reload the homepage. The seeded main story is `The next attack surface isn’t a device. It’s an AI agent.`

No homepage CSS or 3B artwork is changed by this step.

# CyberDat 0.4.0 — Dynamic Editorial Sections

Only the existing browser Playground homepage renders these sections. The first
production guard in `front-page.php` remains unchanged and falls back to `index.php`.
No fixture, dashboard or fictional CVE is enabled on production.

## Selection rules

All three sections use standard Posts: public `publish`, no password, latest
publication date DESC, then ID DESC, at most three cards. Sticky status does not
change ordering. The currently selected Featured Story is excluded in each query.

| Section | Existing taxonomy filter | Unchanged archive link |
| --- | --- | --- |
| Latest Analysis | `editorial_format=analysis` | `/analysis/` |
| AI Security | `category=ai-security` | `/topics/ai-security/` |
| Guides & Learning | `editorial_format IN (guides, learning)` | `/guides/` |

One article may appear in multiple matching sections (e.g. Analysis + AI Security).
An article with both Guides and Learning appears only once in their combined
section. Additional categories do not prevent matching AI Security. Category labels
use the existing deterministic lowest-term-ID helper; membership checks consider
all assigned categories, not only the label. Only exact topic terms are selected.

No placeholder cards fill short lists. Empty sections show an explicit message in
Playground/test environments, and return no markup in production. All current
homepage sections remain behind the unchanged Playground guard regardless.

## Media and markup

The common card partial uses WordPress title, excerpt (22 words), publication date,
permalink and category. Text and attributes are escaped; excerpts strip HTML. Core
attachment markup uses `cyberdat-card` (640×400 crop), attachment alt, dimensions,
`srcset`, `sizes`, lazy loading and async decoding. Older attachments work using
their existing sizes; this step does not regenerate production media. Missing or
invalid attachment markup uses the existing local decorative SVG fallback.

No CSS, JS, logo, menu, lead selection, Briefing, SEO or taxonomy registrations
were changed. Duplicate cards across sections are an editorial choice, not a feed
deduplication bug; the browser checks therefore do not require nine unique images.

## Manual check (Playground only)

Open the pinned Playground link in README. Use Open site → admin toolbar → Dashboard
→ Posts → Add New. Enter an explicit SAMPLE title, content, excerpt and optionally
a Featured Image with alt text. For Analysis choose Analysis in Editorial Formats;
for AI Security select the AI Security category; for Guides & Learning select
Guides or Learning. Leave “Use as Featured Story” unchecked. Publish in this
browser sandbox and reload the homepage: the new story becomes the first matching
card, subject to publication date/ID sorting and the three-card cap. For a short
or empty list, move sandbox stories to Draft. Never perform this on cyberdat.eu.

If no story has an explicit Featured flag, the newest story is the Featured
fallback and is consequently excluded from these sections, as defined in step 1.

## Verification and limits

`tests/editorial-sections.test.php`: local query-boundary checks and execution of
the production front-page guard (16 assertions). Existing save-handler (12 cases)
and mobile-navigation tests remain in use. PHP lint, JS syntax and Blueprint schema
validation are local checks; they do not prove real browser layout.

Playground runs the existing step-1 integration suite, then `section-tests.php`
against real WordPress. The latter creates disposable fixtures to test empty/short
lists, ordering and ties, all format/category filters, overlaps, public-only posts,
Featured exclusion/change, new posts, missing/responsive images and output escaping.
`finally` removes its own fixtures and restores the seed posts, with an explicit
comparison of statuses, dates, content, terms and meta. It writes
`section-test-results.json` beside the inspection page; that page displays both
integration reports and provides the 320/768/1440px checks. These real WordPress
and browser tests execute when Playground opens, not in the VPS CLI environment.

## 0.6.0 guard update

The homepage can now also render in the explicitly authorized staging context
described in `deploy/staging/README.md`. Production still falls back to index.
The earlier Playground-only restriction is superseded only by this fail-closed
staging guard; preview mode does not enable live APIs.

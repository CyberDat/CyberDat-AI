# Proposed: catalogue 404 checks after tools are released — WAITING FOR OWNER DECISION

Branch `proposed/catalog-404-check` (from `feature/tools-mcp-checker` @ `35bbc13`). **Not part of
`integration/tools-release-1`.** Applying it changes Research and staging scripts; the owner decides, and the Research
session must be told before it is merged anywhere.

## Problem

Three scripts require every URL in `theme/inc/tools-catalog.json` to return 404 (“Unfinished tool route changed”).
Once any of the four released tool pages is published on staging, they fail:

* `deploy/research/resume-research.py` (line 158)
* `deploy/research/update-research.py` (line 151)
* `deploy/staging/update-tools-ui.py` (line 141)

## Change in this branch (commit on this branch, same as `deploy/tools-prompt-injection-detector/proposed-catalog-404-check.patch`)

Only entries whose catalogue `status` is not `available` must return 404. The four released tools (`available`) are
skipped; the six planned tools must still return 404. Catalogues without a `status` field keep the strict check.

Test: `python -B tests/catalog-404-check.test.py` extracts the catalogue loop from each script with `ast` and runs it
against stub HTTP functions (no network). It passes on this branch and fails on the unpatched scripts.

## Not applied: SEO 0.7 script (SEO Intelligence, not ours)

`deploy/staging/update-seo-0.7.py` (lines 163–164 and 186) checks every URL in the bundled `tools-roadmap.json` for 404
and that no roadmap URL appears in the sitemap. It will fail the same way after publication. A proposed change is in
`seo-0.7-roadmap-404.patch` (applies cleanly with `git apply`); it is **not** applied because SEO Intelligence files
must not be changed without the owner. Note: whether published tool pages may appear in the staging sitemap is an SEO
decision as well.

## Options for the owner

1. Merge this branch (and decide separately on the SEO patch) before publishing tool pages on staging.
2. Keep tool pages unpublished on staging until the Research session adopts its own fix.
3. Publish tool pages and accept that these scripts fail until fixed (not recommended: they guard staging state).

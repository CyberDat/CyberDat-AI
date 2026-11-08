# CyberDat 0.7 — Technical SEO Architecture

## Scope and ownership

Staging only. The editorial homepage, navigation, logo, KEV/NVD modules, existing URL/taxonomy structure, production, server configurations and credentials are unchanged. No live APIs, external accounts, Content AI, AI publication or GSC credentials are enabled. The existing Basic Auth and staging noindex policy remain mandatory.

See [approved Tools Roadmap](tools-roadmap.md) and its machine-readable [catalog](tools-roadmap.json). Native hierarchical Pages provide `/tools/` and the ten permanent child slugs without a new taxonomy, CPT, rewrite namespace or SPA. No functional utilities ship in 0.7.

## Editorial workflow

1. In Pages, edit a planned draft under Tools, with **Tool + SEO Content** template.
2. Use **CyberDat Tool — editorial review** for summary, How It Works, Technical Documentation, Examples & Use Cases, visible FAQ, and an optional published GitHub HTTPS link. The native page title is the H1. Content is server-rendered and readable with JavaScript disabled. Gutenberg remains available for ordinary editorial pages; tool sections use sanitized structured fields to maintain the reusable layout.
3. Implement a reviewed renderer in first-party code, registered through `cyberdat/tool/renderer` for the specific page ID. Callbacks must output accessible utility HTML and handle their own input validation, data privacy and security; callback names cannot be assigned by post meta or REST. No renderer is registered in this release.
4. After implementation/security review and useful expert content, select **Implementation and expert content reviewed**, save the draft, then request publication. Publishing/scheduling is rejected until a renderer and every required content section exist. No word-count padding; target 300–500 useful words, not a mechanical release criterion.
5. A missing implementation or required section fails closed: no public utility, no sitemap entry, noindex. Draft routes return a genuine 404 for guests; authorized native WordPress draft previews show an honest unavailable state. The directory lists only released, public, password-free tools and stays noindex/excluded while empty.

Content remains standard Pages if the theme changes. Draft status protects unfinished pages independently of the theme; readiness, publication and sitemap filters are theme features and require revalidation before any future theme switch.

## SEO integration

Rank Math is the single owner of canonical, descriptions, Open Graph and JSON-LD. The theme emits none of these tags. Core title-tag support remains. The official Rank Math plugin is installed only on staging from a fixed version ZIP, verified against official WordPress.org per-file checksums; version, origin and SHA-256 accompany the private update bundle.

Existing Rank Math Article entities are refined to NewsArticle only for real published News posts with headline, publication date and author already present. Sample fixtures are never promoted to real news schema. No Article is created for Tools. Visible breadcrumbs use Rank Math when enabled, with semantic HTML fallback otherwise; only Rank Math emits BreadcrumbList. FAQ content is visible HTML; no unsupported FAQ rich-result claim or extra schema graph is introduced.

Both Rank Math sitemap and WordPress core sitemap filters exclude incomplete tools and an empty directory. Core sitemap remains disabled when Rank Math owns sitemap. `blog_public=0` is not changed: sitemap can be unavailable on a deliberately non-indexable staging, and verification records its authenticated HTTP status rather than enabling indexing to force a sitemap. All sitemap/robots endpoints stay behind Basic Auth. Public production sitemap, robots.txt and Rank Math settings are untouched.

Tools link to existing Guides, Learning and Analysis archives and released tools; these editorial archives and articles link back to the Tools directory. No dead links to draft tools are added. Homepage composition and header/menu are unchanged.

## REST and future SEO Intelligence

Native `/wp-json/wp/v2/pages` and existing editorial-format REST endpoints remain. `_cyberdat_tool` is registered as a typed object with explicit allowed fields, sanitization and edit-post authorization. Standard WordPress authentication and REST nonce/application-password controls apply; no new unauthenticated write endpoint, credentials, GSC integration or auto-publishing is introduced. An agent may propose draft text and metadata; reviewed implementation and human editorial approval remain release prerequisites. GSC import/analysis is a later, separately authorized service.

## Owner-run staging update

The prepared private bundle contains `source.json` with the exact Git commit and SHA-256 for every theme file, the previous approved theme manifest, verified plugin ZIP/provenance, roadmap, seed/check scripts and `BUNDLE-SHA256SUMS`. No credentials are bundled. Do not run the repository script without this preparation bundle.

`update-seo-0.7.py --apply` requires interactive owner sudo. It checks exact staging environment/root/database/theme, existing Basic Auth, original pinned theme, bundle integrity, free space, and absence of an existing Rank Math destination. It asks for the **existing** Basic Auth and WordPress passwords using hidden input; passwords are never command arguments, saved or printed. It fails rather than overwriting a partial previous update.

Before changes it saves the staging theme and a compressed logical staging database snapshot in a root-only directory `/var/backups/cyberdat-staging/seo-0.7-<UTC>/`. These local rollback files contain sensitive staging data and must remain root-only; they are not production backup replacements and are not copied to Git or external services. The old theme is also retained outside the document root. The update installs only theme/plugin files, creates the genuine directory and ten drafts, enables only sitemap/schema modules and breadcrumb presentation, and flushes WordPress rewrites without changing Nginx. No service reload, DNS, certificate, Cron or production change occurs.

The consolidated verification checks real WordPress guards/metadata, no live API/mail, authenticated HTTP, guest 401, draft/unknown 404, protected paths 403, no duplicate SEO tags, noindex, REST, administrator login, protected configuration hashes and production HTTPS. Secrets and raw logs are not printed.

On failure, stop and inspect the reported phase; never rerun blindly. The script prints safe fixed failure reasons and retains the staging rollback snapshot. With owner approval, use the printed `--rollback <exact-backup-directory>` command. Rollback restores the staging theme and complete staging DB snapshot, so **all staging edits after that snapshot are lost**. Retain/freeze later staging edits first. Updated theme/plugin files are retained, not destructively deleted. Never point rollback at production. No automatic rollback or production restore occurs.

## Evidence and remaining checks

`php tests/tools.test.php` checks readiness, content sanitization, capability/nonce, scheduling/publication guard, sitemap exclusion, staging robots and schema ownership. Existing editorial, KEV, NVD, navigation and preview-guard suites must also pass. PHP lint covers all theme/seed/check PHP; Python is parsed without running the deployment.

Runtime deployment/HTTP/admin checks are BLOCKED until the owner runs the prepared command with sudo. Do not mark these PASS from static tests. Browser visual 320/768/1440, Gutenberg editorial authoring and real released-tool behavior are not established by PHP tests. There are intentionally no functional tool UIs to validate in 0.7. Complete hostile-code/network isolation remains outside the protection of WordPress HTTP filters and this change.

See [source validation evidence](seo-0.7-validation.md). The separately pinned `seo-0.7-source.json` supersedes the historical 0.6 theme manifest only for this owner-approved staging update.

# Tools catalog UI update after 0.7

## Scope

Ten planned tools are rendered in the initial server HTML, with original local inline SVG icons, technical descriptions, categories, phase/release labels and Coming Soon status. Cards are deliberately not links and contain no forms or claims of released functionality. The approved canonical roadmap and native draft pages remain unchanged. This is a roadmap catalog, not a released-tool listing; a future release must explicitly update the presentation when functionality is approved.

The page uses the existing dark palette and scoped CSS: one column below 42rem, two from 42rem, three from 70rem. Cards have min-width:0, wrapped text, equal-height flex composition and no fixed content height. Header/subtitle share a left alignment. Intermediate desktop navigation can wrap to accommodate the seventh item without forcing horizontal overflow.

Category filters are progressive enhancement: the ten cards remain visible without JavaScript; buttons stay hidden until initialization. Native buttons support keyboard activation, aria-pressed tracks selection and a polite status reports counts. Filtering does not navigate, fetch data or process input. The JS has no dependencies or external requests.

Tools is appended to the primary menu output, shared by desktop and mobile, with deduplication and aria-current. The existing six stored menu items and their order are preserved; the fallback menu also includes Tools when the hub exists. No menu/database update occurs. Footer branding/copyright say CyberDat; only staging gets a separate small environment badge. WordPress blogname and SEO settings are not changed.

## Safety and deployment

The SEO guard, core/Rank Math sitemap ownership, unfinished draft status, noindex, Basic Auth, homepage, CISA KEV/NVD and live API settings remain unchanged. No utility implementation, tool-page publication, external API, plugin installation or staging reinstallation occurs.

`update-tools-ui.py` is a separate **theme-only** update, not the staging installer or the 0.7 installation script. The private preparation bundle pins the new Git commit and per-file SHA-256/Git blob IDs; the historical 0.7 source manifest remains historical. Before deployment, all previous 75 theme files and new release files must match their manifests; unrelated changes stop the update. The bundle is checksum-verified. The script checks exact staging root, environment, database identity and active theme. It uses existing root-owned WP-CLI as the staging Unix user, asks only for the existing Basic Auth password via getpass and never prints secrets.

A root-only `/var/backups/cyberdat-staging/tools-ui-<UTC>/` snapshot saves the complete previous theme with SHA-256 and previous manifest. Atomic renames switch only the staging theme; the original is also retained outside the web root. No configuration reload or explicit database write is performed. Read-only WordPress bootstrap/HTTP checks can perform normal application housekeeping; selected settings/menu/draft state are compared before/after, not claimed byte-immutable.

The owner-run command is supplied with the prepared bundle. On failure, do not rerun blindly: retain the snapshot and inspect the safe phase/reason. The printed `--rollback <exact-directory>` command restores only the previous staging theme and retains the updated theme outside the web root. It does not restore/delete a database, alter menus, remove archives or change production.

## Verification evidence

- PASS: actual PHP template render produces all ten cards and Coming Soon labels without JS; no card anchors; roadmap slug/phase alignment.
- PASS: menu output preserves the original six items, appends exactly one Tools item, marks current state and leaves footer menu untouched.
- PASS: JS VM tests exercise every category, reset, counts, aria-pressed and missing-page/unrelated-click safety.
- PASS: existing mobile navigation tests, Tools security contracts and 27 environment/preview guard cases.
- PASS: all theme PHP lint, new JS syntax check and Python AST parsing without executing deployment.
- PASS: byte comparisons for homepage, logo, editorial lead, KEV/NVD, existing navigation JS and preview guard.
- PASS: CSS contracts specify 1/2/3 columns. This is not evidence of browser geometry.
- BLOCKED pending owner sudo: real staging theme update and focused HTTP/menu/card/asset/draft-route/noindex checks.
- UNVERIFIED: actual browser screenshots/overflow at 320, 768 and 1440 px; mobile pointer/keyboard interaction; browser console. No browser engine is available in this session. Node.js from the existing VS Code installation was used; no software was installed.

After the owner runs the update, HTTP checks must return Tools/home/login 200 with Basic Auth, 401 anonymously, ten non-clickable cards, seven navigation items, CyberDat footer plus Staging badge, draft routes 404, assets 200 and unchanged selected staging state/config fingerprints. Production HTTPS must remain 200. Browser checks remain a separate visual confirmation, not implied by HTTP success. No AI Agents 0.8 work is included.

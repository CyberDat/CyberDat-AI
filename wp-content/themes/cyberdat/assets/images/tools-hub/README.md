# CyberDat Tools Hub illustrations

Original vector artwork for the Cyber Command + Cyber Glass Hub. These files do not reuse the reference screenshot or upstream LOLBAS data. Every current catalogue entry has its own illustration; unknown future entries retain the existing catalogue icon until dedicated artwork is reviewed.

All artwork is decorative: empty alt text, aria-hidden, explicit dimensions. Example fragments are synthetic design elements, not tool output or user input. SVGs contain no scripts, external resources, remote fonts or animations. The hero is hidden at narrow widths; cards reserve their illustration space before loading. Shared navigation and individual tool pages do not load the new Hub stylesheet.

12 SVGs total 28,346 bytes before compression (10,689 bytes gzip -9); largest 2,942 bytes. System monospace fallback only. No image API or CDN dependency.

The previews of tools 5-10 and of the Email Header Analyzer (quick utility) follow the layout of tools 1-4: a window with three dots, a synthetic input, a result box and an emblem. Their text uses only example.com/example.net, DEMO_ names and CANARY-<digits> markers; tests/tools-hub-previews.test.cjs checks this and the static-SVG rules for every catalogue entry. The template is unchanged: a preview is picked up by its catalogue slug.

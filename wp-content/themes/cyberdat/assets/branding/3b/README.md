# Approved CyberDat 3B assets

Source: user-supplied `cyberdat-3b-assets (9).zip`. The six selected SVG/PNG/ICO files are copied without drawing or geometry changes.

- Header: `cyberdat-3b-horizontal-dark-bg.svg`, original viewBox `76 104 960 304`.
- Favicon: standalone SVG, ICO with 16/32/48 frames, and matching PNG sizes.
- Header display widths: 168px below 360px, 184px normally, 208px at desktop 1024px and above. Height is automatic with the original aspect ratio.
- The logo is an external local SVG image with an accessible CyberDat alternative text. It is not injected into the page as inline SVG.
- Theme favicon tags are used only when WordPress has no explicitly configured Site Icon. No Site Icon option is changed by the theme.

## Security inspection

All five SVG files in the supplied archive were parsed and inspected using a strict SVG element allowlist. No scripts, event handlers, foreignObject, image embedding, external href/src, inline CSS, DOCTYPE/entities, remote fonts or remote URL references were found. Gradient references resolve to IDs inside the same SVG; IDs are unique per document. PNG dimensions and all three ICO directory entries were checked.

Selected PNG icons were visually inspected at native size and enlarged on a dark background. The supplied brand-board PNG was inspected as a visual reference. SVG/browser rendering, menu layout and page overflow at 320/768/1440px are covered by the updated Playground browser inspector, not pre-claimed as passed in a headless-browser-free authoring environment.

No logo artwork was regenerated. No favicon was registered in the production database, and no production files were modified.

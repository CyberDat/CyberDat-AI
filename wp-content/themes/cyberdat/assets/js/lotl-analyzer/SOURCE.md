# LotL / LOLBAS Analyzer — source and notices

CyberDat's LotL JavaScript work (app.js, engine.js, worker.js and the modified
lolbas-data.js snapshot), its tool-specific CSS/PHP renderer and build script
are distributed under GNU GPL version3. Copyright (C)2026 CyberDat contributors;
the data also retains copyright of the LOLBAS Project contributors. Changes dated
2026-11-13 add licensing/source delivery. NO WARRANTY, including merchantability
or fitness for a particular purpose. You may copy, redistribute and modify under
the GPL; the complete terms are in [LICENSE-LOLBAS.txt](LICENSE-LOLBAS.txt).

This notice does not automatically relicense independent CyberDat tools, agents
or the remainder of the site. Shared theme files retain their existing GPLv2-or-later
license (compatible with GPLv3). Legal characterization of the theme/aggregate
boundary is UNVERIFIED; this is not a legal determination. All theme sources are
provided publicly rather than withheld on the basis of that interpretation.

## Public corresponding source

- [Tool JS, including the modified dataset](https://github.com/CyberDat/CyberDat-AI/tree/feat/tools-release-1-license-claims/wp-content/themes/cyberdat/assets/js/lotl-analyzer)
- [Full theme source, including CSS, PHP and shared dependencies](https://github.com/CyberDat/CyberDat-AI/tree/feat/tools-release-1-license-claims/wp-content/themes/cyberdat)
- [Dependency-free data generator](https://github.com/CyberDat/CyberDat-AI/blob/feat/tools-release-1-license-claims/deploy/tools-lotl-analyzer/update-lolbas-data.cjs)
- [Pinned preferred-form upstream YAML source archive, with LICENSE/NOTICE/README](https://github.com/CyberDat/CyberDat-AI/raw/refs/heads/feat/tools-release-1-license-claims/deploy/tools-lotl-analyzer/upstream-source-2056cb7.tar.gz)
- [Source hashes and provenance](https://github.com/CyberDat/CyberDat-AI/blob/feat/tools-release-1-license-claims/deploy/tools-lotl-analyzer/upstream-source-manifest.json)

The public repository is retained under owner decision D7. Sources are available
without credentials or charge. Branch links are checked at release preparation;
the final report also pins the Git commit and theme/source hashes for retrieval
if the branch later moves. Do not remove access when distributing the tool.

Upstream commit2056cb7662509dc998fc6ce79636aec4e6c0397f,248 YAML files/490 commands.
Original authors/acknowledgements are retained in the source archive. Browser data
is a modified YAML-to-JavaScript subset; fields omitted there are documented in
its header. Original complete notices are preserved in NOTICE-LOLBAS.md and in
the source archive. Other linked projects' content is not bundled.

## Rebuild without Git/network

Use Node.js (standard runtime; no npm dependencies), extract the pinned archive,
and run from the corresponding repository checkout:

    node deploy/tools-lotl-analyzer/update-lolbas-data.cjs --source /path/to/lolbas-source --source-metadata deploy/tools-lotl-analyzer/lolbas-snapshot.json --output-dir /private/output --generated-date 2026-11-13

The generator checks all248 pinned input hashes. Compare the generated entries
and metadata with lolbas-data.js; the release report records byte/hash reproduction.
The unminified app/engine/worker are already the preferred form for modification;
no bundler, private module, account, compilation key or hosted API is required.

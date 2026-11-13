# Tools Release 1 — source and license delivery (D6 option A, D7 public)

Owner chose GPL compliance with LOLBAS retained; no repository settings changed.
This records technical delivery and the remaining legal uncertainty, not a legal opinion.

Concrete file/dependency boundary and remaining legal questions are now listed in
[GPL-BOUNDARY.md](GPL-BOUNDARY.md) and gpl-boundary.json. D6 remains PARTIAL.

## Scope and preferred source

LOLBAS upstream is pinned at `2056cb7662509dc998fc6ce79636aec4e6c0397f`.
The modified browser snapshot contains248 entries/490 commands, generated from
248 original YAML files. The complete preferred-form YAML (including original
Author/Acknowledgement fields omitted from browser data), original LICENSE,
NOTICE.md and README.md are in `deploy/tools-lotl-analyzer/upstream-source-2056cb7.tar.gz`.
All251 files have SHA256 entries in upstream-source-manifest.json. Archive SHA256:
`fa823d580bcbac5eb8ccd3eaa191ca34943a745985d5812f01f669a68794c8a6`.

CyberDat distributes LotL app.js, engine.js, worker.js, lolbas-data.js, its specific
CSS/PHP renderer and data generator under GPL version3. Dated modification notices,
copyright attribution and no-warranty notices are included. Full upstream GPL and
MITRE notice are copied verbatim to LICENSE-LOLBAS.txt and NOTICE-LOLBAS.md. The
UI links to those files, full theme source and the preferred YAML archive. SOURCE.md
includes an offline dependency-free Node rebuild recipe. No private dependencies
or access credentials are required. Tests actually reproduce shipped data byte-for-byte
and reject a modified YAML input. See source-availability.json for anonymous HTTP
verification of the public URLs after publishing the source commit.

The existing shared WordPress theme license remains GPLv2-or-later, compatible
with GPLv3. Independent Log Anonymizer, Prompt Injection Detector, MCP Checker,
Research/Content agents and other site components are not automatically relicensed.
All theme source is nevertheless delivered publicly, including shared dependencies.

**UNVERIFIED:** legal characterization of the combined LotL/theme work and the
boundary between one work and an aggregate has not received independent legal
review. Technical source/notices checks do not establish legal certainty. D6 is
PARTIAL pending that scope review; do not label it unconditionally closed.

## Other tools and dependencies

| Component | Actual use | Delivery |
|---|---|---|
| Log Anonymizer | CyberDat format rules/validation | No external dataset bundled |
| Prompt Injection Detector | CyberDat heuristic rules/normalization | No model or external service |
| LotL | Modified LOLBAS data and CyberDat logic | GPLv3, full preferred source/notices above |
| MITRE ATT&CK references | IDs retained from LOLBAS | Original full upstream MITRE notice retained |
| GTFOBins | Not used | No data bundled |
| MCP Checker | MCP specification as reference; package names as identifiers | No specification text/library bundled |
| Node/Playwright/browser test runtime | Private test-only downloads | Not part of theme archive or website |

GPL provisions consulted: [GPLv3 sections4–6](https://www.gnu.org/licenses/gpl-3.0.html)
and [GNU GPL FAQ on source and aggregation](https://www.gnu.org/licenses/gpl-faq.en.html).
The public GitHub repository and the public source branch remain available under
D7. A later visibility or source removal decision would require a new delivery review.

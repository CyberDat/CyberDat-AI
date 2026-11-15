# MITRE ATLAS data — license and attribution (tool 7)

| Item | Value |
|---|---|
| Data | MITRE ATLAS (Adversarial Threat Landscape for AI Systems), release 2026.10 (2026-10-28), format 6.1.0 |
| Source | github.com/mitre-atlas/atlas-data, commit `f56c1468731d6428e5bf875263b4643b46d67437`, file `dist/v6/ATLAS-2026.10.yaml` |
| License | Apache License 2.0 (repository `LICENSE`: “Copyright 2021-2026 MITRE … Licensed under the Apache License, Version 2.0”) |
| Checked | 2026-11-15, from the repository files at the pinned commit (LICENSE, README.md, data file), not from memory |
| SHA-256 | LICENSE `fa6c92ab3dc75d41413884e8b38cc54cd4e72f4c8f68fc7e77824e48e3047d40`; data file `ac41ee9f99a47084ba5fdfc77ae83a28687e12390240fffeb37df7914ffe142d`; Apache-2.0 text `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30` |

## What the license requires and how it is met

* **Copy of the license** (Apache-2.0 §4a): the upstream notice is shipped verbatim as `assets/js/atlas-mapper/LICENSE-ATLAS.txt`. The upstream repository contains only that short notice, so the full license text from apache.org is shipped as `assets/js/atlas-mapper/LICENSE-APACHE-2.0.txt`.
* **Notice of changes** (§4b): the header of `atlas-data.js`, the page block “Data source and license” and every export state that the data was modified: Converted from YAML to JavaScript by CyberDat: subset of fields (tactics, techniques, mitigations, achieves/specializes/mitigates relationships); Markdown links turned into plain text (internal links keep their ATLAS id) and citation markers removed; one HTML example inside a code block is kept as text; case studies, entities and software omitted. No ids or relationships were added.
* **Retained notices** (§4c): “Copyright 2021-2026 MITRE” is kept in the data file header, on the page and in exports. The upstream repository has no NOTICE file, so §4d does not apply.
* **Trademarks** (§6): the license grants no trademark rights. The page uses “MITRE ATLAS” only to identify the data source and states that the CyberDat mapping is not endorsed by MITRE.

## Note for the owner

The README of the data repository ends with the usual MITRE line “©2021-2026 The MITRE Corporation. ALL RIGHTS RESERVED. Approved for Public Release; Distribution Unlimited.” I read this as the copyright notice that goes with the Apache-2.0 grant in `LICENSE`, not as a conflicting restriction: the data files carry no other terms. The license is permissive (no copyleft, commercial use allowed). If you read the README line differently, this is the point to decide before publication.

## Updating the data

`deploy/tools-atlas-mapper/update-atlas-data.cjs` pins the commit, the data file and LICENSE by SHA-256 and refuses to run when the upstream LICENSE changes (YAML parser `yaml` 2.6.1, ISC, build time only). After an update, `tests/atlas-mapper-engine.test.cjs` fails if a technique id used by the CyberDat mapping disappeared or the snapshot files differ from the recorded output.

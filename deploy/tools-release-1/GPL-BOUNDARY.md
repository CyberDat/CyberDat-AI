# D6 — concrete engineering boundary and unresolved legal scope

**PARTIAL.** Owner selected optionA. This document identifies actual file/data
relationships and declared licenses, not a legal determination of full compliance.
Hashes and exact paths: gpl-boundary.json. No Research/Content/SEO files were changed.

## Explicitly distributed under GPLv3 in this release

| Exact path | Relationship |
|---|---|
| wp-content/themes/cyberdat/assets/js/lotl-analyzer/lolbas-data.js |Modified248-entry/490-command LOLBAS YAML subset, directly contains upstream data |
| wp-content/themes/cyberdat/assets/js/lotl-analyzer/engine.js |Consumes that data inside the worker; purpose-built LotL analysis |
| wp-content/themes/cyberdat/assets/js/lotl-analyzer/worker.js |importScripts loads both data and engine into the same worker; messages with app |
| wp-content/themes/cyberdat/assets/js/lotl-analyzer/app.js |LotL DOM interface, worker protocol and report generation |
| wp-content/themes/cyberdat/assets/css/lotl-analyzer.css |Dedicated LotL presentation |
| wp-content/themes/cyberdat/inc/tool-lotl-analyzer.php |Dedicated renderer/config/assets hook; constructs worker/data/license/source URLs |
| wp-content/themes/cyberdat/template-parts/tools/lotl-command-analyzer.php |Dedicated LotL HTML/config interface and notices |
| deploy/tools-lotl-analyzer/update-lolbas-data.cjs |Preferred-form source generator, modifications included, no private npm dependency |

All8 carry dated GPL3 notices. This deliberately includes the tightly integrated
LotL UI/worker/data work rather than assuming only the data file is covered.
The original source archive upstream-source-2056cb7.tar.gz contains248 full YAML
with authors/acknowledgements and LICENSE, NOTICE.md, README.md (251 files).
The YAML-to-JS subset is documented; snapshot/provenance JSON records every hash.
Original GPL and MITRE notices are retained byte-for-byte in the shipped
LICENSE-LOLBAS.txt and NOTICE-LOLBAS.md and in the source archive. SOURCE.md links
to all preferred sources and documents an offline byte-exact rebuild.

## Shared theme dependencies — source supplied, legal classification UNVERIFIED

inc/tool-lotl-analyzer.php registers into inc/tools.php's renderer hooks and uses
WordPress escaping/enqueue/get_template_part functions. functions.php loads these
modules; page-templates/tool.php invokes the selected renderer. The page uses the
shared header/footer/navigation and tokens.css/main.css/tools.css/tools-common.css.
inc/tool-security.php supplies the common security policy. inc/assets.php/setup.php
and tools-catalog.json provide common theme services/catalogue. These14 concrete
shared paths are listed in the JSON. They retain the existing theme GPLv2-or-later
license; the complete125-file theme source is publicly supplied as well.

The other three tools have separate app/engine/worker bundles. Inspection found
no imports of their engines/data into the LotL worker and no Research/Content/SEO
collector dependency in LotL. This is engineering evidence of separation, not a
legal declaration that packaging/interaction necessarily constitutes an aggregate.
No blanket GPL3 relicensing of those independent components was performed.

## Questions that remain legal review items

1. Whether the dedicated PHP renderer together with the shared WordPress theme
   helpers forms one combined work, and the required license notice/scope for that
   combined work. Existing shared GPLv2-or-later is compatible with GPLv3, but that
   does not by itself determine which files form one work.
2. Whether the separately implemented other tools bundled in one theme qualify as
   an aggregate in the actual distribution. Separate workers/message passing alone
   are not a conclusive legal test. Do not infer automatic relicensing either way.
3. Whether the concrete corresponding-source offer, pinned public archive and
   continued source retention/access obligations are sufficient for the final
   distribution method. Public access and reproducibility have technical evidence;
   long-term source availability remains an owner responsibility.

Sources consulted: [GPLv3 definitions/sections5–6](https://www.gnu.org/licenses/gpl-3.0.html),
[GNU GPL FAQ on aggregation, linking and JavaScript](https://www.gnu.org/licenses/gpl-faq.en.html).
No permission request, relicensing of upstream data, private-repository change or
claim of authoritative legal approval is made. D6 remains PARTIAL; owner D1 remains
separate and installation is forbidden in this stage.

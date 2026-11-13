# D14 — Independent Product Acceptance: public minimized report

**PARTIAL: 32 PASS / 8 FAIL from 40 new frozen cases,10 per tool. No product fix.**
Tested base0b73a9f98d1da980051865cfa4896827074ab49e. Expectations were authored and
hashed before execution and remained unchanged:
`90af74dd5a38336d05b93366bc719be15a04b1c97fcde41b6ac236a38635399d`.
The author previously implemented tools; this is a new separate product-case set,
not an external human audit. No existing fixture set was copied or retuned.

| Tool | PASS | FAIL | All 10 expected/actual/risks |
|---|---:|---:|---|
|Log Anonymizer |7 |3 |[LOG.md](LOG.md) |
|Prompt Injection Detector |5 |5 |[INJECTION.md](INJECTION.md) |
|LotL Analyzer |10 |0 |[LOTL.md](LOTL.md) |
|MCP Checker |10 |0 |[MCP.md](MCP.md) |

[Machine acceptance](ACCEPTANCE.json), [frozen protocol](PROTOCOL.json).
40 scored real UI/worker/export cases in isolated Chromium141;8 failing cases were
repeated unchanged in Firefox142/WebKit26 (16 unscored confirmations). Every failed
predicate reproduced. A separate localization of LA07 found file CRLF preserved by
File.text and the engine, but normalized by textarea in the small-file UI path.

Observed privacy/network:370 expected static GETs,0 HTTP after input,0 request
bodies/unexpected attempts/CSP/JS/console errors,0 persistent web-storage writes,
0 active HTML/script execution;50 local blob exports. The network guard recorded
no attempted exfiltration. No known synthetic provider secret was exposed in the
MCP report/error/console checks. This is bounded application-context observation,
not secure erasure/extension/whole-OS traffic or universal secret-detection assurance.
Local export omissions in LA05/LA06 are HIGH sharing risks despite no network leak.

Failures:2 complete detection misses (PI04/PI06),1 below-required-severity attack
(PI07, still two low findings),1 incomplete sanitizer outcome (PI02, already high),
2 sensitive-value coverage cases (LA05/LA06),1 format loss (LA07),1 benign medium
false positive (PI08). Counts are case outcomes, not estimated real-world accuracy.
PI reports may contain excerpts, LotL reports commands and policy export is
intentionally unredacted. Replacement-map export was outside these 40 cases.
All 10 LotL/MCP PASS does not prove complete coverage or overturn earlier limitations.

Closed staging readiness PARTIAL: further restricted manual testing requires
separate D1/D6 owner decisions. Installation remains NOT authorized. Public release
NOT READY: D14 has 8 FAIL and D6 combined-work/aggregate scope is still UNVERIFIED.
Existing package remains unchanged, SHA256
`9fae3b45f8edbb49e5ea31314183f0dc7909457e1b7b63cb745a9678531ad46b`.
No tool/rule/threshold/old-expectation changes, staging/WordPress/SQL/systemd/agents/
production operations, main merge or publication. No new deployment backup/rebuild.

Automatic approval review rejected uploading detailed synthetic materials because
of personal-looking strings, credential-like values and sensitive target paths.
This public packet therefore omits all raw inputs/reports/events and executable
harness files. Full 40-case definitions, raw export hashes, detailed records and56
screenshots remain private in the task workspace for the owner. Public case records
provide original private-record/input SHA256 plus semantic expected/actual/risks.
Evaluation used raw results BEFORE publication minimization; no score was changed.
[Publication decision](PUBLICATION.json). No product fixes were made. Stop after report.

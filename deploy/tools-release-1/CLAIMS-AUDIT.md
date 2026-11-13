# Limited user-claims audit — D5/D6/D7 (historical snapshot)

Performance/browser outcomes below describe ae48da0 before stabilization; the current
REPORT.md supersedes those outcomes. Claim wording and limitations remain applicable.

Scope: four tool templates, tool hub, UI/engine comments, proposed editorial JSON,
COPY-REVIEW and relevant tests. This is a bounded source/fixture review, not a claim
that every security issue or every possible input has been tested.

| Tool | Supported behavior/evidence | Explicit limitation |
|---|---|---|
| Privacy Shield Log Anonymizer | Worker-side pattern matching/validators, bounded highlighted preview, local copy/download;41 PHP checks,21 Chromium browser checks | Cannot find every secret/PII; mapping export intentionally contains originals and requires acknowledgement. User must review output. Existing adversarial performance test FAIL on this host. |
| Indirect Prompt Injection Sanitizer & Detector | Heuristic pattern/normalization/decoding; no model invocation;42 PHP checks,4 corpus checks,21 Chromium checks | Sanitized text remains untrusted. Reworded attacks/benign false positives possible; no safe-to-feed-to-LLM guarantee. Existing4-second performance guard FAIL on this host. |
| LotL / LOLBAS Analyzer | Bundled248-entry snapshot, commands are analyzed as text, encoded text is decoded without execution;20 engine/47 PHP/16 Chromium checks | Match is neither malice nor proof of execution. No match is not a safe verdict. Detection hints are starting points. GPL scope review remains UNVERIFIED. |
| MCP Security & Policy Checker | Recognized credential patterns/structural suppression, textual configuration/policy checks;24 engine/51 PHP/20 Chromium checks plus9 new privacy checks | Masking is best effort. Unknown credentials can remain in names/excerpts. Policy downloads are verbatim/unredacted; review exports. Does not execute servers or audit remote code/packages. |

## Privacy statement scope

All four now say **this tool does not transmit the text you enter**, rather than
making a statement about every browser component. Tools do not write input/results
to persistent browser storage; memory is used while processing. Static assets can
be fetched on load/cancel. CSP and worker network-API guards are tested in the local
fixture; the public deployment's headers are still UNVERIFIED. Browser extensions,
session restore, clipboard and user downloads are outside tool control. Closing a
tab is not a secure-erasure guarantee. No claim of universal detection or anonymization.

MCP app.js's comment and proposed editorial copy use the same limited wording.
The policy validation API is a parser/validator, not a sanitizer. Raw parse outputs
must not be treated as safe-to-share redacted reports.

## MCP logic and new regressions

engine.js1.0.1 omits arbitrary input keys/words/bad enum values from parser/policy
errors. Output suppression covers known token formats and string values in env,
headers, CLI option values and URL queries/fragments. Rule IDs, severity and static
metadata stay intact. It does not elevate unknown values into security findings
merely to hide them. Worker diagnostics/progress/results do not call console logging.
Known values inside policy-check warning output are also suppressed.

Nine regressions cover recognized keys/JWTs; opaque values with arbitrary names;
Unicode/escaping; values equal to rule IDs/severity; parser/policy errors; policy
value output; worker error/result/progress channels; UI/export wording. A deliberate
free-form tool-name case proves an unknown secret CAN survive; the warning must
remain. A blanket promise would therefore still be false.

## Actual browser results and bounds

Chromium suites: Log21, Injection21, LotL16, MCP20 =78 checks PASS in the isolated
loopback fixture (no WordPress/SQL). Includes worker/no-transmission, XSS/text-only,
exports/storage, keyboard,360/390/768px, contrast and no-JS behavior.33 screenshots
are retained locally in claims-evidence/*-browser-verified/. Browser screenshots
show this test fixture, not staging pages.

Firefox: Log14/LotL10/Injection13 checks completed; MCP10 checks completed then its
keyboard Ctrl+Enter wait timed out. This MCP path is FAIL/UNRESOLVED; it is not
silently waived. WebKit launch failed because the host lacks its older required
libraries; all WebKit acceptance is UNVERIFIED. No global browser/package install,
new service or security configuration change was made.

Before source publication, a public HTTP hash check caught newline normalization
of upstream NOTICE.md. It was corrected with a binary Git blob, then checked
anonymously again. The final source commit and package match the original bytes.
Earlier failed runs are retained, not rewritten as passes.

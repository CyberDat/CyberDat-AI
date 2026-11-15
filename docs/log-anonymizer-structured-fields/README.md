# Log Anonymizer: structured credential fields

Prepared offline on 2026-11-15. **Not deployed.** Branch
`fix/log-anonymizer-csv-sensitive-fields`, based on accepted source
`458f97c8ddeadee72c5b767a6dd2da68a054d056`. Engine1.0.4, rules2026-11-15.1.

## Reproduction and scope

The exact plain three-column example was already masked by the accepted source,
with legacy USER/SECRET/HOST labels. Its username and password were exposed when
the first header contained a UTF-8 BOM, or an unrelated header contained Unicode.
The old CSV classifier required every header to be ASCII and used physical lines;
failed inference fell back to ordinary detectors, which recognized the URL host
but had no header-to-value association. `User ID` and spaced JSON keys also lacked
explicit coverage. This reproduces the reported failure class; it does not assert
which bytes were in the owner's original uploaded file.

The existing span-based, browser-local engine and Worker remain in use. No new
runtime dependency, network service, AI, persistent storage or deployment mechanism
was introduced. Five LA runtime files change: engine, app, Worker, PHP version
constants and one limitations paragraph. Hub, pages/SEO metadata, other engines,
Research, Content, systemd and production are outside this change.

## Behavior

- A raw-offset CSV reader replaces the old physical-line splitter. Comma, tab and
  semicolon delimiters, BOM, quoting/doubled quotes, column order, padding, empty
  values, CR/LF/CRLF and quoted multiline records are retained. It never
  reserializes the document. Chunk boundaries retain complete logical records.
- Recognized Username / User name / Login / User ID variants receive USERNAME
  labels; Password / Passwd / Pwd receive PASSWORD; API Key / Access Token /
  Auth Token receive TOKEN; Secret / Client Secret / Private Key / Credentials
  receive SECRET. Case, underscores, hyphens and spacing variants are supported
  by the bounded header grammar.
- Complete sensitive cells take precedence over nested hostname/custom matches.
  Other fields still use existing IP, host, email and other detectors. Category
  switches and generic labels still apply; disabling a group disables its masks.
- Ordinary logs retain USER and SECRET prefixes for compatibility. Existing
  password=/token:/username= support is preserved; known spaced keys and User ID
  are added. Numeric JSON User ID replacements are quoted to keep valid JSON.
- Typed CSV counts are added as `fieldStats` and displayed with existing group
  totals; the existing opt-in map includes typed labels and occurrence counts.
  **The map intentionally contains originals and is sensitive.** It is not a
  diagnostic report and remains acknowledgment-gated.
- Worker errors use fixed messages and sanitized custom-rule details. Invalid
  regex errors no longer reflect the entered pattern; file-size errors omit the
  filename. No new diagnostic logging is added.

## Limits

This is heuristic redaction, not a guarantee that all sensitive data is removed.
It requires a first-record header, supported names and recognized delimiters;
unknown/translated headings, preambles, single-column tables and arbitrary bare
secrets are not inferred. Up to512 columns,128 characters per header and64KiB
header probing are supported. Recognized tables reject later malformed records;
ambiguous first rows may fall back to ordinary text rules rather than being
recognized as CSV. JSON support is scalar key/value matching, not a complete
JSON parser or arbitrary nested/escaped-key schema inference. Existing limits
for other detectors remain. Download encoding remains UTF-8, including when the
original file required UTF-16 decoding. Multiline credential cells retain their
line breaks and repeat the same label on each nonempty physical segment;
replacement counts count those segments. Physical Safari/iPhone and installed
WordPress were not tested in this source-only task.

## Verification

See [acceptance.json](acceptance.json) for executed checks and pinned runtime hashes.
Raw generated fixtures, original-value maps, logs and downloads remain outside Git.
New tests construct synthetic values at runtime and print case labels/counts only.
`log-anonymizer-engine.test.cjs` moves its old User ID negative example into the
positive examples because the owner's requirements explicitly classify User ID
as sensitive. Frozen corpus hashes and performance thresholds are unchanged.

The first browser run passed Firefox and stopped Chromium/WebKit at the empty
textarea case: its new test wrongly assumed Playwright normalized CRLF equally.
A separate minimal diagnostic showed Chromium/WebKit retained CRLF while Firefox
normalized LF. The test now uploads an actual CSV file and demands byte-exact
CRLF preservation in all browsers. Product code did not change for that correction;
failed attempt evidence was retained privately. Earlier exploratory harness issues
(missing Git wrapper, a test filename absent from this checkout) are not counted
as product passes. During development, mixed-log inference/reader regressions were
fixed before final acceptance; all4006 frozen results now match the accepted base.

No staging check, package rebuild or deployment is implied by these local results.
A future installation requires separate authorization and a package based on the
then-current live theme; historical deployment manifests must not be reused.

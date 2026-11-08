# CyberDat 0.5.0 step 2 — official NVD enrichment

## Source and documentation

Only https://services.nvd.nist.gov/rest/json/cves/2.0 is permitted, with one strictly
validated KEV CVE ID in `cveIds`. Current documentation:
https://nvd.nist.gov/developers/vulnerabilities and
https://nvd.nist.gov/developers/start-here . The site now serves an Angular shell;
the actual documentation text was inspected in its public official JS bundle.
Bundle URL, SHA-256, retrieval date and confirmed parameters/limits are recorded in
`provenance.json`. `cveId` is deprecated but still worked for the original manual
snapshot requests; new worker URLs use `cveIds`. NVD permits up to 100 IDs per call,
but this implementation deliberately requests only one.

Confirmed published limits: 5 requests per rolling 30 seconds without a key,
50 with a key; NVD recommends sequential requests with a six-second pause.
Our worker is substantially slower: one request per >=60 seconds, even with a key.
No other data aggregator, whole-NVD import, external source lookup or public
refresh endpoint is present.

## Module, queue and storage

`inc/nvd-data.php` is separate from KEV and HTML. Only local/development/staging or
explicit Playground contexts can operate the service. Automatic Cron additionally
requires `CYBERDAT_NVD_LIVE === true` and is always disabled in Playground.
Neither Blueprint nor theme defines that flag. `CYBERDAT_NVD_API_KEY` is optional
and read only from process environment (`getenv`), ASCII alphanumeric/hyphen,
<=256 bytes, supplied via the `apiKey` HTTP header. It is never stored in options,
URLs, HTML or application reports/logs. No real key was used for development.

HTTP uses WordPress `wp_safe_remote_get`, fixed HTTPS hostname/path, validated ID,
10-second timeout, no redirects, TLS verification and 1 MiB response cap plus one
byte to detect truncation. Require HTTP 200, JSON MIME, JSON depth <=48, v2.0
envelope, exactly one matching CVE and bounded consumed fields. Rejected records,
missing/mismatched IDs, malformed CVSS, 403/404/429/5xx/timeout/JSON errors retain
last-good data. No returned URLs are fetched. Official record links are built
from validated IDs. Raw API bodies, affected products and references are discarded
from the operational cache; only the small offline fixture retains original bytes.

No schema migration or custom table is required:

- `cyberdat_nvd_cve_{CVE-ID}`: normalized English description, chosen assessment,
  successful-check timestamp and snapshot flag; non-autoloaded.
- `cyberdat_nvd_index`: bounded per-ID summary/queue state, severity, checked time,
  errors, failure count and retry time; non-autoloaded. Homepage distribution reads
  this summary, not 1769 individual records. The three visible rows read three
  per-ID records; repeat get_option calls benefit from WordPress request caching.
- `cyberdat_nvd_runtime`: persistent earliest next run, non-autoloaded.
- `cyberdat_nvd_lock`: atomic option lock, owner token, 120-second lease,
  compare-and-delete recovery/release. Ownership checked before saving a response.

At most **2000 current KEV IDs**, newest first. Reconciliation deletes only this
module's own cached records when removed from KEV or outside that cap. No posts,
WordPress settings, KEV cache or other plugin data are pruned. If KEV exceeds the
cap, coverage remains partial; it never silently claims the full catalog.

Queue state is implicit in the persistent index: unseen IDs and snapshot IDs first,
newer dateAdded / CVE ID DESC; then live entries stale after seven days, oldest
successful check first. Not-yet-due retry entries are skipped. One CVE maximum per
Cron event and a persisted >=60-second global gap, so progress resumes after restarts
without refetching fresh entries. No sleep or long batch occupies a PHP worker.
HTTP failures back off exponentially (5 min to 24 h); 403/429 minimum 15 min;
404 or an empty NVD result minimum 24 h. Retry-After seconds or HTTP dates are also
respected, including delays exceeding normal backoff. A global pause prevents
hammering an unavailable API; a missing individual CVE waits 24 hours without
blocking other IDs beyond the normal one-minute gap (or Retry-After). Absence in NVD is never interpreted as absence of a
vulnerability or as score 0. Last success timestamps do not advance on failure.

Fresh: successful live check <=7 days and no subsequent failure. Stale: older,
failed recheck or any fixed snapshot. Coverage includes retained stale records,
explicitly counting stale/snapshot records in the caption; it is not silently
presented as current or complete.

## CVSS selection and display

Version priority: **4.0 > 3.1 > 3.0 > 2.0**. Within a version: exact NIST source
`nvd@nist.gov`, then Primary before Secondary, source casefold/raw lexical order,
vector lexical order and score tie breaker. This is a product policy, not a claim
that NIST mandates this priority. It does not choose the highest score. UUID source
identifiers are displayed verbatim without inventing organization names.

Numeric score, version, source, source type and vector are retained. A supplied
v3/v4 severity must match its standard score band or validation fails. If absent,
show Unclassified rather than inventing a category. A genuine 0.0 remains 0.0 /
Unclassified; absent assessment is null / Not rated. CVSS v2 scores are always
**Unclassified** in the modern distribution, with original legacy severity retained
separately: no automatic translation of the old High band into modern Critical.
CVSS severity is distinct from KEV's evidence of exploitation.

Dashboard preserves KEV metrics and dateAdded graph. Its existing ring/legend now
shows Critical, High, Medium, Low, Unrated / Unclassified, only among successfully
loaded NVD records. The required coverage caption supplies both numerator and full
KEV denominator. Latest KEV table gains one score/severity column, version/source,
checked UTC time and fixed official NVD link. Native details exposes the English
description without JS. Existing horizontal table scroll and all CSS remain;
logo, menu, editorial blocks and production guard are unchanged.

## Official offline snapshot

Seven original API responses were retrieved **2026-11-08, 06:09–06:11 UTC**.
Exact per-response URLs, HTTP status, acquisition times and SHA-256 are in
`provenance.json`; the compressed bundle contains the original JSON strings.
`responses.json.gz.b64` decodes as base64 → gzip → JSON map of CVE IDs to original
response strings. Validate both bundle hash and each original response hash before
import. No API calls are made when Playground opens.

| CVE | Selected score | Version | Severity | Source |
| --- | ---: | --- | --- | --- |
| CVE-2026-19868 | 7.5 | 3.1 | High | 134c704f-9b21-4f2e-91b3-4a467353bcc0 |
| CVE-2024-27834 | 5.5 | 3.1 | Medium | nvd@nist.gov |
| CVE-2026-119977 | 8.1 | 3.1 | High | security@wordfence.com |
| CVE-2021-44228 | 10.0 | 3.1 | Critical | nvd@nist.gov |
| CVE-2024-3400 | 10.0 | 3.1 | Critical | nvd@nist.gov |
| CVE-2025-10035 | 9.8 | 3.1 | Critical | nvd@nist.gov |
| CVE-2018-13379 | 9.8 | 3.1 | Critical | nvd@nist.gov |

Coverage is **7 of 1769**, not a distribution of all KEV: Critical 4, High 2,
Medium 1, Low 0, Unrated / Unclassified 0. Every fixture is marked SNAPSHOT / NOT LIVE
and Stale, even on acquisition day. Original KEV snapshot remains byte-identical.
The official 2.0 Log4Shell assessment (9.3, legacy High) is exercised by tests after
removing only the newer assessment from the test envelope; it is not the selected
homepage score and is never relabeled Critical.

**Verification limit:** these real responses have no CVSS 4.0 or 3.0 assessment.
A bounded official search also did not provide a usable example. Their key/version
support and fail-closed validation are implemented, but a successful official-fixture
parsing/priority test for those versions remains pending. No synthetic positive
CVSS assessment has been invented to conceal this gap. The real-response tests
verify 3.1/2.0 selection, source priority and numeric differences. Revisit this
specific gap when an official KEV/NVD response containing those versions is available.

## Checks and future staging operation

`php tests/nvd.test.php` runs the actual module with isolated WordPress primitives
and intercepted HTTP; `tests/nvd-cases.php` is shared by real WordPress Playground.
It verifies checksums, matching KEV IDs, parsing/errors, missing score/CVE,
403/404/429/500, Retry-After, failure retention/recovery, one-item queue, persistent
rate gap, source/version priority, partial denominator, stale cache, HTML escaping,
cache-only rendering and disabled Cron. `finally` restores original KEV/NVD cache,
queue, runtime, lock and per-ID records. Existing KEV and editorial suites continue.

Playground imports originals and then runs that same suite with actual WP options
and WP HTTP filters. Its report joins the existing inspection panel; browser checks
include 320/768/1440px, menu, overflow, ring coverage, row scores and editor blocks.
Authoring has no browser engine: real WP-WASM and rendered-width results must run
when opening the preview, and are not claimed as preverified.

For a later approved staging test only: ensure a separate restricted staging site,
set environment type staging, enable `CYBERDAT_NVD_LIVE` in its configuration, and
optionally supply `CYBERDAT_NVD_API_KEY` through its process environment. Ensure a
working minute-level WP-Cron runner. No real flag/key or Cron execution was enabled
here. Disabling the flag clears the event on next init; cache remains. Production
is refused by the data service and still guarded in front-page.php.

At one CVE/minute, initial 1769-record enrichment takes at least **29 h 29 min**
without errors. Traffic-driven WP-Cron or backoff can extend that to days. A key
raises NVD's allowance but does not accelerate this conservative worker. Weekly
rechecks spread the same bounded workload. Typical normalized storage is a few MB;
a 16 KiB description bound plus bounded assessment gives roughly <=40 MB for 2000
records, plus summary/WordPress DB overhead. Raw responses are not operational cache.
CLI tests run with 128 MB PHP memory; that is not a production concurrency benchmark.
No production connection, database/service/configuration change, merge or deploy
is included. Do not proceed to automation/agents or production without approval.

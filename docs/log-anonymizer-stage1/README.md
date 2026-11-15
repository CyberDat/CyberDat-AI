# Log Anonymizer Stage 1 — 2026-11-15

**PARTIAL. No staging installation. Stage 2 not started.** The owner requires one
regression pass per stage, with no repeats. That pass found three existing CSV
case failures and a PHP text-contract failure. Narrow corrections were applied
afterwards but were not rerun; they are not certified PASS. No backup was created
because the deployment gate was never reached.

## Commits and scope

Base4a6f4ea; tests committed first in0b69e17 and59e7ce2. The first fixture version
returned3PASS/73FAIL. The second commit makes query samples syntactically valid;
it predates implementation. Source changes are limited to LA engine/app/PHP/template
and the explicitly permitted translation attributes/disclosure in the other three
tool templates. Other engines, pages/SEO metadata, Research/Content, SQL, timers,
production and main are unchanged. No runtime dependency or external data service.

## Requirement status

| Item | Implementation / acceptance |
|---|---|
|1.1|USER/SECRET shared across log/CSV; identity keyed by category and normalized value; credential fieldTypes in map and fieldStats; new tests pass|
|1.2|Tables detected within mixed text, bounded by blank/different-shaped rows; shared labels across query/table; new tests pass; three standalone compound-heading regressions corrected after the single run, UNVERIFIED|
|1.3|Unicode word splitting, camelCase boundaries and metadata-word exclusions; account/AWS report tests pass|
|1.4|Requested username/secret/name/phone keys and enabled identifier/personal category; all new context tests pass|
|1.5|Checksum IBAN, non-short SID and account position in supported AWS ARNs; new tests pass|
|1.6|Whole Unicode NFC/NFD email, international domains and percent40 form; new tests pass|
|1.7|Session-specific of-user rule; benign phrase retained; new tests pass|
|1.8|Bounded unquoted multiword names; stops at separators/next field; new tests pass|
|1.9|Requested exact German/Russian keys implemented; new tests pass|
|1.10|Input/results/preview protected by translate=no/notranslate; all-template static check passes. Source/status/map wrapper coverage was extended after the run, UNVERIFIED. Disclosure does not promise protection from extensions|
|1.11|Limits updated. PHP contract stopped at a changed first-sentence prefix; that prefix was restored after the run, UNVERIFIED|

New76/76, original engine61/61, existing structured51/54, frozen holdouts35/35.
Original4000ms assertions retained and passed; no additional performance campaign.
Five changed PHP files linted. PHP contract14 checks passed before the wording
failure; remaining checks did not execute. D14 LA: Chromium10/10, Firefox10/10,
WebKit10/10. Firefox had no interception and its network property remains UNVERIFIED.
Frozen D14 case/expectation file was not edited. Browser evidence is from a local
PHP-rendered fixture, not installed WordPress. No second regression run was made.

## Frozen results, without source values

All4006 output texts and pre-existing map/count/preview fields match the accepted
baseline. Rule1.1 adds field-type metadata in2836 results;1170 results are identical
after projecting only zero-valued newly introduced category schema. Rules1.2–1.11
produce no other differences in this corpus. Unexpected changes:0. Original frozen
files/hashes were not rewritten. Examples for rule1.1: case0,1,5,6,8; each has only
additional map fieldTypes / subtype fieldStats and unchanged output. Hashes are
provided in acceptance.json; no original values or raw screenshots are published.

## Existing expectation changes

- structured-fields: USERNAME/PASSWORD/TOKEN expectations become USER/SECRET;
  subtype counts use password/token rather than label prefixes. The old malformed-
  CSV rejection case becomes the owner-specified table-boundary continuation case.
- structured-browser: corresponding label/map/statistics expectations and table-
  boundary case updated. This auxiliary browser suite was not run in this stage;
  the required original D14 ran once per browser instead.
- PHP:15 category checkboxes becomes16 for the owner-approved new category.
  The first Limitations-prefix assertion was retained; its failure was not hidden.
- Original61 engine expectations and all D14 expectations remain unchanged from4a6.

## Remaining limits and blockers

The post-run corrections require a new separately authorized acceptance pass before
installation. Three compound CSV headings were affected by inference despite working
inside tables recognized via another sensitive column. The final correction adds
those known compound headings to the same inference vocabulary.

Matching remains heuristic: arbitrary unlabelled people/phones, bare S3 bucket
names, unsupported encodings, unknown keys and ambiguous/malformed table boundaries
can be missed. JSON is scalar-pattern based, not a general parser. CSV inferred
headers are bounded; typed names are not universal language understanding. Numeric
JSON sensitive scalars become string labels. New SID/IBAN/AWS_ACCOUNT prefixes are
the explicit format-specific exceptions requested by the owner; same-category
identity reuses the first encountered label within the run. Replacement maps retain
originals and must stay private. Translation opt-out is a request, not a barrier
against browser extensions.

Strict Mode, generated key descriptions, CSV column selection and Additional keys
are NOT IMPLEMENTED. No Stage2 commit or deployment is claimed. Public-launch
acceptance remains open; licensing/shared-theme and Firefox limitations are retained.

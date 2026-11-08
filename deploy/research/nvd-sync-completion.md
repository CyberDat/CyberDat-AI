# NVD incremental window completion (staging only)

## Diagnosis

At the observed state, 50 of 918 modified-date results were committed and 53 NVD CVEs were indexed (including three separate KEV lookups). The request already sent `startIndex` and `resultsPerPage`. The missing component was prompt continuation: the source timer ran every two hours and the five-minute dispatcher handled requests/errors/backfill but not a healthy unfinished incremental window. Request success was also labelled Fresh without an independent completion label.

## Change

- Continue pending incremental windows using the existing five-minute dispatcher, two requests per run, 50 records per page. Partial success sets the next due time five minutes ahead; errors retain exponential backoff / Retry-After. A stopped process resumes its committed offset.
- Skip optional KEV enrichment while a window is pending. The source's two-hour timer still starts later overlapping incremental windows; a scheduled invocation respects next_due rather than behaving as a manual request.
- Retain each page's offset, CVE identifiers and identifier hash in the same InnoDB transaction as its upserts and cursor. Check contiguous positions and unique identifiers before advancing the completed-window timestamp checkpoint. Retain the latest completed window ledger as evidence, separately from a new in-progress window.
- Pre-ledger cursors are preserved; fetch their committed prefix once to establish evidence and then continue at the saved offset. Existing rows use the same source-ID upsert. This is verification of one current window, not a historical database import.
- If totalResults changes or an identifier overlaps pages, reset this window's offsets/ledger and back off; retain existing records. NVD supplies no immutable snapshot token: the ledger proves unique, contiguous results observed during a stable-total traversal, not an absolute guarantee against every concurrent upstream mutation. Subsequent incremental windows retain a two-hour overlap.
- Keep existing GET_LOCK, HTTPS allowlist, public-IP pinning, response/time budgets, max 5,000 NVD rows and last-good cache. No schema migration, external dependency, new service, public endpoint or automatic publication.
- Display request-age Fresh/Stale/Error separately from NVD Window In Progress/Complete. Total indexed NVD, KEV-linked chart subset and full KEV catalog remain explicit. Complete refers to the bounded modified-date window, never the whole historical NVD.

Official API parameter reference: [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities); [NVD developer guidance](https://nvd.nist.gov/developers/start-here).

## Tests and owner execution

Run `php8.4 tests/nvd-resume.test.php`, `php8.4 tests/research.test.php`, `php8.4 tests/nvd.test.php` and `php8.4 tests/dashboard-scope.test.php`. The owner coordinator also runs the existing real-MariaDB integration fixtures in temporary tables after backup; no fixture records enter the Research Queue.

`deploy/research/complete-nvd.py` is bundled with three pinned candidate plugin files, their before/after SHA-256, the read-only nvd-proof.php, a COMMIT file and BUNDLE-SHA256SUMS. It requires owner sudo and the existing Basic Auth password via hidden terminal input; no WordPress password is requested. Do not rerun the original staging or Research installers.

Before modifying the three plugin files it pauses only the NVD and dispatcher timers/workers, checks other Research workers are idle and creates a private root-only staging SQL and plugin backup. Backup files can contain staging secrets; keep private. Original backup and production are untouched. The coordinator limits continuation to 40 batches / 25 minutes; any failure retains the last committed cursor and restores previously active timers. Resume an interrupted release only with its explicit backup path, not --apply. Existing healthy partial windows are also continued by the dispatcher.

After completion it verifies the ledger, presence of all completed-window IDs in the DB, no duplicate NVD IDs, Dashboard count and every projected CVSS assessment against SQL, a no-op immediate scheduled invocation, authenticated HTML, Basic Auth/noindex, Tools, protected fingerprints and production HTTPS. It prints actual counts and timestamps, never API bodies or credentials. Future scheduled recurrence is UNVERIFIED until observed.

An explicit --rollback-code restores only the three saved plugin files; it does not discard accumulated CVEs, restore SQL, reset checkpoints, modify schedules/configuration or delete backups. A database restore is not automatic and would require a separate reviewed decision. No production cache flush, PHP-FPM reload, DNS/TLS or mail changes.

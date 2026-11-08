# Dashboard data provenance and explicit NVD scope

## Established code path

The installed theme `cyberdat_kev_view()` delegates to `cyberdat_research_kev_view()` when the staging Research provider is enabled. `cyberdat_nvd_view()` and `cyberdat_nvd_coverage()` use the same provider. `cyberdat_research_data()` reads the `dashboard` row of the staging `cdra_state` table; only a database failure uses the private last-verified JSON cache. The legacy WordPress snapshot options remain stored for development/fallback compatibility but are not selected by an active Research provider.

The projection's CVSS records intentionally use a join between synchronized NVD items, their CVE relationships and active KEV items, with a 2,000-match presentation cap. The severity donut is the **NVD ∩ KEV subset**, not the entire synchronized NVD population. The projection separately stores `indexed_cves`, the total synchronized NVD count. The old center label LOADED was ambiguous even though the status caption already showed both counts.

The limited change exposes that existing count through the provider's coverage metadata and clarifies only chart text/attributes: KEV MATCHES, Severity of KEV-linked CVEs, chart subset count, synchronized NVD count and full CISA catalog count. No metric, source query, synchronization checkpoint, source connector, schema, schedule, SEO setting or chart CSS changes.

A CISA catalog can have the same count/version/entries as the previously imported snapshot if CISA has not released a new catalog. Recent successful retrieval/validation must not be represented as a new source release. The report compares both dates and individual records; it does not manufacture changed CVEs.

## Cache inspection

Read-only inspection found staging FPM `php_admin_flag[opcache.enable] = off` and an empty OPcache file-cache setting. WordPress has no object-cache.php or advanced-cache.php drop-in. No fastcgi_cache/proxy_cache directives were found in the staging vhost or checked nginx.conf/conf.d configurations. No cache clear, OPcache reset, service reload or production action is part of this patch.

## Owner-run proof and conditional display update

`check-dashboard.py --apply-labels` requires owner sudo and only the existing Basic Auth password, entered hidden. It uses one consistent read-only SQL transaction to compare active database KEV/NVD counts, Research projection values, selected theme provider values, legacy snapshot metadata, source health, three real latest KEV IDs and their SQL-backed CVSS assessments. It then compares those CVEs, timestamps, indexed count and chart subset against authenticated live HTML.

If the provider is inactive, reads the fallback file, selects a snapshot, disagrees with SQL, or has a projection temporarily lagging a running job, the script stops **before** cosmetic changes. It does not toggle provider flags, rebuild projections, start a job, import data or clear caches to disguise a mismatch.

Only after SQL/provider/HTML provenance passes does it create a private two-file backup under `/var/backups/cyberdat-staging/dashboard-labels-<UTC>/` and atomically replace the coverage helper and chart template. Original files/checksums and before-proof evidence remain root-only. It verifies the clarified HTML, Basic Auth/noindex, Tools, protected configuration hashes and production HTTPS. Actual runtime evidence is printed as public CVE IDs/metrics/source timestamps; credentials, hashes of user passwords and cookie values are never printed. Any source data change between reads can be a legitimate scheduled ingestion; the script itself performs no import.

The printed `--rollback-labels <exact-backup-directory>` command restores only these two display files after checksum checks. It does not alter database data, source timers, credentials or caches.

## Validation

PASS: isolated rendering with 3 KEV-linked CVEs, 53 indexed NVD CVEs and 1,769 full KEV entries makes all three scopes explicit. PHP syntax and coordinator AST checks are required. Previous KEV/NVD presentation tests remain compatible with the optional new scope fields; development snapshots retain their original labeling.

BLOCKED pending owner execution: current SQL/HTML samples, latest actual timestamps/counts, proof of selected runtime source, two-file deployment and post-deploy HTTP verification. Prior reports are evidence of earlier successful syncs, not substitutes for this current read-only comparison. Do not claim a snapshot bug or completed deploy from static code inspection alone.

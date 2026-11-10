# Research Agent 0.8.2 stabilization — 2026-11-10

Status: PREPARED, staging deployment and new-source persistence pending. Branch: feat/cyberdat-research-agent-0.8.1.

## Verified baseline

Owner read-only snapshot 16:32:02 UTC: KEV 1773; NVD 3638; queue 5779; 307 discovery topics; zero duplicate source IDs and zero correlated live topics. NVD transport at 15:40:16 recovered automatically by 15:50:40; latest success 16:29:39, HTTP 200, no current error. Checkpoint 1794305945 is preserved. Historical curl errno was not recorded: precise DNS/TLS/timeout cause cannot be reconstructed. No collector change is justified.

Crossref automatic cursor continuation is evidenced by the 15:45 dispatcher cycle: records 21→44, offset 25→50; later snapshot 116/offset150. This proves Crossref recurrence, not every source cadence.

## Confirmed changes

* Healthy overdue legacy jobs were skipped: fixed timers fired seconds before health.next_due, and dispatcher retried errors/pending NVD only. Select oldest eligible due source fairly using existing intervals/backoff and global lock. No timer/unit edits.
* Correct token boundaries (enrollment is not LLM), exploit-parallelism false positives, model-backdoor/malware distinction, crypto/OT and contextual AI-security categories. Event invitation penalty is an explicit heuristic, not a paid-content assertion. Existing manual decisions are preserved.
* Scoped endpoint/host corrections below; fetch security implementation, redirect prohibition, DNS/public-IP pinning and response caps are unchanged.
* Real SAP ICM2SHELL/ProxyGate pair 5559/5600 is eligible for audited merge/split/merge via existing APIs, only if exact evidence and New/manual-unassigned conditions still match. Independent publications remain intact. This is manual editorial correlation, not proof of independent reporting or automatic grouping.

## Recheck of all 28 previously disconnected channels

| Channel | Public probe result / limitation |
|---|---|
| Microsoft Security Blog | PENDING_PERSISTENCE: HTTPS fetch and existing parser passed; https://www.microsoft.com/en-us/security/blog/feed/ |
| Microsoft Defender Threat Intelligence | UNSUPPORTED: Overlapping Microsoft publisher topic feed; intentionally consolidated into Microsoft Security Blog rather than duplicate polling/records |
| Microsoft Research Security | UNSUPPORTED: Official general Research RSS includes non-security content and is not a scientific-paper metadata feed; security-specific relevance requires confirmation |
| Project Zero | PENDING_PERSISTENCE: HTTPS fetch and existing parser passed; https://projectzero.google/feed.xml |
| Google Threat Intelligence / Mandiant | PENDING_PERSISTENCE: HTTPS fetch and existing parser passed; https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/ |
| Google Security Blog | PENDING_PERSISTENCE: HTTPS fetch and existing parser passed; https://blog.google/security/rss/ |
| Cisco Security Advisories | PENDING_PERSISTENCE: HTTPS fetch and existing parser passed; https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml |
| CrowdStrike Research | PENDING_PERSISTENCE: HTTPS fetch and existing parser passed; https://www.crowdstrike.com/en-us/blog/feed |
| Sophos X-Ops | PENDING_PERSISTENCE: HTTPS fetch and existing parser passed; https://www.sophos.com/en-us/category/threat-research/feed |
| FortiGuard Labs | BLOCKED: Official tested RSS landing/threat feed URLs returned 404; no functioning documented machine-readable endpoint verified |
| Elastic Security Labs | PENDING_PERSISTENCE: HTTPS fetch and existing parser passed; https://www.elastic.co/security-labs/rss/feed.xml |
| Trail of Bits | PENDING_PERSISTENCE: HTTPS fetch and existing parser passed; https://blog.trailofbits.com/index.xml |
| ENISA | BLOCKED: Official site accessible; tested RSS endpoints returned HTTP 404 |
| BSI / CERT-Bund Security Advisories | PENDING_PERSISTENCE: HTTPS fetch and existing parser passed; https://wid.cert-bund.de/content/public/securityAdvisory/rss |
| Dark Reading | PENDING_PERSISTENCE: HTTPS fetch and existing parser passed; https://www.darkreading.com/rss.xml |
| The Record | PENDING_PERSISTENCE: HTTPS fetch and existing parser passed; https://therecord.media/feed |
| OWASP GenAI Security Project | PENDING_PERSISTENCE: HTTPS fetch and existing parser passed; https://genai.owasp.org/feed/ |
| MITRE ATLAS | UNSUPPORTED: Official ATLAS site is a technique/knowledge-base application, not a verified dated publication feed |
| DeepMind Security Research | UNSUPPORTED: Official general blog RSS works but contains product announcements; security-specific filtering required before enabling this channel |
| NVIDIA Security | BLOCKED: Official advertised/tag feed returned HTTP 200 with zero records; tested category RSS URLs returned HTTP 404 |
| GitHub Security Lab | BLOCKED: Official advertised Atom feed returned HTTP 200 with zero publication records; cannot prove ingestion |
| OpenAlex | BLOCKED: Official keyless metadata GET succeeds (HTTP 200), but reliable cursor pagination requires an owner-provisioned API key; no key created |
| Semantic Scholar API | BLOCKED: Official metadata API returned HTTP 429; shared anonymous quota unavailable, API key/rate-limit provisioning required; no bypass |
| USENIX Security Symposium | UNSUPPORTED: Official Security 2026 proceedings HTML accessible (HTTP 200); no verified supported incremental metadata feed/API for this channel |
| IEEE Symposium on Security and Privacy | UNSUPPORTED: Official 2026 accepted-papers HTML accessible (HTTP 200); no verified supported incremental metadata feed/API for this channel |
| ACM CCS | BLOCKED: Official ACM proceedings endpoint returned HTTP 403; no access-control bypass |
| NDSS Symposium | UNSUPPORTED: Official 2026 accepted-papers HTML accessible (HTTP 200); oEmbed is not a paper-discovery feed |
| RAID Symposium | UNSUPPORTED: Original catalog hostname did not resolve; official 2026 site is accessible but has no verified supported incremental metadata feed/API |

OpenAlex basic keyless queries succeeded; full cursor access requires an owner-provisioned key (official documentation: https://help.openalex.org/api/authentication/). Semantic Scholar returned 429; access/quota provisioning remains blocked. UNSUPPORTED means no verified connector under the current metadata-only policy, not that a publisher has no possible integration.

## Acceptance and operational limits

Existing 11-suite offline batch passed; latest 14 classification and 8 fairness regressions pass. Fixed-fixture database tests run after backup before new source enablement. Public endpoint probes do not count as CONNECTED: persistence and last_success are required.

36 latest real records were reviewed across three streams; regression excerpts include TUTTI, BioBind, LoRA and OT papers. This is a diagnostic sample, not a measured global precision rate. Scheduled new-source recurrence, live correlation and actual classification correction remain pending deployment evidence.

Read-only resources: load 0.09/0.06/0.07, available RAM ~2.05 GiB of ~3.83 GiB; Research tables 33,603,584 bytes. No load test. Existing capacity limits remain; long-duration growth/load is UNVERIFIED.

Owner-run stabilize-research.py creates a private staging SQL/plugin backup before three-file patching, executes integration fixtures, bounded derived corrections, controlled new feeds and one protection/SQL smoke test. Controlled due recovery is never counted as automatic recurrence. --observe BACKUP is read-only. --resume BACKUP retains partial progress. Code rollback disables new jobs and restores classifier/dispatcher while retaining registry definitions and all actual records/audit; it is not a destructive SQL restore.

Public theme, Analytics 2.1, SEO, mail, TLS, DNS, existing HTTP client and NVD ingestion code are not deployment targets. No automatic posts, new service, Content/Social/Ollama or production writes.

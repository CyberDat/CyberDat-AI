# Content Agent 0.9.0 Stage 1.1 — Evidence Enrichment

Staging only. No LLM/GPU, publishing, Research collector/timer, public design or SEO changes. Based on Content branch `feat/cyberdat-content-agent-0.9.0`, parent `a04d21be8d768fba6ca9abd911a75220528bb47b` (including menu fix `e045209582fb3eb1d48a82e7ed350502f753294f`). All 8 installed Content and 21 Research files matched the working snapshot before changes. Existing tables matched the previous audit; real eligible handoffs: zero. Only TEST job1/draft1 existed.

## Contract

`cyberdat-content-brief/2` adds source/item/topic IDs, original/canonical URLs, source version hashes, author attribution, source publication/update dates and available precision, manual classification/priority with reasons, paper metadata/abstract, CVE/CWE/CVSS and official local-CVE context. Unknown values remain null; empty arrays/strings are not converted into invented facts. Every projected field has an origin and source hash. Legacy briefs/draft versions remain unchanged. The updated mock worker accepts both v1 and v2; real jobs remain unclaimable.

Read-only Research adapter joins at most20 sources including bounded official CVE matches, without network or state writes. `cdca_research_evidence(id,false)` is an explicit CLI/test preview; normal import still requires a current human-selected approved hash. Research private `cyberdat-research-handoff/1` remains untouched and is not falsely called the Content payload.

Sufficiency is template/depth-specific. Dated substantive official news can support a **news brief**, and local official CVE/technical data can support **bounded metadata analysis**. Abstracts cannot enable a full methodology/experiment review. Threat/AI deep analysis remains blocked until appropriate reviewed technical context exists. Two URLs never establish independence. Gate availability is not semantic truth; source claims are unverified. The no-LLM stage does not offer a human verification override that pretends to validate facts automatically.

## Isolated enrichment

Two additive tables (existing job/version/event/agent schemas retained):

- `stg_cdca_enrichments`: job/item/source snapshot, unique request key, status, attempts/backoff, bounded JSON payload and timestamps.
- `stg_cdca_evidence`: unique fragment key, enrichment/item IDs, source-version hash, JSON fragment/locator/context/type/verification/limitations, creation time.

Original Research payloads and editorial decisions are not rewritten. Enrichment can be requested only for selected/queued current jobs. Admin POST requires existing capability, nonce and revision; GET only reads stored data. CLI explicitly processes one job; no added scheduler, service or public extraction API. Immutable draft quality stores the exact effective brief/enrichment hash. Existing v1 draft1 remains unchanged.

Authorized staging CLI:

```
wp cyberdat-content evidence_preview --item=ID --template=paper  # read-only
wp cyberdat-content enrich --job=ID                            # local DB evidence only
wp cyberdat-content enrich --job=ID --network                  # explicit bounded retrieval
```

Do not use production, public Ollama, an unselected real item, mass imports, or old pinned Stage1 deployment scripts. UI requests do not start network work. Gate failure blocks queueing real deep-analysis jobs; mock TEST fixtures retain their explicitly synthetic technical-test bypass, and mock workers still cannot claim real jobs.

## Content and network policy

Content classification is `metadata_only`, `summary`, `abstract`, or `full_text`, with availability, suspected/unknown clipping, URL/time/hash/method/status/usage limitations. **This stage never assigns `full_text`**: even extracted CISA article/main text is a bounded excerpt with possible page chrome. Legacy truncation is true at known collector caps, otherwise null because historical flags do not exist. Scientific metadata retains preprint status and original dates.

Only exact official CISA catalog paths, bounded CISA advisory paths and single-ID arXiv metadata queries have extraction policies. Other publishers retain their already collected metadata and report `access_not_permitted`; accessible HTML alone does not grant permission. No PDF reader, JS execution, paywall/CAPTCHA bypass, arbitrary URL or third-party LLM exists. arXiv [API terms](https://info.arxiv.org/help/api/tou.html) permit descriptive metadata under CC0, while e-print redistribution rights remain separate.

The independent HTTPS client checks strict URL policy, all DNS answers through existing public-IP validation, pins the connection IP, verifies TLS, disables proxies/automatic redirects and validates every manual same-host redirect (max2). robots.txt is fetched before content and fails closed. Maximum body2MiB, text12k characters, headers32KiB, connect5s/total15s, six HTTP requests/client, two sources/job, three attempts with stored backoff/Retry-After. No infinite retry. The existing ingestion lock serializes opt-in real network retrieval with Research's public-API use; no collector code or frequency is changed. Multiple enrichment processes are serialized separately.

## Verification and rollback

Backup: `/var/backups/cyberdat-staging/content-evidence-1.1-20261111T050721Z`. Before changes: full private staging SQL dump, Content archive, protected/Research/timer/theme/production fingerprints and post hashes. Gzip validated; archive restored into a private scratch directory and all hashes matched. SQL restoration into isolated TEMPORARY Content tables is required by the deployment controller; it never restores the live Research database.

Pure policy/contract checks and existing mock worker/menu tests pass. Candidate MariaDB:25 existing checks plus23 new evidence checks, four real source records copied only into TEMPORARY fixture jobs. Three limited live network cases use TEMPORARY evidence storage. See final acceptance JSON for actual deployed evidence, limitations and test counts; do not infer acceptance from this preparation description.

Code rollback restores the backed-up Content directory with atomic directory exchange and retains additive evidence tables/audit. No automatic SQL rollback is performed because Research continues ingesting. Deployment completion/HTTP checks pending at initial runtime commit; final status is recorded separately.

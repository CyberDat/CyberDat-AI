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

Pure policy/contract checks and existing mock worker/menu tests pass. Candidate MariaDB:25 existing checks plus24 new evidence checks, four real source records copied only into TEMPORARY fixture jobs. Three limited live network cases use TEMPORARY evidence storage. See final acceptance JSON for actual deployed evidence, limitations and test counts; do not infer acceptance from this preparation description.

Code rollback restores the backed-up Content directory with atomic directory exchange and retains additive evidence tables/audit. No automatic SQL rollback is performed because Research continues ingesting. Initial preparation commit was followed by the completed staging acceptance below.


## Final staging acceptance — 2026-11-11 05:32:30 UTC

**Backend implementation/staging regressions PASS; overall PARTIAL.** Evidence and measured limits: [acceptance JSON](acceptance-2026-11-11.json). Original backup remains unchanged. No real Research selection, Content job creation, version rewrite, article generation/publication or model execution. Production tree/configuration fingerprints match, and all SQL operations target staging only.

- **25 existing Content +24 evidence TEMPORARY-table checks PASS**, including v2 enriched brief claim/mock save, snapshot hash in quality, stale source hash rejection, retry exhaustion/Retry-After, unavailable worker/network and unchanged live jobs/posts. Eight Python mock-worker tests accept v1/v2 and reject real jobs/Ollama. Three installed WordPress menu/access lifecycle cases pass. Twenty pure evidence/policy checks pass; PHP lint passes.
- Four existing inputs (arXiv5663, Crossref6093, CISA advisory6145, NVD6514) were read-only inputs to four separate temporary local-enrichment jobs. The NVD case has CVE/CVSS/CWE; a real grouped topic retains distinct publication records. Historical source rows/decisions were not rewritten.
- Three bounded live network cases used temporary jobs. **Two inputs obtained additional external evidence** (CISA advisory6145 and KEV6144); arXiv5663 was denied by robots and retained its existing abstract. This is two successful input cases, not a claim of two independent sources/corroboration: some fetched evidence belongs to the same vulnerability context. The CISA seven-source case fetched only the first two permitted sources and deferred five. Repeating all cases produced zero extra HTTP requests. Fixture storage was dropped; both new live tables remain empty.
- **Full text NO.** CISA article/main extraction is a bounded source excerpt, with potential page chrome and completeness unproven. arXiv abstract is not a paper review; Crossref without text is insufficient. No PDF/full-paper extractor, paywall bypass or automatic semantic verification is implemented. Other publishers remain metadata-only unless a separate safe extraction policy exists. Deep paper/threat/AI generation stays blocked; even sufficient news/CVE scopes do not enable real workers or publication in this stage.
- **HTTP/admin PASS:** homepage, Threat Intelligence, Tools and both authenticated queues200; anonymous protection401, worker without private key403, noindex retained. Dashboard SQL equality: NVD4052, KEV1779. Original TEST job1 remains draft_ready, exactly version1, posts61 with unchanged full-row hash. No new indicator in either checked PHP/Nginx log file.
- **Backup restoration PASS:** Content archive restored privately/hash-compared, gzip validated; all four original Content tables restored into TEMPORARY tables and every column/row hash compared to live unchanged Content. No live SQL restoration or destructive rollback. Initial restore-check harness wrongly assumed single-line INSERT; corrected to handle quoted multiline SQL before any runtime exchange.
- Source/collector/timer/config/theme/SEO and entire production file hashes unchanged. Browser interaction, responsive layout, keyboard behavior and actual home-PC worker remain **UNVERIFIED**. No browser is available in this environment; no browser/service/model was installed. These limits and unavailable scientific full-text enrichment prevent an unconditional overall PASS.

The [redacted brief example](brief-example.redacted.json) is an **excerpt produced by the installed serializer** for existing Research5644. Authors are masked; summary/abstract are shortened to120 characters for the report, and some keys/fragments are omitted. Its is_test=false describes a read-only real-item preview, **not** a created/selected Content job. No proposed JSON is presented as persisted data.

Stop after reporting this stage. Ollama, Social Agent and automatic publication remain disabled.

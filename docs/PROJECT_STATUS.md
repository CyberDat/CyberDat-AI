# CyberDat — Project Status (source of truth)

Last updated: 2026-11-11
Repository: CyberDat/CyberDat-AI
Current stage: **Content Agent 0.9.0 Stage 1.1 — candidate tested; staging deployment/acceptance pending**

## Important rule
Before planning the next CyberDat task, read this file and relevant repository code. Do not infer completion from an older conversation or from a roadmap. Mark tasks complete only after confirmation/testing. Update this file at the end of each work session.

## Content evidence Stage 1.1 preparation — 2026-11-11

Authorized no-GPU/no-LLM implementation on `feat/cyberdat-content-agent-0.9.0`, based on `a04d21be8d768fba6ca9abd911a75220528bb47b`. Installed Content/Research hashes and SQL schemas matched the prior audit. Backup `/var/backups/cyberdat-staging/content-evidence-1.1-20261111T050721Z`; gzip and private archive restore/hash checks PASS.

Implemented brief/2 with retained provenance/academic/CVE metadata, two additive evidence tables, bounded opt-in enrichment, conservative content levels, template/depth sufficiency gate, admin evidence details and v1/v2 mock compatibility. Research collectors/timers, source payloads, editorial decisions, public theme/SEO and production are outside the change. Existing mock job1/draft1 is retained.

Candidate tests: pure contracts/policy, 8 Python worker cases, 3 installed-core menu cases; 25 existing Content DB cases and23 new evidence DB cases pass. Four real inputs are read-only; writes use TEMPORARY fixture tables. Live robots policy correctly denies arXiv API retrieval; existing abstracts remain usable. Initial CISA HTML marker mismatch was observed in a bounded test and the extractor was adapted to article/main excerpts without claiming full text. Deployment and final HTTP/regression acceptance still PENDING at this preparation commit. [Design/limits](../deploy/content-0.9.0-stage1.1/README.md).

## Content Agent Stage 1 accepted — 2026-11-10 18:53:33 UTC

**PASS for the authorized no-GPU/no-LLM preparation and staging mock acceptance.** This does not accept a real home-PC/LLM publishing pipeline. Branch: `feat/cyberdat-content-agent-0.9.0`. Runtime base `727b56be04f590e65ca7b967838cd753ef38b8f9` plus menu fix `e045209582fb3eb1d48a82e7ed350502f753294f`. Backup: `/var/backups/cyberdat-staging/content-0.9-20261110T181827Z`.

Implemented: separate Content plugin/tables, read-only selected-evidence adapter, all requested queue statuses, versioned JSON drafts, audit, deduplication, leases/retry, capability/nonce/revision checks, five English templates, traceability/structure/CVE checks and an outbound HTTPS Python mock worker. Mock-only is enforced on both sides; drafts never enter WordPress posts. Research collection remains independent of LLM. No source, collector or timer changes.

Owner-confirmed: 25 Content TEMPORARY-table checks, existing Research tests, 11 discovery checks, read-only handoff with zero real selected items, one actual authenticated HTTPS mock worker cycle on VPS, and one saved TEST job 1 / version 1 in `draft_ready`. Offline 12-suite batch and three installed-core menu lifecycle cases pass. The menu-order continuation patched only Content admin registration priority and completed acceptance without reinstall, migration or another mock run.

Content Queue and Research Queue return HTTP 200 after the existing admin login. Worker key denial 403, anonymous protection 401, noindex, existing public routes, SQL Dashboard comparison and checked logs pass. WordPress posts remain 61. Research/timer/config/theme fingerprints unchanged; production not modified. Observed versions: WordPress 7.1.4, PHP 8.4.27. [Final evidence and architecture](../deploy/content-0.9.0/README.md).

**UNVERIFIED:** actual home-PC worker/Windows ACL, existing Ollama availability/models/GPU presence, real browser Content Queue interaction and real-model factual/injection quality. These were not run; no model was loaded/downloaded and no home connection or public Ollama port was configured. Next steps require separate authorization; work stops after Stage 1. Research 0.8.2's older PARTIAL limitations remain historical facts, not silently resolved by Content work.

## Content Stage 1 installation continuation (history) — 2026-11-10

Owner deployment created backup `/var/backups/cyberdat-staging/content-0.9-20261110T181827Z` and installed the standalone Content plugin/schema. PASS: 25 Content temporary-table checks, existing Research/discovery integration tests, read-only handoff (`selected_count=0`), actual HTTPS mock worker claim/submission and saved TEST job 1/version 1. No real Research selection or model run.

The final smoke test stopped at the Content Queue admin page. Confirmed menu registration order bug: at priority 10, Content's submenu may be registered before Research's parent, causing WordPress to record/check different hook names. A focused installed-core lifecycle test reproduces the bug; priority 20 for the Content submenu passes both loading orders and preserves unauthorized denial. A one-file finish controller is prepared; live admin/protection/regression completion remains PENDING. Original runtime commit `727b56be04f590e65ca7b967838cd753ef38b8f9`; no reinstall, migration, fixture generation or collector/timer changes are required for continuation.

## Content Agent 0.9.0 — Initial preparation (history), 2026-11-10

The owner's new specification authorizes Content Queue and mock worker preparation; older statements that Content work is not authorized are historical. Research remains partially accepted with documented source/coverage limits; no collector, source, timer, public design, Analytics or SEO change is part of this stage.

Architecture analysis completed: Research's private CLI handoff is read-only, limited to editor-selected unchanged evidence. A separate staging-only Content plugin adds isolated queue/version/audit/worker tables, capability/nonce/revision-protected human transitions, a private authenticated HTTPS pull endpoint and a standard-library Python worker. Mock-only is enforced by both sides; real research jobs cannot be generated. Drafts live outside WordPress posts, with no publication operation. Five English editorial templates, evidence traceability, known-CVE and structure checks are prepared; semantic truth still requires human review.

Offline implementation/tests are prepared. Staging backup, additive schema, temporary-table integration tests and the exact worker's mock HTTPS round trip remain **PENDING** until owner-run acceptance succeeds. Home-PC transport, existing Ollama/model inventory and GPU presence are **UNVERIFIED**; no accessible home address/private connection was configured. No model was downloaded or run.

See [Stage 1 architecture and deployment](../deploy/content-0.9.0/README.md). Work is on a dedicated Content feature branch based on final Research status `b8807a0bc140a0792b6d6c4f08552331c885a0ca`. No production change.

## Final stabilization acceptance — 2026-11-10 17:44:28 UTC

**PARTIAL; runtime deployment and bounded integration/regression checks PASS.** 29/45 channels have real persisted records (12 new); 8 BLOCKED and 8 UNSUPPORTED have specific reasons in the [final stabilization report](../deploy/research-0.8.2/stabilization-2026-11-10.md).

Runtime commit: `411341bf67d3717ad4de8c054ec0d141109767b4`.
Branch: `feat/cyberdat-research-agent-0.8.1`.
Backup: `/var/backups/cyberdat-staging/research-stabilization-20261110T171824Z`.

Latest proof: **552 discovery publications** (News 87, Technical Research 294, Papers 171), zero duplicate source-ID groups, Dashboard SQL match, all six timers active. KEV: 1773. NVD: 3688, HTTP 200 success **17:40:40 UTC**, error cleared, cursor 100, completed checkpoint **10:19:05 UTC** preserved. The bounded window and historical coverage remain partial. Crossref automatic progress from 129 to 134 to 150 records, cursor 175 to 200 to 225, proves scheduled continuation after deployment; no manual sync was run.

Sophos remains at zero records with `transport` and advanced retry/backoff state; it is not CONNECTED. Low-level errno was not persisted, so the exact cause is UNVERIFIED. First 4h/24h recurrence of every new source, long-term load/growth and whole-corpus classification/grouping precision remain UNVERIFIED. No further deployment was performed for observation. Real SAP merge/split/merge and preservation of both publications PASS. Derived metadata was updated for 327 records while preserving manual decisions and source dates; no LLM was used.

Resources during deployment: load 0.26, available RAM 2.04 GiB, Research tables 32.41 MiB; this was not a stress or long-term test. Research Queue login, capability/nonce fixtures, SQL Dashboard, protected routes and unchanged public theme/Analytics/config/timers PASS. No automatic publication or production changes. Work stops with documented limitations; Content/Social/Ollama and subsequent stages were not started.

### Previous observations (history)

## Latest observation — 2026-11-10 17:28:11 UTC

**PARTIAL.** Post-deployment Crossref recurrence confirmed: success17:20:09 UTC, count129→134, cursor175→200. Discovery total now536 (News87, Research294, Papers155); duplicate source IDs0; SQL Dashboard matchtrue; six timers active.

**NVD current error** `nvd_pagination_changed` at17:25:08; last success17:15:37, 3688 records. Unchanged collector detects different totalResults for the same window and restarts only the page ledger/cursor (now0), preserving completed checkpoint10:19:05 UTC and all stored records. Old/new totals were not logged. Retry due17:30:08. No 429 evidence or collector change. Sophos0/transport has not yet retried; oldest-due NVD consumed17:25 cycle. 29 CONNECTED means proven persistence, not all currently healthy. Await one later read-only retry observation; no manual sync/redeploy. See [observation evidence](../deploy/research-0.8.2/stabilization-observation-2026-11-10.json).

## Stabilization deployed — 2026-11-10 17:19:50 UTC

**Overall PARTIAL; staging deployment/integration/protection checks PASS.** Runtime commit `411341bf67d3717ad4de8c054ec0d141109767b4`, branch `feat/cyberdat-research-agent-0.8.1`. Backup `/var/backups/cyberdat-staging/research-stabilization-20261110T171824Z`.

**29/45 channels** now have real persisted records (12 newly connected); 8 BLOCKED and 8 UNSUPPORTED have explicit reasons. Sophos staging transport error remains in normal backoff/retry; no weakened fetch protection. Three discovery streams: News 87, Technical Research 294, Papers 150 (**531** total), zero duplicate source IDs. Full channel reasons and evidence: [stabilization record](../deploy/research-0.8.2/stabilization-2026-11-10.md).

NVD recovered automatically: 3688 records, HTTP 200 last success 17:15:37 UTC; checkpoint 10:19:05 UTC, pending cursor600. KEV1773 verified 17:18:32 UTC. Healthy-overdue dispatcher gap fixed without timer or collector changes. v2 classification derivations applied to 327 records, preserving manual decisions/source dates; this does not mean 327 labels were wrong. Real SAP publication merge/split/merge PASS; publications retained. Two correlated topics exist, only the named SAP pair has a documented real-event evidence review.

SQL Dashboard, existing Research Queue login, Basic Auth/noindex, unchanged public theme/Analytics/config/timers and no post publication PASS. Prior Edge admin/browser checks remain valid for unchanged UI. Resources modest (load0.26, available RAM2.04GiB, Research tables32.41MiB); long-term growth/load UNVERIFIED. Crossref/news recurrence observed; first post-deployment cycles of newly added long-interval feeds and Sophos recovery remain UNVERIFIED. Production not modified. No Content/Social/Ollama started.

## Earlier verified staging state (history) — 2026-11-10

**Research Agent 0.8.2: PARTIAL.** Controlled live ingestion and all database integration tests completed successfully on staging. Persisted: 50 news, 120 technical research records and 42 papers (21 arXiv + 21 Crossref), across 12 new sources. Five existing collectors remain healthy; public Dashboard matches SQL and protected theme/Analytics/config/timer hashes are unchanged. No automatic publication or production change.

Actual all-source queue: 5684 records at 2026-11-10T15:34:31Z; no duplicate source-ID groups. 212 discovery topics, zero multi-publication live groups in this batch; grouping is fixture-tested, not falsely claimed demonstrated on real related stories.

Backup: `/var/backups/cyberdat-staging/research-0.8.2-20261110T151206Z`. Runtime release `ec8be39b8210580e201b4a4ac8956fc4be3f2bb8` with orchestration/fixture continuation commits documented in [acceptance evidence](../deploy/research-0.8.2/acceptance-2026-11-10.md).

Still UNVERIFIED: real new-source scheduled recurrence, browser interaction with the expanded admin UI, long-term load. 28 other source channels remain blocked/disabled, including OpenAlex/Semantic Scholar and unverified conference endpoints. No Content Agent, Social Agent, n8n or LLM started.

## Preparation history — current authorized specification, 2026-11-10

The owner's Research Agent 0.8.2 specification supersedes the older stage numbering below. This phase extends Research Agent only; Content Agent, Social Agent, n8n and LLM workflows are not authorized.

Verified preparation:
- Read this document from `main` and inspected the existing 0.8.1 collectors, secure client, store, queue, audit and dispatcher.
- Working branch: `feat/cyberdat-research-agent-0.8.1`; baseline `e6744f179d7d31ed62f0116fca5d1387b4fe8ad9`.
- New source catalog, metadata parsers, deterministic classification, topic correlation, academic identifiers, queue/registry admin and additive table migration prepared locally.
- Real public endpoint/parser verification includes news, technical research, arXiv and Crossref. This is NOT staging persistence or ACTIVE-source evidence.
- Offline discovery and existing Research/Threat Pulse/Dashboard/Analytics regression tests pass.
- Staging database fixture tests, live persistence, actual source counts, deployment, resource impact and scheduled recurrence remain UNVERIFIED until owner-run privileged verification completes.
- Owner-run staging application on 2026-11-10 created `/var/backups/cyberdat-staging/research-0.8.2-20261110T151206Z` and exchanged the plugin code, then stopped at the first migration command. The deploy script used hyphens while the actual WP-CLI registers underscore subcommand names. No discovery source was enabled by this run.
- A tested resume-only launcher corrects those two command names in memory, preserving the original pinned bundle and backup. Staging database integration and live acceptance remain unverified. No production or timer changes.
- Threat Analytics UX 2.1 currently works in supplied browser checks. Earlier intermittent absence of the period model remains unexplained; not claimed fixed by this phase.

See [Research Agent 0.8.2](../deploy/research-0.8.2/README.md) for source catalog, limitations and staged acceptance procedure.

Next concrete action: execute the prepared staging-only, backup-first deployment through the owner's interactive sudo session, then inspect its safe evidence. Do not label 0.8.2 complete before all mandatory streams persist real records and queue/scheduler checks pass.

## Historical status before the new 0.8.2 specification (user-confirmed)
- VPS / WordPress / infrastructure: completed.
- Base SEO stage 0.7: completed.
- Research Agent stage 0.8.1: **NOT completed**. Current task is to further configure the Research Agent to **collect source articles and cybersecurity news/materials**, not just CVE records.
- Content Agent stage 0.8.2: not started / awaiting Research Agent completion.
- Social Agent: planned, not started.
- Threat Intelligence Dashboard and browser-based Tools: planned extensions; do not distract from current stage.

## Current work: Research Agent
Goal: reliably collect relevant source articles and news for editorial processing.
Remaining tasks to validate and implement:
- Review existing n8n/Research Agent workflows and source integrations before modifying anything.
- Ingest full article content where lawful/available, along with title, source URL, publisher, publication date, summary and attribution; preserve links to originals.
- Deduplicate stories; categorize and prioritize; handle fetch failures and missing data.
- Queue structured research items for future Content Agent.
- Test with real samples; inspect logs and ensure staging changes do not accidentally publish to production.
- Keep human approval mandatory for all published content.

## Project architecture / constraints
- CyberDat.eu: English-language cybersecurity news, analysis, Guides, Learning, Threat Intelligence and Tools.
- WordPress on VPS; custom lightweight dark theme; GitHub + CI/CD; staging -> production; backups and MFA.
- Research Agent -> Content Agent (local Ollama) -> Social Agent -> human approval before publication.
- Future tools: see the approved Stage 0.9 roadmap below. Sensitive user inputs must be processed client-side with privacy tests.
- Future threat dashboard: CISA KEV, NVD, FIRST EPSS, interactive filtering and local JSON upload.
- Prioritize one task at a time; avoid expanding MVP prematurely.

## Approved future roadmap — Stage 0.9: AI Security & Security Tools
Status: **PLANNED; not started**. Do not move from Research Agent 0.8.1 until the current editorial-agent work is completed and confirmed.

Execution order:
1. **0.9.1 Log Anonymizer** — `/tools/log-anonymizer`: browser-side redaction of logs/secrets; clearly warn that detection is not exhaustive.
2. **0.9.2 Indirect Prompt Injection Payload Sanitizer & Detector** — `/tools/prompt-sanitizer`: client-side signature checks for role spoofing and suspicious instructions; bounded Base64/hex/zero-width/spacing normalization; show findings and allow reviewable sanitization. Untrusted-content delimiters are not a security guarantee; avoid claiming fully safe automatic sanitization. SEO topics: online prompt injection sanitizer, sanitize logs for LLM, RAG prompt injection detector.
3. **0.9.3 Living off the Land Command Analyzer** — `/tools/lolbas-analyzer`: static PowerShell/Bash analysis; do not execute submitted commands; cite LOLBAS and relevant references.
4. **0.9.4a System Prompt & Agent Leak Inspector** — `/tools/agent-leak-inspector`: five-dimension heuristic review (prompt exposure, instruction hierarchy, jailbreak resilience, structured-output boundaries, tool/data isolation) and 10 locally generated adversarial test ideas for authorized systems. Do not present a heuristic score as proven resilience or send sensitive system prompts to third parties. SEO topics: system prompt security audit, test system prompt leakage, LLM jailbreak analyzer.
5. **0.9.4b MCP Security & Policy Checker** — `/tools/mcp-security-checker`: static analysis of MCP configuration/manifests and tool descriptions, risky shell/tool permissions, wildcards and overly broad access; suggest least-privilege patches with manual review. Static checks cannot prove absence of RCE or privilege escalation. SEO topics: MCP security audit, model context protocol security, AI agent manifest validator.
6. **0.9.5 OT / IoT Dork Helper** — `/tools/ot-dork-helper`: authorized perimeter audit query helper for Shodan/Censys, without facilitating indiscriminate targeting of exposed industrial systems.

Shared acceptance requirements:
- Separate indexable tool URLs with useful explanations, examples, internal links and accurate structured metadata.
- Process pasted prompts, logs and manifests locally in the browser; no telemetry of submitted sensitive content; test privacy claims.
- Versioned rules, transparent limitations, safe input/output handling, bounded parsing and tests with benign/adversarial fixtures.
- Copy/export where appropriate, mobile and keyboard accessibility, CI/CD checks, human review before deployment.
- No user-supplied code/commands executed as part of static inspection.

## Historical next action (superseded by the current specification)
Inspect the current Research Agent implementation/workflow and identify why it is not yet collecting article content. Then configure and test one source end-to-end.

## Session log
- 2026-11-09: Approved three additional AI Security tools and Stage 0.9 execution order; planning only, no implementation started.
- 2026-11-09: User corrected project status: work is still on Research Agent 0.8.1, specifically configuring article/news collection. Established this status document to avoid outdated roadmap assumptions.

## End-of-session update template
Date:
Stage:
Completed and tested:
Changes / commit / workflow:
Issues / blockers:
Next single action:


## Continuation — 2026-11-10: discovery fixture evidence

The owner confirmed additive schema version 1 and successful legacy temporary-table integration tests. The new discovery suite passed idempotency, canonical aliases, event preservation, independent-CVE separation and manual classification retention, then correctly rejected a stale fixture hash (`source_changed_reload`). The fixture had cached its hash before restoring the original source ID after an alias test.

Fix scope: refresh the fixture hash before positive approval and explicitly retain the negative stale-form rejection test. Runtime evidence/hash checks are unchanged. Resume snapshots the previous fixture under the existing private backup and updates that one test file with exact old/new checksum checks. No source was enabled; the diagnostic reported real queue count 5472 both before and after. Remaining tests/live persistence are still UNVERIFIED until resume succeeds.

## Subsequent scheduler/browser evidence — 2026-11-10

At 15:46:22 UTC, the read-only observer showed Crossref had automatically advanced 21→44 records and offset 25→50, with last success 15:45:10 UTC matching the dispatcher timer's 15:45:03–15:45:11 run. One new-source automatic continuation is therefore confirmed; recurrence of all sources remains unverified. Scientific records increased to 65, total discovery records to 235, with zero duplicate source-ID groups. NVD separately reported a transport error with backoff; no checkpoint reset was performed.

The owner-run Edge check passed login, all three stream filters, source HTTPS links, scientific metadata presence, Crossref DOI search, pagination and a 45-row Source Registry. Zero runtime JS exceptions; ten network console entries were all `secure.gravatar.com / net::ERR_BLOCKED_BY_CLIENT`, produced by the test harness's deliberate external-resource blocking. No external avatar access is enabled by the correction.

A genuine admin-layout overflow was detected at 768 px (not at 320 px). A scoped Research Queue/Source Registry stylesheet and asset hook are prepared and offline-tested, with backup-first staging patch and browser recheck still pending. The public theme/Analytics are not modified. Overall remains PARTIAL until admin layout verification completes and remaining limitations are recorded.

## Admin asset delivery continuation — 2026-11-10

Owner-run admin UI update created `/var/backups/cyberdat-staging/research-admin-ui-20261110T160728Z`, then failed CSS HTTP verification. Read-only inspection confirmed the newly created plugin `assets` directory was mode 0700: explicit mkdir mode 0755 had been narrowed by the controller's umask 077. Existing Nginx rules do not deny this CSS path. The dedicated public stylesheet directory must be 0755 for Nginx traversal; private paths remain unchanged.

A pinned continuation validates the existing backup/release, directory owner, sole CSS file and exact hashes, records previous mode privately, changes only this directory to 0755, then runs existing UI verification. It does not reapply code, migrate data, alter sources/timers or change production. Verification and browser layout acceptance remain pending.

## Owner-confirmed browser acceptance — 2026-11-10

The admin asset permission continuation passed: only the dedicated public CSS directory changed to 0755; existing administrator login/Research Queue HTTP 200, unchanged public theme/other Research code/protected configuration/timers and production HTTPS 200 were verified. UI backup: `/var/backups/cyberdat-staging/research-admin-ui-20261110T160728Z`.

The updated Windows Edge run completed PASS. Confirmed: News/Research/Papers filters, bounded rows, HTTPS source links, scientific metadata presence, actual Crossref DOI search, server pagination, 45 Source Registry rows, and no recorded horizontal overflow at 768/320 px. No unexpected console errors or runtime exceptions; deliberately harness-blocked Gravatar avatars remain separately classified, without enabling external requests. Login succeeded and Threat Pulse 2.1 served its valid period model.

Screenshots/report: `C:\Users\CyberDat\CyberDat-research-0.8.2-browser-20261110T161210Z`. Automated browser checks passed; screenshots have not been independently visually reviewed here. The helper did not change editorial statuses, classifications, event groups or source settings. Those write operations are database/capability/nonce fixture-tested, not real-browser mutation-tested.

Controlled MVP ingestion and read-only browser acceptance: PASS. Overall phase remains PARTIAL: 17 working channels versus 45 configured; blocked academic/vendor channels remain explicit, only Crossref automatic continuation has been observed for the new sources, long-term load and complete historical coverage are not claimed. No subsequent agent phase started.

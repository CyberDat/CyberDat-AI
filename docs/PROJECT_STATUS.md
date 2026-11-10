# CyberDat — Project Status (source of truth)

Last updated: 2026-11-10
Repository: CyberDat/CyberDat-AI
Current stage: **0.8.2 — Research Agent: news, technical research and scientific discovery (IN PROGRESS)**

## Important rule
Before planning the next CyberDat task, read this file and relevant repository code. Do not infer completion from an older conversation or from a roadmap. Mark tasks complete only after confirmation/testing. Update this file at the end of each work session.

## Latest verified staging state — 2026-11-10

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

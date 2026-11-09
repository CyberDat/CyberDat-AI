# CyberDat — Project Status (source of truth)

Last updated: 2026-11-09
Repository: CyberDat/CyberDat-AI
Current stage: **0.8.1 — Research Agent (IN PROGRESS)**

## Important rule
Before planning the next CyberDat task, read this file and relevant repository code. Do not infer completion from an older conversation or from a roadmap. Mark tasks complete only after confirmation/testing. Update this file at the end of each work session.

## Confirmed progress (user-confirmed)
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

## Next concrete action
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

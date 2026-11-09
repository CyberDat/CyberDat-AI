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
- Future tools: Log Anonymizer first, then LotL Analyzer and OT Dork Helper; sensitive user inputs processed client-side with privacy tests.
- Future threat dashboard: CISA KEV, NVD, FIRST EPSS, interactive filtering and local JSON upload.
- Prioritize one task at a time; avoid expanding MVP prematurely.

## Next concrete action
Inspect the current Research Agent implementation/workflow and identify why it is not yet collecting article content. Then configure and test one source end-to-end.

## Session log
- 2026-11-09: User corrected project status: work is still on Research Agent 0.8.1, specifically configuring article/news collection. Established this status document to avoid outdated roadmap assumptions.

## End-of-session update template
Date:
Stage:
Completed and tested:
Changes / commit / workflow:
Issues / blockers:
Next single action:

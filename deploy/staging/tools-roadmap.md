# CyberDat — approved Tools Roadmap

Superseded on 2026-11-11 by the owner's "CyberDat Tools" specification v1.0 (replaces the 0.7 list and roadmap v2.1).
Release 1.1 is shown on `/tools/`; later releases stay in the catalogue data only. A tool is listed as Available only
when its page passes the fail-closed readiness check.

| Release | Phase | Tool | Permanent URL | Status |
|---|---|---|---|---|
| 1.1 | 1 | Privacy Shield Log Anonymizer | `/tools/log-anonymizer/` | implemented, owner acceptance pending |
| 1.1 | 1 | Indirect Prompt Injection Sanitizer & Detector | `/tools/prompt-injection-detector/` (proposed, confirmed at owner acceptance) | implemented, owner acceptance pending |
| 1.1 | 1 | LotL / LOLBAS Command Analyzer | `/tools/lolbas-analyzer/` | planned |
| 1.2 | 2 | MCP Security & Policy Checker | `/tools/mcp-security-checker/` | planned |
| 1.2 | 2 | System Prompt & Agent Leak Inspector | `/tools/agent-leak-inspector/` | planned |
| 1.2 | 2 | AI Model Bill of Materials | `/tools/ai-model-bom/` | planned |
| 1.2 | 2 | MITRE ATLAS Attack Vector Mapper | `/tools/mitre-atlas-mapper/` | planned |
| 1.3 | 3 | LLM Prompt Injection Test Bench | `/tools/prompt-injection-test-bench/` | planned (prompt generation only, no paid API calls) |
| 1.3 | 3 | YARA/Sigma Rule Validator & Converter | `/tools/yara-sigma-validator/` | planned |
| 1.3 | 3 | Docker & Kubernetes Hardening Audit Generator | `/tools/container-hardening-audit/` | planned |

Backlog (not started, not planned without an owner decision): Modbus/BACnet Frame Decoder, IoT & Industrial
Exposure Query Helper, Security Webhook & OOB Listener. Their 0.7 draft pages (`/tools/modbus-decoder/`,
`/tools/iot-exposure-query-builder/`, `/tools/webhook-oob-listener/`) may still exist as unpublished drafts on staging.

## Page contract

Each tool has its own native hierarchical WordPress Page and permanent URL, with server-rendered HTML. Utility first, followed by How It Works, Technical Documentation, Examples & Use Cases, FAQ, optional GitHub Source Code when published, and Related Tools / Guides. Aim for 300–500 useful expert words without padding. No SPA-only content or duplicate archive is introduced.

0.7 creates drafts only; no tool is functional. A reviewed implementation callback and populated editorial fields are required before publication. The directory remains noindex and outside sitemap while no tools are ready. Unfinished routes return a real 404 to guests, not a fake working interface. Draft previews are for authorized editors only.

## Privacy and future implementation

Process sensitive input in the client wherever feasible. Modbus may later add BACnet support. The Webhook & OOB Listener needs a separately approved secure backend, abuse controls, retention rules and isolation; it must not be implemented as an unrestricted WordPress endpoint. Future open-source algorithm cores need tests, explicit licenses and no secrets before publication under CyberDat on GitHub.

Traffic strategy: tool-based search 50–60%, direct/bookmarked 20–30%, other channels 10–30%. These are strategic targets, not guaranteed forecasts or measured results.

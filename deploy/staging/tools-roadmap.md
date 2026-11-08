# CyberDat — approved Tools Roadmap

Approved by the owner for the 0.7 architecture stage. All tools below are planned, not released.

| Release | Phase | Tool | Permanent URL |
|---|---|---|---|
| 1.1 | 1 | Privacy Shield Log Anonymizer | `/tools/log-anonymizer/` |
| 1.1 | 1 | IoT & Industrial Exposure Query Helper | `/tools/iot-exposure-query-builder/` |
| 1.1 | 1 | LotL / LOLBAS Command Analyzer | `/tools/lolbas-analyzer/` |
| 1.2 | 2 | LLM Prompt Injection Test Bench | `/tools/prompt-injection-test-bench/` |
| 1.2 | 2 | Modbus/BACnet Frame Decoder | `/tools/modbus-decoder/` |
| 1.2 | 2 | Docker & Kubernetes Hardening Audit Generator | `/tools/container-hardening-audit/` |
| 1.2 | 2 | AI Model Bill of Materials (A-BOM) | `/tools/ai-model-bom/` |
| 1.3 | 3 | YARA/Sigma Rule Validator & Converter | `/tools/yara-sigma-validator/` |
| 1.3 | 3 | MITRE ATLAS Attack Vector Mapper | `/tools/mitre-atlas-mapper/` |
| 1.3 | 3 | Security Webhook & OOB Listener | `/tools/webhook-oob-listener/` |

## Page contract

Each tool has its own native hierarchical WordPress Page and permanent URL, with server-rendered HTML. Utility first, followed by How It Works, Technical Documentation, Examples & Use Cases, FAQ, optional GitHub Source Code when published, and Related Tools / Guides. Aim for 300–500 useful expert words without padding. No SPA-only content or duplicate archive is introduced.

0.7 creates drafts only; no tool is functional. A reviewed implementation callback and populated editorial fields are required before publication. The directory remains noindex and outside sitemap while no tools are ready. Unfinished routes return a real 404 to guests, not a fake working interface. Draft previews are for authorized editors only.

## Privacy and future implementation

Process sensitive input in the client wherever feasible. Modbus may later add BACnet support. The Webhook & OOB Listener needs a separately approved secure backend, abuse controls, retention rules and isolation; it must not be implemented as an unrestricted WordPress endpoint. Future open-source algorithm cores need tests, explicit licenses and no secrets before publication under CyberDat on GitHub.

Traffic strategy: tool-based search 50–60%, direct/bookmarked 20–30%, other channels 10–30%. These are strategic targets, not guaranteed forecasts or measured results.

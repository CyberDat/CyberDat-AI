# OWASP 2026 — sources, 2025 → 2026 mapping and CyberDat AI tools

Checked on 2026-11-27 against the official OWASP GenAI Security Project sources. IDs and titles below are copied
from those sources, not reconstructed.

## Sources

| What | Official source |
|---|---|
| OWASP Top 10 for LLM Applications 2026 (publication) | https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/ |
| Canonical Markdown source (one file per entry) | https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2026/final |
| Citation metadata | https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/blob/main/CITATION.cff |
| What changed against 2025 | `2026/final/LLM00_Preface.md`, section "What's New in the 2026 Top 10" |
| OWASP Top 10 for Agentic Applications 2026 | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ |
| Agentic IDs and titles as used by the LLM list | `2026/final/mappings/asi-2026.json` in the canonical repository |
| 2025 list (archived) | https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/tree/main/2_0_vulns |

- **Release date:** `CITATION.cff` (`date-released: 2026-08-04`) and the repository README ("published August 4,
  2026") give 4 August 2026. The resource page on genai.owasp.org shows "August 3, 2026". This document uses the
  repository date.
- **License:** CC BY-SA 4.0 (`CITATION.cff`: `license: CC-BY-SA-4.0`; the site footer: "Creative Commons
  Attribution-ShareAlike v4.0").
- **The old repository** `OWASP/www-project-top-10-for-large-language-model-applications` is marked as a legacy
  archive since commit `dc801d2` (2026-08-05) and points to the active repository.
- **Agentic Top 10 2026:** published on 9 December 2025 (resource page; `asi-2026.json`: "2026 (announced
  2025-12-09)"); site license CC BY-SA 4.0.

## OWASP Top 10 for LLM Applications 2026

| ID | Title | Canonical file |
|---|---|---|
| LLM01:2026 | Prompt Injection | `LLM01_PromptInjection.md` |
| LLM02:2026 | Sensitive Information Disclosure | `LLM02_SensitiveInformationDisclosure.md` |
| LLM03:2026 | Excessive Agency | `LLM03_ExcessiveAgency.md` |
| LLM04:2026 | Supply Chain | `LLM04_SupplyChain.md` |
| LLM05:2026 | Data and Model Poisoning | `LLM05_DataModelPoisoning.md` |
| LLM06:2026 | Unbounded Consumption | `LLM06_UnboundedConsumption.md` |
| LLM07:2026 | Misinformation | `LLM07_Misinformation.md` |
| LLM08:2026 | Hidden Context Exposure | `LLM08_HiddenContextExposure.md` |
| LLM09:2026 | Vector and Embedding Weaknesses | `LLM09_VectorAndEmbeddingWeaknesses.md` |
| LLM10:2026 | Improper Output Handling | `LLM10_ImproperOutputHandling.md` |

## OWASP Top 10 for Agentic Applications 2026

| ID | Title |
|---|---|
| ASI01 | Agent Goal Hijack |
| ASI02 | Tool Misuse & Exploitation |
| ASI03 | Identity & Privilege Abuse |
| ASI04 | Agentic Supply Chain Vulnerabilities |
| ASI05 | Unexpected Code Execution (RCE) |
| ASI06 | Memory & Context Poisoning |
| ASI07 | Insecure Inter-Agent Communication |
| ASI08 | Cascading Failures |
| ASI09 | Human-Agent Trust Exploitation |
| ASI10 | Rogue Agents |

Titles are as in `asi-2026.json`. That file notes title variants: the announcement uses the short form "Tool Misuse"
for ASI02.

## 2025 → 2026

All ten 2025 entries continue in 2026. According to "What's New in the 2026 Top 10", nothing was split, merged into
another entry, dropped or added. Entries were re-ranked, one was renamed, and four grew in scope ("We folded newer,
sharper risks into the entries that already own them").

| 2025 | 2026 | Change (official wording in quotes) |
|---|---|---|
| LLM01:2025 Prompt Injection | LLM01:2026 Prompt Injection | Rank kept; scope grew: "Prompt Injection now covers cross-modal attacks, the kind that hide instructions inside an image or an audio track." |
| LLM02:2025 Sensitive Information Disclosure | LLM02:2026 Sensitive Information Disclosure | Rank kept ("held second") |
| LLM03:2025 Supply Chain | LLM04:2026 Supply Chain | Moved 3 → 4; scope grew: "now accounts for the trust failure when a promoted model artifact is not what it claims to be." |
| LLM04:2025 Data and Model Poisoning | LLM05:2026 Data and Model Poisoning | Moved 4 → 5; scope grew: "now absorbs fine-tuning subversion." |
| LLM05:2025 Improper Output Handling | LLM10:2026 Improper Output Handling | Moved 5 → 10 ("fell the furthest"); scope grew: "now spans the insecure code that assistants generate at scale." |
| LLM06:2025 Excessive Agency | LLM03:2026 Excessive Agency | Moved 6 → 3 ("the most consequential move on the list") |
| LLM07:2025 System Prompt Leakage | LLM08:2026 Hidden Context Exposure | Renamed and broadened: "What used to be System Prompt Leakage is now Hidden Context Exposure, a broader framework for the same failure to trust information that should have stayed out of reach." |
| LLM08:2025 Vector and Embedding Weaknesses | LLM09:2026 Vector and Embedding Weaknesses | Moved 8 → 9 |
| LLM09:2025 Misinformation | LLM07:2026 Misinformation | Moved 9 → 7 |
| LLM10:2025 Unbounded Consumption | LLM06:2026 Unbounded Consumption | Moved 10 → 6 ("rose four places") |

LLM08:2026 counts the system prompt, developer instructions, retrieved policy text and the schemas of exposed tools
as hidden context.

## Inventory in the repository (before this change, at 6e5ba9c)

Searched for `LLMxx`, `LLMxx:2025`, "OWASP", "owasp.org", "System Prompt Leakage", "Agentic" and "ASIxx" in the
theme, tests, deploy and docs. Excluded: generated manifests, the Public Suffix List data and the flag SVGs.

| File | Place | Current text | Change |
|---|---|---|---|
| `template-parts/tools/agent-leak-inspector.php` | Sources list | "Background reading: the OWASP Top 10 for Large Language Model Applications (2025), entry “System Prompt Leakage”, by the OWASP GenAI Security Project. It is referenced here by name only; no text is copied." | → 2026, entry LLM08:2026 “Hidden Context Exposure” (by name) |
| `template-parts/tools/{prompt-injection-detector, prompt-injection-test-bench, agent-leak-inspector, mcp-security-checker, mitre-atlas-mapper, ai-model-bom}.php` | Under the version line | no OWASP line | new line "Mapped to OWASP Top 10 for LLM Applications 2026: …" (tool-level, see below); ATLAS Mapper says it maps to MITRE ATLAS and names the official LLM↔ATLAS crosswalk (Appendix A). Names only, no links: the tool pages reference sources by name, and their accepted tests reject links in the tool markup. The URLs are in this document |
| same six templates | Version line | "Engine X · rules Y" / "· CyberDat mapping Y" / "· test library Y" | appended ", updated YYYY-MM-DD" (the date part of the ruleset identifier) |
| `tests/leak-inspector.test.php` | Expected page phrases | "OWASP Top 10 for Large Language Model Applications" | unchanged (the phrase stays on the page) |
| `tests/mcp-checker-engine.test.cjs:114` | Guard | rule texts must not contain `OWASP` or `LLM0\d` | unchanged: the MCP mapping is on the page, not in the rules |
| `tests/fixtures/prompt-injection-detector/benign.json` (ai-07) | Detector corpus (benign text) | "OWASP lists prompt injection as LLM01. …" | unchanged: frozen corpus input; LLM01 is still Prompt Injection in 2026 |
| `assets/js/atlas-mapper/atlas-data.js` | MITRE ATLAS data (MITRE text) | "OWASP Agent Memory Guard", "Agentic AI" | unchanged: third-party data release |
| `assets/js/ai-model-bom/engine.js`, `template-parts/tools/ai-model-bom.php` | Format credit | "OWASP CycloneDX project" | unchanged: CycloneDX, not the LLM Top 10 |
| `deploy/tools-leak-inspector/*`, `deploy/tools-release-1.2/COPY-REVIEW.md` | Historical package records | 2025 "System Prompt Leakage" | unchanged: records of installed packages, not page text |
| `deploy/research-0.8.2/*` | Research source list | "OWASP GenAI" feed | unchanged: Research (out of scope) |

No other places had OWASP references:
- **Rule IDs:** none had an `LLMxx:2025` ID or an OWASP source field.
- **JSON exports:** no export had an OWASP field. The exports already carry the engine version and the ruleset ID
  (`ruleset`; ATLAS `mappingRules`; Test Bench `library`).
- **Tools catalogue:** none in `inc/tools-catalog.json`.
- **Editorial texts:** none in `deploy/*/editorial*.json`.

So no editorial change in the database is needed.

## Tool-level mapping shown on the pages (CyberDat's mapping)

The mapping states which official entries each tool helps with. It does not claim that a tool covers an entry fully;
the coverage limits are in `docs/OWASP-2026-GAPS.md`.

| Tool | OWASP LLM Top 10 2026 | OWASP Agentic Top 10 2026 (related) | Why |
|---|---|---|---|
| Indirect Prompt Injection Sanitizer & Detector | LLM01:2026 | ASI01 | Finds injection patterns in text an LLM or agent will read (indirect injection, hidden text) |
| LLM Prompt Injection Test Bench | LLM01:2026 | ASI01 | Builds injection test documents and checks whether a model followed them |
| System Prompt & Agent Leak Inspector | LLM08:2026, LLM02:2026, LLM03:2026 | ASI01, ASI02 | Leak checks of hidden context and secrets (LLM08, LLM02); audit rules for unconfirmed actions and data sent out by tools (LLM03, ASI02) and external content ranked above the operator's rules (ASI01) |
| MCP Security & Policy Checker | LLM03:2026, LLM04:2026 | ASI02, ASI03, ASI04 | MCP servers as tool supply (LLM04, ASI04); broad tool capabilities and commands (LLM03, ASI02); credentials and privileges in the config (ASI03) |
| MITRE ATLAS Attack Vector Mapper | — | — | Maps to MITRE ATLAS only; the page names the official LLM Top 10 2026 crosswalk to MITRE ATLAS (`2026/final/Appendix_A_Related_Framework_Mappings.md`) |
| AI Model BOM | LLM04:2026 | — | Model, dataset and dependency inventory with license and provenance checks (supply chain) |

## Rule sources (Part 3)

The task asks for a source field on every rule (OWASP 2026 ID, MITRE ATLAS ID or research link) only where the
source is known.

| Tool | Rules | Recorded source |
|---|---|---|
| Prompt Injection Detector | TEXT_RULES (ruleset 2026-11-14.1) | none recorded: CyberDat's own rules |
| Test Bench | test library 2026-11-21.1 | none recorded |
| Leak Inspector | LKI-* (2026-11-24.1) | none recorded |
| MCP Checker | MCP-* (2026-11-13.1) | none recorded; the engine header says "Rules are CyberDat's own wording" |
| AI Model BOM | BOM-* (2026-11-14.1) | none recorded |
| ATLAS Mapper | MAP-* (2026-11-24.1) | each rule's MITRE ATLAS technique IDs, already part of every rule (`techniques`) |

Nothing is invented, so the source is empty for every rule except the ATLAS mapping rules. No field was added to the
rule objects, for two reasons:
- the frozen Codex baseline `tests/tools-stabilization.test.cjs` hashes the Prompt Injection rule descriptors and
  outputs byte for byte;
- `tests/mcp-checker-engine.test.cjs` forbids external IDs in the MCP rules.

An all-empty field would add nothing and would break both. The ruleset ID is date-based (`YYYY-MM-DD.N`). It is in
every JSON export already, and the page now shows "rules ID, updated YYYY-MM-DD".

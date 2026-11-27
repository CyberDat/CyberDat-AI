# OWASP 2026 — what the CyberDat AI tools do not cover (report only)

Report only: nothing here is implemented. The owner decides what, if anything, to build.

The entry descriptions follow the official 2026 texts (`GenAI-Security-Project/GenAI-LLM-Top10`, `2026/final`). For the
Agentic Top 10 2026 only the IDs and titles were read from an official source (`2026/final/mappings/asi-2026.json`),
so the descriptions of the ASI items are kept to what their titles say.

- **Tools in scope:** Prompt Injection Detector (PID), Test Bench (TB), Leak Inspector (LKI), MCP Checker (MCP),
  ATLAS Mapper (ATL), AI Model BOM (BOM).
- **Effort:** S = days, M = 1–2 weeks, L = more than 2 weeks; for one developer, including corpora and tests.
- **"In the browser":** whether the tool can keep its rule that everything runs locally in the tab with no network.

## OWASP Top 10 for LLM Applications 2026

| Entry | What is not covered | Closest tool | Effort | In the browser? |
|---|---|---|---|---|
| LLM01:2026 Prompt Injection | **Cross-modal injection:** the 2026 entry now covers "image, audio, or video content" and "sub-perceptual perturbations in images, audio, or video". PID reads text only. It does not check images (visible text such as OCR, metadata, alt text), audio (transcripts) or perturbations. | PID (text inside images and audio); TB (cross-modal test cases) | Image metadata, alt text and SVG text: S. OCR of visible text: M (a local OCR model has to be bundled; it is large). Audio transcription: L. Adversarial perturbations: not feasible as a rule-based check. | Metadata and SVG: yes. OCR: possible with a bundled WASM model of several MB. Audio: hardly (a speech model of 40 MB or more). Perturbations: no. |
| LLM01:2026 | **Injection through memory, tool output and reasoning traces as separate channels:** PID checks any pasted text, but has no input mode for a whole memory store or agent trace. | PID | S (import formats only) | yes |
| LLM02:2026 Sensitive Information Disclosure | **Disclosure surfaces beyond text:** the entry lists "tool-call arguments, reasoning traces, retrieved chunks, multimodal output, logs, telemetry, embeddings, and observable inference properties". LKI checks prompts and responses; Log Anonymizer masks logs. Embeddings and inference properties (timing, token length, log-probabilities) are not checked. | LKI; Log Anonymizer | Tool-call and trace formats: S–M. Embeddings and side channels: L, and they need runtime data, not a pasted text. | Text formats: yes. Side channels: no (they need a live system). |
| LLM03:2026 Excessive Agency | **Runtime agency:** LKI (prompt audit) and MCP (configuration) find agency written into prompts and configs. Nothing checks what an agent actually did (tool-call logs against a policy). | MCP (policy mode); LKI | M: a tool-call log checker against an MCP policy | yes (pasted logs) |
| LLM04:2026 Supply Chain | **Artifact integrity:** the 2026 scope adds "the trust failure when a promoted model artifact is not what it claims to be". BOM checks declared metadata (licenses, versions, pinning). It does not verify hashes, signatures or file formats of model artifacts (pickle and other unsafe serialisations). | BOM | Signature and hash checks: M. Static scan of model files for unsafe serialisation: M–L. | Hash checks of a file the user selects: yes. Large model files (GBs) are slow in a tab. |
| LLM05:2026 Data and Model Poisoning | **Not covered** (the 2026 scope includes fine-tuning subversion and RAG poisoning). BOM only records dataset provenance. | BOM (provenance); ATL maps described incidents | L. Detecting poisoning needs datasets and model behaviour, not rules on text. | Only small dataset samples |
| LLM06:2026 Unbounded Consumption | **Not covered:** no tool checks rate, token or cost limits. | MCP (policy limits) | S–M: a config check for missing limits (max tokens, timeouts, budgets) | yes |
| LLM07:2026 Misinformation | **Not covered:** the risk is about correctness of model output. | none | L. Not a rule-based browser check. | no |
| LLM08:2026 Hidden Context Exposure | **Broader than LKI's leak check:** the entry covers "extraction, inference, or reconstruction" of hidden context, including retrieved policy text and tool schemas. LKI compares a known prompt with a response (verbatim, encoded). It does not detect paraphrased or inferred reconstruction, and it does not take tool schemas or RAG policy text as a separate "hidden context" input. | LKI | Tool schemas and policy text as extra reference inputs: S. Paraphrase detection: M–L; lexical similarity gives false positives, as the round-12 results show. | Extra inputs: yes. Semantic paraphrase: only with a bundled embedding model (large). |
| LLM09:2026 Vector and Embedding Weaknesses | **Not covered** (similarity search as a trust boundary, RAG access control, cross-tenant leakage). | none (MCP for RAG server configs) | M: a config checker for vector stores (access control, tenancy, metadata filtering) | yes (config text) |
| LLM10:2026 Improper Output Handling | **Partly covered:** PID's sanitized copy helps with HTML and Markdown output. Not covered: the 2026 scope of "insecure code that assistants generate at scale". | PID | Insecure-code patterns in generated code: L (a SAST-like rule set per language) | Small rule sets: yes. A full SAST: no. |

## OWASP Top 10 for Agentic Applications 2026

| Entry (title only) | Current tools | Gap | Effort | In the browser? |
|---|---|---|---|---|
| ASI01 Agent Goal Hijack | PID, TB (injection text); LKI (external content above the operator's rules) | Multi-step agent traces are not analysed as a whole | M | yes |
| ASI02 Tool Misuse & Exploitation | MCP (capabilities); LKI (tool rules) | No runtime tool-call review | M (shared with LLM03) | yes |
| ASI03 Identity & Privilege Abuse | MCP (secrets, credentials in configs) | No check of delegated identities or token scopes beyond the config text | M | yes (config/token metadata) |
| ASI04 Agentic Supply Chain Vulnerabilities | MCP (pinning, sources, name squatting); BOM | No signature or registry verification of MCP servers and tools | M | Registry lookups would need network: no (or a bundled snapshot) |
| ASI05 Unexpected Code Execution (RCE) | MCP (commands in server definitions); LotL Analyzer (command lines) | No check of code an agent generates and runs | L | Partly |
| ASI06 Memory & Context Poisoning | PID (text) | No memory-store import or analysis | S–M | yes |
| ASI07 Insecure Inter-Agent Communication | none | Agent-to-agent message and protocol configs are not checked | M | yes (config text) |
| ASI08 Cascading Failures | none | System-level, needs architecture or runtime data | L | no |
| ASI09 Human-Agent Trust Exploitation | none | Mostly design and UX, not a text pattern | L | no |
| ASI10 Rogue Agents | none | Runtime behaviour monitoring | L | no |

## Candidates

The owner decides. These are the smallest steps that stay inside the browser-only model:

| # | Step | Tool | Effort |
|---|---|---|---|
| 1 | Image and SVG text, metadata and alt-text injection check | PID | S |
| 2 | Tool schemas and RAG policy text as additional "hidden context" references | LKI | S |
| 3 | Missing limits in configs (tokens, timeouts, budgets, rate) | MCP | S–M |
| 4 | Tool-call log review against an MCP policy | MCP | M |

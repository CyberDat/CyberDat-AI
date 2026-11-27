# Package ai-tools-owasp-2026 — AI tools reference the OWASP 2026 editions

This is a delta package over the theme at `6e5ba9c`: the 451 files of `feature/threat-map-1.2`, i.e. after package
threat-map-1.2/1. It is built from branch `feature/ai-tools-owasp-2026`. `manifest.json` lists the base and target
sha256 of every theme file.

The delta changes page text only:

- **1 file added:** `inc/tools-owasp-2026.php`. It holds the official IDs and titles and the tool-level mapping.
- **6 files modified:** the page templates of Prompt Injection Detector, Test Bench, Leak Inspector, MCP Checker,
  ATLAS Mapper and AI Model BOM.
- **No JavaScript file changes.** Engines, rules, masking, JSON exports and the results on the corpora stay
  byte-identical, and the manifest builder stops if any `.js` file differs.

What a visitor sees:

- **Mapping line.** A new line under the version line, for example: "Mapped to OWASP Top 10 for LLM Applications
  2026: LLM01:2026 Prompt Injection. Related: OWASP Top 10 for Agentic Applications 2026, ASI01 Agent Goal Hijack.
  CyberDat's tool-level mapping, referenced by name only; …".
  - There are no links: the tool pages name their sources without links, as before.
  - The ATLAS Mapper page says it maps to MITRE ATLAS and names the official LLM↔ATLAS crosswalk instead.
- **Version line.** It now ends with "· rules updated YYYY-MM-DD". On the ATLAS page the wording is "mapping
  updated"; on the Test Bench page it is "test library updated".
- **Leak Inspector.** Its background reading now cites LLM08:2026 "Hidden Context Exposure" (2026) instead of the
  2025 entry "System Prompt Leakage".

No editorial JSON is needed, because no documentation or FAQ text in the database mentions OWASP. There are no
database, timer or `wp-config.php` changes.

The sources, the 2025 → 2026 table and the inventory are in `docs/OWASP-2026-MAPPING.md`. The list of risks the tools
do not cover is in `docs/OWASP-2026-GAPS.md`.

## Installation (Codex)

1. Back up the theme. Every theme file must equal `manifest.json` → `base` (451 files).
2. Copy the 7 files from `delta_files`, taken from `theme_commit`. Every theme file must then equal `target` (452
   files).
3. Open the six AI tool pages:
   - each shows the OWASP 2026 line;
   - the version line ends with "updated YYYY-MM-DD";
   - the tools work as before;
   - no page loads anything from another host.

## Rollback

Restore the theme from the backup. Every file must equal `base`.

## Tests

- `tests/ai-tools-owasp-2026.test.cjs` runs in CI. It checks that the user-facing texts contain no `LLMxx:2025` IDs
  and no "System Prompt Leakage", and that the IDs and titles match the official tables in the docs.
- The PHP tests of the six tools still check the old version-line prefix "Engine X · rules Y". The prefix is
  unchanged, so they stay valid.
- `tests/ai-tools-owasp-2026-manifest.test.cjs` checks the manifest.

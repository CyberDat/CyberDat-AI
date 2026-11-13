# MCP Security & Policy Checker — release 1.2, tool 4

> **2026-11-13:** this tool is deployed as part of `integration/tools-release-1`. Its own `manifest.json` was replaced by the combined `deploy/tools-release-1/manifest.json`; follow `deploy/tools-release-1/HANDOFF.md`, not the staging steps below.


Branch `feature/tools-mcp-checker` (from `feature/tools-lotl-analyzer` @ `23b8dd5`). Page `/tools/mcp-security-checker/`
(URL from the Stage 0.9 roadmap, confirmed by the owner at acceptance). Not merged, not deployed. The owner allowed
starting this tool before the release 1.1 staging session as a one-time exception.

## 1. Sources and licences (checked 2026-11-12)

| Source | Use | Licence (from the current repository files) |
|---|---|---|
| Model Context Protocol specification, `modelcontextprotocol/modelcontextprotocol` @ `06e9234` (2026-11-12) | Background reading only: client configuration shapes, tool fields (`inputSchema`, `annotations`), and the statement that tool descriptions and annotations should be treated as untrusted (sections “Security and Trust & Safety”, “Tools”). Referenced on the page **by name only**, no text copied, no link. | `LICENSE`: transition from MIT to Apache-2.0; new code and specification contributions Apache-2.0, documentation (excluding specifications) CC-BY-4.0, contributions without relicensing consent remain MIT. |
| MCP documentation in the same repository | Only to compile the short built-in list of well-known package names for look-alike checks (names such as `@modelcontextprotocol/server-filesystem`, `mcp-server-git`). Package names are facts, not copied text. | as above |

Nothing else was used. No OWASP or other rule set, no database, no copyleft data is bundled
(`bundled_third_party_data: none` in `manifest.json`). All rule texts, explanations, fixes and the example policy are
CyberDat's own wording. The tool has no ATT&CK or OWASP mapping.

## 2. Audit and plan (done before implementation)

* Reused framework: renderer filter `cyberdat/tool/renderer`, fail-closed readiness, strict CSP from
  `inc/tool-security.php` (`connect-src 'none'`, `worker-src 'self'`), Web Worker with network APIs disabled,
  `assets/css/tools-common.css`, `tests/lib/synthetic-secrets.cjs`, local WordPress seed.
* The corpus and the held-out set were written and **committed before the engine** (`6a81a5c`).
* Prompt Injection Detector reuse: **not used.** A shared module would mean editing the detector's files and proving
  identical behaviour; the poisoning rules needed here are narrower (descriptions, schema texts, hidden characters,
  cross-server references). The MCP rules are independent; the detector is unchanged (its tests pass as before).
* `/tools/` hub: it lists release 1.1 only (`$current_release = '1.1'` in `page-templates/tools.php`). Showing
  release 1.2 cards is an owner decision, so the hub is unchanged and the catalogue test now asserts it.

## 3. Product and architecture

* **Input**: JSON or JSONC up to 5 MB, several documents one after another. Formats: `mcpServers` (object or array),
  `servers` (VS Code), `mcp.servers` (VS Code settings), `context_servers` (old `command.path` and new shape),
  `mcp_servers`, a single server object, a bare map of servers, tool lists `{"tools": [...]}`, arrays of tools and
  `tools/list` JSON-RPC responses (with `serverInfo.name`). Tool lists inside a server entry (`"tools": [...]`) are
  analysed together with that server.
* **Parser**: own recursive-descent JSON/JSONC reader (`parseDocuments`). Line/column error messages with hints
  (single quotes, unquoted keys, `True/None`, raw line breaks), duplicate-key detection with both lines, 64-level depth
  limit, `__proto__` safe. Nothing is evaluated.
* **Security check**: 50 rules in 8 groups (below). Every finding: rule id, group, severity, server, JSON location with
  line, evidence (masked), explanation, suggested fix. No corrected configuration is generated.
* **Masking**: every secret the engine recognizes is remembered and replaced by `first ≤4 characters…•••• (N characters)`
  in every string that leaves the engine (findings, notes, server summaries, policy results).
* **Policy check**: JSON policy (`version`, `allowed/deniedCommands`, `allowed/deniedPackages`, `requirePinnedVersions`,
  `allowed/deniedHosts`, `requireHttps`, `allowed/deniedPaths`, `allowedTransports`, `allowedEnv`,
  `forbidLiteralSecrets`, `deniedTools`, `allowAutoApprove`, `maxServers`, `maxToolsPerServer`). Validation reports
  unknown settings with a suggestion, wrong types, bad version, wildcards in paths, duplicates. Empty policy → “no
  rules”. Overlapping allow/deny → warning, denied wins. Paths: prefix containment, a path also violates a denied path
  it contains (`/` contains `~/.ssh`), `~` also matches `/home/<n>`, `/Users/<n>`, `C:\Users\<n>`. Globs use a
  linear two-pointer matcher (no regular expressions from user input).
* **Safety**: worker, CSP, `textContent` only, no links are ever created, URLs from the input are never opened, no
  storage; the policy leaves the tab only via “Download policy”. The JSON report contains findings and one-line server
  summaries (masked), not the configuration.

### Rule groups (ids `MCP-<group>-NNN`)

| Group | Rules |
|---|---|
| Secrets (SEC 001–005) | literal secret in env by name; known credential formats anywhere (GitHub, GitLab, Slack, OpenAI, Anthropic, AWS key id/secret, Google, Stripe, JWT, private key, npm, Hugging Face); credentials in URLs (userinfo, query); literal credential headers; secrets as CLI arguments |
| Launch commands (CMD 001–009) | download piped to a shell / `iex`; shell wrapper (info) or chained shell command (medium), encoded PowerShell; unpinned `npx`/`uvx`/`pnpm dlx`/`pipx run` (info since 2026-11-13, owner decision); privileged containers, docker socket, host namespaces, dangerous capabilities; root/home mounts; sudo/doas/runas; executables in temp/downloads; inline code (`node -e`, `python -c`); installs from URL/Git without commit pin |
| File access (FS 001–004) | filesystem root, home directory, credential locations (`.ssh`, `.aws`, `.env`, `/etc`, keychains, MCP configs), wildcards |
| Remote (NET 001–008) | plain HTTP to public hosts (high with credentials), no credentials (info), metadata addresses, tunnels, unusual hosts (raw IP, punycode, capture services, dynamic DNS), uncommon port (info), TLS checks disabled, private-network HTTP (info) |
| Capabilities (CAP 001–008) | command/code execution (high with unrestricted argument), file write/delete (raised by root/sensitive access), arbitrary URL requests, browser automation/JS evaluation, email/messages, unrestricted code arguments, SQL execution, private data + outbound channel combination (high when auto-approved) |
| Poisoning (TP 001–007) | zero-width, bidi and Unicode tag characters (tags decoded for review), instruction overrides, concealment from the user, requests for credentials/private files (also in argument descriptions), hidden markup, rules for other servers' tools, very long descriptions / encoded blobs; combinations raise to high |
| Names (NAME 001–004) | same tool name on several servers, near-identical names, duplicate JSON keys, look-alike package names (short built-in list, no registry access) |
| Hygiene (HYG 001–005) | unpinned images, file server without directories, no timeouts (info), automatic approval (`autoApprove`, `alwaysAllow`, `trust`; high with side-effect tools), very large tool lists |

## 4. Files

New: `inc/tool-mcp-checker.php`, `template-parts/tools/mcp-security-checker.php`, `assets/js/mcp-checker/{engine,worker,app}.js`,
`assets/css/mcp-checker.css`, tests (`tests/mcp-checker-{engine,corpus,browser,xbrowser}.test.cjs`, `tests/mcp-checker.test.php`,
`tests/fixtures/mcp-checker/{corpus,holdout}.json`), `deploy/tools-mcp-checker/{README.md,editorial.json,manifest.json}`.
Shared places: `functions.php` (require), `inc/tools-catalog.json` (status `available`, description), `deploy/staging/tools-roadmap.{json,md}`,
`tests/tools-catalog.test.php` (tool 4 checks, hub still 1.1 only), `tests/local-wp/{compose.yaml,seed.php,up.sh}`.
Files of the three previous tools are unchanged; `tools-common.css` is unchanged.

## 5. Tests (Windows 11, Node 24.14.1, PHP from the pinned WordPress image, offline)

| Suite | Result |
|---|---|
| `mcp-checker-engine.test.cjs` | 24/24: parser errors with line/column, JSONC, duplicates, `__proto__`, depth; all formats; every one of the 50 rules produced by some test input; severity calibration (internal/local servers quiet); references and placeholders are not secrets; masking of every synthetic secret in results and policy results; policy validation (invalid, empty, conflicting), every policy setting, compliant config; glob linearity; 14 ReDoS inputs (each < 2 s); 5 MB tool list (~9,000 tools) in ~0.35 s; static contract (no network/storage/eval/HTML APIs, no look-behind) |
| `mcp-checker-corpus.test.cjs` | metrics below; guards: main detection ≥ 90 %, medium+ FP ≤ 5 % |
| `mcp-checker.test.php` | 50/50 |
| `mcp-checker-browser.test.cjs` (Edge, CDP) | 20/20 |
| `mcp-checker-xbrowser.test.cjs` (Playwright 1.49.1) | Firefox 11/11, WebKit 11/11 |
| `no-token-shaped-strings.test.cjs` | PASS, 433 tracked files; gitleaks 8.21.2 on all new files: 0 findings |
| Regression | Log Anonymizer, Prompt Injection Detector, LotL: engine, PHP and Edge suites pass unchanged; catalogue 36/36 |

Large input: 4.8 MB tool list — Edge 0.3 s, Firefox 0.5 s, WebKit 0.7 s.

## 6. Detection and false positives (honest)

**The corpus and the held-out set were written by the tool author, with the rule groups in mind. The numbers are
optimistic and say little about real-world accuracy.** An independent corpus from the owner would be much more useful.

| Set | Detected (expected group, ≥ expected severity) | Most specific rule | Legit with medium+ | Legit with low+ |
|---|---|---|---|---|
| Main corpus, first run | 50/52 (96.2 %) | 50/52 | 0/40 | 14/40 (35 %) |
| Main corpus, final | 52/52 (100 %) | 52/52 | 0/40 | 14/40 (35 %) |
| **Held-out, first run** | **15/15 (100 %)** | 15/15 | **0/15** | 3/15 (20 %) |
| Held-out, final | 15/15 | 15/15 | 0/15 | 2/15 (13.3 %) |

* Fixes after the first run were general: secret flags of the form `--api-token` (flag name suffix), auto-approval is
  judged after the tools are classified, and `request` in a tool name counts as a web request only in `http_request`-
  like names. The last one also removed a held-out false positive (`create_pull_request`); the held-out output was
  printed together with the main corpus and seen, but no rule was written for it.
* Remaining low findings on legit configurations are intended hygiene advice: unpinned `npx`/`uvx` packages
  (13 of 14; most official examples are unpinned) and `write_file` on a file server (1).

## 7. Interface

English only. Callouts “Local only” and “A review aid, not a guarantee.” Step 1: configuration box, file, example,
clear; mode radio group (Security check / Policy check); policy box with file, example policy, download and a
“Policy settings” reference. Step 2: verdict, summary, findings-by-group table, notes/warnings, one card per server
(sorted by severity) with findings: badge, title, rule id, group, location + line, “Found:” (masked), explanation,
“Suggested fix:”. Export JSON. No-findings verdict: “No known issues matched. This does not mean the configuration is
safe.” Sections: How it works, Privacy, Limitations, Sources. Contrast ≥ 7.59:1; 360/390/768 px without horizontal
overflow; keyboard order text box → file → buttons → mode → Check, arrows switch mode, Ctrl+Enter runs.

## 8. Decisions and conflicts

* `/tools/` lists only release 1.1 → the page is reachable by URL but not linked from the hub until the owner decides.
* Research 404 checks: the Research scripts check every catalogue URL; publishing this page needs the same owner
  decision as for tools 1–3 (`proposed-catalog-404-check.patch` from the detector branch, not applied).
* Stacked branches: this branch contains tools 1–3 and the secret-scanning fix. Merge order stays
  log-anonymizer → prompt-injection-detector → lotl-analyzer → mcp-checker.

## 9. Owner-run staging check (not performed by the agent)

1. Back up the staging site and theme.
2. Fetch `feature/tools-mcp-checker`; verify file hashes against `manifest.json`
   (`git -c core.autocrlf=false archive` gives the LF bytes the hashes refer to).
3. Decide the Research 404 check question before publishing.
4. Create the page `tools/mcp-security-checker` under the `/tools/` hub with the Tool template, paste the fields from
   `editorial.json`, review, set reviewed, publish. Confirm `cyberdat_tool_ready()` is true.
5. Check response headers on the page: CSP with `connect-src 'none'`, `worker-src 'self'`, nonce.
6. Run `node tests/mcp-checker-browser.test.cjs https://<staging>/tools/mcp-security-checker/` and the Playwright
   cross-browser test against the staging URL.
7. Manually: DevTools Network shows no request while checking, exporting or downloading the policy; try Safari and an
   iPhone; paste a real (redacted) configuration of your own and review the findings for noise.

## 10. Remaining limitations

* Text only: no server is started, no package/domain reputation, no code audit; servers can change tools later.
* JSON/JSONC only (no TOML/YAML client configurations).
* Poisoning and secret rules are pattern-based: reworded injections and unusual secrets can be missed; a harmless
  value in a variable named “password” is reported.
* Look-alike package names: short built-in list only.
* Real Safari and iOS not tested (Playwright WebKit on Windows only).

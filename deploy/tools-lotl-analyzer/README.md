# Tools 1.1 — LotL / LOLBAS Command Analyzer

Branch `feature/tools-lotl-analyzer`, created from the tip of `feature/tools-prompt-injection-detector` (`6e95847`). Theme files are pinned in `manifest.json` (theme commit `908ffd1`).

Versions: engine `1.0.0`, CyberDat heuristics `2026-11-12.1`, LOLBAS data `2056cb7662509dc998fc6ce79636aec4e6c0397f` (2026-09-26).

Proposed URL: `/tools/lotl-command-analyzer/` (confirmed by the owner at acceptance). The tool name is unchanged.

**Not deployed.** Merge to `main`, staging and production require explicit owner approval.

## 1. Licences and data source (checked against current repository files, 2026-11-12)

### LOLBAS (used)

- **Repository and commit:** `https://github.com/LOLBAS-Project/LOLBAS`, `main` at `2056cb7662509dc998fc6ce79636aec4e6c0397f`, committed 2026-09-26T09:13:22+01:00 (“Add 'file createnew' command to Fsutil.yml (#525)”).
- **`LICENSE`:** the full text of the GNU General Public License, version 3, 29 June 2007.
- **`NOTICE.md`** says: “The LOLBAS Project is licensed under GPL 3.0.” It also says LOLBAS “is a consumable resource for commercial entities, private entities, and individuals”, and that using it does not imply endorsement.
- **Disclaimers in `NOTICE.md`:** LOLBAS “does NOT claim that detection resources/information … offer complete and proper defensive/analytic coverage”. Detection references and IOCs are not guaranteed to detect the behaviour.
- **ATT&CK in `NOTICE.md`:** MITRE ATT&CK mappings are LOLBAS's own. The notice reproduces the ATT&CK terms of use: “Any copy you make … is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy.” It also quotes the designation “© 2021 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.”
- **Attribution:** no separate data licence and no attribution clause beyond GPL-3.0 itself. GPL-3.0 still requires:
  - keeping the licence and notices;
  - prominent notices of modification with a relevant date (§5a);
  - the GPL-3.0 licence for the work as a whole (§5c);
  - providing the corresponding source to recipients (§6).

### How the tool complies

- **Data file.** `assets/js/lotl-analyzer/lolbas-data.js` is a converted subset of the LOLBAS YAML. Its header states:
  - the source repository, commit and date;
  - the GPL-3.0 licence;
  - “MODIFIED version, converted by CyberDat on 2026-11-12”;
  - exactly which fields were kept and which omitted.
- **Licence text.** The upstream `LICENSE` is copied verbatim to `assets/js/lotl-analyzer/LICENSE-LOLBAS.txt`, and the page links to it.
- **Corresponding source.** The upstream YAML at the pinned commit, plus the conversion script `deploy/tools-lotl-analyzer/update-lolbas-data.cjs`, is published in this repository. `lolbas-snapshot.json` records the sha256 of every source YAML file.
- **The page's “Data source and license” block** names:
  - LOLBAS and its contributors, with a link to the repository;
  - the commit and date;
  - GPL-3.0 and the fact that the data is modified;
  - the ATT&CK trademark and the MITRE designation, as reproduced in the LOLBAS notice;
  - the Microsoft trademark.
- **ATT&CK ids** are copied from the LOLBAS `MitreID` field only. Engine tests verify that every id shown exists in the LOLBAS entry. The CyberDat heuristics have no ATT&CK mapping.
- **Update process.** The data is fetched at build time only, by `node deploy/tools-lotl-analyzer/update-lolbas-data.cjs --fetch <commit-sha>` or `--source <checkout>`. The script refuses to update if the upstream licence is no longer GPL-3.0. The browser never contacts GitHub; this is checked in Edge, Firefox and WebKit.

### Owner decision needed: GPL-3.0 and the tool's own code

The theme declares “GNU General Public License v2 or later” (`style.css`), which is compatible with distributing a combined work under GPL-3.0. The worker loads the GPL-3.0 data and the engine into one program, so the safest reading is that `engine.js`, `worker.js` and `app.js` of this tool are distributed under GPL-3.0 as a combined work. The repository is public, so the source is available.

The owner should confirm this licensing position for the commercial site; this is not legal advice. No GPL notice has been added to CyberDat's own files yet, because that is the owner's choice.

### GTFOBins (not used)

At `https://github.com/GTFOBins/GTFOBins.github.io`, commit `acd524623f9c406acedd2754ebd9c2431f3675ad` (2026-05-27), the `LICENSE` file is also the GNU GPL v3. It is therefore not under a different licence than LOLBAS. It would bring the same copyleft obligations: notices, the licence text, the modified-version notice, the source, and GPL-3.0 for the combined work.

As instructed, GTFOBins data is not included, and tests check that it is absent. The owner can decide later with the same compliance pattern.

## 2. Preliminary tasks

1. **Shared styles: done in a separate commit, `0f5e158`.**
   - The generic `.cd-la-*` workspace rules moved unchanged from `log-anonymizer.css` to `assets/css/tools-common.css` (handle `cyberdat-tools-common`); class names are unchanged.
   - `log-anonymizer.css` keeps only Log Anonymizer rules: rule editor, category marks, replacement map. Both earlier tools now load `tools-common.css`.
   - Proof: `tests/tools-visual-snapshot.cjs`, headless Edge. It covers both tool pages at 1440 and 360 px, in the initial and result states. For every element it records the full sorted computed style (1,218,940 values), the layout box and viewport screenshots.
   - Before and after the refactor: 0 computed-style or box differences, and all screenshots byte-identical (`evidence-2026-11-12/styles-refactor/compare-before-after.txt`).
   - A later re-run after the whole tool-3 work again shows 0 style differences. Two screenshot frames differed by ≤ 40 pixels with a channel delta of ≤ 2/255. The same anti-aliasing noise also appears between two runs of identical code, so it is not a style change.
2. **Detector verdict: fixed minimally in `ce08313`.**
   - The old headline was “No known injection patterns found.”, followed by “This does not mean the text is safe …”. It never said “safe” or “no injection found”.
   - The headline now reads “No known patterns matched.”, with the same second sentence.
   - A test guards against wording that claims safety.

## 3. Product and architecture

- **Input:** command lines, one per line, up to 5 MB, at most 20,000 commands per run (more are counted as skipped). Lines from log records with a `CommandLine` field (JSON or key: value) are recognized.
- **Static analysis only:**
  - deobfuscation: `^`, quotes inside words, PowerShell backticks, Unicode dashes, random case;
  - PowerShell `-EncodedCommand` and its abbreviations (Base64, UTF-16LE), and `FromBase64String` literals, decoded up to 2 levels;
  - nested `cmd /c "…"` and `powershell -Command "…"` commands.
  - Nothing is executed or evaluated.
- **Matching:** tokens are compared with every documented LOLBAS command of the recognized binary.
  - Literal flags and words count as the signature; concrete example values (URLs, IPs, paths) are ignored.
  - Placeholder requirements are also checked: remote URL, `\\host\share`, ADS syntax.
  - A match is “full” or “partial”. Severity comes from the LOLBAS category and the specificity of the match.
- **Output per command:**
  - recognized LOLBAS binaries with their documented functions;
  - matched usages, each with category, LOLBAS description, ATT&CK id from LOLBAS, privileges and the documented command;
  - “what to look for” (IOC text and detection references from LOLBAS, as plain links);
  - CyberDat heuristics, labelled separately (`LOT-H-001` … `LOT-H-014`).
- **Verdicts:**
  - With no match: “No known patterns matched. This does not mean the command is safe.”
  - The page states prominently that most LOLBAS binaries are legitimate and that a match is not a verdict.
- **Framework:** same as the earlier tools — renderer filter, strict CSP (`connect-src 'none'`), Web Worker with network APIs disabled, `tools-common.css`, English UI with How it works, Data source and license, Privacy and Limitations.

## 4. Files

**New:**
- `inc/tool-lotl-analyzer.php`
- `template-parts/tools/lotl-command-analyzer.php`
- `assets/js/lotl-analyzer/{engine,worker,app,lolbas-data}.js`
- `assets/js/lotl-analyzer/LICENSE-LOLBAS.txt`
- `assets/css/lotl-analyzer.css`
- `deploy/tools-lotl-analyzer/*`
- `tests/lotl-analyzer*.{cjs,php}`
- `tests/fixtures/lotl-analyzer/*`
- `tests/tools-visual-snapshot.cjs`

**Shared places changed:**

| File | Change |
|---|---|
| `functions.php` | +1 `require_once` |
| `inc/tools-catalog.json`, `deploy/staging/tools-roadmap.{json,md}` | Tool 3 slug `lolbas-analyzer` → `lotl-command-analyzer`, URL accordingly, status `available`, description present tense. Title and release unchanged. |
| `assets/css/tools-common.css` (new), `assets/css/log-anonymizer.css`, `inc/tool-log-anonymizer.php`, `inc/tool-prompt-injection-detector.php`, `assets/css/prompt-injection-detector.css`, `template-parts/tools/prompt-injection-detector.php` | Shared-styles task (comments and enqueue only; proven visually identical) |
| `assets/js/prompt-injection-detector/app.js` | Verdict wording task |
| `tests/log-anonymizer.test.php`, `tests/prompt-injection-detector.test.php`, `tests/prompt-injection-detector-engine.test.cjs`, `tests/tools-catalog.test.php` | Updated expectations |
| `tests/local-wp/*` | Seed for the third page |

The previous `deploy/tools-*/manifest.json` files pin their own branches. For files changed here, `manifest.json` of this branch lists `base_sha256`.

## 5. Tests (Windows 11, Node 24.14.1, PHP from the pinned WordPress image, offline)

| Suite | Result |
|---|---|
| `tests/lotl-analyzer-engine.test.cjs` (data, parser, matching, decoding, contracts, ReDoS, 5 MB) | 20/20 PASS. Each of 10 adversarial 32 KB lines ≤ 13 ms; 20,000 commands in 0.2 s. |
| `tests/lotl-analyzer-corpus.test.cjs` | Regression guards PASS; numbers below |
| `tests/lotl-analyzer.test.php` | 44/44 PASS |
| `tests/tools-catalog.test.php`, `tests/prompt-injection-detector.test.php`, `tests/log-anonymizer.test.php` | 34, 42, 40 PASS |
| `tests/lotl-analyzer-browser.test.cjs` (Edge, CDP) | 16/16 PASS (first-party only, nothing from GitHub, CSP, XSS, storage, 4.9 MB, Cancel, keyboard, contrast ≥ 7.59:1, 360/390/768 px, no-JS) |
| `tests/lotl-analyzer-xbrowser.test.cjs` (Playwright 1.49.1) | Firefox 10/10, WebKit 10/10 PASS |
| Regression: Log Anonymizer and Prompt Injection Detector Edge suites | 21/21 and 21/21 PASS |
| Full `tests/` suite | 42 pass, 13 fail. The 13 failures are the same set as on the base (Linux-only Python `pwd`, `content-admin-menu`, `editorial-sections`). |

A 4.9 MB input of short lines took 0.4 s in Edge, 2.5 s in Firefox and 1.0 s in WebKit; the 20,000-command limit applies.

Real Safari, iOS and Android devices were not tested.

## 6. Detection and false positives (honest)

**The corpus was written by the tool author (Claude), so these numbers are inflated.**

- A suspicious case is “flagged” when its verdict is medium or high.
- “Function correct” means the expected LOLBAS binary and category were reported, or, for heuristic-only cases, a medium+ heuristic fired.
- False positive: a benign administrative command flagged medium+ (“any” also counts low).

| | Flagged | Function correct | FP medium+ | FP any |
|---|---|---|---|---|
| Main corpus (35 suspicious / 45 benign), first run before tuning | 24/35 (68.6%) | 22/35 (62.9%) | 3/45 (6.7%) | 6/45 (13.3%) |
| Main corpus, final | 34/35 (97.1%) | 31/35 (88.6%) | 0/45 (0%) | 5/45 (11.1%) |
| **Held-out (15 / 15), first run** | **12/15 (80%)** | **10/15 (66.7%)** | **2/15 (13.3%)** | 4/15 (26.7%) |
| Held-out, after the main-corpus fixes | 13/15 (86.7%) | 12/15 (80%) | 2/15 (13.3%) | 4/15 (26.7%) |

- **How the held-out set was used.** It was written before the engine and never used for tuning. Its first-run output was printed in the same run as the main corpus, so I saw it. All later changes were generic fixes driven by main-corpus failures.
- **Fixes after the first run:**
  - concrete example values were removed from signatures;
  - the illustrative file extension in placeholders is no longer required;
  - quoted arguments are compared word by word;
  - `;` is no longer treated as a cmd separator;
  - nested `cmd /c` commands are analyzed;
  - the case-obfuscation check looks only at the binary name;
  - stricter partial matching;
  - support for ADS placeholders;
  - matches that need a remote location are at least medium;
  - a data-driven heuristic for a remote location passed to a download-capable binary.
- **Remaining misses:**
  - `bitsadmin /transfer` is not a documented LOLBAS command; only heuristic LOT-H-014 catches it;
  - `msbuild` with `.csproj` has no LOLBAS template;
  - for cmstp, my expected category differs from the LOLBAS category;
  - held-out: `cscript //E:jscript` on a `.txt` file and `control.exe` with a `.cpl` file were only low.
- **Held-out false positives:**
  - `msiexec /i \\fileserver\…msi`: an internal file share is treated as a remote location (high);
  - `reg export … .reg`: partial match with LOLBAS “ADS” (medium).
- **Raw numbers:** `evidence-2026-11-12/metrics-first-run.json`, `metrics.json`, `corpus-first-run.txt`, `corpus-tests.txt`.

The owner may provide an independent corpus; the held-out mechanism in the corpus test can run it unchanged.

## 7. Interface (screenshots in the local evidence directory, not committed)

**Step 1 — Add command lines:**
- a text area;
- “Load a text file”, “Load examples” (8 illustrative lines, example.com only) and “Clear everything”;
- callouts “Local only” and “A match is not a verdict”.

Then “Analyze commands” (progress bar, Cancel).

**Step 2 — Review the analysis:**
- a verdict line and a summary by severity;
- a table of matched LOLBAS functions;
- command cards sorted by severity, each with:
  - the command as text and what was analyzed after deobfuscation;
  - a block per binary tagged “From LOLBAS”: description, documented functions, the matched usages (function, ATT&CK id from LOLBAS, privileges, documented command);
  - a “What to look for” section with LOLBAS hints;
  - a link to the LOLBAS entry;
  - CyberDat heuristics tagged “CyberDat heuristic”;
  - decoded PowerShell with its own analysis;
- “Download analysis (JSON)”.

At 360 px the layout is a single column with no horizontal scroll.

## 8. Conflicts with parallel work

- **Research 404 checks.** The Research deploy scripts and `deploy/staging/update-tools-ui.py` assert that every catalogue URL returns 404 on staging. The unapplied proposal `deploy/tools-prompt-injection-detector/proposed-catalog-404-check.patch` (skip `status: available`) also covers this tool, because it is generic.
- **Data file size.** `lolbas-data.js` is 388 KB and is loaded by the worker when the page loads. It is cacheable and contains no input.

## 9. Owner-run staging check (not performed by the agent)

1. Make a verifiable backup.
2. Check out the branch via git and verify `manifest.json` (sha256 of LF bytes).
3. Decide on the 404 check conflict before publishing.
4. Create the `/tools/` child page `lotl-command-analyzer` with the “Tool + SEO Content” template. Fill the editorial fields from `deploy/tools-lotl-analyzer/editorial.json`, mark them reviewed and publish. The publication guard keeps the page a draft otherwise.
5. Check that `curl -sI` on the page shows the CSP with `connect-src 'none'`. Check that `/wp-content/themes/cyberdat/assets/js/lotl-analyzer/LICENSE-LOLBAS.txt` is served (200).
6. Run the browser suites against the staging URL:
   - `node tests/lotl-analyzer-browser.test.cjs https://staging.cyberdat.eu/tools/lotl-command-analyzer/`;
   - the xbrowser test with Playwright installed outside the repo.
7. Manual checks:
   - load the examples;
   - in DevTools → Network, confirm there are no requests during analysis and nothing to github.com;
   - confirm the “Data source and license” block shows the commit and date.
   Ideally do this in real Safari or on an iPhone.
8. On `/tools/`, all three release 1.1 cards should show Available.

## 10. Remaining limitations

- Only Windows LOLBAS is covered; there is no Linux/macOS data (GTFOBins is pending an owner decision).
- Renamed binaries cannot be recognized from the command line.
- Deobfuscation is static and limited: no environment-variable substrings, concatenation, compression or script files.
- Matching relies on documented flags. Unusual forms are missed, and some administrative commands partially match (the low false-positive rate measured above).
- An internal UNC share counts as remote.
- At most 20,000 commands per run; 300 cards are rendered, and all commands are included in the JSON report.
- The GPL-3.0 licensing of the combined tool code needs owner confirmation (section 1).
- `style-src 'unsafe-inline'` remains, inherited from the shared CSP.

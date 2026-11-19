# Sources and licenses — quick utility 1 (Email Header Analyzer)

For the owner and Codex. Checked on 2026-11-19 against the actual files in the upstream repository.

| Source | Commit and date | License file | License | How it is used |
|---|---|---|---|---|
| Public Suffix List, https://publicsuffix.org/list/public_suffix_list.dat | list of 2026-11-17 16:14 UTC (HTTP Last-Modified), retrieved 2026-11-19; SHA-256 `809adae1a2cb1621b70165c11e0d14412d3f104f40a4ebed9a99e23c54f78d71` | header of the data file; MPL-2.0 text from https://www.mozilla.org/media/MPL/2.0/index.txt (SHA-256 `3f3d9e00…9d04`) | Mozilla Public License 2.0 | Shipped **unmodified** as its own data file (`assets/js/email-header-analyzer/public_suffix_list.dat`, 6,951 ICANN and 3,512 private rules) with the license text (`LICENSE-MPL-2.0.txt`, verbatim). `psl-data.js` carries the same bytes as one JS string so the worker can load it (the page CSP forbids fetch); its header names MPL-2.0 and the source; a test checks the string equals the file byte for byte. Used only to find organizational domains for DMARC alignment and lookalike checks |
| IETF standards (message format, Received, Authentication-Results, SPF, DKIM, DMARC, ARC) | — | — | — | Background reading, referenced by name; no text copied |
| Brand list | — | — | — | Own short list written by CyberDat (18 brands: words in display names and their organizational domains) |

Third-party code: none. Punycode, PSL lookup, header, Received, Authentication-Results and date parsing are own code.
Nothing is loaded from a CDN; no DNS, WHOIS or reputation service is contacted.

Update procedure: `node deploy/tools-utilities-1/update-psl.cjs --fetch` downloads from publicsuffix.org (the only
source the list authors ask for) and the MPL-2.0 text from mozilla.org; reproducibility comes from the pinned SHA-256
and list date — the script refuses to write when the bytes differ, so a newer list needs a reviewed update of hash and
date; `--check` verifies the committed files. Provenance: `psl-snapshot.json`.

## Decision on the Public Suffix List

MPL-2.0 is copyleft at the file level: the covered file (and modifications of it) must stay available under MPL-2.0;
the tool's own code is a separate Larger Work and is not affected. Therefore the list is not modified, not merged into
the engine and is published as its own file with its license text, commit and date. Without the list, alignment would
be approximate (the engine has a crude fallback and says so in the result); with it, example.co.uk and evil.co.uk are
different organizations.

## Owner decisions (2026-11-19)

1. The Public Suffix List under MPL-2.0 is accepted as described; the header of `psl-data.js` names MPL-2.0 and the
   source (`386e37c`).
2. `update-psl.cjs` downloads from publicsuffix.org, as the authors ask; reproducibility through the pinned SHA-256 and
   the list date, no GitHub commit. The snapshot was switched accordingly: the earlier GitHub copy (commit `f7796455…`,
   SHA-256 `135dda6f…`) was replaced by the publicsuffix.org list of 2026-11-17 (4 private rules fewer); corpus,
   held-out and engine results are unchanged.
3. The catalogue card stays; its label reads "Quick utility" instead of "Phase 4 · Release utilities-1".
4. URL `/tools/email-header-analyzer/` confirmed.

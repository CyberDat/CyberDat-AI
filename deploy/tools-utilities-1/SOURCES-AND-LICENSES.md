# Sources and licenses — quick utility 1 (Email Header Analyzer)

For the owner and Codex. Checked on 2026-11-19 against the actual files in the upstream repository.

| Source | Commit and date | License file | License | How it is used |
|---|---|---|---|---|
| publicsuffix/list (`public_suffix_list.dat`) | `f7796455091118a5617cc7588523b083a8223301`, 2026-11-19 08:30 UTC | `LICENSE` (SHA-256 `66a3107d…d5172`) and the header of the data file | Mozilla Public License 2.0 | Shipped **unmodified** as its own data file (`assets/js/email-header-analyzer/public_suffix_list.dat`, SHA-256 `135dda6f…f29d`, 6,951 ICANN and 3,516 private rules) with the license text (`LICENSE-MPL-2.0.txt`, verbatim). `psl-data.js` carries the same bytes as one JS string so the worker can load it (the page CSP forbids fetch); a test checks the string equals the file byte for byte. Used only to find organizational domains for DMARC alignment and lookalike checks |
| IETF standards (message format, Received, Authentication-Results, SPF, DKIM, DMARC, ARC) | — | — | — | Background reading, referenced by name; no text copied |
| Brand list | — | — | — | Own short list written by CyberDat (18 brands: words in display names and their organizational domains) |

Third-party code: none. Punycode, PSL lookup, header, Received, Authentication-Results and date parsing are own code.
Nothing is loaded from a CDN; no DNS, WHOIS or reputation service is contacted.

Update procedure: `node deploy/tools-utilities-1/update-psl.cjs --fetch` (pinned commit and SHA-256; refuses on any
change of the data or the license, which then needs a reviewed pin update or an owner decision);
`--check` verifies the committed files. Provenance: `psl-snapshot.json`.

## Decision on the Public Suffix List

MPL-2.0 is copyleft at the file level: the covered file (and modifications of it) must stay available under MPL-2.0;
the tool's own code is a separate Larger Work and is not affected. Therefore the list is not modified, not merged into
the engine and is published as its own file with its license text, commit and date. Without the list, alignment would
be approximate (the engine has a crude fallback and says so in the result); with it, example.co.uk and evil.co.uk are
different organizations.

## Questions for the owner (before publication)

1. Accept shipping the Public Suffix List under MPL-2.0 as described (unmodified `public_suffix_list.dat`, its license
   text, and the `psl-data.js` carrier with the same bytes)? If not, the tool can run without it and mark alignment as
   approximate in the result and in the Limitations.
2. The upstream file asks to be pulled only from publicsuffix.org; the update script pulls the pinned commit from the
   GitHub repository for reproducibility. Keep this, or switch the script to publicsuffix.org with a hash check?
3. The catalogue entry (release `utilities-1`, phase 4, category Quick Utilities) makes the hub show an 11th
   “Coming soon” card and a Quick Utilities filter button. Keep it in the catalogue before publication?
4. URL `/tools/email-header-analyzer/` is a proposal — confirm.

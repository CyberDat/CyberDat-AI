# Sources and licenses — release 1.3 (tools 8, 9, 10)

For the owner and Codex. Checked on 2026-11-18 against the actual license files in the upstream repositories at the
commits below. **No third-party code, data, rules or text is bundled in any of the three tools**, so no license file has
to be shipped with them. Sources are referenced on the pages by name only.

| Tool | Source | Commit checked | License file | License | How it is used |
|---|---|---|---|---|---|
| 9 | SigmaHQ/sigma-specification | `ba9251aa834b11a70dbf80836b453dba99c5159e` | `LICENSE` | Public domain dedication | Background reading for the checks; referenced by name |
| 9 | SigmaHQ/sigma (rule collection) | `698f0912f571d5fac3bf8c51f5421139834a011c` | `LICENSE` | Detection Rule License (DRL) 1.1 | **Not used.** No SigmaHQ rule in the tool, tests, corpus or examples |
| 9 | VirusTotal/yara | `6d47342e825e59f5d8f20874d0778332bcec83a6` | `COPYING` | BSD 3-Clause | Background reading for the YARA syntax; referenced by name |
| 10 | kubernetes/website (documentation) | `614d8c734369cef1f12d3cbf7deb3f8b437965f1` | `LICENSE` | CC BY 4.0 | Background reading (incl. Pod Security Standards); referenced by name, no text copied |
| 10 | docker/docs (documentation) | `f8d4abc333036d7d71928bab49a417876d348966` | `LICENSE` (+ README “released under the Apache 2.0 license”) | Apache License 2.0 | Background reading; referenced by name, no text copied |
| 10 | CIS Benchmarks | — | — | Not open | **Not used.** No CIS text, item numbers or structure; the page says the rules are not a CIS Benchmark |
| 8 | — | — | — | — | Template library, canary checks and texts are written by CyberDat; no external prompt or attack collection |

Third-party libraries: none in any of the three tools (own YAML subset reader, own Dockerfile reader, own condition
parser and converters). Nothing is loaded from a CDN.

## Questions for the owner

1. Tool 9: SigmaHQ rules stay excluded (DRL 1.1 requires attribution and has conditions for rule use). If you want
   example rules from SigmaHQ in the tool or in the independent acceptance, that is your decision.
2. Tool 10: CIS is mentioned by name only to say that the rules are not a CIS Benchmark. If you prefer no mention at
   all, remove that sentence from the Limitations, Sources and FAQ (three places).
3. Tool 10: the Kubernetes documentation is CC BY 4.0. No text was copied, so attribution is not required; it is named
   in Sources for transparency.

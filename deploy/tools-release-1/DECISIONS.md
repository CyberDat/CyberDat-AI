# Owner decisions — safe preparation,2026-11-13

Latest owner instructions supersede the previous handoff. Preparation does not
authorize installation; unrelated Research/Content approvals do not apply here.

| ID | Actual status | Blocks |
|---|---|---|
| D1 | Preparation authorized; staging install NOT authorized | Any live installation/page mutation/rollback |
| D3 | DECIDED: retain Research0ef03e9; separate theme-only payload | Full repository deployment forbidden |
| D2 | Pending corrected route policy and legacy-check adoption; old status-only patch insufficient | Publication/checks |
| D4 | Confirm four canonical slugs; old LotL draft uses lolbas-analyzer | Creating pages |
| D5 | Per-page editorial/copy review, including MCP masking claims | reviewed/publish |
| D6 | LOLBAS A source/license delivery, B independent rules/data, or C permission undecided | Installing this payload and publishing LotL: static JS/data is served with theme |
| D7 | Repository visibility/source-distribution decision pending | D6/LotL source links |
| D8 | Hub currently release1.1 only; MCP1.2 direct URL works but is absent from hub | Claim of all4 discoverable on hub |
| D9 | Decide reuse of ID51/stale Rank Math description; old LotL ID53 and3 removed backlog drafts. No deletion/redirect chosen | Pages/SEO |
| D10 | Naming difference unchanged | Not a technical blocker |
| D11 | SEO publication/sitemap policy and interlocking old SEO deploy/SQL rollback pending | SEO acceptance/publication |
| D12 | Main merge not requested or performed | Not required for staging |
| D13 | Existing test-secret alerts unchanged | Not a deployment blocker |
| D14 | Independent5–10 samples/tool evaluation pending | Product acceptance PASS |
| D15 | AUTHORIZED AND APPLIED: 11 repository entry points and their 11 manifest-listed prepared copies protected,2026-11-13T16:41:51Z; backup tools-d15-20261113T164151Z | Closed for this exact scope; no scope expansion |

Before future install: valid root-owned controls/authorization, fresh backup and
live preflight. Arbitrary root execution outside controlled entry points cannot
be prevented by a userspace interlock. Old Research rollback hash guards remain
unchanged and will refuse Tools drift; future Research rollback needs review.

The22 historical source copies listed in d15-residual-paths.json were inspected
but NOT modified: they are outside the approved manifest. Do not invoke them with
sudo or restore them over guarded entry points. Collectors do not reference these
Python entry points. Old legacy --verify modes are not an approved read-only route:
some perform cache/fixture/scheduler operations. Use the new read-only preflight
or static legacy_guard.py checker. Neither executes old code.

D1 remains NOT approved. D6/D7 remain unresolved; D5's MCP promise of complete
secret concealment is not accepted or fixed by D15. These are not waived for release.

D8 changes or D6 optionB require a new artifact/hash/tests. Never modify approved
bytes while keeping old hashes. Real WP selective restore/HTTP/browser acceptance
remain UNVERIFIED under today's read-only staging restriction.

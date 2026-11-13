# Changed files — D5/D6/D7 preparation

| Paths | Change/purpose |
|---|---|
| assets/js/mcp-checker/engine.js (theme prefix below) |1.0.1 bounded credential suppression; safe parser/policy diagnostics; best-effort result note; preserves static rule metadata |
| assets/js/mcp-checker/app.js, inc/tool-mcp-checker.php |Matching engine version, verbatim policy export warning, scoped source comment |
| template-parts/tools/{log-anonymizer,prompt-injection-detector,lotl-command-analyzer,mcp-security-checker}.php; page-templates/tools.php |Accurate privacy/safety limits and LotL source/notices links |
| assets/js/lotl-analyzer/{app,engine,worker,lolbas-data}.js; assets/css/lotl-analyzer.css; inc/tool-lotl-analyzer.php |GPL3 notices/date/copyright/warranty; source/notice URL config; deterministic rebuilt data; no LotL detection-logic rewrite |
| assets/js/lotl-analyzer/{NOTICE-LOLBAS.md,SOURCE.md} |Two added theme files: complete upstream notice and corresponding-source/scope/rebuild information |
| deploy/tools-lotl-analyzer/{update-lolbas-data.cjs,lolbas-snapshot.json,upstream-source-manifest.json,upstream-source-2056cb7.tar.gz} |Pinned preferred YAML/notices/license delivery and offline integrity-checked reproducible generator |
| deploy/tools-*/editorial.json; deploy/tools-release-1/{LICENSES.md,COPY-REVIEW.md,CLAIMS-AUDIT.md} |Proposed editorial/privacy copy and bounded license/claims review; no WordPress-page write |
| tests/*tool*.test.* and relevant fixtures/lib |Imported actual four-tool test suites from integration, corrected old masking-text expectation,9 new privacy and7 new source checks, isolated PHP/HTTP fixture; no staging test data |
| tests/release-manifest.test.cjs, no-token-shaped-strings.test.cjs |Full125-file manifest verification; explicit exported tracked-list support when Git executable absent, original scanning rules retained |
| deploy/tools-release-1/{build-package.py,deploy-theme.py,git-theme-trees.json,manifest.json,tests/test_safe_release.py,route-catalog.json} |125-file target and exact new Git pins/source revision;46 tests retained; catalog check uses release-specific policy without editing SEO files |
| deploy/tools-release-1/{REPORT,HANDOFF,DECISIONS}.md; docs/PROJECT_STATUS.md |Current results, owner decisions and unresolved conditions, superseding historical status |
| deploy/tools-release-1/*d567*.json, source-availability.json, source-tree-verification.json, artifact-SHA256SUMS, evidence-d567-*/ and claims-evidence/ |Machine-readable real test/hash/source/preservation evidence, including failures |

All relative theme paths above are beneath wp-content/themes/cyberdat/.
Actual complete file list/diff is available in this branch's Git history. Final
package bytes are frozen at source commita5611f225ad1ff9858f84103036b73cc7c38568c;
subsequent evidence/controls/documentation commits do not alter the theme.
Research/Content/SEO collector code, deployed theme, pages, SQL and systemd untouched.

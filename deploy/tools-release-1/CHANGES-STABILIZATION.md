# Final Test Stabilization — changed source groups

Task base ae48da0e635b45a5e1fefdda54bb95eed2b2cd61; same feature branch.

- Theme assets/js/log-anonymizer/engine.js: key-first scanning with original
  value grammar/quoted resume behavior; classify before value processing;1.0.2.
- Theme assets/js/prompt-injection-detector/engine.js: bounded character metadata
  cache, avoid unused descriptions/common-message allocation;1.0.1. Rules unchanged.
- Theme inc/tool-log-anonymizer.php and inc/tool-prompt-injection-detector.php:
  engine versions match the intentional metadata changes.
- tests/tools-stabilization.test.cjs, tests/lib/tools-stabilization-vectors.cjs,
  tests/fixtures/tools-stabilization/baseline.json: six regressions,4006/245 frozen
  old-result equivalence cases, signature hash/context checks and4000ms bounds.
- tests/prompt-injection-detector-engine.test.cjs and .test.php: update explicit
  engine-version assertion only; no ruleset/performance/accuracy threshold changes.
- Four tests/*-xbrowser.test.cjs: optional task-local WebKit executable support;
  MCP additionally verifies actual keyboard focus before Ctrl+Enter.
- deploy/tools-release-1/GPL-BOUNDARY.md and gpl-boundary.json: concrete8-file
  declared GPL scope,14 shared paths and unresolved legal questions.
- ISOLATED-BROWSER-TESTS.md: private Debian13 runtime/Mesa reproduction; no system
  install. Browser wrapper and52 package hashes are evidence, not theme payload.
- git-theme-trees.json, manifest.json, artifact-SHA256SUMS: new exact theme/source/
  archive pins. Safe deployment/rollback code and46/10 test sets retained.
- REPORT/HANDOFF/DECISIONS, docs/PROJECT_STATUS.md, LICENSES/CLAIMS-AUDIT references:
  current statuses and boundaries. Detailed machine/log evidence retained separately.

Only four theme files changed relative to ae48da0; full payload remains125 files.
No Research/Content/SEO code, staging files/pages/SQL, timers or production changed.

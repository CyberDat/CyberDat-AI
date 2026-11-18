# Independent acceptance — Docker & Kubernetes Hardening Audit Generator

For the agent or person running acceptance (Codex) and the owner. All numbers published by the tool author are **not
independent**. This kit lets someone else measure the rules on their own configuration files.

## Protocol

1. Collect or write 30–60 files: Dockerfiles, Compose files and Kubernetes manifests (several documents per file are
   fine), about a quarter well hardened, plus a few Helm templates and broken YAML. Real files from your projects are
   the most useful; replace real secrets, registry names and host names with obviously fake values first (or use
   `tests/lib/synthetic-secrets.cjs` values for secret-shaped strings).
2. Do not look at `engine.js` or `tests/fixtures/container-hardening-audit/corpus.json` / `holdout.json`. Use
   `rules.json` in this folder (finding ids, severity and meaning) to label every file before the first run: the exact
   list of finding ids you expect, or `error` with the expected input error code. Add `mustNotShow` for secret values.
3. Set `"provenance": "independent"` and `"authoredByToolAuthor": false`, freeze the file, keep it outside the repository
   and run:
   `node tests/container-hardening-audit-independent.cjs /private/path/set.json --details`
   The output contains case ids, finding ids and counts only, never file text.
4. Publish only the summary and the file hash. Fixes after acceptance must be checked on new cases.

## Format

`template.json`: `cases[]` with `id`, `name` (file name; `Dockerfile`/`Containerfile` selects the Dockerfile reader),
`text`, `expect` or `error`, optional `mustNotShow`.

## What this does not measure

Whether a configuration is hardened. The rules are CyberDat's own and are not a CIS Benchmark; settings inherited from
base images, override files, namespaces or admission policies are unknown to the checks.

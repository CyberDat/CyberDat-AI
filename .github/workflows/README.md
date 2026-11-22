# CI: secret scan and fast tests

Two workflows run on every push and every pull request **except `main`** (`branches-ignore: [main]`; `main` is not
touched). Both have `permissions: contents: read`, use no repository secrets, check out with
`persist-credentials: false` and pin every action by commit SHA.

| Workflow | Jobs |
|---|---|
| [`secret-scan.yml`](secret-scan.yml) | **gitleaks**: the full history of the checked-out ref, with [`.gitleaks.toml`](../../.gitleaks.toml) and the baseline [`.gitleaksignore`](../../.gitleaksignore), values redacted; **no-token-shaped-strings** (`tests/no-token-shaped-strings.test.cjs`) |
| [`fast-tests.yml`](fast-tests.yml) | [`../scripts/fast-tests.sh`](../scripts/fast-tests.sh): every Node test `tests/*.test.cjs` except the skip list below, then `php -l` on every PHP file of `wp-content/themes`, `wp-content/plugins`, `tests` and `preview` (PHP of the runner image) |

Pins: `actions/checkout` v5.0.0 = `08c6903cd8c0fde910a37f88322edcfb5dd907a8`, `actions/setup-node` v5.0.0 =
`a0853c24544627f65ddf259abe73b1d18a591444` (tags resolved on 2026-11-22; v5 runs on Node 24, v4 on the deprecated Node 20), gitleaks v8.21.2 as the image
`zricethezav/gitleaks@sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46`, run with
`--network none`. Node **24.14.1**, the version the tests are developed and accepted with, runner `ubuntu-24.04`.
The fast tests check out the full history (`fetch-depth: 0`): the manifest tests read the package base commits.

Why Node is pinned to 24.14.1: on Node 24.22.3 `url.domainToASCII('xn--already.example')` returns the name instead of
`''`, so `tests/email-header-analyzer-engine.test.cjs` also compares the back conversion, and the engine's `toUnicode`
decodes the invalid label `xn--already` to control characters instead of leaving it as it is. That is an engine finding
in `wp-content/` (frozen during the utilities-1 installation), recorded here for a later fix; it is not a CI problem.

## Skipped in the fast tests (explicit)

| Tests | Why |
|---|---|
| `tests/*-browser.test.cjs` (14) | Playwright browsers and a running page (local sandbox `tests/tools-sandbox-server.py` or staging) |
| `tests/*-xbrowser.test.cjs` (11) | the same, Firefox and WebKit |
| `tests/d14-remediation.test.cjs` | the owner-private frozen fixture directory (passed as an argument; not in the repository) |
| `tests/release-manifest.test.cjs` | checks the frozen release-1 theme (125 files, POSIX modes) of the installed release-1 package; the integration theme has more files since, so it fails on `2f72379` as well |
| `tests/*.test.php`, `tests/*.test.py` | not part of this workflow (PHP is linted only); several need WordPress, Content/Research data or staging |
| `tests/*.cjs` without `.test.` (`tools-export-surface-audit.cjs`, `email-header-analyzer-independent.cjs`, …) | diagnostics and runners for the owner's independent sets, not tests |

The skip list lives in `fast-tests.sh` (`SKIP=( pattern|reason )`) and is printed in the job log line by line.
Local run before the first push (2026-11-22, Node 24, PHP 8.4 of the pinned WordPress image): Node 54/54 passed, 27 skipped;
PHP lint 142/142.

## gitleaks configuration and baseline

* `.gitleaks.toml` = the default gitleaks rules plus an allowlist **by path only**: `tests/lib/synthetic-secrets.cjs`
  (the single source of synthetic token-shaped values) and `tests/fixtures/` (corpora and fixtures built from them).
  No value, regex or rule is allowlisted; nothing real is allowed.
* `.gitleaksignore` = the baseline: one fingerprint `commit:file:rule:line` per reviewed historical finding (34
  fingerprints, 39 findings in 8 commits). Only those exact positions are ignored. A new commit with the same value,
  or a new line in one of these files, is reported. The file holds no values and no author data.
* Checked locally (2026-11-22): the full history (all refs) with the config and the baseline → no leaks; a test commit
  in a throw-away clone with a synthetic GitHub token in `tests/` → 1 finding (github-pat), the same value in
  `tests/fixtures/` → allowed.

Reviewed baseline (values compared in memory with `tests/lib/synthetic-secrets.cjs`; none printed):

| Commit | File | Rules (findings) | Verdict |
|---|---|---|---|
| `1f3b41c` (2026-11-11, Log Anonymizer) | `tests/log-anonymizer-engine.test.cjs` | github-pat 2, gitlab-pat 2, gcp-api-key 2, jwt 1, curl-auth-header 1, generic-api-key 1, private-key 6 | synthetic: equal to `GITHUB_PAT`, `GITLAB_PAT`, `GOOGLE_API_KEY`, `JWT_3`, `BASIC_AUTH`, `X_API_KEY_2`; the six private key blocks are short placeholders that do not parse as keys (Node `crypto`) |
| `1f3b41c` | `wp-content/themes/cyberdat/assets/js/log-anonymizer/app.js` | github-pat 1, jwt 1 | synthetic: the page example, equal to `GITHUB_PAT`, `JWT_6` |
| `93a729a` (2026-11-15) | `tests/leak-inspector-unicode.test.cjs` | generic-api-key 3 | synthetic: `ASSIGNED_PLAIN`, `ASSIGNED_PLAIN_2` |
| `7520e32` (2026-11-15) | `tests/tools-release-1.2-unicode.test.cjs` | generic-api-key 1 | synthetic: `ASSIGNED_PLAIN_2` |
| `4c6ddb6` (2026-11-13) | `tests/independent-eval/templates/log-anonymizer.json` | generic-api-key 1 | synthetic: part of `GENERIC_API_KEY` |
| `9bbae3d`, `21a967a` | `deploy/tools-lotl-analyzer/lolbas-snapshot.json`, `upstream-source-manifest.json` | generic-api-key 5 + 5 + 5 | not a secret: SHA-256 hashes of LOLBAS files whose names contain "key" (`Cmdkey.yml`, …) |
| `731c9cd` | `deploy/tools-release-1/protected-files.json` | generic-api-key 1 | not a secret: SHA-256 of `api.php` |
| `d0df9ca` | `deploy/content-0.9.0-stage1.1/acceptance-2026-11-11.json` | generic-api-key 1 | not a secret: SHA-256 of `api.php` |

Findings in `tests/fixtures/` (`1f3b41c` `mixed.log`, `1a5cfcd` `keyvalue.log`, `f567a82` `benign.json`; 8 findings) are
covered by the path allowlist and are synthetic as well. New package manifests with a file hash next to a "key" file
name will be reported again: check them and add their fingerprints, do not allowlist hex values.

**Updating the baseline** after a reviewed false positive: run gitleaks with `--report-format json`, check the value
without printing it, append the finding's `Fingerprint` with a `#` comment saying why, and commit. Never add a real
secret: rotate it and remove it instead.

## Local pre-commit hook (optional)

`bash tools/install-gitleaks-pre-commit.sh` installs `.git/hooks/pre-commit`, which runs
`tools/git-hooks/pre-commit-gitleaks.sh`: gitleaks on the staged changes with `.gitleaks.toml`, a local `gitleaks`
binary if present, otherwise the same pinned Docker image (`--network none`). `--force` replaces another hook (backup
kept), `--remove` uninstalls. One deliberate skip: `SKIP_GITLEAKS=1 git commit …` (CI still scans). Checked in a
throw-away clone: a clean commit passes, a commit with a synthetic GitHub token is refused.

## GitHub Secret Scanning alerts

`GITHUB_TOKEN=… node tools/list-secret-scanning-alerts.cjs` lists the open alerts (read-only) with file, line, commit and
a verdict: the value is compared in memory with `tests/lib/synthetic-secrets.cjs` and private key blocks are parsed; only
the type, the first four characters and the length are printed. It never closes an alert; the owner does that.

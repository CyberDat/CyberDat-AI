# HANDOFF — CyberDat Tools release 1 → staging (for Codex)

Audience: the agent with VPS access (Codex). Prepared by Claude Code on the owner's machine without VPS access, so
**nothing here assumes the current VPS state**: step 0 collects it read-only first. No secrets, tokens or passwords are in
this file or in the repository; use your own credential store and never print credentials.

## What to deploy

| Item | Value |
|---|---|
| Repository | `CyberDat/CyberDat-AI` |
| Branch | `integration/tools-release-1` (not merged into `main`) |
| Theme commit (files to deploy) | `cd7df0c2a2fa5b5634977d765884b599a3495340` |
| Expected current staging theme (base) | Research 0.8.3 tip `c3f9a5e7172f83006f3b078705a9d89e709619f8` |
| Files | 32 theme files under `wp-content/themes/cyberdat` (4 modified, 28 added) — `deploy/tools-release-1/manifest.json` |
| Tools | Privacy Shield Log Anonymizer, Indirect Prompt Injection Sanitizer & Detector, LotL / LOLBAS Command Analyzer (release 1.1), MCP Security & Policy Checker (release 1.2) |
| Pages (after owner review only) | `/tools/log-anonymizer/`, `/tools/prompt-injection-detector/`, `/tools/lotl-command-analyzer/`, `/tools/mcp-security-checker/` |
| Not part of this deployment | `proposed/catalog-404-check` (`d7281116`), Research/Content/SEO code, plugins, server configuration, `docs/PROJECT_STATUS.md` |

Staging layout (from `deploy/staging/README.md`): WordPress `/var/www/cyberdat-staging/public`, theme
`/var/www/cyberdat-staging/public/wp-content/themes/cyberdat`, runtime user `cyberdat-staging`, PHP `/usr/bin/php8.4`,
WP-CLI `/opt/cyberdat-tools/wp-cli.phar`, backups `/var/backups/cyberdat-staging`, origin `https://staging.cyberdat.eu`
(HTTP Basic Auth on every resource). Verify each of these in step 0; stop if any differs.

## Hard prohibitions

1. **Production is off-limits**: no change under `/var/www/cyberdat/`, production Nginx/PHP-FPM/database or `cyberdat.eu`.
2. No merge into `main`, no force-push, no history rewrite, no change to repository settings or GitHub alerts.
3. Do not apply `proposed/catalog-404-check` or `deploy/proposed-catalog-404/seo-0.7-roadmap-404.patch` without the owner's written decision (DECISIONS.md D2, D11).
4. Do not publish any tool page and do not set `reviewed` without the owner's explicit confirmation for that page.
5. Do not touch Research Agent, Content Agent, SEO Intelligence code, their services, timers, bundles or data; do not stop timers unless the owner says so.
6. Do not modify the DR environment (`cyberdat-dr-*`, `cyberdat-restore-db`).
7. Do not print, log or copy credentials, `wp-config.php` contents, cookies or tokens. Do not paste real secrets into the tools.
8. If anything differs from this document (paths, base hashes, running jobs), **stop and report**; do not improvise a fix.

## Owner decisions required before starting (DECISIONS.md)

| Needed for | Decision |
|---|---|
| Any step after 0 | D1 approval to deploy; D3 ordering with Research 0.8.3 (Research scripts replace the whole theme from their own bundle) |
| Creating pages (6.2) | D4 page URLs; D9 what to do with SEO 0.7 drafts (`log-anonymizer`, `lolbas-analyzer`, backlog drafts) |
| `reviewed` (6.3) | D5 copy review (COPY-REVIEW.md) |
| Publishing (6.4) | D2 Research 404 checks; D6/D7 LOLBAS licence and repository visibility (LotL page) |

Step 0 is read-only and may run before decisions.

## Step 0 — collect the current state (read-only)

Run as a user that can read the paths; write output only to a new private directory. Define:

```bash
set -euo pipefail; set +x; umask 077
STAMP=$(date -u +%Y%m%dT%H%M%SZ); OUT=/root/tools-release-1-state-$STAMP; mkdir -m 700 "$OUT"
WPROOT=/var/www/cyberdat-staging/public; THEME=$WPROOT/wp-content/themes/cyberdat
WP="runuser -u cyberdat-staging -- /usr/bin/php8.4 -d memory_limit=128M /opt/cyberdat-tools/wp-cli.phar --path=$WPROOT"
```

| # | Purpose | Command (all read-only) |
|---|---|---|
| 0.1 | Host, time, disk | `hostname; date -u; df -h /var/www /var/backups \| tee $OUT/disk.txt` |
| 0.2 | Paths are real directories | `stat -c '%U:%G %a %F %n' $WPROOT $THEME \| tee $OUT/paths.txt; readlink -f $THEME` |
| 0.3 | Theme version and owner | `grep -m1 '^Version:' $THEME/style.css; stat -c '%U:%G' $THEME/functions.php` |
| 0.4 | Full theme hash list | `(cd $THEME && find . -type f -print0 \| sort -z \| xargs -0 sha256sum) > $OUT/theme-before.sha256; wc -l $OUT/theme-before.sha256` |
| 0.5 | WordPress and active theme | `$WP core version; $WP option get stylesheet; $WP option get template` |
| 0.6 | Catalogue on the server | `python3 -c "import json;[print(t['release'],t.get('status'),t['slug']) for t in json.load(open('$THEME/inc/tools-catalog.json'))]"` |
| 0.7 | Pages under /tools/ incl. SEO 0.7 drafts | `$WP post list --post_type=page --post_status=any --fields=ID,post_name,post_status,post_parent,page_template --format=csv > $OUT/pages.csv; $WP post list --post_type=page --post_status=any --meta_key=_cyberdat_tools_architecture --fields=ID,post_name,post_status --format=csv` |
| 0.8 | Research services and timers | `systemctl list-timers 'cyberdat-research-*' --all --no-pager; systemctl list-units 'cyberdat-research@*' --all --no-pager; journalctl -u 'cyberdat-research@*' --since -24h --no-pager \| tail -n 40` |
| 0.9 | No deployment job running | `pgrep -af 'update-research\|resume-research\|update-tools-ui\|update-seo\|finish-research' \|\| echo none` |
| 0.10 | Research bundle that would overwrite the theme (D3) | `ls -la /opt/cyberdat-research 2>/dev/null; ls -la /opt/cyberdat-research/*/theme 2>/dev/null \| head` |
| 0.11 | HTTP state before | `curl -sS --netrc-file <your-netrc> -o /dev/null -w '%{http_code} %{url_effective}\n' https://staging.cyberdat.eu/tools/ https://staging.cyberdat.eu/tools/log-anonymizer/ https://staging.cyberdat.eu/tools/mcp-security-checker/` (tool URLs are expected to be 404 now) |

Then compare with the expected base. On your workstation (repository clone):

```bash
git fetch origin integration/tools-release-1
BASEDIR=$(mktemp -d); git -c core.autocrlf=false archive c3f9a5e7172f83006f3b078705a9d89e709619f8 wp-content/themes/cyberdat | tar -x -C "$BASEDIR"
(cd "$BASEDIR/wp-content/themes/cyberdat" && find . -type f -print0 | sort -z | xargs -0 sha256sum) > base.sha256
diff base.sha256 theme-before.sha256 && echo "staging theme == Research 0.8.3 base"
```

* Identical → continue (after D1/D3).
* Different → **stop** and report the differing files: Research or another session changed the theme, and the
  integration branch must first be rebased or merged on top of that state (owner decision D3).

## Step 1 — prepare and verify the artifact (workstation)

```bash
git checkout --detach origin/integration/tools-release-1
STAGE=$(mktemp -d); git -c core.autocrlf=false archive cd7df0c2a2fa5b5634977d765884b599a3495340 wp-content/themes/cyberdat | tar -x -C "$STAGE"
python3 deploy/tools-release-1/verify-manifest.py "$STAGE/wp-content/themes/cyberdat"          # expect: 32 files, 0 mismatches
python3 deploy/tools-release-1/verify-manifest.py "$BASEDIR/wp-content/themes/cyberdat" --expect base   # expect: 0 mismatches
tar -C "$STAGE/wp-content/themes" -czf cyberdat-theme-release-1.tar.gz cyberdat; sha256sum cyberdat-theme-release-1.tar.gz
```

Copy `cyberdat-theme-release-1.tar.gz`, `deploy/tools-release-1/{manifest.json,verify-manifest.py,tool-pages.php}` and the
`deploy/tools-*/editorial.json` files to a new 0700 directory on the VPS (e.g. `/root/tools-release-1-$STAMP/`), and
verify the tarball SHA-256 after copying.

## Step 2 — backup with SHA-256 (VPS)

Follow the conventions of `deploy/staging/backup.md` (umask 077, `set -Eeuo pipefail`, no passwords on the command line, root's MariaDB
Unix-socket authentication, verify the database name without printing `wp-config.php`).

```bash
BK=/var/backups/cyberdat-staging/tools-release-1-$STAMP; mkdir -m 700 "$BK"
tar -C $WPROOT/wp-content/themes -czf "$BK/theme-before.tar.gz" cyberdat
mysqldump --single-transaction --routines --triggers cyberdat_staging | gzip > "$BK/db-before.sql.gz"   # confirm the DB name first
cp $OUT/theme-before.sha256 "$BK/"; (cd "$BK" && sha256sum theme-before.tar.gz db-before.sql.gz theme-before.sha256 > SHA256SUMS)
chmod 600 "$BK"/*; cat "$BK/SHA256SUMS"
```

Report the three SHA-256 values. Check that the dump is non-empty and the tarball lists `cyberdat/style.css`.

## Step 3 — replace the theme atomically (VPS, after D1 and D3)

```bash
TMP=$WPROOT/wp-content/themes/.cyberdat-release-1-$STAMP; RET=$WPROOT/wp-content/themes/.cyberdat-before-$STAMP
mkdir -m 750 "$TMP"; tar -C "$TMP" -xzf /root/tools-release-1-$STAMP/cyberdat-theme-release-1.tar.gz
chown -R --reference=$THEME "$TMP/cyberdat"   # same owner/group as the current theme (recorded in 0.3)
python3 /root/tools-release-1-$STAMP/verify-manifest.py "$TMP/cyberdat" --manifest /root/tools-release-1-$STAMP/manifest.json
for f in $(cd "$TMP/cyberdat" && find . -name '*.php'); do /usr/bin/php8.4 -l "$TMP/cyberdat/$f" >/dev/null || echo "LINT FAIL $f"; done
mv "$THEME" "$RET" && mv "$TMP/cyberdat" "$THEME" && rmdir "$TMP"
```

Keep `$RET` until the owner accepts the deployment. Do not delete it.

## Step 4 — verify the deployed theme

```bash
python3 /root/tools-release-1-$STAMP/verify-manifest.py "$THEME" --manifest /root/tools-release-1-$STAMP/manifest.json   # 0 mismatches
$WP eval 'foreach (["cyberdat_log_anonymizer_render","cyberdat_prompt_detector_render","cyberdat_lotl_render","cyberdat_mcp_render","cyberdat_tool_security_header_lines"] as $f) { echo $f, ": ", function_exists($f) ? "ok" : "MISSING", PHP_EOL; }'
curl -sS --netrc-file <your-netrc> -o /dev/null -w '%{http_code} %{url_effective}\n' https://staging.cyberdat.eu/ https://staging.cyberdat.eu/tools/ \
  https://staging.cyberdat.eu/wp-content/themes/cyberdat/assets/js/lotl-analyzer/LICENSE-LOLBAS.txt \
  https://staging.cyberdat.eu/wp-content/themes/cyberdat/assets/js/mcp-checker/worker.js
```

Expected: home and `/tools/` are 200 with authentication; `/tools/` still shows three “Coming soon” cards (no tool page is ready
yet); LICENSE-LOLBAS.txt and worker.js are 200; the tool URLs are still 404 (no pages yet), so the Research and staging 404 checks
still pass at this point.

## Step 5 — security checks of the theme without published pages

* `tools-catalog.json` on the server lists 10 tools; 4 are `available` (`verify-manifest` already proved the bytes).
* `curl -sS --netrc-file <your-netrc> https://staging.cyberdat.eu/wp-content/themes/cyberdat/assets/js/lotl-analyzer/LICENSE-LOLBAS.txt | head -3` shows “GNU GENERAL PUBLIC LICENSE / Version 3”.

## Step 6 — pages (each sub-step needs the owner)

Run with the deployed artifact's `deploy` directory copied to the VPS as `/root/tools-release-1-$STAMP/deploy`
(containing `tools-log-anonymizer/`, `tools-prompt-injection-detector/`, `tools-lotl-analyzer/`, `tools-mcp-checker/` with their
`editorial.json`, and `tools-release-1/tool-pages.php`):

```bash
D=/root/tools-release-1-$STAMP/deploy
$WP eval-file $D/tools-release-1/tool-pages.php plan $D            # 6.1 read-only; send the output to the owner
$WP eval-file $D/tools-release-1/tool-pages.php draft $D           # 6.2 after D4 and D9: drafts with editorial fields, reviewed=false
$WP eval-file $D/tools-release-1/tool-pages.php reviewed $D <slug> # 6.3 per page, only after the owner confirms its texts (D5)
$WP eval-file $D/tools-release-1/tool-pages.php publish $D <slug>  # 6.4 per page, only after D2 (and D6/D7 for lotl-command-analyzer)
```

The script never changes published pages in `draft` mode, refuses an unexpected parent or template, refuses to publish a page that
is not ready, and never edits Rank Math fields (the SEO 0.7 draft of `log-anonymizer` has the description “planned … not released”,
which the owner or SEO session must update — D9).

## Step 7 — checks after publishing each page

For each published URL `U`:

1. Headers: `curl -sS --netrc-file <your-netrc> -D - -o /dev/null U` contains
   `Content-Security-Policy` with `default-src 'none'`, `connect-src 'none'`, `worker-src 'self'` and a `'nonce-…'` script source,
   no `unsafe-eval` and no external host (`style-src 'self' 'unsafe-inline'` is expected: WordPress core prints inline CSS); plus `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`,
   `Cross-Origin-Opener-Policy`.
2. Assets: the worker, engine (and for LotL `lolbas-data.js`, `LICENSE-LOLBAS.txt`) return 200 from the same origin.
3. Browser tests from a workstation with Edge/Chrome (and Playwright for Firefox/WebKit, not a repository dependency):
   put `user:password` for staging Basic Auth on one line in a 0600 file outside the repository, then

   ```bash
   export CYBERDAT_BASIC_AUTH_FILE=/path/to/staging-basic-auth.txt
   node tests/log-anonymizer-browser.test.cjs https://staging.cyberdat.eu/tools/log-anonymizer/
   node tests/prompt-injection-detector-browser.test.cjs https://staging.cyberdat.eu/tools/prompt-injection-detector/
   node tests/lotl-analyzer-browser.test.cjs https://staging.cyberdat.eu/tools/lotl-command-analyzer/
   node tests/mcp-checker-browser.test.cjs https://staging.cyberdat.eu/tools/mcp-security-checker/
   NODE_PATH=<playwright>/node_modules node tests/<tool>-xbrowser.test.cjs <URL>      # Firefox + WebKit, for each tool
   ```

   Expected locally (2026-11-13): LA 21, PI 21, LotL 16, MCP 20 checks in Edge; Firefox/WebKit 14/14, 13/13, 10/10, 11/11.
   The tests send nothing but page loads; they verify that no request leaves the page while processing input.
4. Manual (owner or Codex with a real device): DevTools → Network while pasting, processing, exporting and clearing — no requests
   except the static worker scripts after Cancel; same check in **Safari on macOS and on an iPhone** (not covered by automation).
5. `/tools/`: published 1.1 tools show “Available” with links; MCP Checker is not on the hub unless the owner decides D8.
6. Planned tools (6 URLs) still return 404.

## Rollback

```bash
mv "$THEME" $WPROOT/wp-content/themes/.cyberdat-failed-$STAMP && mv "$RET" "$THEME"
python3 /root/tools-release-1-$STAMP/verify-manifest.py "$THEME" --manifest /root/tools-release-1-$STAMP/manifest.json --expect base   # 0 mismatches
$WP post update <ID> --post_status=draft    # for every page published in step 6 (IDs from the step 6 output)
```

If `$RET` is not available, restore `theme-before.tar.gz` from `$BK` after checking `SHA256SUMS`. Restore the database dump only with
the owner's approval (pages and meta are the only database changes of this deployment).

## Report format (send to the owner)

1. Step 0 results: paths, theme owner, WordPress version, active theme, `diff` result against base (identical / list of files), pages
   under `/tools/` with status and SEO 0.7 drafts, Research timers and their last runs, running jobs (none expected).
2. Backup directory and the three SHA-256 values; artifact tarball SHA-256.
3. `verify-manifest` output summary (target on the live theme), PHP lint result, function check.
4. Pages: output of `tool-pages.php plan` and of every step actually run, with page IDs.
5. Post-deploy checks per URL: HTTP codes, CSP header (copied), browser test counts per browser, manual Safari/iPhone result.
6. Anything that differed from this document and where you stopped.
7. Status: PASS / PARTIAL / BLOCKED, with the open owner decisions.

#!/usr/bin/env bash
# Fast checks without browsers, private fixtures or staging: every Node test tests/*.test.cjs except the explicit skip
# list below, then `php -l` on every PHP file of the theme, the plugins, the tests and the previews.
# Used by .github/workflows/fast-tests.yml; runs the same way locally from the repository root:  bash .github/scripts/fast-tests.sh
set -u
cd "$(dirname "$0")/../.."

# Explicit skip list: "<pattern>|<reason>". Keep it in step with .github/workflows/README.md.
SKIP=(
	'-browser\.test\.cjs$|needs Playwright browsers and a running page (local sandbox or staging)'
	'-xbrowser\.test\.cjs$|needs Playwright browsers and a running page (local sandbox or staging)'
	'^tests/d14-remediation\.test\.cjs$|needs the owner-private frozen fixture directory (argument)'
	'^tests/release-manifest\.test\.cjs$|checks the frozen release-1 theme (125 files, POSIX modes) against the installed release-1 package; the integration theme has moved on since (fails on 2f72379 as well)'
)

fail=0; ran=0; skipped=0; failed_list=()
for f in tests/*.test.cjs; do
	reason=''
	for s in "${SKIP[@]}"; do
		if [[ "$f" =~ ${s%%|*} ]]; then reason="${s#*|}"; break; fi
	done
	if [ -n "$reason" ]; then echo "SKIP $f — $reason"; skipped=$((skipped + 1)); continue; fi
	start=$(date +%s)
	if node "$f" > /tmp/fast-test.out 2>&1; then
		echo "PASS $f ($(( $(date +%s) - start )) s)"
	else
		echo "FAIL $f"; sed -e 's/^/    /' /tmp/fast-test.out | tail -n 25
		fail=$((fail + 1)); failed_list+=("$f")
	fi
	ran=$((ran + 1))
done
echo "Node tests: $((ran - fail))/$ran passed, $skipped skipped"

lint_fail=0; lint_n=0
while IFS= read -r -d '' p; do
	lint_n=$((lint_n + 1))
	if ! out=$(php -l "$p" 2>&1); then echo "LINT-FAIL $p"; echo "$out" | sed -e 's/^/    /'; lint_fail=$((lint_fail + 1)); fi
done < <(find wp-content/themes wp-content/plugins tests preview -name '*.php' -type f -print0 2>/dev/null)
echo "PHP lint ($(php -r 'echo PHP_VERSION;')): $((lint_n - lint_fail))/$lint_n files without syntax errors"

if [ "$fail" -gt 0 ] || [ "$lint_fail" -gt 0 ]; then
	[ "$fail" -gt 0 ] && printf 'failed: %s\n' "${failed_list[@]}"
	exit 1
fi

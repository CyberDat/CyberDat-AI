#!/usr/bin/env bash
# pre-commit hook: gitleaks on the staged changes, with the repository's .gitleaks.toml (same rules as CI).
# Uses a local gitleaks binary when one is on PATH, otherwise the pinned Docker image. Values are redacted.
# Installed by tools/install-gitleaks-pre-commit.sh (optional). Skip once, deliberately: SKIP_GITLEAKS=1 git commit ...
set -u
[ "${SKIP_GITLEAKS:-}" = "1" ] && { echo "pre-commit: gitleaks skipped (SKIP_GITLEAKS=1)" >&2; exit 0; }
root="$(git rev-parse --show-toplevel)" || exit 1
cd "$root" || exit 1
IMAGE='zricethezav/gitleaks@sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46' # v8.21.2
args=(git --pre-commit --staged --redact --no-banner --exit-code 1)
if command -v gitleaks > /dev/null 2>&1; then
	gitleaks "${args[@]}" --config .gitleaks.toml .
elif command -v docker > /dev/null 2>&1; then
	src="$root"
	if command -v cygpath > /dev/null 2>&1; then src="$(cygpath -w "$root")"; fi # Git Bash on Windows
	MSYS_NO_PATHCONV=1 docker run --rm --network none -v "$src":/repo \
		-e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0=/repo \
		"$IMAGE" "${args[@]}" --config /repo/.gitleaks.toml /repo
else
	echo "pre-commit: neither gitleaks nor docker found; install one, or commit with SKIP_GITLEAKS=1 (CI still scans)." >&2
	exit 1
fi
status=$?
if [ "$status" -ne 0 ]; then
	echo "pre-commit: gitleaks reported a possible secret in the staged changes (values redacted above). Use synthetic values from tests/lib/synthetic-secrets.cjs." >&2
fi
exit "$status"

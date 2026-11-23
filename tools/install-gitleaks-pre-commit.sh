#!/usr/bin/env bash
# Optional: install the gitleaks pre-commit hook of this repository (tools/git-hooks/pre-commit-gitleaks.sh).
# Nothing in the repository needs it; CI (.github/workflows/secret-scan.yml) scans every push anyway.
#   bash tools/install-gitleaks-pre-commit.sh            install (refuses to replace a different existing hook)
#   bash tools/install-gitleaks-pre-commit.sh --force    replace an existing pre-commit hook (a backup is kept)
#   bash tools/install-gitleaks-pre-commit.sh --remove   remove the hook installed by this script
set -eu
root="$(git rev-parse --show-toplevel)"
hooks="$(git rev-parse --git-path hooks)"
case "$hooks" in /*|[A-Za-z]:*) ;; *) hooks="$root/$hooks" ;; esac
target="$hooks/pre-commit"
marker='# installed by tools/install-gitleaks-pre-commit.sh'

if [ "${1:-}" = "--remove" ]; then
	if [ -f "$target" ] && grep -qF "$marker" "$target"; then rm -f "$target"; echo "Removed $target"; else echo "No hook installed by this script at $target"; fi
	exit 0
fi
if [ -e "$target" ] && ! grep -qF "$marker" "$target"; then
	if [ "${1:-}" != "--force" ]; then echo "A different pre-commit hook exists at $target. Re-run with --force to replace it (a backup is kept)." >&2; exit 1; fi
	cp "$target" "$target.backup.$(date +%Y%m%d%H%M%S)"
fi
mkdir -p "$hooks"
cat > "$target" <<EOF
#!/usr/bin/env bash
$marker
exec bash "\$(git rev-parse --show-toplevel)/tools/git-hooks/pre-commit-gitleaks.sh" "\$@"
EOF
chmod +x "$target"
echo "Installed $target (runs tools/git-hooks/pre-commit-gitleaks.sh: local gitleaks, or the pinned Docker image)."
command -v gitleaks > /dev/null 2>&1 || command -v docker > /dev/null 2>&1 || echo "Note: neither gitleaks nor docker is on PATH; the hook will refuse commits until one is installed (or SKIP_GITLEAKS=1)."

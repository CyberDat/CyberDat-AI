#!/usr/bin/env python3
"""Prepared legacy interlock. Never executes or modifies an old deploy script."""
from pathlib import Path
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from safe_theme import need

MARKER = '# CYBERDAT_TOOLS_RELEASE_1_LEGACY_INTERLOCK'
GUARD = """# CYBERDAT_TOOLS_RELEASE_1_LEGACY_INTERLOCK
from pathlib import Path as _ToolsLegacyPath
if (_ToolsLegacyPath('/var/www/cyberdat-staging/public/wp-content/themes/cyberdat') / 'inc/tool-security.php').exists():
 raise SystemExit('BLOCKED: Tools Release 1 installed; legacy theme/SQL deploy or rollback requires a compatible package; do not bypass this interlock')
import os as _tools_os, stat as _tools_stat, fcntl as _tools_fcntl
_tools_release_fd = _tools_os.open('/run/lock/cyberdat-staging-tools-release-1.lock', _tools_os.O_RDWR | _tools_os.O_CREAT | _tools_os.O_NOFOLLOW, 0o600)
_tools_lock_stat = _tools_os.fstat(_tools_release_fd)
if not (_tools_stat.S_ISREG(_tools_lock_stat.st_mode) and _tools_lock_stat.st_uid == 0 and _tools_stat.S_IMODE(_tools_lock_stat.st_mode) == 0o600):
 raise SystemExit('BLOCKED: unsafe Tools release lock')
try:
 _tools_fcntl.flock(_tools_release_fd, _tools_fcntl.LOCK_EX | _tools_fcntl.LOCK_NB)
except BlockingIOError:
 raise SystemExit('BLOCKED: Tools deployment or another legacy deployment is running')
if (_ToolsLegacyPath('/var/www/cyberdat-staging/public/wp-content/themes/cyberdat') / 'inc/tool-security.php').exists():
 raise SystemExit('BLOCKED: Tools installed while waiting for release lock')
"""


def require_interlocks(paths):
    for p in paths:
        p = Path(p)
        need(p.is_file() and not p.is_symlink(), 'legacy entry point missing or unsafe')
        code = p.read_text()
        need(GUARD in code[:3000], 'legacy interlock not adopted: ' + str(p))
        prefix = code[:code.index(GUARD)]
        need(all(not l.strip() or l.startswith('#') for l in prefix.splitlines()),
             'legacy interlock runs after executable code')


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('paths', nargs='+', type=Path)
    a = p.parse_args()
    require_interlocks(a.paths)
    print('PASS: known legacy entry points have fail-closed pre-execution interlocks')

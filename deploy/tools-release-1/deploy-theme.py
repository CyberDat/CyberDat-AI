#!/usr/bin/env python3
"""Prepared staging entry point. Nothing mutates without fresh owner authorization.

No sandbox flag and no arbitrary destination argument. The sandbox tests import
the identical Transaction engine, never this live entry point.
"""
import argparse
import base64
import fcntl
import getpass
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import time
import urllib.error
import urllib.request
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from safe_theme import Transaction, need, digest, verify, acquire_lock
from legacy_guard import require_interlocks
from route_policy import validate

ROOT = Path('/var/www/cyberdat-staging/public')
THEME = ROOT / 'wp-content/themes/cyberdat'
BACKUPS = Path('/var/backups/cyberdat-staging')
PRIVATE = Path('/opt/cyberdat-tools/tools-release-1')
HERE = Path(__file__).resolve().parent
ORIGIN = 'https://staging.cyberdat.eu'
RESEARCH = '0ef03e9cb0d8821546983c84fc6998e85cf03f2e'


def sql_read_identity():
    need(os.geteuid() == 0 and ROOT.resolve() == ROOT and THEME.resolve() == THEME,
         'requires root and exact real staging paths')
    q = """SET SESSION TRANSACTION READ ONLY; START TRANSACTION WITH CONSISTENT SNAPSHOT;
SELECT JSON_OBJECTAGG(option_name,option_value) FROM stg_options WHERE option_name IN ('home','siteurl','template','stylesheet');
SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='cyberdat_staging' AND TABLE_NAME IN ('stg_posts','stg_postmeta') AND ENGINE='InnoDB'; ROLLBACK;"""
    r = subprocess.run(['/usr/bin/mariadb', '--no-defaults', '--protocol=SOCKET',
                        '--socket=/run/mysqld/mysqld.sock', '--user=root', '--skip-password',
                        '--batch', '--raw', '--skip-column-names', 'cyberdat_staging'],
                       input=q, text=True, capture_output=True, timeout=20)
    need(r.returncode == 0, 'read-only staging identity query failed')
    lines = r.stdout.strip().splitlines()
    need(len(lines) == 2 and lines[1] == '2', 'page restore requires two InnoDB tables')
    need(json.loads(lines[0]) == {'home': ORIGIN, 'siteurl': ORIGIN, 'template': 'cyberdat', 'stylesheet': 'cyberdat'},
         'staging database identity mismatch')
    config = (ROOT / 'wp-config.php').read_text()
    import re
    need(re.search(r"define\s*\(\s*['\"]WP_ENVIRONMENT_TYPE['\"]\s*,\s*['\"]staging['\"]", config),
         'explicit staging environment definition required')


def private_root_file(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink() and path.stat().st_uid == 0
         and not (stat.S_IMODE(path.stat().st_mode) & 0o027), 'unsafe private root-owned file')


def authorize(path, spec, package_path):
    private_root_file(path)
    a = json.loads(path.read_text())
    need(a.get('origin') == ORIGIN and a.get('research_commit') == RESEARCH
         and a.get('artifact_sha256') == spec['archive_sha256']
         and a.get('package_sha256') == digest(package_path)
         and a.get('install_approved') is True and a.get('legacy_interlocks_approved') is True
         and time.time() < a.get('expires_epoch', 0) <= time.time() + 86400,
         'no valid owner installation/legacy authorization; preparation is not installation approval')
    return a


PARENT_ARCHIVE = '5ce6c412c8444d36e9ac2f6960c4ee71c3cea7fec3dc0468afd0a4ee9317bc8b'
PARENT_PACKAGE = '3ec45c9198efad34c5a107a58144032bf31a0d32832e2c6dfefba7600516a65e'
HUB_REVISION = 'tools-hub-catalog-10-filter-counter/1'
INTEGRATION_REVISION = 'tools-wordpress-editorial-seo/1'
INTEGRATION_PARENT_ARCHIVE = '90992a0476df96ef622187ede08bb40638a6024441b13cdbe279008b0912d799'
INTEGRATION_PARENT_PACKAGE = 'da9a1a4b1847da4633f8d24287946e066510d8734b4c5642c7b32b12028731a5'
CANONICAL_REVISION = 'tools-staging-rank-math-canonical/1'
CANONICAL_PARENT_ARCHIVE = 'd7bc61591c833dbfcebb9d4fa02cf06b99dd8ba241c2fa1095763aa1e82e8edc'
CANONICAL_PARENT_PACKAGE = '98008bd5f9ee98f24da4a56ccf80b47f3b56c37330998005f6cc28bddc4f39fd'


def approved_release(spec, parent=None):
    if spec.get('research_commit') != RESEARCH or len(spec.get('target', {})) != 125:
        return False
    if len(spec.get('base', {})) == 95 and 'revision' not in spec:
        return True
    if spec.get('revision') == CANONICAL_REVISION and parent:
        before, after = spec.get('base', {}), spec.get('target', {})
        return (parent.get('archive_sha256') == CANONICAL_PARENT_ARCHIVE
                and spec.get('parent_archive_sha256') == CANONICAL_PARENT_ARCHIVE
                and before == parent.get('target') and len(before) == 125
                and set(before) == set(after)
                and [n for n in before if before[n] != after[n]] == ['inc/tools.php'])
    if spec.get('revision') == INTEGRATION_REVISION and parent:
        before, after = spec.get('base', {}), spec.get('target', {})
        return (parent.get('archive_sha256') == INTEGRATION_PARENT_ARCHIVE
                and spec.get('parent_archive_sha256') == INTEGRATION_PARENT_ARCHIVE
                and before == parent.get('target') and len(before) == 125
                and set(before) == set(after)
                and sorted(n for n in before if before[n] != after[n]) == ['inc/tools.php', 'page-templates/tool.php'])
    if spec.get('revision') != HUB_REVISION or not parent:
        return False
    before, after = spec.get('base', {}), spec.get('target', {})
    return (parent.get('archive_sha256') == PARENT_ARCHIVE
            and spec.get('parent_archive_sha256') == PARENT_ARCHIVE
            and before == parent.get('target') and len(before) == 125
            and set(before) == set(after)
            and [n for n in before if before[n] != after[n]] == ['page-templates/tools.php'])


def guard(spec):
    sql_read_identity()
    parent = None
    if spec.get('revision') in (HUB_REVISION, INTEGRATION_REVISION, CANONICAL_REVISION):
        p = HERE / 'parent-package.json'
        private_root_file(p)
        need(digest(p) == ({HUB_REVISION: PARENT_PACKAGE, INTEGRATION_REVISION: INTEGRATION_PARENT_PACKAGE, CANONICAL_REVISION: CANONICAL_PARENT_PACKAGE}[spec['revision']]), 'revision parent package SHA256 mismatch')
        parent = json.loads(p.read_text())
    need(approved_release(spec, parent), 'wrong pinned release or unapproved hotfix delta')
    protections = json.loads((HERE / 'protected-files.json').read_text())
    for name, sha in protections['files'].items():
        p = Path(name)
        need(not p.is_symlink() and digest(p) == sha, 'protected runtime drift: ' + name)


def checked_controls():
    need(HERE.parent == PRIVATE and HERE.name.startswith('release-') and HERE.resolve() == HERE,
         'controls must be sealed under the existing private staging allowlist')
    runtime = pwd.getpwnam('cyberdat-staging')
    for p in [Path('/opt'), Path('/opt/cyberdat-tools')]:
        need(p.resolve() == p and p.stat().st_uid == 0 and not (stat.S_IMODE(p.stat().st_mode) & 0o022),
             'control ancestors must be root-owned and non-writable to runtime users')
    for p in [PRIVATE, HERE]:
        need(p.stat().st_uid == 0 and p.stat().st_gid == runtime.pw_gid
             and stat.S_IMODE(p.stat().st_mode) == 0o750, 'unsafe private control directory')
    for p in HERE.iterdir():
        if p.is_file():
            private_root_file(p)
            need(p.stat().st_gid == runtime.pw_gid and stat.S_IMODE(p.stat().st_mode) == 0o640,
                 'helpers must be root:cyberdat-staging 0640')
        else:
            need(False, 'unexpected control subdirectory or link')
    return runtime


class Pages:
    def __init__(self, artifact_sha):
        self.artifact_sha = artifact_sha

    def call(self, mode, payload=None):
        # SQL identity precedes every bootstrap and every page/meta mutation.
        sql_read_identity()
        checked_controls()
        env = ['HOME=/var/lib/cyberdat-staging',
               'WP_CLI_CONFIG_PATH=/var/lib/cyberdat-staging/cli.yml',
               'CYBERDAT_TOOLS_ARTIFACT_SHA256=' + self.artifact_sha]
        cmd = ['/usr/sbin/runuser', '-u', 'cyberdat-staging', '--', '/usr/bin/env', *env,
               '/usr/bin/php8.4', '-d', 'memory_limit=192M', '-d', 'disable_functions=mail',
               '-d', 'sendmail_path=/bin/false', '-d', 'opcache.enable_cli=0',
               '-d', 'sys_temp_dir=/var/lib/cyberdat-staging/tmp', '-d',
               'open_basedir=/var/www/cyberdat-staging:/var/lib/cyberdat-staging:/var/log/cyberdat-staging:/run/mysqld:/etc/ssl/certs:/opt/cyberdat-tools:/etc/cyberdat-staging',
               '/opt/cyberdat-tools/wp-cli.phar', '--path=' + str(ROOT), '--no-color', '--skip-packages',
               '--skip-plugins=cyberdat-research,cyberdat-content',
               '--user=cyberdat_staging_admin', 'eval-file', str(HERE / 'wp-state.php'), mode]
        r = subprocess.run(cmd, input=json.dumps(payload) if payload else '', text=True,
                           capture_output=True, cwd='/var/lib/cyberdat-staging/research', timeout=60)
        need(r.returncode == 0 and not r.stderr.strip(), 'private staging WP-CLI operation failed; no raw output printed')
        return json.loads(r.stdout)

    def snapshot(self):
        return self.call('snapshot')

    def restore(self, before, expected):
        return self.call('restore', {'before': before, 'expected': expected})


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise RuntimeError('unexpected redirect; no credentials forwarded')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=['preflight', 'install', 'rollback', 'recover', 'record-pages', 'check-routes'])
    p.add_argument('--package', required=True, type=Path)
    p.add_argument('--authorization', type=Path)
    p.add_argument('--backup', type=Path)
    a = p.parse_args()
    spec = json.loads(a.package.read_text())
    guard(spec)
    runtime = pwd.getpwnam('cyberdat-staging')
    if a.mode == 'preflight':
        verify(THEME, spec['base'], (runtime.pw_uid, runtime.pw_gid))
        require_interlocks(json.loads((HERE / 'legacy-entrypoints.json').read_text())['installed_paths'])
        print('PASS: read-only staging identity, pinned Research, full base theme and legacy interlocks')
        return
    need(a.authorization is not None, 'explicit future installation authorization required')
    authorize(a.authorization, spec, a.package)
    if a.mode == 'install':
        owner = json.loads(a.authorization.read_text())
        need(all(owner.get('decisions', {}).get(k) is True for k in ['D6', 'D7']),
             'LotL static JS is served with the theme; resolve source/license decisions before installing it')
    checked_controls()
    require_interlocks(json.loads((HERE / 'legacy-entrypoints.json').read_text())['installed_paths'])
    need(a.backup is not None and a.backup.parent == BACKUPS and a.backup.name.startswith('tools-release-1-')
         and a.backup.resolve() == a.backup, 'unsafe Tools backup path')
    if a.backup.exists():
        need(a.backup.stat().st_uid == 0 and stat.S_IMODE(a.backup.stat().st_mode) == 0o700, 'unsafe backup ownership/mode')
    need(BACKUPS.stat().st_uid == 0 and stat.S_IMODE(BACKUPS.stat().st_mode) == 0o700, 'unsafe backup parent')
    os.umask(0o077)
    # This lock is exclusive to release operations. Collectors keep running.
    with acquire_lock('/run/lock/cyberdat-staging-tools-release-1.lock'):
        tx = Transaction(THEME, a.backup, spec, Pages(spec['archive_sha256']),
                         lambda: guard(spec), (runtime.pw_uid, runtime.pw_gid))
        if a.mode == 'install':
            need(shutil.disk_usage(THEME.parent).free > 256 * 1024 * 1024, 'insufficient release/backup space')
            tx.install(a.package.parent / 'theme.tar.gz')
        elif a.mode == 'rollback': tx.rollback()
        elif a.mode == 'recover': tx.recover()
        elif a.mode == 'record-pages': tx.record_pages()
        elif a.mode == 'check-routes':
            password = getpass.getpass('EXISTING staging HTTP Basic Auth password (hidden): ')
            auth = 'Basic ' + base64.b64encode(('cyberdat_staging_admin:' + password).encode()).decode()
            opener = urllib.request.build_opener(NoRedirect())
            def fetch(path):
                request = urllib.request.Request(ORIGIN + path, headers={'Authorization': auth})
                try:
                    with opener.open(request, timeout=20) as r: return r.status, r.read(2097152)
                except urllib.error.HTTPError as e: return e.code, e.read(2097152)
            validate(json.loads((THEME / 'inc/tools-catalog.json').read_text()), tx.pages.call('routes'), fetch)
        print('PASS: ' + a.mode + '; Research collectors/timers/checkpoints not changed by this command')


if __name__ == '__main__':
    try: main()
    except Exception as e:
        print('BLOCKED: ' + type(e).__name__ + ': ' + str(e))
        raise SystemExit(1)

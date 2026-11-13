#!/usr/bin/env python3
"""Owner-authorized D15 only: back up and prefix exactly 22 manifest files.

Never imports/executes a legacy script, loads WordPress, changes SQL or operates
systemd. systemctl show and fixed SELECT queries are read-only evidence.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from safe_theme import need, digest, save, acquire_lock, syncdir
from legacy_guard import GUARD, require_interlocks

WORK = Path('/home/cyberdat/cyberdat-deploy/tools-release-1-safe-work')
BACKUPS = Path('/var/backups/cyberdat-staging')
THEME = Path('/var/www/cyberdat-staging/public/wp-content/themes/cyberdat')
NAMES = ['kev', 'nvd', 'cisa-advisories', 'cert-eu', 'msrc', 'dispatch']


def utc(): return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sql_snapshot():
    query = """SET SESSION TRANSACTION READ ONLY; START TRANSACTION WITH CONSISTENT SNAPSHOT;
SELECT JSON_OBJECT('identity',JSON_OBJECTAGG(option_name,option_value)) FROM stg_options WHERE option_name IN ('home','siteurl','template','stylesheet');
SELECT JSON_OBJECT('counts',JSON_OBJECT('queue',(SELECT COUNT(*) FROM stg_cdra_items),'nvd',(SELECT COUNT(*) FROM stg_cdra_items WHERE source='nvd'),'posts',(SELECT COUNT(*) FROM stg_posts),'content_jobs',(SELECT COUNT(*) FROM stg_cdca_jobs),'content_versions',(SELECT COUNT(*) FROM stg_cdca_versions)));
SELECT JSON_OBJECT('key',state_key,'checkpoint',CASE WHEN state_key LIKE '%checkpoint%' THEN JSON_EXTRACT(payload,'$') ELSE NULL END,'last_success',JSON_EXTRACT(payload,'$.last_success'),'last_scheduled_success',JSON_EXTRACT(payload,'$.last_scheduled_success'),'last_error',JSON_EXTRACT(payload,'$.last_error'),'next_due',JSON_EXTRACT(payload,'$.next_due')) FROM stg_cdra_state WHERE state_key IN ('nvd_checkpoint','discovery_checkpoint:crossref','health:nvd','health:crossref');
ROLLBACK;"""
    r = subprocess.run(['/usr/bin/mariadb', '--no-defaults', '--protocol=SOCKET',
                        '--socket=/run/mysqld/mysqld.sock', '--user=root', '--skip-password',
                        '--batch', '--raw', '--skip-column-names', 'cyberdat_staging'],
                       input=query, text=True, capture_output=True, timeout=20)
    need(r.returncode == 0, 'read-only SQL evidence failed; no raw output printed')
    rows = [json.loads(x) for x in r.stdout.splitlines()]
    need(rows[0]['identity'] == {'home': 'https://staging.cyberdat.eu',
         'siteurl': 'https://staging.cyberdat.eu', 'template': 'cyberdat', 'stylesheet': 'cyberdat'},
         'staging SQL identity mismatch')
    return rows


def snapshot():
    need(THEME.resolve() == THEME, 'unsafe staging theme path')
    spec = json.loads((HERE / 'manifest.json').read_text())
    actual = {p.relative_to(THEME).as_posix(): digest(p) for p in THEME.rglob('*') if p.is_file()}
    need(actual == {k: v['sha256'] for k, v in spec['base'].items()}, 'staging95 theme drift; D1 not authorized')
    protected = json.loads((HERE / 'protected-files.json').read_text())['files']
    need(all(digest(p) == h for p, h in protected.items()), 'Research/Content/unit/launcher drift')
    units = {}
    for name in NAMES:
        entry = {}
        for kind, unit in [('timer', 'cyberdat-research-' + name + '.timer'),
                           ('service', 'cyberdat-research@' + name + '.service')]:
            r = subprocess.run(['/usr/bin/systemctl', 'show', unit,
                '--property=ActiveState,Result,ExecMainStatus,ExecStart,WorkingDirectory,LastTriggerUSec,NextElapseUSecRealtime'],
                capture_output=True, text=True, timeout=10)
            need(r.returncode == 0, 'read-only unit inspection failed')
            entry[kind] = dict(l.split('=', 1) for l in r.stdout.splitlines() if '=' in l)
        need(entry['timer'].get('ActiveState') == 'active', 'Research timer not active')
        need('/opt/cyberdat-research/run.sh ' + name in entry['service'].get('ExecStart', ''),
             'unexpected scheduled entry point')
        need(entry['service'].get('WorkingDirectory') == '/var/lib/cyberdat-staging/research',
             'unexpected service working directory')
        units[name] = entry
    return {'utc': utc(), 'theme95_sha256': actual, 'protected43_sha256': protected,
            'units': units, 'sql_read_only': sql_snapshot()}


def active_legacy(paths):
    wanted = {str(Path(p)) for p in paths}; hits = []
    for p in Path('/proc').iterdir():
        if not p.name.isdigit() or int(p.name) == os.getpid(): continue
        try:
            args = (p / 'cmdline').read_bytes().split(b'\0')
            cwd = (p / 'cwd').resolve()
            for arg in args[1:]:
                if not arg or arg.startswith(b'-'): continue
                name = Path(os.fsdecode(arg))
                candidate = name if name.is_absolute() else cwd / name
                if str(candidate) in wanted: hits.append({'pid': int(p.name), 'path': str(candidate)})
        except (OSError, UnicodeError): pass
    return hits


def candidate(raw):
    lines = raw.splitlines(keepends=True); i = int(lines[0].startswith(b'#!'))
    return b''.join(lines[:i]) + GUARD.encode() + b''.join(lines[i:])


def replace_checked(path, data, entry):
    need(digest(path) == entry['before'], 'target changed during maintenance')
    tmp = path.with_name(path.name + '.d15-partial')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, entry['mode'])
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
            os.fchown(f.fileno(), entry['uid'], entry['gid']); os.fchmod(f.fileno(), entry['mode'])
        need(digest(path) == entry['before'], 'target changed before atomic replacement')
        os.replace(tmp, path); syncdir(path.parent)
    except BaseException:
        # Preserve evidence; do not run any old deployment/rollback or delete backups.
        raise


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--apply-d15', action='store_true'); args = ap.parse_args()
    need(os.geteuid() == 0 and HERE == WORK / 'deploy/tools-release-1', 'owner sudo and exact work path required')
    plan = json.loads((HERE / 'd15-plan.json').read_text())
    manifest = json.loads((HERE / 'legacy-entrypoints.json').read_text())
    need(plan['base_commit'] == '731c9cd1557c828520abce059eeced36f65d3141', 'wrong D15 base')
    need(len(manifest['repository_scripts']) == len(manifest['installed_paths']) == 11, 'scope changed')
    approved = []
    for repo, prepared in zip(manifest['repository_scripts'], manifest['installed_paths']):
        approved.extend([('repository', str(WORK / repo)), ('prepared', prepared)])
    need([(x['kind'], x['path']) for x in plan['targets']] == approved, 'unapproved target list')
    need(digest(HERE / 'legacy_guard.py') == plan['guard_module_sha256']
         and hashlib.sha256(GUARD.encode()).hexdigest() == plan['guard_sha256'], 'interlock changed')
    need(not active_legacy([p for _, p in approved]), 'active legacy process; stop before changes')
    originals = []
    for e in plan['targets']:
        p = Path(e['path']); st = p.lstat()
        need(p.resolve() == p and stat.S_ISREG(st.st_mode) and not p.is_symlink(), 'unsafe target path')
        raw = p.read_bytes(); data = candidate(raw)
        need(hashlib.sha256(raw).hexdigest() == e['before'] and hashlib.sha256(data).hexdigest() == e['after'],
             'entry point differs from approved preimage')
        need((st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode)) == (e['uid'], e['gid'], e['mode']), 'target metadata changed')
        compile(data, str(p), 'exec'); originals.append((e, raw, data))
    before = snapshot()
    if not args.apply_d15:
        print(json.dumps({'preflight': 'PASS', 'entrypoints': 11, 'files': 22, 'writes': False})); return
    need(BACKUPS.is_dir() and not BACKUPS.is_symlink() and BACKUPS.stat().st_uid == 0
         and stat.S_IMODE(BACKUPS.stat().st_mode) == 0o700, 'unsafe backup parent')
    with acquire_lock('/run/lock/cyberdat-staging-tools-release-1.lock'):
        need(not active_legacy([p for _, p in approved]), 'legacy became active; no scripts changed')
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        backup = BACKUPS / ('tools-d15-' + stamp); backup.mkdir(mode=0o700)
        save(backup / 'before.json', before); save(backup / 'plan.json', plan)
        for i, (e, raw, data) in enumerate(originals):
            p = backup / (str(i).zfill(2) + '.py'); p.write_bytes(raw); p.chmod(0o600)
            with p.open('rb') as f: os.fsync(f.fileno())
            need(digest(p) == e['before'], 'backup checksum failed')
        sums = {p.name: digest(p) for p in backup.iterdir() if p.is_file()}
        save(backup / 'checksums.json', sums); syncdir(backup)
        print('BACKUP: ' + str(backup), flush=True)
        result = {'status': 'APPLYING', 'backup': str(backup), 'started_utc': utc(), 'patched': []}
        save(backup / 'result.json', result)
        try:
            for e, raw, data in originals:
                replace_checked(Path(e['path']), data, e)
                need(digest(e['path']) == e['after'], 'post-write checksum mismatch')
                require_interlocks([e['path']]); result['patched'].append(e['path'])
                save(backup / 'result.json', result)
            after = snapshot(); save(backup / 'after.json', after)
            need(after['theme95_sha256'] == before['theme95_sha256']
                 and after['protected43_sha256'] == before['protected43_sha256'], 'protected drift after maintenance')
            result.update(status='PASS', completed_utc=utc(), entrypoints=11, protected_copies=11,
                          sql_write=False, wordpress_bootstrap=False, legacy_execution=False,
                          theme_or_collector_or_timer_changed=False)
            save(backup / 'result.json', result); print(json.dumps(result))
        except BaseException:
            result['status'] = 'PARTIAL_RETAINED'; save(backup / 'result.json', result); raise


if __name__ == '__main__':
    try: main()
    except Exception as e:
        print('BLOCKED: D15: ' + type(e).__name__ + ': ' + str(e)); raise SystemExit(1)

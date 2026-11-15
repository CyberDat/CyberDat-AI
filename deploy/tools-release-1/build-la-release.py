#!/usr/bin/env python3
"""Compose the owner-approved six-file Unicode delta over the accepted Hub.

Offline preparation only. No installed WordPress paths or database calls.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time
sys.dont_write_bytecode = True
D = Path(__file__).resolve().parent
sys.path.insert(0, str(D))
from safe_theme import need, digest, manifest, lint, save


def module(name, path):
    s = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


live = module('la_live', D / 'deploy-theme.py')
archive = module('la_archive', D / 'build-package.py').archive
FILES = {'deploy-theme.py', 'safe_theme.py', 'legacy_guard.py', 'route_policy.py',
         'staging-contract.php', 'wp-state.php', 'tool-pages.php',
         'protected-files.json', 'legacy-entrypoints.json', 'editorial-integration.json'}


def git(git_binary, *args):
    r = subprocess.run([git_binary, '-C', str(D.parents[1]), *args],
                       capture_output=True, timeout=30)
    need(r.returncode == 0, 'source Git verification failed')
    return r.stdout


def package(parent_dir, git_binary, output):
    need(not output.exists(), 'fresh package output required')
    need(digest(parent_dir / 'theme.tar.gz') == live.LA_PARENT_ARCHIVE
         and digest(parent_dir / 'package.json') == live.LA_PARENT_PACKAGE,
         'accepted Hub parent artifact mismatch')
    parent = json.loads((parent_dir / 'package.json').read_text())
    theme = D.parents[1] / 'wp-content/themes/cyberdat'
    source = git(git_binary, 'rev-parse', 'HEAD').decode().strip()
    expected = git(git_binary, 'ls-tree', '-rz', '--full-tree', source,
                   'wp-content/themes/cyberdat').split(b'\0')
    blobs = {}
    for entry in expected:
        if not entry:
            continue
        meta, path = entry.split(b'\t')
        mode, kind, sha = meta.split()
        need(mode == b'100644' and kind == b'blob', 'source links/executables refused')
        blobs[path.decode().split('wp-content/themes/cyberdat/', 1)[1]] = sha.decode()
    full = manifest(theme)
    need(set(full) == set(blobs), 'source file set drift')
    for name, sha in blobs.items():
        b = (theme / name).read_bytes()
        need(hashlib.sha1(b'blob ' + str(len(b)).encode() + b'\0' + b).hexdigest() == sha,
             'uncommitted theme bytes: ' + name)
    excluded = {'assets/images/tools-hub/README.md'}
    need(excluded <= set(full), 'source illustration README missing')
    target = {n: v for n, v in full.items() if n not in excluded}
    spec = {**parent, 'revision': live.LA_REVISION, 'parent_archive_sha256': live.LA_PARENT_ARCHIVE,
            'base': parent['target'], 'target': target, 'candidate_commit': live.LA_CANDIDATE,
            'theme_commit': source, 'excluded_source_files': sorted(excluded)}
    need(live.approved_release(spec, parent), 'not the exact approved six-file delta')
    count = lint(theme)
    output.mkdir(mode=0o700)
    archive(theme, target, output / 'theme.tar.gz')
    spec.update(archive_sha256=digest(output / 'theme.tar.gz'),
                theme_tree_sha1=git(git_binary, 'rev-parse', source + ':wp-content/themes/cyberdat').decode().strip())
    save(output / 'package.json', spec)
    (output / 'parent-package.json').write_bytes((parent_dir / 'package.json').read_bytes())
    save(output / 'manifest.json', {'base': spec['base'], 'target': target})
    (output / 'SHA256SUMS').write_text(''.join(digest(output / n) + '  ' + n + '\n'
        for n in ['theme.tar.gz', 'package.json', 'parent-package.json', 'manifest.json']))
    return {'files': len(target), 'modified': sorted(live.LA_TARGET_SHA256), 'unchanged': 131,
            'added': [], 'removed': [], 'php_linted': count,
            'archive_sha256': spec['archive_sha256'], 'package_sha256': digest(output / 'package.json')}


def controls(approval, package_dir, authorization, output):
    need(not output.exists(), 'fresh controls output required')
    pins = json.loads(approval.read_text())
    need(set(pins['files']) == FILES, 'exact helper approval required')
    payload = {}
    for name, sha in pins['files'].items():
        p = D / name
        need(p.is_file() and not p.is_symlink() and digest(p) == sha,
             'unreviewed helper bytes: ' + name)
        b = p.read_bytes()
        if p.suffix == '.py':
            compile(b, str(p), 'exec')
        payload[name] = b
    need(digest(package_dir / 'parent-package.json') == live.LA_PARENT_PACKAGE,
         'parent manifest checksum mismatch')
    spec = json.loads((package_dir / 'package.json').read_text())
    parent = json.loads((package_dir / 'parent-package.json').read_text())
    need(live.approved_release(spec, parent)
         and digest(package_dir / 'theme.tar.gz') == spec['archive_sha256'],
         'unapproved package scope or archive drift')
    a = json.loads(authorization.read_text())
    need(a['origin'] == live.ORIGIN and a['research_commit'] == live.RESEARCH
         and a['artifact_sha256'] == spec['archive_sha256']
         and a['package_sha256'] == digest(package_dir / 'package.json')
         and a['install_approved'] is True and a['legacy_interlocks_approved'] is True
         and all(a['decisions'].get(n) is True for n in ['D6', 'D7'])
         and time.time() < a['expires_epoch'] <= time.time() + 86400
         and a['page_approvals'] == {n: [] for n in ['draft', 'reviewed', 'publish']},
         'missing exact owner authorization; no page actions allowed')
    payload.update({n: (package_dir / n).read_bytes()
                    for n in ['package.json', 'parent-package.json', 'theme.tar.gz']})
    payload['authorization.json'] = authorization.read_bytes()
    output.mkdir(mode=0o700)
    for name, data in payload.items():
        (output / name).write_bytes(data)
        (output / name).chmod(0o640)
    save(output / 'controls-sha256.json', {n: digest(output / n) for n in sorted(payload)})
    (output / 'controls-sha256.json').chmod(0o640)
    return {'files': len(payload), 'controls_sha256': digest(output / 'controls-sha256.json')}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('mode', choices=['package', 'controls'])
    p.add_argument('--parent', type=Path)
    p.add_argument('--git', dest='git_binary')
    p.add_argument('--approval', type=Path)
    p.add_argument('--authorization', type=Path)
    p.add_argument('--package', type=Path)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    print(json.dumps(package(a.parent, a.git_binary, a.output) if a.mode == 'package'
                     else controls(a.approval, a.package, a.authorization, a.output)))
